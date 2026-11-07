// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T307 acceptance, the ACL matrix end to end: the gateway's visibility rules (advisory) times the target daemon's
// own allowlist (the authority), with the real gateway (`wrangler dev`, real Durable Objects, a mock IdP) and real
// `parleyd` processes. The target publishes a card in each visibility mode; three callers try `parley-cli test`
// against it: a second device of the target's owner, a device of another owner who is in the card's group, and a
// device of a third owner who is in no group. The test bot's allowlist is the target's own owner, so what each
// caller meets is one of three outcomes, told apart by the reason the CLI reports:
//   PASS     the gateway shows the target and the daemon allows the caller;
//   refused  the gateway let the request through (the card is visible, or there is nothing to hide) and the DAEMON
//            said no: the gateway's "visible" granted nothing;
//   hidden   the gateway would not carry the request ("offline", the same answer as for a device that is not
//            there): the daemon never saw it. The caller's daemon waits for an offline target until the task expires,
//            so this outcome shows up when the CLI's timeout (20 s here) runs out; PASS and refused take about a second.
// The rows cover no card, tenant, private, a group the caller is in, a group the caller is not in, a group that
// was deleted and a group that is empty, and the rows change while the daemons run (visibility follows the
// admin's edits at once). Nothing a caller does reaches PASS unless it is the owner's own device.
//
// The test reads the target's device key from its home directory (key store "file") to publish the cards as the
// target does. That is test-only access to a key the test itself created for a throwaway pod.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, createPrivateKey, sign as cryptoSign } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { connectToken, registerRoot, signBinding, signRevocations, startGateway } from "./harness/gateway.mjs";

const repo = join(fileURLToPath(import.meta.url), "..", "..");
const isWindows = process.platform === "win32";
const wrangler = join(repo, "gateway", "node_modules", ".bin", isWindows ? "wrangler.cmd" : "wrangler");
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const missing = !haveGo ? "go not installed" : !existsSync(wrangler) ? "gateway dependencies not installed (cd gateway && npm ci)" : "";
const opts = missing ? { skip: process.env.CI ? false : missing, timeout: 420000 } : { timeout: 420000 };

// Go's root.Fingerprint: the first 26 base32 characters of SHA-256(public key), in groups of four.
function fingerprint(pub) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const b of createHash("sha256").update(pub).digest()) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; out.length < 26; i += 5) out += alphabet[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return out.match(/.{1,4}/g).join("-");
}

const post = async (url, path, token, body) => {
  const res = await fetch(`${url}${path}`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => ({})) };
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function capture(child) {
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  const done = new Promise((resolve) => child.on("close", (code) => resolve({ code, out })));
  return { child, done, output: () => out };
}

// What a caller met, from the CLI's own words (cmd/parley-cli/test.go reasonHint): the daemon's refusal names the
// test bot's owner rule; a gateway that would not carry the request reads as an unreachable device.
function outcome(r) {
  if (r.code === 0 && /PASS: the other device answered/.test(r.out)) return "PASS";
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /FAIL/);
  assert.doesNotMatch(r.out, /PASS/);
  if (/the test bot answers only devices of its own owner/.test(r.out)) return "refused";
  if (/was not reachable/.test(r.out)) return "hidden";
  return `other: ${r.out}`;
}

// The Ed25519 private key a file key store keeps as hex of the 32-byte seed (internal/keystore).
function deviceFrom(home, id, version) {
  const seed = Buffer.from(readFileSync(join(home, "device.key"), "utf8").trim(), "hex");
  assert.equal(seed.length, 32);
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  return { id, version, sign: (msg) => cryptoSign(null, msg, key) };
}

// Rows: the card the target publishes (or none), the groups that exist, and what each caller meets.
// Callers: own = a second device of the target's owner; member = another owner in group "eng" when it has members;
// stranger = a third owner in no group.
const ROWS = [
  { name: "no card published", card: null, groups: {}, own: "PASS", member: "refused", stranger: "refused" },
  { name: "tenant-wide card", card: { visibility: "tenant" }, groups: {}, own: "PASS", member: "refused", stranger: "refused" },
  { name: "private card", card: { visibility: "private" }, groups: {}, own: "PASS", member: "hidden", stranger: "hidden" },
  { name: "group card, caller in the group", card: { visibility: "groups", groups: ["eng"] }, groups: { eng: ["svc-member"] }, own: "PASS", member: "refused", stranger: "hidden" },
  { name: "group card, group is empty", card: { visibility: "groups", groups: ["eng"] }, groups: { eng: [] }, own: "PASS", member: "hidden", stranger: "hidden" },
  { name: "group card, group does not exist", card: { visibility: "groups", groups: ["eng"] }, groups: null, own: "PASS", member: "hidden", stranger: "hidden" },
  { name: "group card, the caller's group is another one", card: { visibility: "groups", groups: ["ops"] }, groups: { eng: ["svc-member"], ops: ["svc-nobody"] }, own: "PASS", member: "hidden", stranger: "hidden" },
  { name: "tenant-wide again, after the group edits", card: { visibility: "tenant" }, groups: null, own: "PASS", member: "refused", stranger: "refused" },
];

test("T307: ACL matrix: gateway visibility x the target daemon's allowlist, real gateway and real daemons", opts, async (t) => {
  const bin = mkdtempSync(join(tmpdir(), "parley-bin-"));
  const homes = [];
  const exe = (n) => join(bin, isWindows ? `${n}.exe` : n);
  for (const n of ["parley-cli", "parleyd"]) {
    const built = spawnSync("go", ["build", "-o", exe(n), `./cmd/${n}`], { cwd: repo, encoding: "utf8" });
    assert.equal(built.status, 0, built.stderr);
  }
  const gw = await startGateway({ admins: "acme:admin@acme.test" });
  const daemons = [];
  try {
    const admin = (await gw.signIn({ tenant: "acme", role: "admin", email: "admin@acme.test" })).token;
    const rootKey = await registerRoot(gw.url, admin);
    const fp = fingerprint(rootKey.publicKey);
    assert.equal((await post(gw.url, "/v1/admin/revocations", admin, { list: signRevocations(rootKey, { tenant: "acme" }) })).status, 200);

    const cli = (home, args, env = {}) => capture(spawn(exe("parley-cli"), args, { env: { ...process.env, PARLEY_HOME: home, ...env }, stdio: ["ignore", "pipe", "pipe"] }));
    const waitFor = async (what, f, n = 300) => {
      for (let i = 0; i < n; i++) {
        const v = await f();
        if (v) return v;
        await sleep(100);
      }
      assert.fail(`timed out waiting for ${what}`);
    };
    const enrolled = new Set();
    const enroll = async (owner) => {
      const home = mkdtempSync(join(tmpdir(), "parley-home-"));
      homes.push(home);
      const token = (await post(gw.url, "/v1/admin/enrollment-tokens", admin, { owner })).body.token;
      const run = cli(home, ["enroll", "-token", "-gateway", gw.url, "-tenant", "acme", "-root", fp, "-name", `pod-${owner}`, "-key-store", "file"], { PARLEY_ENROLL_TOKEN: token });
      const req = await waitFor("the enrollment request", async () => (await post(gw.url, "/v1/admin/enrollments", admin, {})).body.pending?.find((p) => p.owner === owner && !p.decided && !enrolled.has(p.id)));
      enrolled.add(req.id);
      assert.equal((await post(gw.url, "/v1/admin/enrollments/decide", admin, { id: req.id, decision: "approved" })).status, 200);
      const b = signBinding(rootKey, { tenant: "acme", owner, id: req.id, publicKey: Buffer.from(req.signing_key, "base64") });
      assert.equal((await post(gw.url, "/v1/admin/bindings", admin, { id: req.id, binding: b })).status, 200);
      const ok = await run.done;
      assert.equal(ok.code, 0, ok.out);
      return { home, id: req.id };
    };

    const target = await enroll("svc-owner");
    const own = await enroll("svc-owner");
    const member = await enroll("svc-member");
    const stranger = await enroll("svc-stranger");
    const all = { target, own, member, stranger };
    for (const d of Object.values(all)) {
      const p = capture(spawn(exe("parleyd"), [], { env: { ...process.env, PARLEY_HOME: d.home }, stdio: ["ignore", "pipe", "pipe"] }));
      daemons.push(p);
    }
    await waitFor("the daemons to answer on their sockets", async () => {
      for (const d of daemons) assert.equal(d.child.exitCode, null, `a daemon exited early (${d.child.exitCode}):\n${d.output()}`);
      return (await Promise.all(Object.values(all).map((d) => cli(d.home, ["list"]).done))).every((r) => r.code === 0);
    }, 450);

    // The target publishes as itself: a card for its bot, replaced in place each row (same name).
    const targetDevice = deviceFrom(target.home, target.id, 1);
    const publish = async (card) => {
      const tok = await connectToken(gw.url, "acme", targetDevice, { scope: "api" });
      assert.equal(tok.status, 200, JSON.stringify(tok.body));
      const r = await post(gw.url, "/v1/cards/publish", tok.body.token, { card: { name: "Reviewer", description: "Reviews diffs", tags: ["review"], examples: ["review this"], ...card } });
      assert.equal(r.status, 200, JSON.stringify(r.body));
    };
    let live = new Set();
    const setGroups = async (groups) => {
      for (const g of live) assert.equal((await post(gw.url, "/v1/admin/groups/delete", admin, { name: g })).status, 200);
      live = new Set();
      for (const [name, members] of Object.entries(groups ?? {})) {
        assert.equal((await post(gw.url, "/v1/admin/groups/put", admin, { name, members })).status, 200);
        live.add(name);
      }
    };

    const seen = [];
    for (const row of ROWS) {
      await setGroups(row.groups);
      if (row.card) await publish(row.card);
      // The three callers go at once: nothing one of them meets depends on another.
      const results = await Promise.all(
        ["own", "member", "stranger"].map(async (who) => {
          const at = Date.now();
          const r = outcome(await cli(all[who].home, ["test", "-to", target.id, "-timeout", "20s"]).done);
          t.diagnostic(`${row.name} / ${who}: ${r} in ${Date.now() - at} ms`);
          return [who, r];
        }),
      );
      // A daemon that died says so, with its own output, instead of the row failing as "not reachable". The exit event comes
      // before the pipes are drained, so wait for the close (done) before reading what it printed last.
      for (const [i, d] of daemons.entries()) {
        if (d.child.exitCode === null && d.child.signalCode === null) continue;
        const { out } = await d.done;
        assert.fail(`daemon ${i} (pid ${d.child.pid}) exited (${d.child.exitCode}, signal ${d.child.signalCode}) at ${new Date().toISOString()} during "${row.name}":\n${out}`);
      }
      for (const [who, got] of results) {
        seen.push(`${row.name} / ${who}: ${got}`);
        assert.equal(got, row[who], `${row.name}: ${who} met ${got}, want ${row[who]}\n${daemons.map((d, i) => `--- daemon ${i}\n${d.output()}`).join("\n")}`);
      }
    }

    // The matrix saw every outcome, and only the owner's own device ever got through.
    assert.ok(seen.some((s) => s.endsWith("PASS")) && seen.some((s) => s.endsWith("refused")) && seen.some((s) => s.endsWith("hidden")), seen.join("\n"));
    assert.deepEqual(seen.filter((s) => s.endsWith("PASS") && !s.includes(" / own:")), []);
    assert.equal(seen.length, ROWS.length * 3);
  } finally {
    const codes = [];
    for (const d of daemons) {
      d.child.kill("SIGTERM");
      codes.push(await Promise.race([d.done.then((r) => r.code), sleep(15000).then(() => "hung")]));
      d.child.kill("SIGKILL");
    }
    await gw.close();
    for (const dir of [bin, ...homes, gw.state, gw.log]) rmSync(dir, { recursive: true, force: true });
    if (!isWindows) assert.deepEqual(codes.filter((c) => c !== 0 && c !== null), [], "a daemon did not shut down cleanly");
  }
});
