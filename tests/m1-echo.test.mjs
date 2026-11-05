// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Milestone M1 (T414) end to end against the real gateway (`wrangler dev`, real Durable Objects, a mock IdP): real
// `parleyd` processes and the real `parley-cli`. The test plays the admin: it registers the root, posts the signed
// revocation list, and approves each device and posts its root-signed binding. Nothing in the daemons is injected:
// they connect with connect tokens, find each other's bindings through the gateway, exchange prekeys over the live
// relay, and `parley-cli test` sends a sealed task to the other daemon's test bot and checks the sealed echo.
//  1. Two devices of one owner: the test passes.
//  2. A device of another owner: the test bot refuses it (the target's own allowlist), the test fails, and the
//     bot of the owner's other device never sees it.
//  3. A device id the gateway does not know: the test fails at once.
//  4. A daemon that is not running: the test says so.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { registerRoot, signBinding, signRevocations, startGateway } from "./harness/gateway.mjs";

const repo = join(fileURLToPath(import.meta.url), "..", "..");
const isWindows = process.platform === "win32";
const wrangler = join(repo, "gateway", "node_modules", ".bin", isWindows ? "wrangler.cmd" : "wrangler");
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const missing = !haveGo ? "go not installed" : !existsSync(wrangler) ? "gateway dependencies not installed (cd gateway && npm ci)" : "";
const opts = missing ? { skip: process.env.CI ? false : missing, timeout: 240000 } : { timeout: 240000 };

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

test("M1/T414: parley-cli test between two real daemons through the real gateway", opts, async (t) => {
  const bin = mkdtempSync(join(tmpdir(), "parley-bin-"));
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
    const list = signRevocations(rootKey, { tenant: "acme" });
    assert.equal((await post(gw.url, "/v1/admin/revocations", admin, { list })).status, 200);

    const cli = (home, args, env = {}) => capture(spawn(exe("parley-cli"), args, { env: { ...process.env, PARLEY_HOME: home, ...env }, stdio: ["ignore", "pipe", "pipe"] }));
    const waitFor = async (what, f, n = 300) => {
      for (let i = 0; i < n; i++) {
        const v = await f();
        if (v) return v;
        await sleep(100);
      }
      assert.fail(`timed out waiting for ${what}`);
    };
    // A pod enrolls with an admin-minted token; the admin (this test) approves it and posts its binding.
    const enroll = async (owner) => {
      const home = mkdtempSync(join(tmpdir(), "parley-home-"));
      const token = (await post(gw.url, "/v1/admin/enrollment-tokens", admin, { owner })).body.token;
      const run = cli(home, ["enroll", "-token", "-gateway", gw.url, "-tenant", "acme", "-root", fp, "-name", `pod-${owner}`, "-key-store", "file"], { PARLEY_ENROLL_TOKEN: token });
      const req = await waitFor("the enrollment request", async () => (await post(gw.url, "/v1/admin/enrollments", admin, {})).body.pending?.find((p) => p.owner === owner && !p.decided && !enrolled.has(p.id)));
      enrolled.add(req.id);
      assert.equal((await post(gw.url, "/v1/admin/enrollments/decide", admin, { id: req.id, decision: "approved" })).status, 200);
      const b = signBinding(rootKey, { tenant: "acme", owner, id: req.id, publicKey: Buffer.from(req.signing_key, "base64") });
      assert.equal((await post(gw.url, "/v1/admin/bindings", admin, { id: req.id, binding: b })).status, 200);
      const ok = await run.done;
      assert.equal(ok.code, 0, ok.out);
      assert.equal(JSON.parse(readFileSync(join(home, "config.json"), "utf8")).device_id, req.id);
      return { home, id: req.id };
    };
    const enrolled = new Set();
    const startDaemon = (d) => {
      const p = capture(spawn(exe("parleyd"), [], { env: { ...process.env, PARLEY_HOME: d.home }, stdio: ["ignore", "pipe", "pipe"] }));
      daemons.push(p);
      return p;
    };

    const a = await enroll("svc-ci");
    const b = await enroll("svc-ci");
    const c = await enroll("svc-other");

    // 4. No daemon is running yet: the test says so, and does not hang.
    const down = await cli(a.home, ["test", "-to", b.id]).done;
    assert.equal(down.code, 1, down.out);
    assert.match(down.out, /not running or not reachable/);

    const [da, db, dc] = [startDaemon(a), startDaemon(b), startDaemon(c)];
    await waitFor("the daemons' sockets", () => [a, b, c].every((d) => existsSync(join(d.home, "parleyd.sock"))));

    // 1. Two devices of one owner.
    const pass = await cli(a.home, ["test", "-to", b.id, "-timeout", "90s"]).done;
    assert.equal(pass.code, 0, `${pass.out}\n--- a\n${da.output()}\n--- b\n${db.output()}`);
    assert.match(pass.out, /PASS: the other device answered, end to end encrypted/);
    // And back the other way, from the second device.
    const back = await cli(b.home, ["test", "-to", a.id, "-timeout", "90s"]).done;
    assert.equal(back.code, 0, back.out);

    // 2. Another owner's device is refused by the target's own allowlist.
    const refused = await cli(c.home, ["test", "-to", b.id, "-timeout", "30s"]).done;
    assert.equal(refused.code, 1, refused.out);
    assert.match(refused.out, /FAIL/);
    assert.match(refused.out, /owner/);
    assert.doesNotMatch(refused.out, /PASS/);

    // 3. A device the gateway does not know.
    const unknown = await cli(a.home, ["test", "-to", "f".repeat(32), "-timeout", "30s"]).done;
    assert.equal(unknown.code, 1, unknown.out);
    assert.match(unknown.out, /FAIL/);

    // Nothing the daemons log carries a task text or a key.
    for (const d of [da, db, dc]) assert.doesNotMatch(d.output(), /parley-test [0-9a-f]{32}|parley echo/);
  } finally {
    for (const d of daemons) {
      d.child.kill("SIGTERM");
      await Promise.race([d.done, sleep(5000)]);
      d.child.kill("SIGKILL");
    }
    await gw.close();
  }
});
