// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T411 end to end against the real gateway (`wrangler dev`, real Durable Objects, a mock IdP). The test plays the
// admin (approves requests and posts bindings signed by the registered root) and, for the sign-in, the user's browser.
//  1. The real `parley-cli enroll -token` binary: a wrong fingerprint is refused, a pod enrolls, a pod killed while
//     waiting resumes with the same request and key, and the replace flow.
//  2. The Go sign-in and enrollment code (internal/enroll TestAgainstWorker) through the gateway's device login:
//     the "browser" follows the printed address through the mock IdP, reads the code from the confirmation page,
//     and posts the form; then it approves the enrollment that follows.
// (The employee-enrollment journey row stays planned: "device shows online" is not part of this test.)

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { registerRoot, signBinding, startGateway } from "./harness/gateway.mjs";

const repo = join(fileURLToPath(import.meta.url), "..", "..");
const isWindows = process.platform === "win32";
const wrangler = join(repo, "gateway", "node_modules", ".bin", isWindows ? "wrangler.cmd" : "wrangler");
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const missing = !haveGo ? "go not installed" : !existsSync(wrangler) ? "gateway dependencies not installed (cd gateway && npm ci)" : "";
const opts = missing ? { skip: process.env.CI ? false : missing } : {};

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

test("T411: parley-cli enroll against the real gateway: pod token, wrong fingerprint, restart while waiting, replace", opts, async (t) => {
  const bin = join(mkdtempSync(join(tmpdir(), "parley-bin-")), isWindows ? "parley-cli.exe" : "parley-cli");
  const built = spawnSync("go", ["build", "-o", bin, "./cmd/parley-cli"], { cwd: repo, encoding: "utf8" });
  assert.equal(built.status, 0, built.stderr);

  const gw = await startGateway({ admins: "acme:admin@acme.test" });
  try {
    const admin = (await gw.signIn({ tenant: "acme", role: "admin", email: "admin@acme.test" })).token;
    const rootKey = await registerRoot(gw.url, admin);
    const fp = fingerprint(rootKey.publicKey);
    const mint = async () => (await post(gw.url, "/v1/admin/enrollment-tokens", admin, { owner: "svc-ci" })).body.token;

    const cli = (home, args, env = {}) => {
      const child = spawn(bin, args, { env: { ...process.env, PARLEY_HOME: home, ...env }, stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (out += d));
      const done = new Promise((resolve) => child.on("close", (code) => resolve({ code, out })));
      return { child, done, output: () => out };
    };
    const podEnroll = (home, extra = [], env = {}) => cli(home, ["enroll", "-token", "-gateway", gw.url, "-tenant", "acme", "-root", fp, "-name", "ci-pod", "-key-store", "file", ...extra], env);
    const waitFor = async (what, f) => {
      for (let i = 0; i < 200; i++) {
        const v = await f();
        if (v) return v;
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.fail(`timed out waiting for ${what}`);
    };
    const pendingRequest = () => waitFor("the enrollment request", async () => (await post(gw.url, "/v1/admin/enrollments", admin, {})).body.pending?.[0]);
    const approve = async (p) => {
      assert.equal((await post(gw.url, "/v1/admin/enrollments/decide", admin, { id: p.id, decision: "approved" })).status, 200);
      const b = signBinding(rootKey, { tenant: "acme", owner: p.owner, id: p.id, publicKey: Buffer.from(p.signing_key, "base64") });
      assert.equal((await post(gw.url, "/v1/admin/bindings", admin, { id: p.id, binding: b })).status, 200);
    };

    // A wrong fingerprint is refused and leaves nothing behind.
    const bad = mkdtempSync(join(tmpdir(), "parley-home-"));
    const refused = await cli(bad, ["enroll", "-token", "-gateway", gw.url, "-tenant", "acme", "-root", fingerprint(Buffer.alloc(32, 7)), "-key-store", "file"], { PARLEY_ENROLL_TOKEN: await mint() }).done;
    assert.equal(refused.code, 1);
    assert.match(refused.out, /does not match the fingerprint/);
    assert.equal(existsSync(join(bad, "device.key")), false);

    // A pod enrolls with its token; the admin approves; the config and binding are stored.
    const home = mkdtempSync(join(tmpdir(), "parley-home-"));
    const run = podEnroll(home, [], { PARLEY_ENROLL_TOKEN: await mint() });
    const req = await pendingRequest();
    assert.equal(req.owner, "svc-ci");
    assert.equal(req.kind, "pod");
    await waitFor("the device fingerprint line", () => run.output().includes(req.fingerprint));
    await approve(req);
    const ok = await run.done;
    assert.equal(ok.code, 0, ok.out);
    assert.match(ok.out, new RegExp(`Enrolled as device ${req.id} in tenant acme`));
    const cfg = JSON.parse(readFileSync(join(home, "config.json"), "utf8"));
    assert.equal(cfg.device_id, req.id);
    assert.equal(Buffer.from(cfg.root_public_key, "base64").equals(rootKey.publicKey), true);
    assert.equal(existsSync(join(home, "bindings.json")), true);
    assert.equal(JSON.parse(readFileSync(join(home, "enrollment.json"), "utf8")).phase, "bound");
    assert.ok(!ok.out.includes("pet_"), "the enrollment token must not be printed");

    // Restart while waiting: killed before the approval, then `enroll` finishes with the same request and key.
    const home2 = mkdtempSync(join(tmpdir(), "parley-home-"));
    const first = podEnroll(home2, [], { PARLEY_ENROLL_TOKEN: await mint() });
    const req2 = await pendingRequest();
    await waitFor("the saved enrollment state", () => existsSync(join(home2, "enrollment.json")));
    first.child.kill("SIGKILL");
    await first.done;
    const key = readFileSync(join(home2, "device.key"));
    await approve(req2);
    const resumed = await cli(home2, ["enroll"]).done;
    assert.equal(resumed.code, 0, resumed.out);
    assert.equal(JSON.parse(readFileSync(join(home2, "config.json"), "utf8")).device_id, req2.id);
    assert.deepEqual(readFileSync(join(home2, "device.key")), key, "the device key changed across the restart");
    // The state ends bound (the file stays as the record) and a second run is refused rather than minting a new key.
    assert.equal(JSON.parse(readFileSync(join(home2, "enrollment.json"), "utf8")).phase, "bound");
    const again = await cli(home2, ["enroll"]).done;
    assert.equal(again.code, 1);
    assert.match(again.out, /already enrolled/);
    assert.deepEqual(readFileSync(join(home2, "device.key")), key);

    // A lost key is an explicit -replace: a new identity, with the old device id reported for the admin to revoke.
    const lost = cli(home2, ["enroll", "-token", "-replace", "-key-store", "file"], { PARLEY_ENROLL_TOKEN: await mint() });
    const req3 = await waitFor("the replacement request", async () => (await post(gw.url, "/v1/admin/enrollments", admin, {})).body.pending?.find((p) => p.id !== req2.id));
    assert.notEqual(req3.id, req2.id);
    await approve(req3);
    const replaced = await lost.done;
    assert.equal(replaced.code, 0, replaced.out);
    assert.match(replaced.out, new RegExp(`revoke the replaced device\\(s\\): ${req2.id}`));
    assert.equal(JSON.parse(readFileSync(join(home2, "config.json"), "utf8")).device_id, req3.id);
  } finally {
    await gw.close();
  }
});

test("T411: sign-in through the gateway's device login, then enrollment, from the Go code against the real gateway", opts, async () => {
  const gw = await startGateway({ admins: "acme:admin@acme.test", userDomains: "acme:acme.test" });
  try {
    const admin = (await gw.signIn({ tenant: "acme", role: "admin", email: "admin@acme.test" })).token;
    const rootKey = await registerRoot(gw.url, admin);
    const child = spawn("go", ["test", "-count=1", "-v", "./internal/enroll", "-run", "^TestAgainstWorker$"], {
      cwd: repo,
      env: { ...process.env, PARLEY_TEST_GATEWAY_BASE: gw.url, PARLEY_TEST_GATEWAY_TENANT: "acme", PARLEY_TEST_ROOT_FP: fingerprint(rootKey.publicKey) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    const exited = new Promise((resolve) => child.on("close", (code) => resolve(code)));
    const waitFor = async (what, f) => {
      for (let i = 0; i < 600; i++) {
        const v = await f();
        if (v) return v;
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.fail(`timed out waiting for ${what}\n${out}`);
    };

    // The user's browser: the printed address, through the mock IdP, to the page that shows the code.
    const link = await waitFor("the sign-in address", () => /Sign in in your browser: (\S+)/.exec(out)?.[1]);
    const code = /The page will show the code (\S+)\./.exec(out)[1];
    const jar = new Map();
    const keep = (res) => { for (const c of res.headers.getSetCookie()) { const [kv] = c.split(";"); const i = kv.indexOf("="); jar.set(kv.slice(0, i), kv.slice(i + 1)); } };
    const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    let res = await fetch(`${link}&login_hint=alice@acme.test`, { redirect: "manual" });
    keep(res);
    res = await fetch(res.headers.get("location"), { redirect: "manual" });
    const back = new URL(res.headers.get("location"));
    res = await fetch(`${gw.url}${back.pathname}${back.search}`, { headers: { cookie: cookie() }, redirect: "manual" });
    const html = await res.text();
    assert.equal(res.status, 200, html);
    assert.match(html, new RegExp(code), "the page must show the code the terminal showed");
    assert.equal(res.headers.getSetCookie().some((c) => c.startsWith("parley_session=")), false, "no session cookie for a device login");
    const field = (n) => new RegExp(`name="${n}" value="([^"]*)"`).exec(html)[1];
    const form = new URLSearchParams({ tenant: field("tenant"), id: field("id"), confirm: field("confirm") });
    const cross = await fetch(`${gw.url}/v1/login/confirm`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", Origin: "https://evil.example" }, body: form });
    assert.equal(cross.status, 400, "a confirmation from another origin must be refused");
    const ok = await fetch(`${gw.url}/v1/login/confirm`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", Origin: gw.url }, body: form });
    assert.equal(ok.status, 200);

    // The enrollment that follows is the user's: the admin sees alice, approves, and the Go side finishes.
    const req = await waitFor("the enrollment request", async () => (await post(gw.url, "/v1/admin/enrollments", admin, {})).body.pending?.[0]);
    assert.equal(req.owner, "alice@acme.test");
    assert.equal(req.kind, "user");
    await waitFor("the fingerprint line", () => out.includes(req.fingerprint));
    assert.equal((await post(gw.url, "/v1/admin/enrollments/decide", admin, { id: req.id, decision: "approved" })).status, 200);
    const b = signBinding(rootKey, { tenant: "acme", owner: req.owner, id: req.id, publicKey: Buffer.from(req.signing_key, "base64") });
    assert.equal((await post(gw.url, "/v1/admin/bindings", admin, { id: req.id, binding: b })).status, 200);
    assert.equal(await exited, 0, out);
    assert.match(out, new RegExp(`ENROLLED ${req.id}`));
    assert.match(out, /--- PASS: TestAgainstWorker/);
  } finally {
    await gw.close();
  }
});
