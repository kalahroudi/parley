// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// The assertions parked while the Worker's /v1/connect and /a2a were closed (no device credential existed), now run
// against the real gateway (`wrangler dev`, real Durable Objects) with device connect tokens (T415): a device proves
// possession of its bound key and receives a connect token; /v1/connect and /a2a accept it and nothing else; revoked,
// expired and unbound devices and a replayed challenge are refused. The Go side runs against the same gateway: the
// daemon tunnel client (internal/tunnel TestAgainstWorker), once with a token handed to it and once earning its own
// with internal/connect from the device key, through the real enrollment flow, which also proves the Go and
// TypeScript sides sign and verify the same bytes. The canary acceptance over the same path is
// tests/canary-acceptance.test.mjs. (The file keeps its old name; its parked-test key was T310, which T415 replaced.)

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { taskTicked } from "./harness/pending.mjs";
import { connectMessage, connectToken, enrollDevice, registerRoot, startGateway } from "./harness/gateway.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const isWindows = process.platform === "win32";
const wrangler = join(root, "gateway", "node_modules", ".bin", isWindows ? "wrangler.cmd" : "wrangler");
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const missing = !haveGo ? "go not installed" : !existsSync(wrangler) ? "gateway dependencies not installed (cd gateway && npm ci)" : "";
const opts = missing ? { skip: process.env.CI ? false : missing } : {};

test("taskTicked reads the checkbox", () => {
  const md = "- [x] T301 Task\r\n- [ ] T310 Tokens\n  - [x] T3101 sub\n";
  assert.equal(taskTicked(md, "T301"), true);
  assert.equal(taskTicked(md, "T310"), false);
  assert.equal(taskTicked(md, "T3101"), true);
  assert.equal(taskTicked(md, "T999"), false);
});

const post = async (url, path, token, body) => {
  const res = await fetch(`${url}${path}`, { method: "POST", headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => ({})) };
};

// Opens /v1/connect with a token and reports what the gateway did: "welcome" after hello, or "refused".
function tunnel(url, token) {
  return new Promise((resolve) => {
    const ws = new WebSocket(`${url.replace("http", "ws")}/v1/connect`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    const done = (r) => {
      try { ws.close(); } catch {}
      resolve(r);
    };
    ws.addEventListener("open", () => ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 })));
    ws.addEventListener("message", (e) => done(JSON.parse(e.data).t));
    ws.addEventListener("error", () => done("refused"));
    ws.addEventListener("close", () => done("refused"));
  });
}

test("T415: the Worker authenticates device connect tokens on /v1/connect and /a2a with the real gateway, the Go tunnel client and the daemon", opts, async (t) => {
  const gw = await startGateway({ admins: "acme:admin@acme.test", userDomains: "acme:acme.test" });
  try {
    const admin = (await gw.signIn({ tenant: "acme", role: "admin", email: "admin@acme.test" })).token;
    const user = (await gw.signIn({ tenant: "acme", role: "user", email: "alice@acme.test" })).token;
    const rootKey = await registerRoot(gw.url, admin);
    const enroll = (extra = {}) => enrollDevice(gw.url, { tenant: "acme", userToken: user, adminToken: admin, root: rootKey, ...extra });
    const tokenOf = async (d, scope) => {
      const r = await connectToken(gw.url, "acme", d, { scope });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      return r.body.token;
    };

    // A bound device earns tokens. A tunnel token opens the tunnel once; an api token opens /a2a. Nothing else does.
    const dev = await enroll();
    const tunnelToken = await tokenOf(dev, "connect");
    assert.match(tunnelToken, new RegExp(`^pdt_acme\\.${dev.id}\\.[0-9a-f]{64}$`));
    assert.equal(await tunnel(gw.url, tunnelToken), "welcome");
    assert.equal(await tunnel(gw.url, tunnelToken), "refused", "a tunnel token was accepted twice");
    assert.equal(await tunnel(gw.url, undefined), "refused");
    assert.equal(await tunnel(gw.url, `pdt_acme.${dev.id}.${"0".repeat(64)}`), "refused");
    assert.equal(await tunnel(gw.url, `dev:acme:${dev.id}`), "refused");
    assert.equal(await tunnel(gw.url, await tokenOf(dev, "api")), "refused", "an api token opened the tunnel");
    const token = await tokenOf(dev, "api");
    const a2a = (tok) => post(gw.url, "/a2a", tok, { jsonrpc: "2.0", id: 1, method: "NoSuchMethod", params: {} });
    assert.equal((await a2a(token)).body.error.code, -32601);
    assert.equal((await a2a(await tokenOf(dev, "connect"))).status, 401, "a tunnel token opened /a2a");
    assert.equal((await a2a(undefined)).status, 401);
    assert.equal((await a2a(`pdt_acme.${dev.id}.${"1".repeat(64)}`)).status, 401);

    // A replayed challenge, an unbound device, an unknown one, a wrong binding version and a binding the root did
    // not sign are refused with the same answer.
    const ch = (await post(gw.url, "/v1/connect/challenge", undefined, { tenant: "acme", device: dev.id })).body;
    const sig = dev.sign(connectMessage("acme", dev.id, ch.challenge, ch.expires_at, 1, "api")).toString("base64");
    const redeem = () => post(gw.url, "/v1/connect/token", undefined, { tenant: "acme", device: dev.id, challenge: ch.challenge, version: 1, scope: "api", signature: sig });
    assert.equal((await redeem()).status, 200);
    const replay = await redeem();
    assert.deepEqual([replay.status, replay.body], [401, { error: "unauthorized" }]);
    const unbound = await enroll({ bind: false });
    const rogue = await enroll({ root: generateKeyPairSync("ed25519") }); // a binding signed by a key that is not the tenant's root
    const refusals = [
      await connectToken(gw.url, "acme", unbound),
      await connectToken(gw.url, "acme", { id: "e".repeat(32), sign: dev.sign }),
      await connectToken(gw.url, "acme", dev, { version: 2 }),
      await connectToken(gw.url, "acme", rogue),
    ];
    for (const r of refusals) assert.deepEqual([r.status, r.body], [401, { error: "unauthorized" }]);
    // An expired binding is refused.
    const lapsed = await enroll({ notAfter: Math.floor(Date.now() / 1000) - 5 });
    assert.equal((await connectToken(gw.url, "acme", lapsed)).status, 401);

    // Real Go code, real gateway: the tunnel client with a token, then the daemon with its default configuration.
    const go = (pkg, name, env) => {
      const r = spawnSync("go", ["test", "-count=1", "-v", `./${pkg}`, "-run", `^${name}$`], { cwd: root, env: { ...process.env, ...env }, encoding: "utf8" });
      assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
      assert.match(r.stdout, new RegExp(`--- PASS: ${name}`), `${name} did not run:\n${r.stdout}`);
    };
    go("internal/tunnel", "TestAgainstWorker", { PARLEY_TEST_GATEWAY: `${gw.url.replace("http", "ws")}/v1/connect`, PARLEY_TEST_GATEWAY_TOKEN: await tokenOf(dev, "connect") });
    const pod = await enroll({ name: "pod", version: 4 });
    go("internal/tunnel", "TestAgainstWorker", {
      PARLEY_TEST_GATEWAY: `${gw.url.replace("http", "ws")}/v1/connect`, PARLEY_TEST_GATEWAY_BASE: gw.url, PARLEY_TEST_GATEWAY_TENANT: "acme",
      PARLEY_TEST_GATEWAY_DEVICE: pod.id, PARLEY_TEST_GATEWAY_SEED: pod.seed.toString("hex"), PARLEY_TEST_GATEWAY_VERSION: "4",
    });

    // Revocation ends a device's tokens at once, new and already issued.
    const live = await tokenOf(pod, "api");
    const liveTunnel = await tokenOf(pod, "connect");
    const revoked = await post(gw.url, "/v1/admin/revocations", admin, { list: { tenant: "acme", version: 1, revoked: [pod.id], signature: "x" } });
    assert.equal(revoked.status, 200);
    assert.equal(await tunnel(gw.url, liveTunnel), "refused");
    assert.equal((await a2a(live)).status, 401);
    assert.equal((await connectToken(gw.url, "acme", pod, { scope: "connect", version: 4 })).status, 401);
    assert.equal((await a2a(token)).status, 200); // the other device is not affected
  } finally {
    await gw.close();
  }
});
