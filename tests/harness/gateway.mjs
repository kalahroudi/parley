// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Starts the real gateway Worker under `wrangler dev` next to a mock OIDC
// server, and signs users in through it. This is how tests get a session: the
// gateway has no development bypass, so a test logs in the way a person does.

import { spawn, spawnSync } from "node:child_process";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { closeSync, mkdtempSync, openSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startMockOidc } from "./oidc.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..", "..");

const freePort = () =>
  new Promise((resolve, reject) => {
    const s = createServer().once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

// Only a child that has not exited: its pid is free once it has, and Windows hands pids out again at once, so
// `taskkill /pid <old> /T /F` would end whatever process got the number (in the full CI run it ended a daemon of
// another test, which then exited with code 1 and no output).
function kill(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else process.kill(-child.pid, "SIGKILL");
  } catch {}
}

// `admins` is the gateway's ADMINS setting (`tenant:email,...`); `users` and `userDomains` are USERS and
// USER_DOMAINS (`tenant:email` / `tenant:domain`), without which no user can sign in. The login rate limits are
// raised out of the way (tests sign in dozens of times from one address); `extra` overrides any variable.
export async function startGateway({ admins = "", users = "", userDomains = "", extra = {} } = {}) {
  const idp = await startMockOidc();
  const port = await freePort();
  const vars = { FLOW_SECRET: "test-flow-secret", RATE_CONNECT_PER_MIN: "100000", RATE_CONNECT_DEVICE_PER_MIN: "100000", GOOGLE_CLIENT_ID: "parley", GOOGLE_ISSUER: idp.issuer, ADMINS: admins, USERS: users, USER_DOMAINS: userDomains, RATE_AUTH_PER_MIN: "100000", RATE_TENANT_LOGIN_PER_MIN: "100000", RATE_SESSION_PER_MIN: "100000", ...extra };
  // Own state directory and inspector port, so several gateways can run side by side (node --test runs files in parallel).
  const state = mkdtempSync(join(tmpdir(), "parley-gw-"));
  const log = `${state}.log`; // beside the state, not in it: wrangler's output (what the gateway logs and what it was asked)
  const args = ["wrangler", "dev", "--port", String(port), "--inspector-port", String(await freePort()), "--persist-to", state];
  for (const [k, v] of Object.entries(vars)) if (v) args.push("--var", `${k}:${v}`);
  const logFd = openSync(log, "w");
  const gw = spawn("npx", args, {
    cwd: join(root, "gateway"),
    stdio: ["ignore", logFd, logFd],
    shell: process.platform === "win32",
    detached: process.platform !== "win32",
  });
  const url = `http://127.0.0.1:${port}`;
  let closing;
  const close = () => (closing ??= (async () => { // once: a second close must not touch a pid that may be someone else's
    kill(gw);
    closeSync(logFd);
    await idp.close();
  })());
  try {
    const end = Date.now() + 60000;
    for (;;) {
      if (gw.exitCode !== null) throw new Error("wrangler dev exited early");
      if (await fetch(`${url}/healthz`).then((r) => r.ok, () => false)) break;
      if (Date.now() > end) throw new Error("gateway did not start");
      await new Promise((r) => setTimeout(r, 200));
    }
  } catch (e) {
    await close();
    throw e;
  }
  return { url, idp, close, state, log, signIn: (o) => signIn(url, o) };
}

// Runs the login the way a browser does (without one) and returns the callback
// response plus, on success, the session cookie value (usable as
// `Authorization: Bearer <token>`) and the CSRF token.
export async function signIn(url, { tenant, role, email }) {
  const qs = new URLSearchParams({ tenant, role, login_hint: email });
  const jar = new Map();
  const keep = (res) => {
    for (const c of res.headers.getSetCookie()) {
      const [kv, ...attrs] = c.split(";");
      const [k, ...v] = kv.split("=");
      if (v.join("=") === "" || /max-age=0/i.test(attrs.join(";"))) jar.delete(k);
      else jar.set(k, v.join("="));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(`${url}/auth/google/login?${qs}`, { redirect: "manual" });
  keep(res);
  res = await fetch(res.headers.get("location"), { redirect: "manual" }); // the mock IdP approves at once
  const back = new URL(res.headers.get("location"));
  res = await fetch(`${url}${back.pathname}${back.search}`, { headers: { cookie: cookie() }, redirect: "manual" });
  const setCookies = res.headers.getSetCookie();
  const body = await res.json();
  const session = setCookies.find((c) => c.startsWith("parley_session="));
  return { status: res.status, body, setCookies, token: session?.split(";")[0].split("=")[1], csrf: body.csrf };
}

// The tenant's root key, registered at the gateway the way the admin's daemon will: the gateway verifies every
// binding against it before a device may connect. Returns the key pair (the test plays the root holder).
export async function registerRoot(url, adminToken) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const res = await fetch(`${url}/v1/admin/root`, { method: "POST", headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" }, body: JSON.stringify({ root_public_key: raw.toString("base64") }) });
  if (res.status !== 200) throw new Error(`registering the root answered ${res.status}`);
  return { privateKey, publicKey: raw };
}

// Length-prefixed text fields (4 bytes, big endian) and 8-byte big-endian integers, as internal/binding and
// internal/connect encode them.
function encode(parts) {
  return Buffer.concat(parts.map((p) => {
    if (typeof p === "bigint") return Buffer.from(new BigUint64Array([p]).buffer).reverse();
    const b = Buffer.from(p);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.length);
    return Buffer.concat([len, b]);
  }));
}

// The binding the root holder signs for a device (internal/binding): `root` is from registerRoot, `publicKey` the
// device's 32-byte key, `notAfter` unix seconds.
export function signBinding(root, { tenant, owner, id, publicKey, version = 1, notAfter = Math.floor(Date.now() / 1000) + 90 * 86400 }) {
  const signature = cryptoSign(null, encode(["parley/binding/v1", tenant, owner, id, publicKey, BigInt(version), BigInt(notAfter)]), root.privateKey);
  return { tenant, owner, device_id: id, signing_key: publicKey.toString("base64"), version, not_after: new Date(notAfter * 1000).toISOString().replace(".000Z", "Z"), signature: signature.toString("base64") };
}

// The revocation list the root holder signs (internal/revocation): `issuedAt` is unix seconds. Post it with
// POST /v1/admin/revocations ({ list }); daemons fetch it from /v1/revocations and refuse to send without a fresh one.
export function signRevocations(root, { tenant, version = 1, issuedAt = Math.floor(Date.now() / 1000), revoked = [] }) {
  const signature = cryptoSign(null, Buffer.concat([encode(["parley/revocation/v1", tenant, BigInt(version), BigInt(issuedAt)]), (() => { const n = Buffer.alloc(4); n.writeUInt32BE(revoked.length); return n; })(), ...revoked.map((id) => encode([id]))]), root.privateKey);
  return { tenant, version, issued_at: new Date(issuedAt * 1000).toISOString().replace(".000Z", "Z"), revoked, signature: signature.toString("base64") };
}

// A device that holds its own key, brought to "approved with a binding the root signed" the way an admin's daemon
// would: the user requests enrollment with the device's public key, the admin approves and posts a binding (signed
// by `root`, see registerRoot) naming that key. `userToken` and `adminToken` are session bearer tokens (see signIn).
// Returns { id, seed, publicKey, binding, version, sign(msg) }: `id` is the device id, `seed` the 32-byte Ed25519
// seed, `binding` the signed binding as the gateway holds it.
export async function enrollDevice(url, { tenant, userToken, adminToken, root, owner = "alice@acme.test", name = "laptop", bind = true, version = 1, notAfter = Math.floor(Date.now() / 1000) + 90 * 86400 }) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pub = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const seed = Buffer.from(privateKey.export({ format: "jwk" }).d, "base64url");
  const post = async (path, token, body) => {
    const res = await fetch(`${url}${path}`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  };
  const req = await post("/v1/enroll/request", userToken, { name, signing_key: pub.toString("base64") });
  if (req.status !== 202) throw new Error(`enrollment request answered ${req.status}`);
  const id = req.body.id;
  const decided = await post("/v1/admin/enrollments/decide", adminToken, { id, decision: "approved" });
  if (decided.status !== 200) throw new Error(`approval answered ${decided.status}`);
  let binding;
  if (bind) {
    binding = signBinding(root, { tenant, owner, id, publicKey: pub, version, notAfter });
    const posted = await post("/v1/admin/bindings", adminToken, { id, binding });
    if (posted.status !== 200) throw new Error(`binding answered ${posted.status}`);
  }
  return { id, seed, publicKey: pub, binding, version, sign: (msg) => cryptoSign(null, msg, privateKey) };
}

// The bytes a device signs to prove it holds its key (internal/connect.Message, gateway/src/connect.ts).
export function connectMessage(tenant, device, challenge, expiresAtMs, version, scope) {
  return encode(["parley/connect/v2", tenant, device, challenge, BigInt(expiresAtMs), BigInt(version), scope]);
}

// Challenge, signature, token: returns the raw responses so a test can assert refusals as well as success.
export async function connectToken(url, tenant, device, { scope = "api", version = device.version ?? 1 } = {}) {
  const post = async (path, body) => {
    const res = await fetch(`${url}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  };
  const ch = await post("/v1/connect/challenge", { tenant, device: device.id });
  if (ch.status !== 200) return ch;
  const signature = device.sign(connectMessage(tenant, device.id, ch.body.challenge, ch.body.expires_at, version, scope)).toString("base64");
  return post("/v1/connect/token", { tenant, device: device.id, challenge: ch.body.challenge, version, scope, signature });
}
