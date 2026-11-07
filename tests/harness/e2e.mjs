// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// What the end-to-end tests with real daemons share (tests/m1-echo.test.mjs, tests/walking-skeleton.test.mjs): the Go
// binaries, a tenant on the real gateway with its root, and pods enrolled the way an admin-minted token enrolls them. The test
// plays the admin: it registers the root, posts the signed revocation list, approves each device and posts its binding.

import { spawn, spawnSync } from "node:child_process";
import { connect, createServer } from "node:net";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { registerRoot, signBinding, signRevocations } from "./gateway.mjs";

export const repo = join(fileURLToPath(import.meta.url), "..", "..", "..");
export const isWindows = process.platform === "win32";
const wrangler = join(repo, "gateway", "node_modules", ".bin", isWindows ? "wrangler.cmd" : "wrangler");
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const missing = !haveGo ? "go not installed" : !existsSync(wrangler) ? "gateway dependencies not installed (cd gateway && npm ci)" : "";
// Skips locally when the toolchain is missing, but fails under CI so a missing one cannot pass silently.
export const testOptions = (timeout) => (missing ? { skip: process.env.CI ? false : missing, timeout } : { timeout });

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Go's root.Fingerprint: the first 26 base32 characters of SHA-256(public key), in groups of four.
export function fingerprint(pub) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const b of createHash("sha256").update(pub).digest()) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; out.length < 26; i += 5) out += alphabet[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return out.match(/.{1,4}/g).join("-");
}

export const post = async (url, path, token, body) => {
  const res = await fetch(`${url}${path}`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => ({})) };
};

// A running child with its output kept; `done` resolves with the exit code and all output when it closes.
export function capture(child) {
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  const done = new Promise((resolve) => child.on("close", (code) => resolve({ code, out })));
  return { child, done, output: () => out };
}

export async function waitFor(what, f, n = 300) {
  for (let i = 0; i < n; i++) {
    const v = await f();
    if (v) return v;
    await sleep(100);
  }
  assert.fail(`timed out waiting for ${what}`);
}

// Builds `parley-cli`, `parleyd` and any other `./cmd/<name>` or `./<dir>` into a fresh directory; returns exe(name).
export function build(targets) {
  const bin = mkdtempSync(join(tmpdir(), "parley-bin-"));
  const exe = (n) => join(bin, isWindows ? `${n}.exe` : n);
  for (const [name, pkg] of Object.entries(targets)) {
    const built = spawnSync("go", ["build", "-o", exe(name), pkg], { cwd: repo, encoding: "utf8" });
    assert.equal(built.status, 0, built.stderr);
  }
  return { bin, exe };
}

// One tenant, "acme", on `gw`, with its root registered and an empty signed revocation list posted.
export async function newTenant(gw, exe) {
  const admin = (await gw.signIn({ tenant: "acme", role: "admin", email: "admin@acme.test" })).token;
  const rootKey = await registerRoot(gw.url, admin);
  const fp = fingerprint(rootKey.publicKey);
  assert.equal((await post(gw.url, "/v1/admin/revocations", admin, { list: signRevocations(rootKey, { tenant: "acme" }) })).status, 200);
  const homes = [];
  const enrolled = new Set();
  const cli = (home, args, env = {}) => capture(spawn(exe("parley-cli"), args, { env: { ...process.env, PARLEY_HOME: home, ...env }, stdio: ["ignore", "pipe", "pipe"] }));
  // A pod enrolls with an admin-minted token; the admin (the test) approves it and posts its binding.
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
    assert.equal(JSON.parse(readFileSync(join(home, "config.json"), "utf8")).device_id, req.id);
    return { home, id: req.id };
  };
  return { admin, rootKey, fp, homes, cli, enroll };
}

// A TCP proxy to the gateway that the test can cut and restore: a daemon whose gateway_url points at it loses its
// connection when the test says so (and cannot reconnect until it restores), while the daemon itself stays up.
export async function cuttableProxy(targetPort) {
  const sockets = new Set();
  let cut = false;
  const server = createServer((client) => {
    if (cut) return client.destroy();
    const upstream = connect(targetPort, "127.0.0.1");
    for (const s of [client, upstream]) {
      sockets.add(s);
      s.on("close", () => {
        sockets.delete(s);
        (s === client ? upstream : client).destroy();
      });
      s.on("error", () => {});
    }
    client.pipe(upstream);
    upstream.pipe(client);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    cut() {
      cut = true;
      for (const s of sockets) s.destroy();
    },
    restore() {
      cut = false;
    },
    close() {
      this.cut();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

// A minimal MCP client: JSON-RPC 2.0, one message per line, over the stdio of `parley-cli mcp`.
export function mcpClient(child) {
  let buf = "";
  let next = 1;
  const pending = new Map();
  child.stdout.on("data", (d) => {
    buf += d;
    for (let i; (i = buf.indexOf("\n")) >= 0; ) {
      const msg = JSON.parse(buf.slice(0, i));
      buf = buf.slice(i + 1);
      pending.get(msg.id)?.(msg);
      pending.delete(msg.id);
    }
  });
  const rpc = (method, params) =>
    new Promise((resolve) => {
      const id = next++;
      pending.set(id, resolve);
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  // A tool call; the result text is the notice (when the content is another agent's) and then JSON.
  const tool = async (name, args = {}) => {
    const r = await rpc("tools/call", { name, arguments: args });
    assert.ok(r.result, `tool ${name} failed at the protocol level: ${JSON.stringify(r.error)}`);
    const text = r.result.content[0].text;
    const at = text.indexOf("{");
    return { isError: r.result.isError, text, json: at >= 0 ? JSON.parse(text.slice(at)) : null };
  };
  return { rpc, tool, notify: (method) => child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method })}\n`) };
}
