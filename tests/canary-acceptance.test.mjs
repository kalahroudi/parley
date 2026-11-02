// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T209 (spike 4): the canary test against the real gateway. One canary per task
// content field (input, result, status, question, error, file name) is sealed by
// the real daemon-side code (internal/acceptance TestEmitCanaryFrames), every
// frame is sent through a running gateway (`wrangler dev`, real Durable Objects,
// persisted to disk), and then everything the gateway holds or said is scanned:
// the whole persisted state directory (Durable Object SQLite and its WAL, and
// the R2 and D1 directories once the gateway has them), its logs, every URL,
// request and response header and body, WebSocket message and error message.
// Pass = zero hits. The scanner is checked against planted canaries first.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { FIELDS, Scan, mintCanaries } from "./canary/canary.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const isWindows = process.platform === "win32";
const wrangler = join(root, "gateway", "node_modules", ".bin", isWindows ? "wrangler.cmd" : "wrangler");
// Mirrors the other acceptance tests: skip locally when a tool is missing, fail under CI.
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const missing = !haveGo ? "go not installed" : !existsSync(wrangler) ? "gateway dependencies not installed (cd gateway && npm ci)" : "";
const opts = missing ? { skip: process.env.CI ? false : missing } : {};

const freePort = () =>
  new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function stopTree(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    const timer = setTimeout(() => kill("SIGKILL"), 8000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    function kill(sig) {
      try {
        if (isWindows) spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
        else process.kill(-child.pid, sig);
      } catch {}
    }
    kill("SIGTERM");
  });
}

// Everything observable on the wire is collected here and scanned afterwards.
function recorder() {
  const seen = [];
  return {
    seen,
    add: (what, data) => seen.push([what, data]),
    async fetch(url, init = {}) {
      this.add("request URL", url);
      this.add("request headers", JSON.stringify(init.headers ?? {}));
      const res = await fetch(url, init);
      const body = await res.text();
      this.add(`response ${res.status} headers`, JSON.stringify([...res.headers]));
      this.add(`response ${res.status} body`, body);
      return res;
    },
  };
}

function connect(url, headers, rec) {
  rec.add("request URL", url);
  rec.add("request headers", JSON.stringify(headers));
  const ws = new WebSocket(url, { headers });
  const inbox = [];
  const waiters = [];
  let closed;
  ws.addEventListener("message", (e) => {
    rec.add("websocket message", String(e.data));
    const m = JSON.parse(e.data);
    const w = waiters.shift();
    if (w) w(m);
    else inbox.push(m);
  });
  ws.addEventListener("close", (e) => {
    closed = e;
    rec.add("websocket close", `${e.code} ${e.reason}`);
    for (const w of waiters.splice(0)) w(null);
  });
  const opened = new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve);
    ws.addEventListener("error", () => reject(new Error("websocket error")));
  });
  return {
    opened,
    next: () => (inbox.length ? Promise.resolve(inbox.shift()) : closed ? Promise.resolve(null) : new Promise((r) => waiters.push(r))),
    send(m) {
      const s = JSON.stringify(m);
      rec.add("websocket sent", s.length > 200 ? s.slice(0, 40) + "...(frame body, scanned as wire frames)" : s);
      ws.send(s);
    },
    close: () => ws.close(),
  };
}

test("canary scan: every sink the test scans can see a planted canary", () => {
  const dir = mkdtempSync(join(tmpdir(), "parley-canary-ctl-"));
  try {
    const canaries = mintCanaries();
    mkdirSync(join(dir, "do"));
    // A canary in a file name, one in file contents, a row of text in a db-like file.
    writeFileSync(join(dir, "do", `${canaries.filename}.sqlite`), "");
    writeFileSync(join(dir, "do", "a.sqlite"), Buffer.concat([Buffer.alloc(100), Buffer.from(canaries.input), Buffer.alloc(9)]));
    const scan = new Scan(canaries);
    scan.path(dir);
    scan.text("log", `error: ${canaries.error}`);
    scan.text("URL", `https://gw/v1/x?q=${encodeURIComponent(canaries.result)}`);
    scan.text("header", `x-note: ${canaries.status}`);
    scan.text("body", JSON.stringify({ q: canaries.question }));
    assert.deepEqual([...new Set(scan.hits.map((h) => h.field))].sort(), [...FIELDS].sort());
    assert.throws(() => scan.assertClean(), /canary leak/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("acceptance: canaries sealed by the daemon leave zero hits in the gateway's storage, logs and traffic", opts, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "parley-canary-"));
  let gw;
  try {
    // 1. Canaries in every content field, sealed by the real code.
    const canaries = mintCanaries();
    const inFile = join(dir, "canaries.json");
    const outFile = join(dir, "frames.json");
    writeFileSync(inFile, JSON.stringify(canaries));
    const emit = spawnSync("go", ["test", "-count=1", "./internal/acceptance", "-run", "^TestEmitCanaryFrames$"], {
      cwd: root,
      env: { ...process.env, PARLEY_CANARY_IN: inFile, PARLEY_CANARY_OUT: outFile },
      encoding: "utf8",
    });
    assert.equal(emit.status, 0, `${emit.stdout}\n${emit.stderr}`);
    const { frames, blobs } = JSON.parse(readFileSync(outFile, "utf8"));
    assert.deepEqual(frames.map((f) => f.type), ["TASK", "STATUS", "INPUT_REQUIRED", "RESULT", "ERROR"]);
    assert.equal(blobs.length, 1);

    // 2. A real gateway with its state on disk.
    const state = join(dir, "state");
    const logs = join(dir, "wrangler-logs");
    mkdirSync(logs);
    // Another wrangler or workerd on the machine (or a parallel test) can take the
    // ports between picking them and binding them: retry with fresh ones.
    let port, out;
    for (let attempt = 1; ; attempt++) {
      port = await freePort();
      const inspector = await freePort();
      out = [];
      gw = spawn(
        `"${wrangler}" dev --port ${port} --inspector-port ${inspector} --ip 127.0.0.1 --var DEV_AUTH:1 --persist-to "${state}"`,
        {
          cwd: join(root, "gateway"),
          shell: true,
          detached: !isWindows,
          env: { ...process.env, WRANGLER_LOG_PATH: logs, WRANGLER_SEND_METRICS: "false", CI: "1" },
        },
      );
      gw.stdout.on("data", (d) => out.push(d));
      gw.stderr.on("data", (d) => out.push(d));
      let up = false;
      for (let i = 0; i < 300 && gw.exitCode === null; i++) {
        try {
          if ((await fetch(`http://127.0.0.1:${port}/healthz`)).ok) {
            up = true;
            break;
          }
        } catch {}
        if (/Address already in use/.test(Buffer.concat(out).toString())) break;
        await sleep(200);
      }
      if (up) break;
      const log = Buffer.concat(out).toString();
      await stopTree(gw);
      assert.ok(attempt < 4 && /Address already in use/.test(log), `gateway did not start:\n${log}`);
    }
    const base = `http://127.0.0.1:${port}`;

    // 3. Everything goes through: frames both directions, plus the error paths.
    const rec = recorder();
    await rec.fetch(`${base}/healthz`);
    await rec.fetch(`${base}/nope`);
    await rec.fetch(`${base}/v1/connect`);
    const c = connect(`ws://127.0.0.1:${port}/v1/connect`, { Authorization: "Bearer dev:acme:caller" }, rec);
    await c.opened;
    c.send({ t: "hello", v: 1, last_rx: 0 });
    assert.equal((await c.next()).t, "welcome");
    for (const [i, f] of frames.entries()) {
      c.send({ t: "frame", seq: i + 1, body: f.body });
      const ack = await c.next();
      assert.deepEqual(ack, { t: "ack", seq: i + 1 }, `${f.type} not acknowledged`);
    }
    // A malformed frame, to collect the gateway's error message.
    c.send("not json");
    assert.equal((await c.next())?.t, "error");
    c.close();
    await sleep(500);

    // 4. Stop the gateway so its storage is flushed, then scan everything.
    await stopTree(gw);
    const scan = new Scan(canaries);
    for (const [what, data] of rec.seen) scan.text(what, data);
    scan.text("gateway output", Buffer.concat(out));
    for (const f of frames) scan.bytes(`wire frame ${f.type}`, Buffer.from(f.body, "base64"));
    for (const b of blobs) scan.bytes("file blob (R2 object body)", Buffer.from(b.data, "base64"));
    scan.text("file blob (R2 object key)", blobs[0].key);
    scan.path(logs);
    // The scan must cover real storage: the Durable Object databases are there and non-empty.
    const files = [];
    (function walk(p) {
      for (const n of readdirSync(p)) {
        const q = join(p, n);
        statSync(q).isDirectory() ? walk(q) : files.push(q);
      }
    })(state);
    assert.ok(files.some((f) => f.endsWith(".sqlite") && statSync(f).size > 0), `no Durable Object database under ${state}: ${files}`);
    scan.path(state);
    t.diagnostic(`scanned ${scan.sinks.length} sinks, ${files.length} persisted files, ${rec.seen.length} observed messages; skipped: ${scan.skipped.length}`);
    assert.deepEqual(scan.skipped, [], "the scan skipped something it could not read");
    scan.assertClean();
  } finally {
    if (gw) await stopTree(gw);
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});
