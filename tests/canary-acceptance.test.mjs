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
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { FIELDS, Scan, mintCanaries } from "./canary/canary.mjs";
import { sleep, startGateway } from "./harness/wrangler.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const isWindows = process.platform === "win32";
const wrangler = join(root, "gateway", "node_modules", ".bin", isWindows ? "wrangler.cmd" : "wrangler");
// Mirrors the other acceptance tests: skip locally when a tool is missing, fail under CI.
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const missing = !haveGo ? "go not installed" : !existsSync(wrangler) ? "gateway dependencies not installed (cd gateway && npm ci)" : "";
const opts = missing ? { skip: process.env.CI ? false : missing } : {};

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
      res.bodyText = body; // the body is read here, so callers use this and not res.json()
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
    const { frames, blobs, chains } = JSON.parse(readFileSync(outFile, "utf8"));
    assert.deepEqual(frames.map((f) => f.type), ["TASK", "STATUS", "INPUT_REQUIRED", "RESULT", "ERROR"]);
    assert.equal(blobs.length, 1);
    assert.deepEqual(chains.map((c) => c.map((f) => f.type)), [
      ["TASK", "STATUS", "INPUT_REQUIRED", "REPLY", "RESULT"], ["TASK", "ERROR"], ["TASK", "REJECTED"], ["TASK", "CANCEL"],
    ]);

    // 2. A real gateway with its state on disk. Ports, state and log directories are
    // allocated per start (tests/harness/wrangler.mjs), so a parallel wrangler on the
    // machine cannot collide with it.
    gw = await startGateway(join(root, "gateway"), { scratch: join(dir, "gw") });
    const { state, logs, port } = gw;
    const base = gw.url;

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
    // The A2A transport (POST /a2a), T302: the same content over JSON-RPC. Four tasks run
    // through the real lifecycle (answer to a question, error, refusal, cancel); every
    // request that carries readable content in any unsealed place is refused. Responses and
    // the tunnel events are recorded like all other traffic. The JSON-RPC id is left out of
    // the hostile positions: it is echoed back to its own sender by design.
    const sealedType = "application/vnd.parley.sealed";
    const a2a = async (device, method, params, id = 1) => {
      const res = await rec.fetch(`${base}/a2a`, {
        method: "POST",
        headers: { Authorization: `Bearer dev:acme:${device}`, "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      });
      return JSON.parse(res.bodyText);
    };
    const tunnel = async (device) => {
      const t = connect(`ws://127.0.0.1:${port}/v1/connect`, { Authorization: `Bearer dev:acme:${device}` }, rec);
      await t.opened;
      t.send({ t: "hello", v: 1, last_rx: 0 });
      assert.equal((await t.next()).t, "welcome");
      return t;
    };
    const caller = await tunnel("caller");
    const target = await tunnel("target");
    const callerKinds = new Set(["TASK", "REPLY", "CANCEL"]);
    const states = [];
    for (const [i, chain] of chains.entries()) {
      for (const f of chain) {
        const fromCaller = callerKinds.has(f.type);
        const dev = fromCaller ? "caller" : "target";
        const message = { messageId: `m${i}-${states.length}`, role: fromCaller ? "ROLE_USER" : "ROLE_AGENT", parts: [{ raw: f.body, mediaType: sealedType }] };
        if (f.type === "REJECTED") message.metadata = { parley: { kind: "REJECTED" } };
        const r = f.type === "CANCEL"
          ? await a2a(dev, "CancelTask", { id: chain[0].task, metadata: { parley: { messageId: message.messageId, parts: message.parts } } })
          : await a2a(dev, "SendMessage", { message });
        assert.ok(r.result, `${f.type} was refused: ${JSON.stringify(r.error)}`);
        states.push((r.result.task ?? r.result).status.state);
        const ev = await (fromCaller ? target : caller).next();
        assert.equal(ev.t, "event", `${f.type} was not relayed`);
      }
    }
    assert.deepEqual(states, [
      "TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_WORKING", "TASK_STATE_COMPLETED",
      "TASK_STATE_SUBMITTED", "TASK_STATE_FAILED",
      "TASK_STATE_SUBMITTED", "TASK_STATE_REJECTED",
      "TASK_STATE_SUBMITTED", "TASK_STATE_CANCELED",
    ]);
    // Readable content in any unsealed place is refused and goes nowhere.
    const refused = [];
    for (const [field, canary] of Object.entries(canaries)) {
      const sealedPart = { raw: chains[0][0].body, mediaType: sealedType };
      const base = { messageId: `h-${field}`, role: "ROLE_USER", parts: [sealedPart] };
      const hostile = [
        { message: { ...base, parts: [{ text: canary }] } },
        { message: { ...base, parts: [{ data: { v: canary } }] } },
        { message: { ...base, parts: [{ url: `https://example.test/${canary}`, mediaType: sealedType }] } },
        { message: { ...base, parts: [{ ...sealedPart, filename: canary }] } },
        { message: { ...base, parts: [{ ...sealedPart, metadata: { v: canary } }] } },
        { message: { ...base, parts: [{ ...sealedPart, mediaType: canary }] } },
        { message: { ...base, metadata: { v: canary } } },
        { message: { ...base, metadata: { parley: { kind: canary } } } },
        { message: { ...base, text: canary } },
        { message: { ...base, taskId: canary } },
        { message: { ...base, contextId: canary } },
        { message: { ...base, extensions: [canary] } },
        { message: base, metadata: { v: canary } },
        { message: base, configuration: { acceptedOutputModes: [canary] } },
        { message: base, tenant: canary },
        { message: base, [canary]: 1 },
      ];
      for (const params of hostile) refused.push(await a2a("caller", "SendMessage", params));
      refused.push(await a2a("caller", "CancelTask", { id: canary }));
      refused.push(await a2a("caller", "GetTask", { id: canary }));
      refused.push(await a2a("caller", "GetTask", { id: "x", [canary]: 1 }));
      refused.push(await a2a("caller", canary, {}));
    }
    assert.ok(refused.length > 100);
    for (const r of refused) assert.ok(r.error && !r.result, `a hostile request was accepted: ${JSON.stringify(r)}`);
    caller.close();
    target.close();
    // Planted-leak control: a control canary goes into a field the gateway DOES
    // persist (a device name in the Tenant Durable Object). The storage scan below
    // must FIND it, or a zero-hit result on the real canaries would prove nothing.
    const control = mintCanaries(["control"]);
    const enrolled = await rec.fetch(`${base}/v1/enroll/request`, {
      method: "POST",
      headers: { Authorization: "Bearer dev-user:acme:alice@acme.test", "Content-Type": "application/json" },
      body: JSON.stringify({ name: control.control, signing_key: Buffer.alloc(32, 7).toString("base64") }),
    });
    assert.equal(enrolled.status, 202);
    await sleep(500);

    // 4. Stop the gateway so its storage is flushed, then scan everything.
    await gw.stop();
    const out = [gw.output()];
    const scan = new Scan(canaries);
    for (const [what, data] of rec.seen) scan.text(what, data);
    scan.text("gateway output", out[0]);
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
    // The control must be found in storage (and nowhere that would make that
    // meaningless), and the real canaries must not.
    const ctl = new Scan(control);
    ctl.path(state);
    assert.ok(ctl.hits.some((h) => h.sink.startsWith(state) && /\.sqlite(-wal)?$/.test(h.sink)),
      `the planted control canary is not visible in the persisted Durable Object files: scan cannot see storage\n${ctl.report()}`);
    // R2 and D1 are in the plan; the gateway declares neither yet. When it does,
    // their directories must exist under the state directory, and are scanned by
    // scan.path(state) above, so this cannot go green by scanning nothing.
    const cfg = readFileSync(join(root, "gateway", "wrangler.jsonc"), "utf8");
    const present = new Set(readdirSync(state));
    if (/"r2_buckets"/.test(cfg)) assert.ok(present.has("r2"), `R2 is declared but ${state} has no r2 directory: ${[...present]}`);
    if (/"d1_databases"/.test(cfg)) assert.ok(present.has("d1"), `D1 is declared but ${state} has no d1 directory: ${[...present]}`);
    t.diagnostic(`scanned ${scan.sinks.length} sinks, ${files.length} persisted files, ${rec.seen.length} observed messages; skipped: ${scan.skipped.length}`);
    assert.deepEqual(scan.skipped, [], "the scan skipped something it could not read");
    scan.assertClean();
  } finally {
    if (gw) await gw.stop();
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});
