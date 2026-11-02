// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109 (reality check 1): the logic behind tests/reality/probe.mjs, kept free of
// network and clock access so it is unit tested (lib.test.mjs). Probes take the
// WebSocket constructor and clock as arguments; probe.mjs passes the real ones.
// Results hold timings, sizes and counters only, never frame bodies or tokens.

export const MAX_FRAME_BYTES = 1 << 20; // gateway/src/protocol.ts

const sleepReal = (ms) => new Promise((r) => setTimeout(r, ms));

// A tunnel connection speaking protocol v1 (gateway/src/protocol.ts). Frames are
// queued in `inbox`; `next` waits for the first message matching a predicate.
export async function openTunnel({ WebSocket, url, token, session, lastRx = 0, timeoutMs = 15_000, clock = Date.now }) {
  const ws = new WebSocket(url, { headers: { Authorization: `Bearer ${token}` } });
  const inbox = [];
  const waiters = [];
  let closed;
  const settle = () => {
    for (const w of [...waiters]) {
      const i = inbox.findIndex(w.match);
      if (i >= 0) {
        waiters.splice(waiters.indexOf(w), 1);
        w.resolve(inbox.splice(i, 1)[0]);
      } else if (closed) {
        waiters.splice(waiters.indexOf(w), 1);
        w.reject(new Error(`closed ${closed.code}`));
      }
    }
  };
  ws.addEventListener("message", (e) => {
    try {
      inbox.push(JSON.parse(String(e.data)));
    } catch {
      inbox.push({ t: "raw", body: String(e.data) });
    }
    settle();
  });
  ws.addEventListener("close", (e) => {
    closed = { code: e.code, at: clock() };
    settle();
  });
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", () => reject(new Error("connect failed")), { once: true });
  });
  const tunnel = {
    ws,
    get closed() {
      return closed;
    },
    send: (m) => ws.send(typeof m === "string" ? m : JSON.stringify(m)),
    next: (match, ms = timeoutMs) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const i = waiters.indexOf(w);
          if (i >= 0) {
            waiters.splice(i, 1);
            reject(new Error("timed out"));
          }
        }, ms);
        const w = { match, resolve: (m) => (clearTimeout(timer), resolve(m)), reject: (e) => (clearTimeout(timer), reject(e)) };
        waiters.push(w);
        settle();
      }),
    close: () => ws.close(1000, "done"),
  };
  tunnel.send({ t: "hello", v: 1, session, last_rx: lastRx });
  tunnel.welcome = await tunnel.next((m) => m.t === "welcome");
  return tunnel;
}

const now = () => performance.now();

// Limits: the largest frame the real gateway accepts, found by sending frames of
// increasing size on fresh connections. A frame of N body bytes is accepted when
// it is acknowledged, refused when the socket closes first.
export async function probeFrameLimits(opts, sizes = defaultSizes()) {
  const out = [];
  for (const bytes of sizes) {
    const t = await openTunnel(opts);
    const body = "a".repeat(bytes);
    const started = now();
    let outcome;
    try {
      t.send({ t: "frame", seq: 1, body });
      await t.next((m) => m.t === "ack" && m.seq === 1, 30_000);
      outcome = { bytes, accepted: true, ms: Math.round(now() - started) };
    } catch {
      outcome = { bytes, accepted: false, closeCode: t.closed?.code ?? null, ms: Math.round(now() - started) };
    }
    try {
      t.close();
    } catch {}
    out.push(outcome);
  }
  const accepted = out.filter((o) => o.accepted).map((o) => o.bytes);
  const refused = out.filter((o) => !o.accepted).map((o) => o.bytes);
  return {
    results: out,
    largestAccepted: accepted.length ? Math.max(...accepted) : null,
    smallestRefused: refused.length ? Math.min(...refused) : null,
  };
}

// Sizes straddle the documented 1 MiB frame cap (Cloudflare allows 32 MiB per
// message, so the gateway cap, not the platform, should be what refuses).
export function defaultSizes() {
  const frameOverhead = 64; // the JSON envelope around `body`
  return [1 << 10, 64 << 10, 512 << 10, MAX_FRAME_BYTES - frameOverhead, MAX_FRAME_BYTES, MAX_FRAME_BYTES + 1024];
}

// Hibernation timing: after each idle period (no frames, only "ping" if
// `heartbeat`), measure the round trip of a frame. The first frame after a long
// idle includes waking the object; `warmMs` is the same frame sent right after.
// `wokeEstimateMs` is cold minus warm, and the session must still resume.
export async function probeHibernation(opts, idleSeconds, { sleep = sleepReal, heartbeat = false } = {}) {
  const t = await openTunnel(opts);
  const session = t.welcome.session;
  let seq = 0;
  const rtt = async () => {
    const started = now();
    seq++;
    t.send({ t: "frame", seq, body: "x" });
    await t.next((m) => m.t === "ack" && m.seq === seq);
    return now() - started;
  };
  const results = [];
  try {
    for (const idle of idleSeconds) {
      for (let waited = 0; waited < idle; ) {
        const step = heartbeat ? Math.min(20, idle - waited) : idle - waited;
        await sleep(step * 1000);
        waited += step;
        if (heartbeat) {
          t.send("ping");
          await t.next((m) => m.t === "raw" && m.body === "pong");
        }
      }
      if (t.closed) {
        results.push({ idle, survived: false, closeCode: t.closed.code });
        break;
      }
      const coldMs = await rtt();
      const warmMs = await rtt();
      results.push({ idle, survived: true, coldMs: Math.round(coldMs), warmMs: Math.round(warmMs), wokeEstimateMs: Math.round(coldMs - warmMs) });
    }
  } finally {
    try {
      t.close();
    } catch {}
  }
  // The stored session counters must survive hibernation: resuming reports the last rx_seq.
  let resumed = null;
  try {
    const r = await openTunnel({ ...opts, session, lastRx: 0 });
    resumed = { resumed: r.welcome.resumed, rxSeq: r.welcome.rx_seq, expectedRxSeq: seq };
    r.close();
  } catch {
    resumed = { resumed: false };
  }
  return { heartbeat, results, resume: resumed };
}

// Deploy-driven disconnect: send one numbered frame per `intervalMs` for
// `durationMs` while an operator runs `wrangler deploy`, reconnecting with the
// same resume logic as internal/tunnel (retransmit unacknowledged frames after
// a reconnect). Reports every disconnect (close code, time to reconnect) and
// whether any frame was lost (never acknowledged) or acknowledged twice.
export async function probeDeploy(opts, { durationMs, intervalMs = 1000, sleep = sleepReal, clock = Date.now, onEvent = () => {} }) {
  const disconnects = [];
  opts = { ...opts, clock };
  const acked = new Map(); // seq -> times acknowledged
  let outbox = []; // unacknowledged seqs
  let seq = 0;
  let session;
  let t = await openTunnel({ ...opts, session });
  session = t.welcome.session;
  const end = clock() + durationMs;
  const collect = async () => {
    // Collect any acks already queued without waiting.
    for (;;) {
      let m;
      try {
        m = await t.next((x) => x.t === "ack", 0);
      } catch {
        return;
      }
      acked.set(m.seq, (acked.get(m.seq) ?? 0) + 1);
      outbox = outbox.filter((s) => s !== m.seq);
    }
  };
  while (clock() < end) {
    seq++;
    outbox.push(seq);
    try {
      if (t.closed) throw new Error("closed");
      t.send({ t: "frame", seq, body: "d" });
    } catch {
      // handled by the reconnect below on the next loop
    }
    await sleep(intervalMs);
    await collect();
    if (t.closed) {
      const { at: lostAt, code: closeCode } = t.closed;
      onEvent({ disconnected: closeCode });
      let attempts = 0;
      for (;;) {
        attempts++;
        try {
          t = await openTunnel({ ...opts, session, lastRx: 0 });
          break;
        } catch {
          await sleep(Math.min(1000 * attempts, 5000));
          if (clock() > end + 60_000) throw new Error("could not reconnect");
        }
      }
      const resumed = t.welcome.resumed;
      session = t.welcome.session;
      for (const s of outbox) t.send({ t: "frame", seq: s, body: "d" });
      disconnects.push({ closeCode, attempts, resumed, retransmitted: outbox.length, downMs: clock() - lostAt });
      onEvent({ reconnected: true, resumed });
    }
  }
  // Settle: give the last frames a moment to be acknowledged.
  for (let i = 0; i < 10 && outbox.length; i++) {
    await sleep(500);
    await collect();
  }
  try {
    t.close();
  } catch {}
  const lost = outbox.slice();
  const duplicates = [...acked].filter(([, n]) => n > 1).map(([s]) => s);
  return { sent: seq, acknowledged: acked.size, lost, duplicateAcks: duplicates, disconnects };
}

// ---- costs ----

// Usage counted by the operator from the Cloudflare dashboard over the check
// window (or from the probe's own totals), priced with pricing.json. Prices are
// inputs, not constants, because they change: pricing.json records where and
// when they were copied from, and the report repeats that.
export function estimateCost(usage, pricing) {
  const p = pricing.prices;
  const wsRequests = usage.wsMessages / pricing.wsMessageRatio; // incoming WebSocket messages bill 20:1
  const requests = usage.requests + wsRequests;
  const gbSeconds = (usage.durationSeconds * usage.memoryMb) / 1024;
  const parts = {
    requests: Math.max(0, requests - p.includedRequests) / 1e6 * p.perMillionRequests,
    duration: Math.max(0, gbSeconds - p.includedGbSeconds) / 1e6 * p.perMillionGbSeconds,
    rowsRead: Math.max(0, usage.rowsRead - p.includedRowsRead) / 1e6 * p.perMillionRowsRead,
    rowsWritten: Math.max(0, usage.rowsWritten - p.includedRowsWritten) / 1e6 * p.perMillionRowsWritten,
    storage: Math.max(0, usage.storageGb - p.includedStorageGb) * p.perGbMonthStorage,
  };
  // Worker (front door) requests: HTTP and one per WebSocket upgrade; messages are not counted.
  if (p.perMillionWorkerRequests !== undefined) {
    parts.workerRequests = Math.max(0, (usage.workerRequests ?? 0) - p.includedWorkerRequests) / 1e6 * p.perMillionWorkerRequests;
  }
  const usageCost = Object.values(parts).reduce((a, b) => a + b, 0);
  return { parts, usageCost, planCost: p.planPerMonth, total: usageCost + p.planPerMonth, billedRequests: requests, gbSeconds };
}

// Steady-state projection for the capacity question the plan asks: what does one
// always-connected device cost per month, hibernating vs awake the whole time?
// A hibernated object is not billed for duration; heartbeats ("ping") are
// answered by the runtime without waking it, so they cost no duration.
export function perDeviceMonth({ messagesPerDay, awakeSecondsPerDay, rowsWrittenPerMessage = 1, memoryMb = 128 }, pricing) {
  const days = 30;
  const usage = {
    requests: days * 2, // one connect and one reconnect per day, a rough floor
    wsMessages: messagesPerDay * days,
    durationSeconds: awakeSecondsPerDay * days,
    memoryMb,
    rowsRead: messagesPerDay * days,
    rowsWritten: messagesPerDay * days * rowsWrittenPerMessage,
    storageGb: 0,
  };
  // Marginal cost: nothing is "included" for a single device inside a fleet.
  const marginal = { ...pricing, prices: { ...pricing.prices, includedRequests: 0, includedGbSeconds: 0, includedRowsRead: 0, includedRowsWritten: 0, includedStorageGb: 0, planPerMonth: 0 } };
  return estimateCost(usage, marginal);
}

// ---- real IdP logins ----

// A real login starts at the gateway's /auth/:provider/login, which must redirect
// to the real IdP with PKCE S256, a state, a nonce and our callback URL. This
// checks the redirect (the part a script can verify); a person then signs in and
// the callback must return an identity (recorded by hand in the report).
export function checkLoginRedirect(provider, location, { clientId, tenantId, gatewayOrigin }) {
  const problems = [];
  let u;
  try {
    u = new URL(location);
  } catch {
    return { ok: false, problems: ["location is not a URL"] };
  }
  const host = provider === "google" ? "accounts.google.com" : "login.microsoftonline.com";
  if (u.protocol !== "https:") problems.push("not https");
  if (u.hostname !== host) problems.push(`host ${u.hostname}, want ${host}`);
  if (provider === "entra" && !u.pathname.startsWith(`/${tenantId}/`)) problems.push("authorize path is not the configured tenant");
  const q = u.searchParams;
  const want = {
    response_type: "code",
    client_id: clientId,
    redirect_uri: `${gatewayOrigin}/auth/${provider}/callback`,
    code_challenge_method: "S256",
  };
  for (const [k, v] of Object.entries(want)) if (q.get(k) !== v) problems.push(`${k} is ${q.get(k) === null ? "missing" : "wrong"}`);
  for (const k of ["state", "nonce", "code_challenge"]) if (!q.get(k)) problems.push(`${k} missing`);
  if (!(q.get("scope") ?? "").split(" ").includes("openid")) problems.push("scope lacks openid");
  return { ok: problems.length === 0, problems };
}

// ---- report ----

const fmtBytes = (n) => (n === null || n === undefined ? "none" : n >= 1024 ? `${n} B (${(n / 1024).toFixed(1)} KiB)` : `${n} B`);

// Renders collected results as the Markdown tables of reality-check-1.md. A
// section with no data renders as NOT RUN, so a partial run cannot read as a pass.
export function renderReport(r) {
  const L = [];
  L.push(`Run: ${r.when ?? "NOT RUN"}, gateway \`${r.gateway ?? "?"}\`, workers.dev account ${r.account ?? "?"}`, "");
  L.push("### Limits", "");
  if (!r.limits) L.push("NOT RUN", "");
  else {
    L.push("| frame body | accepted | close code | ms |", "|---|---|---|---|");
    for (const o of r.limits.results) L.push(`| ${fmtBytes(o.bytes)} | ${o.accepted ? "yes" : "no"} | ${o.closeCode ?? ""} | ${o.ms} |`);
    L.push("", `Largest accepted ${fmtBytes(r.limits.largestAccepted)}, smallest refused ${fmtBytes(r.limits.smallestRefused)}.`, "");
  }
  L.push("### Hibernation timing", "");
  if (!r.hibernation) L.push("NOT RUN", "");
  else {
    for (const h of r.hibernation) {
      L.push(`Heartbeat pings while idle: ${h.heartbeat ? "yes" : "no"}`, "", "| idle (s) | survived | cold ms | warm ms | wake estimate ms |", "|---|---|---|---|---|");
      for (const x of h.results) L.push(`| ${x.idle} | ${x.survived ? "yes" : `no (close ${x.closeCode})`} | ${x.coldMs ?? ""} | ${x.warmMs ?? ""} | ${x.wokeEstimateMs ?? ""} |`);
      const s = h.resume;
      L.push("", `Resume after idle: ${s.resumed ? "yes" : "NO"}, rx_seq ${s.rxSeq ?? "?"} (expected ${s.expectedRxSeq ?? "?"}).`, "");
    }
  }
  L.push("### Deploy-driven disconnects", "");
  if (!r.deploy) L.push("NOT RUN", "");
  else {
    const d = r.deploy;
    L.push(`Sent ${d.sent}, acknowledged ${d.acknowledged}, lost ${d.lost.length}, duplicate acks ${d.duplicateAcks.length}, disconnects ${d.disconnects.length}.`, "");
    if (d.disconnects.length) {
      L.push("| attempts | session resumed | retransmitted | down ms |", "|---|---|---|---|");
      for (const x of d.disconnects) L.push(`| ${x.attempts} | ${x.resumed} | ${x.retransmitted} | ${x.downMs} |`);
      L.push("");
    }
  }
  L.push("### Costs", "");
  if (!r.cost) L.push("NOT RUN", "");
  else {
    L.push(`Prices from ${r.cost.pricingSource} (${r.cost.pricingAsOf}).`, "", "| item | USD |", "|---|---|");
    for (const [k, v] of Object.entries(r.cost.estimate.parts)) L.push(`| ${k} | ${v.toFixed(4)} |`);
    L.push(`| plan | ${r.cost.estimate.planCost.toFixed(2)} |`, `| total | ${r.cost.estimate.total.toFixed(2)} |`, "");
    if (r.cost.perDevice) L.push(`Marginal cost of one device: $${r.cost.perDevice.total.toFixed(4)} per month at the stated message rate.`, "");
  }
  L.push("### Real logins", "");
  if (!r.logins) L.push("NOT RUN", "");
  else {
    L.push("| provider | redirect check | sign-in completed | identity returned | notes |", "|---|---|---|---|---|");
    for (const x of r.logins) L.push(`| ${x.provider} | ${x.redirect} | ${x.signedIn ?? "NOT RUN"} | ${x.identity ?? "NOT RUN"} | ${x.notes ?? ""} |`);
    L.push("");
  }
  return L.join("\n");
}
