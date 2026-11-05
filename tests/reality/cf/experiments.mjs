// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109: the Node-side measurements against the deployed measurement Worker
// (worker/entry.ts). Each takes `ctx` = { WebSocket, url, token(device), stats }
// and returns plain JSON: timings, close codes and counters only.
import { MAX_FRAME_BYTES, openTunnel, probeFrameLimits } from "../lib.mjs";

const PROBE = '{"t":"probe"}';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const opts = (ctx, device, extra = {}) => ({ WebSocket: ctx.WebSocket, url: ctx.url, token: ctx.token(device), ...extra });

// One probe round trip. `woke` is true when the object was constructed since the
// previous probe, which means it was evicted (hibernated) in between.
export async function probeOnce(ctx, t, prev) {
  const started = performance.now();
  t.send(PROBE);
  ctx.stats.wsMessages++;
  const m = await t.next((x) => x.t === "probe");
  const rtt = Math.round(performance.now() - started);
  return { rtt, boot: m.boot, boots: m.boots, ageMs: m.ageMs, woke: prev ? m.boot !== prev.boot : null };
}

export async function limits(ctx) {
  const sizes = [1 << 10, 64 << 10, 512 << 10, MAX_FRAME_BYTES - 64, MAX_FRAME_BYTES, MAX_FRAME_BYTES + 1024, 8 << 20, 33 << 20];
  const r = await probeFrameLimits(opts(ctx, "limits"), sizes);
  ctx.stats.wsMessages += sizes.length * 2;
  ctx.stats.connections += sizes.length;
  return r;
}

// Idle ladder on one socket: after each idle period, was the object evicted
// (boot id changed) and how long did the first message take?
export async function ladder(ctx, idleSeconds) {
  const t = await openTunnel(opts(ctx, "ladder"));
  ctx.stats.connections++;
  let prev = await probeOnce(ctx, t);
  const rows = [{ idle: 0, ...prev }];
  for (const idle of idleSeconds) {
    await sleep(idle * 1000);
    const warmBefore = t.closed ? null : true;
    if (!warmBefore) {
      rows.push({ idle, closedCode: t.closed.code });
      break;
    }
    const p = await probeOnce(ctx, t, prev);
    const again = await probeOnce(ctx, t, p); // right after: warm round trip
    rows.push({ idle, ...p, warmRtt: again.rtt });
    prev = again;
  }
  t.close();
  return rows;
}

// Do protocol "ping" frames wake a hibernated object, or keep one awake?
// Probe, idle 20 s (hibernates), ping every 3 s for 60 s, probe. If the final
// probe finds an object only a few ms old, it was woken by the probe itself,
// not by the pings.
export async function pings(ctx) {
  const t = await openTunnel(opts(ctx, "pings"));
  ctx.stats.connections++;
  const before = await probeOnce(ctx, t);
  await sleep(20_000);
  const n = 20;
  for (let i = 0; i < n; i++) {
    t.send("ping");
    ctx.stats.wsMessages++;
    await t.next((x) => x.t === "raw" && x.body === "pong");
    await sleep(3000);
  }
  const after = await probeOnce(ctx, t, before);
  t.close();
  return { before, after, pings: n, bootsGained: after.boots - before.boots };
}

// A long idle period, with or without 20 s heartbeats like the daemon's.
export async function longIdle(ctx, seconds, heartbeat) {
  const t = await openTunnel(opts(ctx, heartbeat ? "idle-hb" : "idle-quiet"));
  ctx.stats.connections++;
  const before = await probeOnce(ctx, t);
  for (let waited = 0; waited < seconds && !t.closed; ) {
    const step = heartbeat ? Math.min(20, seconds - waited) : seconds - waited;
    await sleep(step * 1000);
    waited += step;
    if (heartbeat && !t.closed) {
      t.send("ping");
      ctx.stats.wsMessages++;
    }
  }
  if (t.closed) return { seconds, heartbeat, survived: false, closeCode: t.closed.code, before };
  const after = await probeOnce(ctx, t, before);
  t.close();
  return { seconds, heartbeat, survived: true, before, after };
}

// What a real `wrangler deploy` does to live sockets. `deployFn()` runs the deploy
// and returns when wrangler is done. One socket is idle (hibernated) and one is
// kept busy; both record when and with what code they closed, relative to the
// deploy's start and end.
export async function deployDuringSockets(ctx, deployFn) {
  const out = {};
  const idle = await openTunnel(opts(ctx, "dep-idle"));
  const busy = await openTunnel(opts(ctx, "dep-busy"));
  ctx.stats.connections += 2;
  const idleBefore = await probeOnce(ctx, idle);
  const busyBefore = await probeOnce(ctx, busy);
  await sleep(20_000); // let the idle one hibernate
  let seq = 0;
  const pump = setInterval(() => {
    if (!busy.closed) {
      busy.send({ t: "frame", seq: ++seq, body: "x" });
      ctx.stats.wsMessages++;
    }
  }, 200);
  const t0 = Date.now();
  const deployMs = await deployFn().then(() => Date.now() - t0);
  const t1 = Date.now();
  await sleep(5000);
  clearInterval(pump);
  const rel = (c) => (c ? { code: c.code, atMsAfterDeployStart: c.at - t0, duringDeploy: c.at >= t0 && c.at <= t1 } : null);
  out.deployMs = deployMs;
  out.idle = { closed: rel(idle.closed) };
  out.busy = { closed: rel(busy.closed), framesSent: seq };
  if (!idle.closed) out.idle.after = await probeOnce(ctx, idle, idleBefore);
  if (!busy.closed) out.busy.after = await probeOnce(ctx, busy, busyBefore);
  idle.close();
  busy.close();
  return out;
}
