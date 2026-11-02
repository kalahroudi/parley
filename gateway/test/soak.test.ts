// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T108 (spike 1): 20 forced reconnects, some of them deploys, during a 10k-message
// soak in each direction lose or duplicate nothing. The client below mirrors the
// resume logic of internal/tunnel (retransmit the unacknowledged outbox on every
// connect, drop events whose seq was already seen), run against the real Device DO.
// A deploy is modeled as evicting the object and closing its sockets, which is
// what the platform does to a hibernating object on a new version.

import { SELF, env, evictDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { Device } from "../src/device";

const TOTAL = 10_000;
const RECONNECTS = 20;
const BATCH = 600; // new messages per connection; the final connection finishes the rest

const stub = () => env.DEVICE.get(env.DEVICE.idFromName("soak:d1")) as DurableObjectStub<Device>;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(cond: () => boolean, what: string, ms = 20_000): Promise<void> {
  for (const end = Date.now() + ms; !cond(); await sleep(2)) if (Date.now() > end) throw new Error(`timed out: ${what}`);
}

// Daemon state that outlives any one connection.
const daemon = {
  session: undefined as string | undefined,
  lastRx: 0, // highest event seq handed to the application
  nextSeq: 0, // last frame seq assigned
  outbox: [] as { seq: number; body: string }[], // unacknowledged frames
  delivered: new Map<string, number>(), // event body -> times handed to the application
  eventSeqs: [] as number[],
  unackedAtResume: 0, // frames still unacknowledged when a connection died
};

async function connect() {
  const res = await SELF.fetch("https://gw/v1/connect", {
    headers: { Upgrade: "websocket", Authorization: "Bearer dev:soak:d1" },
  });
  const ws = res.webSocket!;
  ws.accept();
  let dead = false;
  let closed = false;
  let welcome: any;
  ws.addEventListener("message", (e) => {
    if (dead || e.data === "pong") return;
    const m = JSON.parse(e.data as string);
    if (m.t === "welcome") welcome = m;
    else if (m.t === "ack") {
      daemon.outbox = daemon.outbox.filter((f) => f.seq > m.seq);
    } else if (m.t === "event") {
      if (m.seq <= daemon.lastRx) return;
      daemon.lastRx = m.seq;
      daemon.eventSeqs.push(m.seq);
      daemon.delivered.set(m.body, (daemon.delivered.get(m.body) ?? 0) + 1);
      ws.send(JSON.stringify({ t: "ack", seq: m.seq }));
    } else throw new Error(`unexpected server message ${e.data}`);
  });
  ws.addEventListener("close", () => (closed = true));
  ws.send(JSON.stringify({ t: "hello", v: 1, session: daemon.session, last_rx: daemon.lastRx }));
  await until(() => !!welcome, "welcome");
  if (!welcome.resumed) daemon.lastRx = 0; // the gateway lost the session; its numbering restarts
  daemon.session = welcome.session;
  daemon.unackedAtResume += daemon.outbox.length;
  daemon.outbox = daemon.outbox.filter((f) => f.seq > welcome.rx_seq);
  return {
    welcome,
    // Everything unacknowledged is retransmitted, in order, before new frames.
    sendFrames: (fresh: number) => {
      for (let k = 0; k < fresh && daemon.nextSeq < TOTAL; k++) {
        daemon.nextSeq++;
        daemon.outbox.push({ seq: daemon.nextSeq, body: `f${daemon.nextSeq}` });
      }
      for (const f of [...daemon.outbox]) ws.send(JSON.stringify({ t: "frame", seq: f.seq, body: f.body }));
    },
    // The daemon stops hearing the gateway (its side of the link is gone) before the socket closes.
    mute: () => (dead = true),
    // Hang up at once: anything the gateway sends or acknowledges from now on is lost.
    drop: async () => {
      dead = true;
      ws.close(1000, "drop");
      await until(() => closed, "close");
    },
    // The gateway side vanished (deploy): the socket closes under the daemon.
    lost: async () => {
      await until(() => closed, "close after deploy");
      dead = true;
    },
  };
}

// The sender (a peer, via the Device DO) pushes events and retries any it knows were
// not received. `limit` bounds new events per connection.
let nextEvent = 0;
let retried = 0; // events resent because the daemon never received the first copy
async function pushEvents(limit: number): Promise<void> {
  const retry: number[] = [];
  for (let i = 0; i < nextEvent; i++) if (!daemon.delivered.has(`e${i}`)) retry.push(i);
  retried += retry.length;
  const fresh: number[] = [];
  for (let k = 0; k < limit && nextEvent < TOTAL; k++) fresh.push(nextEvent++);
  for (const i of [...retry, ...fresh]) {
    if ((await stub().deliver(`e${i}`)).status === "offline") {
      // Not sent; put fresh ones back so they are tried on the next connection.
      nextEvent = Math.min(nextEvent, i);
      return;
    }
  }
}

describe("soak (spike 1)", () => {
  it(`${RECONNECTS} forced reconnects and deploys during a ${TOTAL}-message soak lose or duplicate nothing`, async () => {
    for (let i = 0; i < RECONNECTS; i++) {
      const c = await connect();
      c.sendFrames(BATCH);
      const mode = i % 4;
      if (mode === 0) {
        // Clean: let everything in flight settle, then hang up.
        await pushEvents(BATCH);
        await until(() => daemon.outbox.length === 0 || daemon.nextSeq === 0, "acks");
        await c.drop();
      } else if (mode === 1) {
        // Abrupt: hang up with frames unacknowledged while events are still being pushed.
        c.mute();
        await pushEvents(BATCH); // all lost: the daemon is gone
        await c.drop();
      } else if (mode === 2) {
        // Deploy: the object is evicted and its sockets closed mid-traffic.
        c.mute();
        await pushEvents(BATCH);
        await evictDurableObject(stub(), { webSockets: "close" });
        await c.lost();
      } else {
        // Hibernation only: the socket stays open across eviction, then we hang up.
        await pushEvents(BATCH);
        await evictDurableObject(stub());
        await sleep(2);
        await c.drop();
      }
    }

    // The final connection drains whatever is left.
    const c = await connect();
    expect(c.welcome.resumed).toBe(true);
    while (daemon.nextSeq < TOTAL || daemon.outbox.length > 0 || nextEvent < TOTAL || daemon.delivered.size < TOTAL) {
      c.sendFrames(BATCH);
      await pushEvents(BATCH);
      await until(() => daemon.outbox.length === 0, "final acks");
    }
    await until(() => daemon.delivered.size === TOTAL, "final events");

    // The soak must have exercised recovery, or it proves nothing.
    expect(daemon.unackedAtResume).toBeGreaterThan(0); // acks were lost with the connection
    expect(nextEvent).toBe(TOTAL);
    expect(retried).toBeGreaterThan(0);

    // Daemon to gateway: every frame accepted exactly once, in order.
    const st = (await stub().status()).session!;
    expect(st.rx_seq).toBe(TOTAL);
    expect(daemon.nextSeq).toBe(TOTAL);
    expect(daemon.outbox).toEqual([]);

    // Gateway to daemon: every event reached the application exactly once, with
    // strictly increasing seq (retransmitted events get a new seq and are never doubled).
    const counts = [...daemon.delivered.values()];
    expect(counts.length).toBe(TOTAL);
    expect(counts.every((n) => n === 1)).toBe(true);
    for (let i = 0; i < TOTAL; i++) if (!daemon.delivered.has(`e${i}`)) throw new Error(`event e${i} lost`);
    expect(daemon.eventSeqs.every((s, k) => k === 0 || s > daemon.eventSeqs[k - 1]!)).toBe(true);
  }, 180_000);
});
