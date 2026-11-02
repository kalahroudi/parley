// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, evictDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import type { Device } from "../src/device";

// Sockets outlive a test's storage isolation, so each test gets its own device name.
let n = 0;
let dev = "d0";
beforeEach(() => (dev = `d${++n}`));

const auth = (tenant = "t1", device = dev): Record<string, string> => ({
  Upgrade: "websocket",
  Authorization: `Bearer dev:${tenant}:${device}`,
});

const stubFor = (tenant = "t1", device = dev) =>
  env.DEVICE.get(env.DEVICE.idFromName(`${tenant}:${device}`)) as DurableObjectStub<Device>;

// A minimal daemon: queues parsed server messages so tests can await them in order.
async function connect(tenant = "t1", device = dev) {
  const res = await SELF.fetch("https://gw/v1/connect", { headers: auth(tenant, device) });
  const ws = res.webSocket!;
  expect(res.status).toBe(101);
  ws.accept();
  const inbox: any[] = [];
  const waiters: ((m: any) => void)[] = [];
  let closed: CloseEvent | undefined;
  ws.addEventListener("message", (e) => {
    const m = e.data === "pong" ? { t: "pong" } : JSON.parse(e.data as string);
    const w = waiters.shift();
    if (w) w(m);
    else inbox.push(m);
  });
  ws.addEventListener("close", (e) => {
    closed = e;
  });
  return {
    ws,
    next: () => (inbox.length ? Promise.resolve(inbox.shift()) : new Promise<any>((r) => waiters.push(r))),
    send: (m: unknown) => ws.send(typeof m === "string" ? m : JSON.stringify(m)),
    closed: async () => {
      for (let i = 0; i < 100 && !closed; i++) await new Promise((r) => setTimeout(r, 10));
      return closed;
    },
  };
}

const hello = (session?: string, last_rx = 0) => ({ t: "hello", v: 1, session, last_rx });

describe("connect", () => {
  it("rejects unauthenticated and malformed credentials", async () => {
    for (const h of <Record<string, string>[]>[{ Upgrade: "websocket" }, { Upgrade: "websocket", Authorization: "Bearer dev:t1" }, { Upgrade: "websocket", Authorization: "Bearer dev:t1:d/1" }]) {
      expect((await SELF.fetch("https://gw/v1/connect", { headers: h })).status).toBe(401);
    }
  });

  it("requires a websocket upgrade and a known path", async () => {
    expect((await SELF.fetch("https://gw/v1/connect")).status).toBe(426);
    expect((await SELF.fetch("https://gw/nope")).status).toBe(404);
    expect((await SELF.fetch("https://gw/healthz")).status).toBe(200);
  });

  it("fails closed when dev auth is off", async () => {
    const { default: worker } = await import("../src/index");
    const req = new Request("https://gw/v1/connect", { headers: auth() });
    expect((await worker.fetch(req, { ...env, DEV_AUTH: undefined })).status).toBe(401);
  });

  it("rejects a direct (non-upgrade) request to the Device DO", async () => {
    expect((await stubFor().fetch("https://do/")).status).toBe(426);
  });
});

describe("handshake", () => {
  it("welcomes a new session and answers heartbeats", async () => {
    const c = await connect();
    c.send(hello());
    const w = await c.next();
    expect(w).toMatchObject({ t: "welcome", v: 1, resumed: false, rx_seq: 0 });
    expect(typeof w.session).toBe("string");
    c.send("ping");
    expect(await c.next()).toEqual({ t: "pong" });
  });

  it("closes on a bad message, a frame before hello, or a duplicate hello", async () => {
    for (const first of ["not json", JSON.stringify({ t: "frame", seq: 1, body: "x" }), JSON.stringify({ t: "hello", v: 2, last_rx: 0 })]) {
      const c = await connect();
      c.send(first);
      expect((await c.next()).t).toBe("error");
      expect((await c.closed())?.code).toBe(4400);
    }
    const c = await connect();
    c.send(hello());
    await c.next();
    c.send(hello());
    expect(await c.next()).toEqual({ t: "error", code: "duplicate_hello" });
  });

  it("closes on binary and oversized frames", async () => {
    const a = await connect();
    a.ws.send(new Uint8Array([1]));
    expect((await a.closed())?.code).toBe(4400);
    const b = await connect("t1", dev + "x");
    b.send("x".repeat((1 << 20) + 1));
    expect((await b.closed())?.code).toBe(1009);
    // 600k two-byte characters: under the limit in UTF-16 units, over it in bytes.
    const c = await connect("t1", dev + "y");
    c.send("é".repeat(600_000));
    expect((await c.closed())?.code).toBe(1009);
  });

  it("a new connection supersedes the old one", async () => {
    const a = await connect();
    a.send(hello());
    await a.next();
    const b = await connect();
    expect((await a.closed())?.code).toBe(4409);
    b.send(hello());
    expect((await b.next()).t).toBe("welcome");
  });

  it("isolates devices by tenant", async () => {
    const a = await connect("tenantA");
    a.send(hello());
    const sa = (await a.next()).session;
    const b = await connect("tenantB");
    b.send(hello());
    expect((await b.next()).session).not.toBe(sa);
    expect(await stubFor("tenantA").deliver("x")).toMatchObject({ status: "delivered" });
  });
});

describe("frames from the daemon", () => {
  it("acks each frame and drops a retransmitted duplicate", async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    c.send({ t: "frame", seq: 1, body: "a" });
    expect(await c.next()).toEqual({ t: "ack", seq: 1 });
    c.send({ t: "frame", seq: 1, body: "a" });
    expect(await c.next()).toEqual({ t: "ack", seq: 1 });
    c.send({ t: "frame", seq: 2, body: "b" });
    expect(await c.next()).toEqual({ t: "ack", seq: 2 });
    expect((await stubFor().status()).session?.rx_seq).toBe(2);
  });
});

describe("events to the daemon", () => {
  it("refuses an event too large for the daemon to read, without consuming a seq", async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    // Under the limit as raw bytes, over it once JSON-escaped.
    expect(await stubFor().deliver('"'.repeat(600_000))).toEqual({ status: "too_large" });
    expect(await stubFor().deliver("é".repeat(600_000))).toEqual({ status: "too_large" });
    expect(await stubFor().deliver("ok")).toEqual({ status: "delivered", seq: 1 });
    expect(await c.next()).toEqual({ t: "event", seq: 1, body: "ok" });
  });

  it("is offline until a hello completes, then delivers with increasing seq", async () => {
    expect(await stubFor().deliver("x")).toEqual({ status: "offline" });
    const c = await connect();
    expect(await stubFor().deliver("x")).toEqual({ status: "offline" });
    c.send(hello());
    await c.next();
    expect(await stubFor().deliver("one")).toEqual({ status: "delivered", seq: 1 });
    expect(await stubFor().deliver("two")).toEqual({ status: "delivered", seq: 2 });
    expect(await c.next()).toEqual({ t: "event", seq: 1, body: "one" });
    expect(await c.next()).toEqual({ t: "event", seq: 2, body: "two" });
    c.send({ t: "ack", seq: 2 });
    c.send({ t: "ack", seq: 3 });
    expect(await c.next()).toEqual({ t: "error", code: "bad_ack" });
    expect((await stubFor().status()).session?.acked_tx).toBe(2);
  });

  it("is offline after the daemon disconnects", async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    c.ws.close(1000, "bye");
    await c.closed();
    for (let i = 0; i < 100 && (await stubFor().status()).connected; i++) await new Promise((r) => setTimeout(r, 10));
    expect(await stubFor().deliver("x")).toEqual({ status: "offline" });
  });
});

describe("hibernation and resume", () => {
  it("keeps the socket and session across eviction", async () => {
    const c = await connect();
    c.send(hello());
    const { session } = await c.next();
    c.send({ t: "frame", seq: 1, body: "a" });
    await c.next();
    await evictDurableObject(stubFor()); // hibernates; the socket stays open
    expect(await stubFor().deliver("after")).toEqual({ status: "delivered", seq: 1 });
    expect(await c.next()).toEqual({ t: "event", seq: 1, body: "after" });
    c.send({ t: "frame", seq: 2, body: "b" });
    expect(await c.next()).toEqual({ t: "ack", seq: 2 });
    const st = await stubFor().status();
    expect(st.session).toMatchObject({ id: session, rx_seq: 2 });
  });

  it("answers heartbeats while hibernated", async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    await evictDurableObject(stubFor());
    c.send("ping");
    expect(await c.next()).toEqual({ t: "pong" });
  });

  it("resumes a session after reconnect with no loss or duplicates", async () => {
    const a = await connect();
    a.send(hello());
    const { session } = await a.next();
    a.send({ t: "frame", seq: 1, body: "a" });
    await a.next();
    await stubFor().deliver("e1");
    await a.next();
    await evictDurableObject(stubFor(), { webSockets: "close" });

    const b = await connect();
    b.send(hello(session, 1));
    expect(await b.next()).toMatchObject({ t: "welcome", resumed: true, session, rx_seq: 1 });
    // The daemon retransmits its unacked frame 2 and, defensively, frame 1.
    b.send({ t: "frame", seq: 1, body: "a" });
    b.send({ t: "frame", seq: 2, body: "b" });
    expect(await b.next()).toEqual({ t: "ack", seq: 1 });
    expect(await b.next()).toEqual({ t: "ack", seq: 2 });
    const st = (await stubFor().status()).session!;
    expect(st).toMatchObject({ rx_seq: 2, tx_seq: 1, acked_tx: 1 });
    expect(await stubFor().deliver("e2")).toEqual({ status: "delivered", seq: 2 });
  });

  it("starts a fresh session for an unknown session id", async () => {
    const a = await connect();
    a.send(hello("stale-id", 9));
    const w = await a.next();
    expect(w).toMatchObject({ t: "welcome", resumed: false, rx_seq: 0 });
    expect(w.session).not.toBe("stale-id");
  });

  it("survives 20 reconnects without losing or duplicating frames", async () => {
    let session: string | undefined;
    let acked = 0;
    let total = 0;
    for (let i = 0; i < 20; i++) {
      const c = await connect();
      c.send(hello(session, 0));
      const w = await c.next();
      session = w.session;
      expect(w.rx_seq).toBe(acked);
      // Send the next 3 frames, plus a retransmit of the last acked one.
      if (acked > 0) c.send({ t: "frame", seq: acked, body: "dup" });
      for (let k = 1; k <= 3; k++) c.send({ t: "frame", seq: acked + k, body: "b" });
      const seen: number[] = [];
      for (let k = 0; k < (acked > 0 ? 4 : 3); k++) seen.push((await c.next()).seq);
      acked += 3;
      total += 3;
      expect(seen.at(-1)).toBe(acked);
      c.ws.close(1000, "drop");
      await c.closed();
    }
    expect((await stubFor().status()).session?.rx_seq).toBe(total);
  });
});
