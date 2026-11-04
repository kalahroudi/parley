// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, evictDurableObject, runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_HELD, type Device, type Held } from "../src/device";
import type { Task } from "../src/task";

// Sockets outlive a test's storage isolation, so each test gets its own device name.
let n = 0;
let dev = "d0";
beforeEach(() => (dev = `d${++n}`));


const stubFor = (tenant = "t1", device = dev) =>
  env.DEVICE.get(env.DEVICE.idFromName(`${tenant}:${device}`)) as DurableObjectStub<Device>;

// A minimal daemon: queues parsed server messages so tests can await them in order.
async function connect(tenant = "t1", device = dev) {
  // The Worker's /v1/connect stays closed until connect tokens land, so tests
  // open the socket on the Device DO itself, as the Worker will after authenticating.
  const res = await stubFor(tenant, device).fetch("https://do/", { headers: { Upgrade: "websocket" } });
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
  it("fails closed: no credential opens a device connection yet", async () => {
    for (const h of <Record<string, string>[]>[{ Upgrade: "websocket" }, { Upgrade: "websocket", Authorization: "Bearer dev:t1:d1" }, { Upgrade: "websocket", Authorization: "Bearer dev-admin:t1" }]) {
      expect((await SELF.fetch("https://gw/v1/connect", { headers: h })).status).toBe(401);
    }
  });

  it("requires a websocket upgrade and a known path", async () => {
    expect((await SELF.fetch("https://gw/v1/connect")).status).toBe(426);
    expect((await SELF.fetch("https://gw/nope")).status).toBe(404);
    expect((await SELF.fetch("https://gw/healthz")).status).toBe(200);
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
    // 20 connects, each with ~10 durable writes, and a close that is awaited. Windows CI
    // measured 1.9 s here (run 41685709490; Linux and macOS ~0.3 s), against vitest's 5 s
    // default: 30 s is the headroom for a cold or contended runner, and a hang still fails.
  }, 30_000);
});

describe("socket teardown", () => {
  // A daemon can drop while the object awaits storage, so every reply may find its
  // socket closed. That must not throw: an uncaught exception in a handler is
  // logged as a crash, and (on slow storage) poisons the tests that follow.
  const serverSocket = (state: DurableObjectState) => state.getWebSockets()[0]!;

  it("does not throw when the daemon closed before the welcome", async () => {
    const c = await connect();
    await runInDurableObject(stubFor(), async (instance, state) => {
      const ws = serverSocket(state);
      ws.close(1000, "gone");
      await instance.webSocketMessage(ws, JSON.stringify(hello()));
    });
    expect((await c.closed())?.code).toBe(1000);
  });

  it("does not throw when the daemon closed before a frame's ack", async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    await runInDurableObject(stubFor(), async (instance, state) => {
      const ws = serverSocket(state);
      ws.close(1000, "gone");
      await instance.webSocketMessage(ws, JSON.stringify({ t: "frame", seq: 1, body: "a" }));
      await instance.webSocketMessage(ws, "not json"); // reject() on a closed socket
    });
    expect((await stubFor().status()).session?.rx_seq).toBe(1); // still stored, so a retransmit is a duplicate
  });

  it("reports offline, and burns no seq, when the socket closed before the event", async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    const result = await runInDurableObject(stubFor(), async (instance, state) => {
      serverSocket(state).close(1000, "gone");
      return instance.deliver("x");
    });
    expect(result).toEqual({ status: "offline" });
    expect((await stubFor().status()).session?.tx_seq).toBe(0);
  });

  // The socket drops while deliver awaits storage (the real race, made deterministic).
  for (const op of ["get", "put"] as const) {
    it(`reports offline when the socket closes during the storage ${op}`, async () => {
      const c = await connect();
      c.send(hello());
      await c.next();
      const result = await runInDurableObject(stubFor(), async (instance, state) => {
        const ws = serverSocket(state);
        const orig = state.storage[op].bind(state.storage) as (...a: unknown[]) => Promise<unknown>;
        (state.storage as any)[op] = async (...a: unknown[]) => {
          const r = await orig(...a);
          ws.close(1000, "gone");
          return r;
        };
        try {
          return await instance.deliver("x");
        } finally {
          (state.storage as any)[op] = orig;
        }
      });
      expect(result).toEqual({ status: "offline" });
    });
  }

  // Runs `during` the next storage `op` of the object (after it completes), the way a
  // daemon drop or a new connection lands while a handler is awaiting storage.
  async function atStorage(state: DurableObjectState, op: "get" | "put", during: () => void, run: () => Promise<unknown>) {
    const orig = state.storage[op].bind(state.storage) as (...a: unknown[]) => Promise<unknown>;
    (state.storage as any)[op] = async (...a: unknown[]) => {
      const r = await orig(...a);
      during();
      return r;
    };
    try {
      return await run();
    } finally {
      (state.storage as any)[op] = orig;
    }
  }

  it("a hello that is superseded during its storage write does not become ready or send", async () => {
    const old = await connect();
    await runInDurableObject(stubFor(), async (instance, state) => {
      const ws = serverSocket(state);
      await atStorage(state, "put", () => ws.close(1000, "replaced"), () => instance.webSocketMessage(ws, JSON.stringify(hello())));
      expect((ws.deserializeAttachment() as any)?.ready).toBe(false);
    });
    expect((await stubFor().status()).connected).toBe(false);
    expect((await stubFor().deliver("x")).status).toBe("offline");
    expect((await old.closed())?.code).toBe(1000);
  });

  it("a supersede during deliver's storage write sends nothing on the old socket", async () => {
    const old = await connect();
    old.send(hello());
    await old.next();
    const fresh = await connect(); // supersedes: the old socket is closed 4xxx
    expect((await old.closed())?.reason).toBe("replaced");
    // The old socket is gone; the new one is not ready until its hello, so no event
    // can land anywhere.
    expect(await stubFor().deliver("x")).toEqual({ status: "offline" });
    fresh.send(hello());
    await fresh.next();
    expect(await stubFor().deliver("y")).toMatchObject({ status: "delivered" });
    expect((await fresh.next()).body).toBe("y");
  });

  it("a supersede during deliver's storage write reports offline and sends nothing", async () => {
    const old = await connect();
    old.send(hello());
    await old.next();
    const result = await runInDurableObject(stubFor(), async (instance, state) => {
      const ws = serverSocket(state);
      return atStorage(state, "put", () => {
        ws.serializeAttachment({ ready: false });
        ws.close(4000, "replaced");
      }, () => instance.deliver("x"));
    });
    expect(result).toEqual({ status: "offline" });
    old.ws.close(1000, "done");
  });

  it("status() does not count a closed socket as connected", async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    await runInDurableObject(stubFor(), async (instance, state) => {
      serverSocket(state).close(1000, "gone");
      expect((await instance.status()).connected).toBe(false);
    });
  });

  it("a new connection can replace a socket that already closed", async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    await runInDurableObject(stubFor(), async (_i, state) => serverSocket(state).close(1000, "gone"));
    const c2 = await connect();
    c2.send(hello());
    expect((await c2.next()).t).toBe("welcome");
  });

  it("close and error callbacks on an already-closed socket do not throw", async () => {
    const c = await connect();
    await runInDurableObject(stubFor(), async (instance, state) => {
      const ws = serverSocket(state);
      ws.close(1000, "gone");
      await instance.webSocketClose(ws, 1000);
      await instance.webSocketClose(ws, 1005);
      await instance.webSocketClose(ws, 1006);
      await instance.webSocketError(ws);
    });
    expect((await c.closed())?.code).toBe(1000);
  });

  it("echoes a normal close code, and maps 1005 and 1006 to 1000", async () => {
    for (const [sent, got] of [[4001, 4001], [1005, 1000]] as const) {
      const c = await connect();
      await runInDurableObject(stubFor(), async (instance, state) => instance.webSocketClose(serverSocket(state), sent));
      const closed = await c.closed();
      expect([closed?.code, closed?.reason]).toEqual([got, "closing"]);
    }
  });

  it("a frame after the session vanished is rejected, and an old ack is ignored", async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    await stubFor().deliver("x");
    await c.next();
    c.send({ t: "ack", seq: 1 });
    c.send({ t: "ack", seq: 1 }); // not above acked_tx: no write
    await new Promise((r) => setTimeout(r, 50));
    expect((await stubFor().status()).session?.acked_tx).toBe(1);
    await runInDurableObject(stubFor(), async (_i, state) => state.storage.delete("session"));
    c.send({ t: "frame", seq: 1, body: "a" });
    expect(await c.next()).toEqual({ t: "error", code: "no_session" });
  });

  it("treats a socket with no attachment as not ready", async () => {
    const c = await connect();
    await runInDurableObject(stubFor(), async (instance, state) => {
      const ws = serverSocket(state);
      ws.serializeAttachment(null);
      await instance.webSocketMessage(ws, JSON.stringify({ t: "ack", seq: 1 }));
    });
    expect(await c.next()).toEqual({ t: "error", code: "hello_required" });
  });

  // ---- exact behaviour of the close codes, reasons, limits and counters ----

  const MAX = 1 << 20;
  const ready = async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    return c;
  };

  it("closes a superseded socket with 4409 'replaced'", async () => {
    const old = await ready();
    await runInDurableObject(stubFor(), async (_i, state) => {
      expect((serverSocket(state).deserializeAttachment() as any).ready).toBe(true);
    });
    const fresh = await connect();
    const closed = await old.closed();
    expect([closed?.code, closed?.reason]).toEqual([4409, "replaced"]);
    fresh.ws.close(1000, "done");
  });

  it("answers a non-websocket request with 426 and the explanation", async () => {
    const res = await stubFor().fetch("https://gw/v1/connect");
    expect([res.status, await res.text()]).toEqual([426, "expected websocket"]);
  });

  it("closes on a binary frame with 4400 'text frames only'", async () => {
    const c = await ready();
    c.ws.send(new Uint8Array([1, 2, 3]));
    const closed = await c.closed();
    expect([closed?.code, closed?.reason]).toEqual([4400, "text frames only"]);
  });

  it("closes an oversize frame with 1009, but accepts one of exactly the limit", async () => {
    const pad = (n: number, ch: string) => ch.repeat(n);
    const frame = (body: string) => JSON.stringify({ t: "frame", seq: 1, body });
    const overhead = frame("").length;
    const ok = await ready();
    ok.send(frame(pad(MAX - overhead, "a"))); // exactly MAX bytes, ASCII
    expect(await ok.next()).toEqual({ t: "ack", seq: 1 });
    // exactly MAX bytes with multi-byte characters: fewer than MAX UTF-16 units
    const ok2 = await connect("t1", `${dev}-mb`);
    ok2.send(hello());
    await ok2.next();
    ok2.send(frame("é".repeat(1000) + "a".repeat(MAX - overhead - 2000)));
    expect(await ok2.next()).toEqual({ t: "ack", seq: 1 });
    const big = await connect("t1", `${dev}-big`);
    big.send(frame(pad(MAX - overhead + 1, "a")));
    const closed = await big.closed();
    expect([closed?.code, closed?.reason]).toEqual([1009, "frame too large"]);
    const bigMb = await connect("t1", `${dev}-bigmb`);
    bigMb.send(frame("é".repeat(MAX / 2)));
    expect((await bigMb.closed())?.code).toBe(1009);
  });

  it("rejects an unparseable message with the bad_message error and a 4400 close", async () => {
    const c = await ready();
    c.send("not json");
    expect(await c.next()).toEqual({ t: "error", code: "bad_message" });
    expect((await c.closed())?.code).toBe(4400);
  });

  it("delivers an event of exactly the frame limit and refuses one byte more", async () => {
    const c = await ready();
    const base = new TextEncoder().encode(JSON.stringify({ t: "event", seq: Number.MAX_SAFE_INTEGER, body: "" })).length;
    expect(await stubFor().deliver("a".repeat(MAX - base))).toMatchObject({ status: "delivered" });
    expect((await c.next()).t).toBe("event");
    expect(await stubFor().deliver("a".repeat(MAX - base + 1))).toEqual({ status: "too_large" });
  });

  it("deliver and status treat a socket with no attachment as not ready, without throwing", async () => {
    await connect();
    await runInDurableObject(stubFor(), async (instance, state) => {
      serverSocket(state).serializeAttachment(null);
      expect(await instance.deliver("x")).toEqual({ status: "offline" });
      expect((await instance.status()).connected).toBe(false);
    });
  });

  it("status() reports connected once the hello completes", async () => {
    const c = await connect();
    expect((await stubFor().status()).connected).toBe(false);
    c.send(hello());
    await c.next();
    expect((await stubFor().status()).connected).toBe(true);
  });

  it("resumes only when the offered session id is the stored one", async () => {
    const a = await ready();
    a.ws.close(1000, "x");
    await a.closed();
    const stored = (await stubFor().status()).session!.id;
    const b = await connect();
    b.send(hello("some-other-session"));
    const w = await b.next();
    expect([w.resumed, w.session === stored]).toEqual([false, false]);
  });

  it("never counts more received events as acknowledged than were sent", async () => {
    const c = await connect();
    c.send(hello(undefined, 99));
    await c.next();
    expect((await stubFor().status()).session?.acked_tx).toBe(0);
  });

  it("an ack or frame at or below the stored counter writes nothing and cannot move it back", async () => {
    const c = await ready();
    await stubFor().deliver("1");
    await stubFor().deliver("2");
    await c.next();
    await c.next();
    c.send({ t: "ack", seq: 2 });
    for (const seq of [1, 2, 3]) c.send({ t: "frame", seq, body: "a" });
    for (let i = 0; i < 3; i++) await c.next();
    const puts = await runInDurableObject(stubFor(), async (instance, state) => {
      let n = 0;
      const orig = state.storage.put.bind(state.storage) as (...a: unknown[]) => Promise<unknown>;
      (state.storage as any).put = (...a: unknown[]) => (n++, orig(...a));
      for (const m of [{ t: "ack", seq: 2 }, { t: "ack", seq: 1 }, { t: "frame", seq: 3, body: "a" }, { t: "frame", seq: 2, body: "a" }]) {
        await instance.webSocketMessage(serverSocket(state), JSON.stringify(m));
      }
      (state.storage as any).put = orig;
      return n;
    });
    expect(puts).toBe(0);
    const s = (await stubFor().status()).session!;
    expect([s.acked_tx, s.rx_seq]).toEqual([2, 3]);
  });

  it("closes with 1011 on a socket error", async () => {
    const c = await connect();
    c.send(hello());
    await c.next();
    await runInDurableObject(stubFor(), async (instance, state) => {
      await instance.webSocketError(state.getWebSockets()[0]!);
    });
    const closed = await c.closed();
    expect([closed?.code, closed?.reason]).toEqual([1011, "error"]);
  });
});


// Queued retention: the Task DO holds sealed events for an offline caller; the
// Device DO pushes them when the caller's daemon connects and deletes each one
// when the daemon acknowledges it.
describe("held events (Queued)", () => {
  const taskStub = (id: string) => env.TASK.get(env.TASK.idFromName(`t1:${id}`)) as DurableObjectStub<Task>;
  const heldKeys = (id: string) => runInDurableObject(taskStub(id), async (_, ctx) => [...(await ctx.storage.list({ prefix: "q:" })).keys()]);
  const until = async (f: () => Promise<boolean>) => {
    for (let i = 0; i < 200; i++) {
      if (await f()) return;
      await new Promise((r) => setTimeout(r, 10));
    }
    throw new Error("condition not reached");
  };
  // A queued task from this test's device (the caller) to "srv" holding the given bodies, and the device told about it.
  async function seed(id: string, bodies: string[], ttl = 3600_000) {
    const t = taskStub(id);
    await t.create({ tenant: "t1", id, caller: dev, target: "srv", retention: "queued" });
    for (const b of bodies) await t.enqueue("t1", "srv", b, ttl);
    expect(await stubFor().hold({ tenant: "t1", device: dev, task: id, until: Date.now() + ttl })).toBe("ok");
  }
  const open = async (session?: string, last_rx = 0) => {
    const c = await connect();
    c.send(hello(session, last_rx));
    const welcome = await c.next();
    expect(welcome.t).toBe("welcome");
    return { c, welcome };
  };

  it("pushes held events, oldest task first, when the daemon connects; an acknowledgment deletes them", async () => {
    await seed(`a${n}`, ["one", "two"]);
    await seed(`b${n}`, ["three"]);
    const { c } = await open();
    expect([await c.next(), await c.next(), await c.next()]).toEqual([
      { t: "event", seq: 1, body: "one" },
      { t: "event", seq: 2, body: "two" },
      { t: "event", seq: 3, body: "three" },
    ]);
    expect(await heldKeys(`a${n}`)).toHaveLength(2); // held until acknowledged
    c.send({ t: "ack", seq: 2 });
    await until(async () => (await heldKeys(`a${n}`)).length === 0);
    expect(await heldKeys(`b${n}`)).toHaveLength(1); // seq 3 is not acknowledged yet
    c.send({ t: "ack", seq: 3 });
    await until(async () => (await heldKeys(`b${n}`)).length === 0);
    c.send({ t: "ack", seq: 3 }); // a repeat is harmless
  });

  it("pushes an unacknowledged event again after a reconnect, until the daemon says it has it", async () => {
    await seed(`a${n}`, ["one"]);
    const first = await open();
    expect(await first.c.next()).toEqual({ t: "event", seq: 1, body: "one" });
    first.c.ws.close(1000, "bye"); // dropped before acknowledging
    const second = await open(first.welcome.session, 0);
    expect(await second.c.next()).toEqual({ t: "event", seq: 2, body: "one" });
    second.c.ws.close(1000, "bye");
    // The daemon reports having received seq 2 (hello's last_rx counts as an acknowledgment).
    const third = await open(first.welcome.session, 2);
    await until(async () => (await heldKeys(`a${n}`)).length === 0);
    third.c.send({ t: "ack", seq: 2 });
  });

  it("drops tasks that hold nothing any more, or are gone, and sends nothing for them", async () => {
    await seed(`gone${n}`, ["x"]);
    await runInDurableObject(taskStub(`gone${n}`), (_, ctx) => ctx.storage.deleteAll());
    await seed(`empty${n}`, ["x"]);
    await taskStub(`empty${n}`).ack("t1", dev, 1);
    const { c } = await open();
    c.send({ t: "ping" });
    expect((await c.next()).t).not.toBe("event");
    expect(await runInDurableObject(stubFor(), (_, ctx) => ctx.storage.get("held"))).toEqual([]);
  });

  it("forgets a task after its deadline, whatever the Task DO says", async () => {
    await seed(`a${n}`, ["x"], 900_000);
    await runInDurableObject(stubFor(), async (_, ctx) => {
      const held = (await ctx.storage.get<Held[]>("held"))!;
      await ctx.storage.put("held", held.map((h) => ({ ...h, until: Date.now() - 1 })));
    });
    const { c } = await open();
    c.send({ t: "ping" });
    expect((await c.next()).t).not.toBe("event");
  });

  it("notes a task once, keeps the later deadline, and stops at MAX_HELD tasks", async () => {
    // A frozen clock: on a slow disk the 256 writes below outlast a real one-second deadline.
    vi.useFakeTimers({ toFake: ["Date"] });
    const d = stubFor();
    const at = Date.now() + 1000;
    const h = (task: string, until = at): Held => ({ tenant: "t1", device: dev, task, until });
    expect(await d.hold(h("t0", at))).toBe("ok");
    expect(await d.hold(h("t0", at + 500))).toBe("ok");
    expect(await d.hold(h("t0", at - 500))).toBe("ok");
    expect(await runInDurableObject(d, (_, ctx) => ctx.storage.get("held"))).toEqual([h("t0", at + 500)]);
    for (let i = 1; i < MAX_HELD; i++) expect(await d.hold(h(`t${i}`))).toBe("ok");
    expect(await d.hold(h("overflow"))).toBe("full");
    expect(await d.hold(h("t5", at + 9))).toBe("ok"); // a task already noted is never refused
    // Expired notes make room.
    await runInDurableObject(d, async (_, ctx) => ctx.storage.put("held", (await ctx.storage.get<Held[]>("held"))!.map((x) => ({ ...x, until: Date.now() - 1 }))));
    expect(await d.hold(h("overflow"))).toBe("ok");
    expect(await runInDurableObject(d, (_, ctx) => ctx.storage.get("held"))).toEqual([h("overflow")]);
    vi.useRealTimers();
  });
});
