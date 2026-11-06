// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T503: the offboarding cascade (journey I), the metadata audit CSV, the tenant export and tenant deletion (journey L).
// Everything goes through the gateway as a client would use it: the admin over HTTP with a real session, devices over
// /a2a and /v1/connect (resolved by the test stand-in for the Worker's connect tokens, see wire.ts), and the storage of
// the Durable Objects is read afterwards to check what is, and is no longer, there.

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SEALED_MEDIA_TYPE } from "../src/a2a";
import { CLOSE_REVOKED } from "../src/protocol";
import type { SignedKind } from "../src/parts";
import { TASK_METADATA_RETENTION_MS } from "../src/task";
import { CASCADE_CALLS, CSV_PAGE_MAX, MAX_TASK_LOG, PURGE_CALLS, SESSION_TTL_MS, type TaskLogRow } from "../src/tenant";
import { adminRow, csvCell, csvRow, taskRow } from "../src/export";
import { b64, encodeWire, gw, header, taskBytes, taskHex } from "./wire";

afterEach(() => vi.useRealTimers());

const id = (c: string) => c.repeat(32);
const [A, B, C, D] = [id("a"), id("b"), id("c"), id("d")];
const hexId = (i: number) => i.toString(16).padStart(32, "0");
const key = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const ROLE: Record<string, string> = { TASK: "ROLE_USER", REPLY: "ROLE_USER", CANCEL: "ROLE_USER" };

let n = 0;
function world() {
  const T = `off${++n}`;
  const stub = env.TENANT.get(env.TENANT.idFromName(T));
  const session = (role: "admin" | "user", email = "admin@example.test") => stub.createSession(email, role).then((s) => ({ auth: `Bearer ps_${T}.${s.secret}`, csrf: s.csrf, secret: s.secret }));
  const admin = session("admin").then((s) => s.auth);
  const post = async (path: string, body: unknown, auth?: string | Promise<string>, extra: Record<string, string> = {}) => {
    const a = await auth;
    return SELF.fetch(`https://gw${path}`, { method: "POST", headers: { ...(a ? { Authorization: a } : {}), ...extra }, body: typeof body === "string" ? body : JSON.stringify(body) });
  };
  const rpc = async (device: string, method: string, params: unknown) => {
    const r = await gw("https://gw/a2a", { method: "POST", headers: { Authorization: `Bearer dev:${T}:${device}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    expect(r.status).toBe(200);
    return (await r.json()) as any;
  };
  const send = (kind: SignedKind, from: string, to: string, seq: number, task: string) =>
    rpc(from, "SendMessage", {
      message: {
        messageId: `m${++n}`,
        role: ROLE[kind] ?? "ROLE_AGENT",
        parts: [{ raw: b64(encodeWire({ header: header(kind, { tenant: T, sender: from, target: to, task: taskBytes(task), seq }), bucket: 8192 })), mediaType: SEALED_MEDIA_TYPE }],
      },
    });
  const revoke = async (devices: string[], version: number) => post("/v1/admin/revocations", { list: { tenant: T, version, revoked: devices, signature: "x" } }, admin);
  const get = async (device: string, task: string) => (await rpc(device, "GetTask", { id: taskHex(task) })).result;
  const inTenant = <R>(f: (inst: any, ctx: DurableObjectState) => Promise<R>) => runInDurableObject(stub, f as any) as Promise<R>;
  const storage = (s: DurableObjectStub) => runInDurableObject(s, async (_i, ctx) => Object.fromEntries(await ctx.storage.list()));
  const deviceStorage = (d: string) => storage(env.DEVICE.get(env.DEVICE.idFromName(`${T}:${d}`)));
  const taskStorage = (task: string) => storage(env.TASK.get(env.TASK.idFromName(`${T}:${taskHex(task)}`)));
  return { T, stub, admin, session, post, rpc, send, revoke, get, inTenant, deviceStorage, taskStorage };
}
type World = ReturnType<typeof world>;

// A tunnel the test holds open; `closed` resolves with the close code the gateway sent.
async function tunnel(w: World, device: string) {
  const res = await gw("https://gw/v1/connect", { headers: { Upgrade: "websocket", Authorization: `Bearer dev:${w.T}:${device}` } });
  const ws = res.webSocket!;
  ws.accept();
  const closed = new Promise<number>((r) => ws.addEventListener("close", (e) => r(e.code)));
  const welcomed = new Promise<void>((r) => ws.addEventListener("message", (e) => JSON.parse(e.data as string).t === "welcome" && r()));
  ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
  await welcomed;
  return { ws, closed };
}

// Puts `count` task log rows straight into the tenant's storage (the log holds up to MAX_TASK_LOG, too many to make by
// sending that many tasks).
async function seedLog(w: World, rows: (i: number) => Partial<TaskLogRow>, count: number, from = 1) {
  await w.inTenant(async (_i, ctx) => {
    for (let at = 0; at < count; at += 100) {
      const batch: Record<string, unknown> = {};
      for (let i = at; i < Math.min(count, at + 100); i++) {
        const seq = from + i;
        batch[`tsk:${String(seq).padStart(12, "0")}`] = { task: hexId(seq), caller: C, target: D, created: Date.now(), expires_at: Date.now() + 3600_000, bucket: 4096, retention: "strict", ...rows(i) } satisfies TaskLogRow;
      }
      await ctx.storage.put(batch);
    }
    await ctx.storage.put({ tsks: from + count - 1, ntsk: (((await ctx.storage.get<number>("ntsk")) ?? 0) as number) + count });
    await ctx.storage.setAlarm(Date.now() + 1000); // as logTask arms it, so that a test can run the alarm
  });
}
const logKeys = (w: World) => w.inTenant(async (_i, ctx) => [...(await ctx.storage.list({ prefix: "tsk:" })).keys()]);
const count = (w: World) => w.inTenant(async (_i, ctx) => ctx.storage.get<number>("ntsk"));
const until = async (f: () => Promise<boolean>) => {
  for (let i = 0; i < 300; i++) {
    if (await f()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("timed out");
};

describe("the audit CSV cells", () => {
  it("neutralizes anything a spreadsheet would run, then quotes what needs it", () => {
    for (const c of ["=1+1", "+1", "-1", "@SUM(A1)", "\tx"]) expect(csvCell(c)).toBe(`'${c}`);
    expect(csvCell("\rx")).toBe('"\'\rx"'); // a carriage return first, and quoted because it holds one
    expect(csvCell("=cmd|' /C calc'!A0")).toBe("'=cmd|' /C calc'!A0");
    expect(csvCell("-2+3")).toBe("'-2+3");
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell("two\nlines")).toBe('"two\nlines"');
    expect(csvCell("=a,b")).toBe(`"'=a,b"`);
    expect(csvCell("plain-text 12")).toBe("plain-text 12");
    expect(csvCell(42)).toBe("42");
    expect(csvCell(undefined)).toBe("");
    expect(csvCell("")).toBe("");
    expect(csvCell("a=b")).toBe("a=b"); // only a leading character matters
  });

  it("writes rows as CRLF lines", () => {
    expect(csvRow(["a", 1, undefined, "x,y"])).toBe('a,1,,"x,y"\r\n');
  });

  it("writes an admin event with its detail sorted by key, and an event with none", () => {
    expect(adminRow({ at: 0, action: "group.put", actor: "admin", subject: "eng", detail: { zeta: 1, alpha: "x", mid: 2 } })).toBe("1970-01-01T00:00:00.000Z,group.put,admin,eng,alpha=x;mid=2;zeta=1\r\n");
    expect(adminRow({ at: 0, action: "group.delete", actor: "admin", subject: "=eng" })).toBe("1970-01-01T00:00:00.000Z,group.delete,admin,'=eng,\r\n");
  });

  it("writes a task row, with PURGED for a task whose record is gone and blank owners it does not know", () => {
    const base = { created: 0, task: "t", caller: "c", target: "d", bucket: 4096, retention: "queued", expires_at: 1000 };
    expect(taskRow({ ...base, state: "FAILED", reason: "revoked", updated: 500, ciphertext_deleted_at: 700 }, (d) => (d === "c" ? "=evil@x.test" : undefined))).toBe(
      "1970-01-01T00:00:00.000Z,t,'=evil@x.test,c,,d,FAILED,revoked,1970-01-01T00:00:00.500Z,4096,queued,1970-01-01T00:00:01.000Z,1970-01-01T00:00:00.700Z\r\n",
    );
    expect(taskRow(base, () => "o")).toBe("1970-01-01T00:00:00.000Z,t,o,c,o,d,PURGED,,,4096,queued,1970-01-01T00:00:01.000Z,\r\n");
  });
});

describe("Task DO: revoke and wipe", () => {
  const taskStub = (T: string, t: string) => env.TASK.get(env.TASK.idFromName(`${T}:${t}`));
  const make = async (retention: "strict" | "queued" = "strict") => {
    const T = `off${++n}`;
    const s = taskStub(T, "t1");
    await s.create({ tenant: T, id: "t1", caller: "alice", target: "bob", retention });
    return { T, s };
  };

  it("cancels a live task for either party, with the reason, and says so only once", async () => {
    for (const who of ["alice", "bob"]) {
      const { T, s } = await make();
      expect(await s.revoke(T, who)).toBe(true);
      expect(await s.get(T)).toMatchObject({ state: "CANCELED", reason: "revoked" });
      expect(await s.revoke(T, who)).toBe(false); // already ended
    }
  });

  it("changes nothing for another device, another tenant, a task that is not there, or one that has ended", async () => {
    const { T, s } = await make();
    expect(await s.revoke(T, "carol")).toBe(false);
    expect(await s.revoke("other", "alice")).toBe(false);
    expect((await s.get(T))!.state).toBe("SUBMITTED");
    await s.apply(T, "bob", "COMPLETED", 1);
    expect(await s.revoke(T, "bob")).toBe(false);
    expect((await s.get(T))!.state).toBe("COMPLETED");
    expect(await taskStub(T, "nothing").revoke(T, "alice")).toBe(false);
  });

  it("deletes the held events of a canceled Queued task at once", async () => {
    const { T, s } = await make("queued");
    await s.enqueue(T, "bob", "sealed-body", 3600_000);
    expect(await s.revoke(T, "alice")).toBe(true);
    expect(await s.drain(T, "alice")).toEqual([]);
    expect(await s.get(T)).toMatchObject({ state: "CANCELED", reason: "revoked", ciphertext_deleted_at: expect.any(Number) });
  });

  it("deletes a result still held for a revoked caller after the task has ended, and only the caller's", async () => {
    const { T, s } = await make("queued");
    await s.apply(T, "bob", "COMPLETED", 1);
    await s.enqueue(T, "bob", "sealed-result", 3600_000);
    expect(await s.revoke(T, "bob")).toBe(false); // the target holds nothing: the result is the caller's
    expect(await s.drain(T, "alice")).toHaveLength(1);
    expect(await s.revoke(T, "alice")).toBe(false); // the task had ended: its state stays
    expect(await s.drain(T, "alice")).toEqual([]);
    expect(await s.get(T)).toMatchObject({ state: "COMPLETED", ciphertext_deleted_at: expect.any(Number) });
    expect(await s.revoke(T, "alice")).toBe(false); // nothing held now: nothing written
  });

  it("wipes the record, the held events and the alarm; another tenant's wipe touches nothing", async () => {
    const { T, s } = await make("queued");
    await s.enqueue(T, "bob", "sealed-body", 3600_000);
    expect(await s.wipe("other")).toBe(false);
    expect(await s.get(T)).not.toBeNull();
    expect(await s.wipe(T)).toBe(true);
    expect(await runInDurableObject(s, async (_i, ctx) => [Object.keys(Object.fromEntries(await ctx.storage.list())), await ctx.storage.getAlarm()])).toEqual([[], null]);
    expect(await s.wipe(T)).toBe(false); // nothing left
  });
});

describe("the offboarding cascade", () => {
  it("closes the socket, cancels the live tasks the device takes part in (either role) and leaves everything else alone", async () => {
    const w = world();
    const [ta, tb] = [await tunnel(w, A), await tunnel(w, B)];
    await tunnel(w, C);
    await tunnel(w, D);
    expect((await w.send("TASK", A, B, 0, "asCaller")).result).toBeDefined();
    expect((await w.send("TASK", B, A, 0, "asTarget")).result).toBeDefined();
    expect((await w.send("TASK", C, D, 0, "unrelated")).result).toBeDefined();
    expect((await w.send("TASK", A, B, 0, "done")).result).toBeDefined();
    expect((await w.send("RESULT", B, A, 1, "done")).result.task.status.state).toBe("TASK_STATE_COMPLETED");

    expect((await w.revoke([A], 1)).status).toBe(200);

    expect(await ta.closed).toBe(CLOSE_REVOKED);
    for (const t of ["asCaller", "asTarget"]) {
      expect((await w.get(B, t)).status.state).toBe("TASK_STATE_CANCELED");
      expect((await w.get(B, t)).metadata.parley.reason).toBe("revoked");
    }
    expect((await w.get(B, "done")).status.state).toBe("TASK_STATE_COMPLETED");
    expect((await w.get(C, "unrelated")).status.state).toBe("TASK_STATE_SUBMITTED");
    // The other party is not cut off: its socket stays open and a canceled task is a plain terminal state for it.
    expect((await w.send("STATUS", B, A, 1, "asCaller")).error.code).toBe(-32015);
    expect(await Promise.race([tb.closed, new Promise((r) => setTimeout(() => r("open"), 50))])).toBe("open");
    expect(await w.deviceStorage(A)).toEqual({});
    const events = ((await (await w.post("/v1/admin/audit", {}, w.admin)).json()) as any).events;
    expect(events.at(-1)).toMatchObject({ action: "revocations.put", detail: { revoked: 1, newly_revoked: 1 } });
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("cascade"))).toBeUndefined();
  });

  it("deletes the sealed results a Queued task holds for a revoked caller, and the device's note of them", async () => {
    const w = world();
    expect((await w.post("/v1/admin/retention/put", { mode: "queued" }, w.admin)).status).toBe(200);
    const a = await tunnel(w, A);
    await tunnel(w, B);
    expect((await w.send("TASK", A, B, 0, "q")).result).toBeDefined();
    a.ws.close(1000, "bye");
    await a.closed;
    await until(async () => !(await (env.DEVICE.get(env.DEVICE.idFromName(`${w.T}:${A}`)) as any).status()).connected);
    expect((await w.send("RESULT", B, A, 1, "q")).result).toBeDefined(); // held for the caller that is away
    expect(Object.keys(await w.taskStorage("q")).filter((k) => k.startsWith("q:"))).toHaveLength(1);
    expect(Object.keys(await w.deviceStorage(A))).toContain("held");

    expect((await w.revoke([A], 1)).status).toBe(200);

    expect(Object.keys(await w.taskStorage("q")).filter((k) => k.startsWith("q:"))).toEqual([]);
    expect(await w.deviceStorage(A)).toEqual({});
    // The task had ended, so its state stays; what it held for the revoked caller is gone, and it says when.
    const after = await w.get(B, "q");
    expect(after.status.state).toBe("TASK_STATE_COMPLETED");
    expect(after.metadata.parley.ciphertext_deleted_at).toEqual(expect.any(Number));
  });

  it("hides the bots of the revoked device, and a revocation it already holds does nothing twice", async () => {
    const w = world();
    const { id: dev } = await enrolled(w, "owner@example.test");
    await w.stub.publishCard(dev, { name: "Reviewer", description: "d", tags: [], examples: [] });
    expect(((await w.stub.find(dev, {}, { limit: 10, after: null })) as any).agents).toHaveLength(1);
    expect((await w.revoke([dev], 1)).status).toBe(200);
    expect(((await w.stub.find(dev, {}, { limit: 10, after: null })) as any).error).toBe("not_enrolled");
    expect(await w.inTenant(async (_i, ctx) => [...(await ctx.storage.list({ prefix: "card:" })).keys()])).toEqual([]);
    // The same device in a later list is not new: no second cascade.
    expect((await w.revoke([dev, A], 2)).status).toBe(200);
    const events = ((await (await w.post("/v1/admin/audit", { limit: 100 }, w.admin)).json()) as any).events;
    expect(events.filter((e: any) => e.action === "revocations.put").map((e: any) => e.detail.newly_revoked)).toEqual([1, 1]);
  });

  it("ends a user's session the moment the tenant stops listing them, and no session outlives the identity provider's 24 hours", async () => {
    const w = world();
    const user = await w.session("user", "leaver@example.test"); // the tenant lists its example.test domain (vitest.config.ts)
    const status = async () => (await w.post("/v1/session", {}, user.auth)).status;
    const enroll = async () => (await w.post("/v1/enroll/request", { name: "laptop", signing_key: key() }, user.auth)).status;
    expect(await status()).toBe(200);
    expect(await enroll()).toBe(202);
    const listed = (env as { USER_DOMAINS?: string }).USER_DOMAINS;
    (env as { USER_DOMAINS?: string }).USER_DOMAINS = listed!.split(",").filter((e) => !e.startsWith(`${w.T}:`)).join(",");
    try {
      expect(await status()).toBe(401);
      expect(await enroll()).toBe(401);
    } finally {
      (env as { USER_DOMAINS?: string }).USER_DOMAINS = listed;
    }
    expect(await status()).toBe(200); // listed again
    expect(SESSION_TTL_MS).toBeLessThanOrEqual(24 * 3600_000);
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + SESSION_TTL_MS + 1 });
    expect(await status()).toBe(401); // expired: a new sign-in is a new check with the identity provider
  });

  it("ignores list entries that cannot be devices", async () => {
    const w = world();
    expect((await w.post("/v1/admin/revocations", { list: { tenant: w.T, version: 1, revoked: ["alice", 7, null], signature: "x" } }, w.admin)).status).toBe(200);
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("cascade"))).toBeUndefined();
  });

  it("works through more devices than one pass may touch, and the alarm finishes it", async () => {
    const w = world();
    const ids = Array.from({ length: CASCADE_CALLS + 5 }, (_, i) => hexId(i + 1));
    for (const d of [ids[0]!, ids.at(-1)!]) await runInDurableObject(env.DEVICE.get(env.DEVICE.idFromName(`${w.T}:${d}`)), async (_i, ctx) => ctx.storage.put("session", { id: "s", rx_seq: 0, tx_seq: 0, acked_tx: 0 }));
    expect((await w.revoke(ids, 1)).status).toBe(200);
    const left = await w.inTenant(async (_i, ctx) => (await ctx.storage.get<{ close: string[] }>("cascade"))!.close);
    expect(left).toEqual(ids.slice(CASCADE_CALLS));
    expect(await w.deviceStorage(ids.at(-1)!)).not.toEqual({}); // not reached yet
    expect(await w.deviceStorage(ids[0]!)).toEqual({});
    await until(async () => (await w.inTenant(async (_i, ctx) => ctx.storage.getAlarm())) !== null);
    expect(await runDurableObjectAlarm(w.stub)).toBe(true);
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("cascade"))).toBeUndefined();
    expect(await w.deviceStorage(ids.at(-1)!)).toEqual({});
  });

  it("scans the task log in passes: skips other devices' and expired tasks, resumes where it stopped, and repeats a step that failed", async () => {
    const w = world();
    // 250 live tasks of the revoked device (a pass may cancel 200), among rows that must not be touched.
    await seedLog(w, (i) => (i % 3 === 0 ? { caller: C, target: D } : i % 3 === 1 ? { caller: A, target: D, expires_at: Date.now() - 1 } : { caller: D, target: A }), 750);
    const seen: string[] = [];
    let failOnce = true;
    await w.inTenant(async (inst) => {
      inst.taskStub = (task: string) => ({
        revoke: async (_tenant: string, device: string) => {
          if (failOnce && seen.length === 10) {
            failOnce = false;
            throw new Error("a Task DO is unavailable");
          }
          seen.push(`${task}:${device}`);
          return true;
        },
      });
    });
    expect((await w.revoke([A], 1)).status).toBe(200); // the pass fails at the 11th task and keeps its place
    expect(seen).toHaveLength(10);
    const state = await w.inTenant(async (_i, ctx) => ctx.storage.get<any>("cascade"));
    expect(state).toMatchObject({ close: [], cancel: [A] });
    expect(state.after).toMatch(/^tsk:/);
    for (let i = 0; i < 5 && (await w.inTenant(async (_i, ctx) => ctx.storage.get("cascade"))); i++) await runDurableObjectAlarm(w.stub);
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("cascade"))).toBeUndefined();
    // Exactly the live tasks of A, each once, with A named as the device (the failed one was repeated, not skipped).
    const want = Array.from({ length: 750 }, (_, i) => i).filter((i) => i % 3 === 2).map((i) => `${hexId(i + 1)}:${A}`);
    expect([...seen].sort()).toEqual(want.sort());
  });

  it("adds a later list's devices to a cascade still under way, from the first row again", async () => {
    const w = world();
    await w.inTenant(async (inst) => {
      inst.deviceStub = () => ({ revoke: async () => Promise.reject(new Error("down")) });
    });
    await w.revoke([A], 1);
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("cascade"))).toEqual({ close: [A], cancel: [A] });
    await w.inTenant(async (_i, ctx) => ctx.storage.put("cascade", { close: [A], cancel: [A], after: "tsk:000000000009" }));
    await w.revoke([A, B], 2);
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("cascade"))).toEqual({ close: [A, B], cancel: [A, B] });
    await w.inTenant(async (inst) => {
      delete inst.deviceStub;
    });
    await runDurableObjectAlarm(w.stub);
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("cascade"))).toBeUndefined();
  });

  it("refuses a task for a device that was revoked after it authenticated, and closes the task", async () => {
    const w = world();
    // The list is stored without the cascade having run, as in the moment between a task's creation and its being noted.
    await w.inTenant(async (_i, ctx) => ctx.storage.put("revocations", { tenant: w.T, version: 1, revoked: [B] }));
    expect((await w.send("TASK", A, B, 0, "toRevoked")).error.code).toBe(-32010); // the answer an offline recipient gets
    expect((await w.get(A, "toRevoked")).status.state).toBe("TASK_STATE_CANCELED");
    await w.inTenant(async (_i, ctx) => ctx.storage.put("revocations", { tenant: w.T, version: 2, revoked: [A, B] }));
    expect(await w.stub.logTask({ task: hexId(1), caller: A, target: C, created: 1, expires_at: 2, bucket: 4096, retention: "strict" })).toBe("revoked");
    expect(await logKeys(w)).toEqual([]);
  });
});

describe("the task log", () => {
  it("notes every task with metadata only", async () => {
    const w = world();
    await tunnel(w, B);
    await w.send("TASK", A, B, 0, "one");
    const rows = await w.inTenant(async (_i, ctx) => [...(await ctx.storage.list<TaskLogRow>({ prefix: "tsk:" })).values()]);
    expect(rows).toEqual([{ task: taskHex("one"), caller: A, target: B, created: expect.any(Number), expires_at: expect.any(Number), bucket: 8192, retention: "strict" }]);
  });

  it("refuses a new task at the limit of unexpired tasks, closes it, and makes room only from an expired one", async () => {
    const w = world();
    await tunnel(w, B);
    await seedLog(w, () => ({}), MAX_TASK_LOG);
    expect((await w.send("TASK", A, B, 0, "over")).error.code).toBe(-32017);
    expect((await w.get(A, "over")).status.state).toBe("TASK_STATE_CANCELED");
    expect(await count(w)).toBe(MAX_TASK_LOG);
    expect(await logKeys(w)).toHaveLength(MAX_TASK_LOG);

    // The oldest row is the first to go once it has expired.
    await w.inTenant(async (_i, ctx) => ctx.storage.put("tsk:000000000001", { ...(await ctx.storage.get<any>("tsk:000000000001")), expires_at: Date.now() - 1 }));
    expect((await w.send("TASK", A, B, 0, "fits")).result).toBeDefined();
    let keys = await logKeys(w);
    expect(keys).toHaveLength(MAX_TASK_LOG);
    expect(keys[0]).toBe("tsk:000000000002");
    expect(keys.at(-1)).toBe(`tsk:${String(MAX_TASK_LOG + 1).padStart(12, "0")}`);
    expect(await count(w)).toBe(MAX_TASK_LOG);

    // A live oldest row does not block the tenant while another row has expired: that one goes instead.
    await w.inTenant(async (_i, ctx) => ctx.storage.put("tsk:000000005000", { ...(await ctx.storage.get<any>("tsk:000000005000")), expires_at: Date.now() - 1 }));
    expect((await w.send("TASK", A, B, 0, "fits2")).result).toBeDefined();
    keys = await logKeys(w);
    expect(keys).toHaveLength(MAX_TASK_LOG);
    expect(keys).not.toContain("tsk:000000005000");
    expect(keys[0]).toBe("tsk:000000000002");
  });

  it("drops rows after 90 days, in batches, and wakes up for the next one", async () => {
    const w = world();
    const old = Date.now() - TASK_METADATA_RETENTION_MS - 1000;
    await seedLog(w, () => ({ created: old }), 130);
    await seedLog(w, () => ({ created: Date.now() }), 1, 131);
    await runDurableObjectAlarm(w.stub);
    expect(await logKeys(w)).toEqual([`tsk:${String(131).padStart(12, "0")}`]);
    expect(await count(w)).toBe(1);
    // The next row falls due 90 days after it began; the alarm is armed for the soonest of that and the session's expiry.
    const fresh = await w.inTenant(async (_i, ctx) => (await ctx.storage.get<TaskLogRow>(`tsk:${String(131).padStart(12, "0")}`))!.created);
    expect(await w.inTenant(async (inst) => inst.pruneTaskLog(Date.now()))).toBe(fresh + TASK_METADATA_RETENTION_MS);
  });

  it("drops a log that is entirely old, across more than one batch, and has no next row to wait for", async () => {
    const w = world();
    await seedLog(w, () => ({ created: Date.now() - TASK_METADATA_RETENTION_MS - 1000 }), 256);
    await runDurableObjectAlarm(w.stub);
    expect(await logKeys(w)).toEqual([]);
    expect(await count(w)).toBe(0);
    expect(await w.inTenant(async (inst) => inst.pruneTaskLog(Date.now()))).toBeUndefined();
  });
});

// A pod device, approved and bound, for the owner given.
async function enrolled(w: World, owner: string) {
  const sk = key();
  const { token } = (await w.stub.mintToken(owner))!;
  const r = (await w.stub.request({ token, name: "pod", signing_key: sk })) as { id: string };
  await w.stub.decide(r.id, "approved");
  await w.stub.putBinding(r.id, { device_id: r.id, signing_key: sk, version: 1 });
  return { id: r.id, sk };
}

describe("the tenant export", () => {
  it("gives every section, a page at a time, and nothing that authenticates anyone", async () => {
    const w = world();
    const a = await enrolled(w, "alice@example.test");
    const b = await enrolled(w, "Bob@Example.test");
    await w.stub.publishCard(a.id, { name: "Reviewer", description: "reviews", tags: ["review"], examples: ["review this"] });
    await w.stub.publishCard(b.id, { name: "Writer", description: "writes", tags: [], examples: [] });
    await w.post("/v1/admin/groups/put", { name: "eng", members: ["alice@example.test", "bob@example.test"] }, w.admin);
    await w.post("/v1/admin/retention/put", { mode: "queued", queue_ttl_ms: 1_800_000 }, w.admin);
    await w.stub.setRoot(key());
    await tunnel(w, b.id);
    await w.send("TASK", a.id, b.id, 0, "exp1");
    await w.send("TASK", a.id, b.id, 0, "exp2");

    const page = async (section: string, body: object = {}) => {
      const r = await w.post("/v1/admin/export", { section, ...body }, w.admin);
      expect(r.status).toBe(200);
      return (await r.json()) as any;
    };
    const all = async (section: string, limit: number) => {
      const items: any[] = [];
      let cursor: string | undefined;
      let pages = 0;
      do {
        const p = await page(section, { limit, ...(cursor ? { cursor } : {}) });
        expect(p.section).toBe(section);
        items.push(...p.items);
        cursor = p.next_cursor;
        pages++;
      } while (cursor);
      return { items, pages };
    };

    const settings = (await page("settings")).items[0];
    expect(settings).toMatchObject({ retention: { mode: "queued", queue_ttl_ms: 1_800_000 }, root_public_key: expect.any(String), revocations: null });
    const devices = await all("devices", 1);
    expect(devices.pages).toBe(2);
    expect(devices.items.map((d) => [d.owner, d.status, d.kind, d.binding.device_id === d.id])).toEqual(expect.arrayContaining([["alice@example.test", "approved", "pod", true], ["Bob@Example.test", "approved", "pod", true]]));
    expect(JSON.stringify(devices.items)).not.toMatch(/poll|hash/);
    expect((await all("cards", 1)).items.map((c) => c.name).sort()).toEqual(["Reviewer", "Writer"]);
    expect((await all("groups", 1)).items).toEqual([{ name: "eng", members: ["alice@example.test", "bob@example.test"] }]);
    const audit = await all("audit", 2);
    expect(audit.items.map((e) => e.action)).toEqual(expect.arrayContaining(["group.put", "retention.put", "card.publish"]));
    expect(audit.pages).toBeGreaterThan(1);
    const tasks = await all("tasks", 1);
    expect(tasks.pages).toBe(2);
    expect(tasks.items).toEqual([
      expect.objectContaining({ task: taskHex("exp1"), caller: a.id, target: b.id, state: "SUBMITTED", retention: "queued", bucket: 8192 }),
      expect.objectContaining({ task: taskHex("exp2"), caller: a.id, target: b.id, state: "SUBMITTED" }),
    ]);

    // Nothing in any section carries a session, token, challenge or poll secret (or the hash of one).
    const everything = JSON.stringify([settings, devices.items, audit.items, tasks.items]);
    for (const k of Object.keys(await w.inTenant(async (_i, ctx) => Object.fromEntries(await ctx.storage.list())))) {
      if (/^(ses|tok|dtk|chal|lgn):/.test(k)) expect(everything).not.toContain(k.split(":").at(-1)!);
    }
  });

  it("shows a task whose record has been purged as such", async () => {
    const w = world();
    await seedLog(w, () => ({}), 1);
    expect(((await (await w.post("/v1/admin/export", { section: "tasks" }, w.admin)).json()) as any).items[0]).not.toHaveProperty("state");
  });

  it("includes the revocation list once there is one", async () => {
    const w = world();
    await w.revoke([A], 1);
    expect(((await (await w.post("/v1/admin/export", { section: "settings" }, w.admin)).json()) as any).items[0].revocations).toMatchObject({ version: 1, revoked: [A] });
  });
});

describe("the audit CSV", () => {
  const csv = async (w: World, body: object) => {
    const r = await w.post("/v1/admin/audit/csv", body, w.admin);
    expect(r.status).toBe(200);
    return { text: await r.text(), r };
  };

  it("lists admin actions, header on the first page only, with the cursor in a header", async () => {
    const w = world();
    await w.post("/v1/admin/groups/put", { name: "=eng", members: ["a@example.test"] }, w.admin);
    await w.post("/v1/admin/retention/put", { mode: "queued" }, w.admin);
    await w.revoke([A], 1);
    const first = await csv(w, { kind: "admin", limit: 1 });
    expect(first.r.headers.get("content-type")).toBe("text/csv; charset=utf-8");
    expect(first.r.headers.get("content-disposition")).toBe('attachment; filename="parley-admin-audit.csv"');
    expect(first.r.headers.get("cache-control")).toBe("no-store");
    expect(first.r.headers.get("x-content-type-options")).toBe("nosniff");
    const lines = first.text.split("\r\n");
    expect(lines[0]).toBe("time,action,actor,subject,detail");
    expect(lines[1]).toMatch(/^\d{4}-\d\d-\d\dT[\d:.]+Z,group\.put,admin,'=eng,members=1$/); // the formula is defused
    const next = first.r.headers.get("x-next-cursor")!;
    const rest = await csv(w, { kind: "admin", limit: 100, cursor: next });
    expect(rest.r.headers.get("x-next-cursor")).toBeNull();
    expect(rest.text.startsWith("time,")).toBe(false);
    expect(rest.text.trim().split("\r\n").map((l) => l.split(",")[1])).toEqual(["retention.put", "revocations.put"]);
  });

  it("lists tasks with owners, state codes and the padded size bucket, and defuses an owner that starts a formula", async () => {
    const w = world();
    const a = await enrolled(w, "=HYPERLINK(1)@example.test");
    const b = await enrolled(w, "bob@example.test");
    await tunnel(w, a.id);
    await tunnel(w, b.id);
    await w.send("TASK", a.id, b.id, 0, "csv1");
    await w.send("RESULT", b.id, a.id, 1, "csv1");
    await w.send("TASK", a.id, b.id, 0, "csv2");
    const { text } = await csv(w, { kind: "tasks" });
    const [head, one, two, none] = text.split("\r\n");
    expect(head).toBe("created,task_id,caller_owner,caller_device,target_owner,target_device,state,reason,updated,size_bucket,retention,expires_at,ciphertext_deleted_at");
    const cells = (l: string) => l.split(",");
    expect(cells(one!).slice(1, 7)).toEqual([taskHex("csv1"), "'=HYPERLINK(1)@example.test", a.id, "bob@example.test", b.id, "COMPLETED"]);
    expect(cells(one!)[9]).toBe("8192");
    expect(cells(two!)[6]).toBe("SUBMITTED");
    expect(none).toBe("");
    // A page at a time: the header on the first only, the cursor in a header, the second task on the second page.
    const p1 = await csv(w, { kind: "tasks", limit: 1 });
    expect(p1.text.split("\r\n")).toHaveLength(3);
    const p2 = await csv(w, { kind: "tasks", limit: 1, cursor: p1.r.headers.get("x-next-cursor")! });
    expect(p2.text).toContain(taskHex("csv2"));
    expect(p2.text).not.toContain("created,");
    expect(p2.r.headers.get("x-next-cursor")).toBeNull();
  });

  it("writes only the header for a tenant with nothing yet, and a purged task as PURGED", async () => {
    const w = world();
    expect((await csv(w, { kind: "tasks" })).text).toBe("created,task_id,caller_owner,caller_device,target_owner,target_device,state,reason,updated,size_bucket,retention,expires_at,ciphertext_deleted_at\r\n");
    await seedLog(w, () => ({}), 1);
    expect((await csv(w, { kind: "tasks" })).text).toContain(",PURGED,");
  });

  it("takes up to CSV_PAGE_MAX rows a page and no more", async () => {
    const w = world();
    expect((await w.post("/v1/admin/audit/csv", { kind: "admin", limit: CSV_PAGE_MAX }, w.admin)).status).toBe(200);
    expect((await w.post("/v1/admin/audit/csv", { kind: "admin", limit: CSV_PAGE_MAX + 1 }, w.admin)).status).toBe(400);
  });
});

describe("admin routes: who may use them and what they accept", () => {
  const PATHS = ["/v1/admin/export", "/v1/admin/audit/csv", "/v1/admin/tenant/delete"];
  const ok = (p: string) => (p.endsWith("export") ? { section: "audit" } : p.endsWith("csv") ? { kind: "admin" } : { confirm: "nope" });

  it("needs an admin session: nobody, a user and the cookie without its CSRF token are all refused", async () => {
    const w = world();
    const user = (await w.session("user", "u@example.test")).auth;
    const cookie = await w.session("admin");
    for (const p of PATHS) {
      expect((await w.post(p, ok(p))).status).toBe(401);
      expect((await w.post(p, ok(p), user)).status).toBe(403);
      expect((await SELF.fetch(`https://gw${p}`, { method: "POST", headers: { cookie: `__Host-parley_session=ps_${w.T}.${cookie.secret}`, origin: "https://gw" }, body: JSON.stringify(ok(p)) })).status).toBe(403);
      expect((await SELF.fetch(`https://gw${p}`, { method: "POST", headers: { cookie: `__Host-parley_session=ps_${w.T}.${cookie.secret}`, origin: "https://evil.test", "x-csrf-token": cookie.csrf }, body: JSON.stringify(ok(p)) })).status).toBe(403);
      expect((await SELF.fetch(`https://gw${p}`, { method: "GET", headers: { Authorization: await w.admin } })).status).toBe(405);
    }
    // With the CSRF token and its own origin the cookie works.
    const good = await SELF.fetch("https://gw/v1/admin/export", { method: "POST", headers: { cookie: `__Host-parley_session=ps_${w.T}.${cookie.secret}`, origin: "https://gw", "x-csrf-token": cookie.csrf }, body: JSON.stringify({ section: "settings" }) });
    expect(good.status).toBe(200);
  });

  it("refuses bodies that are not exactly what the route takes", async () => {
    const w = world();
    const bad: [string, unknown][] = [
      ["/v1/admin/export", "not json"],
      ["/v1/admin/export", "[]"],
      ["/v1/admin/export", "null"],
      ["/v1/admin/export", {}],
      ["/v1/admin/export", { section: "sessions" }],
      ["/v1/admin/export", { section: "audit", extra: 1 }],
      ["/v1/admin/export", { section: "audit", limit: 101 }],
      ["/v1/admin/export", { section: "audit", limit: 0 }],
      ["/v1/admin/export", { section: "audit", cursor: "zz" }],
      ["/v1/admin/export", { section: "audit", cursor: 5 }],
      ["/v1/admin/audit/csv", {}],
      ["/v1/admin/audit/csv", { kind: "secrets" }],
      ["/v1/admin/audit/csv", { kind: "admin", limit: 0 }],
      ["/v1/admin/audit/csv", { kind: "admin", limit: 1.5 }],
      ["/v1/admin/audit/csv", { kind: "admin", limit: "5" }],
      ["/v1/admin/audit/csv", { kind: "admin", cursor: "g" }],
      ["/v1/admin/audit/csv", { kind: "admin", section: "audit" }],
      ["/v1/admin/tenant/delete", { confirm: w.T, extra: true }],
      ["/v1/admin/tenant/delete", "x".repeat(3000)],
    ];
    for (const [p, b] of bad) expect([p, (await w.post(p, b, w.admin)).status]).toEqual([p, 400]);
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("deleting"))).toBeUndefined();
  });
});

describe("tenant deletion", () => {
  it("needs the tenant's own name typed, and deletes nothing without it", async () => {
    const w = world();
    await w.revoke([A], 1);
    for (const confirm of [undefined, "", "other", w.T.toUpperCase(), ` ${w.T}`, 5]) {
      const r = await w.post("/v1/admin/tenant/delete", confirm === undefined ? {} : { confirm }, w.admin);
      expect([r.status, ((await r.json()) as any).error]).toEqual([400, "confirm_mismatch"]);
    }
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("revocations"))).toBeDefined();
  });

  it("wipes the tasks, the devices and the tenant's own storage, ends the session and clears the cookie", async () => {
    const w = world();
    const a = await enrolled(w, "alice@example.test");
    const b = await enrolled(w, "bob@example.test");
    const tb = await tunnel(w, b.id);
    await w.post("/v1/admin/retention/put", { mode: "queued" }, w.admin);
    await w.send("TASK", a.id, b.id, 0, "gone1");
    await w.send("TASK", a.id, b.id, 0, "gone2");
    await w.stub.publishCard(a.id, { name: "Reviewer", description: "d", tags: [], examples: [] });
    expect(Object.keys(await w.taskStorage("gone1")).length).toBeGreaterThan(0);
    expect(Object.keys(await w.deviceStorage(b.id)).length).toBeGreaterThan(0);

    const r = await w.post("/v1/admin/tenant/delete", { confirm: w.T }, w.admin);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ deleted: true });
    expect(r.headers.get("set-cookie")).toMatch(/Max-Age=0/);

    expect(await tb.closed).toBe(CLOSE_REVOKED);
    expect(await w.taskStorage("gone1")).toEqual({});
    expect(await w.taskStorage("gone2")).toEqual({});
    expect(await w.deviceStorage(b.id)).toEqual({});
    expect(await w.inTenant(async (_i, ctx) => [Object.keys(Object.fromEntries(await ctx.storage.list())), await ctx.storage.getAlarm()])).toEqual([[], null]);
    expect((await w.post("/v1/admin/export", { section: "audit" }, w.admin)).status).toBe(401); // the session went with it
    expect(await w.get(a.id, "gone1")).toBeUndefined(); // the task is not there for its caller either
  });

  it("admits nothing once it has begun: no session, no device, no enrollment, no sign-in", async () => {
    const w = world();
    const a = await enrolled(w, "alice@example.test");
    const user = await w.session("user", "u@example.test");
    const secret = (await w.session("admin")).secret;
    await w.stub.setRoot(key());
    expect(await w.stub.getSession(secret)).not.toBeNull();
    await w.inTenant(async (_i, ctx) => ctx.storage.put("deleting", Date.now()));
    expect(await w.stub.getSession(secret)).toBeNull();
    expect(await w.stub.getSession(user.secret)).toBeNull();
    expect(await w.stub.issueChallenge(w.T, a.id)).toEqual({ challenge: expect.any(String), expires_at: expect.any(Number) });
    expect(await w.inTenant(async (_i, ctx) => [...(await ctx.storage.list({ prefix: "chal:" })).keys()])).toEqual([]); // nothing stored for a device
    const { token } = (await w.stub.mintToken("x@example.test"))!;
    expect(await w.stub.request({ token, name: "pod", signing_key: key() })).toEqual({ error: "bad_request" });
    expect(await w.stub.loginStart("a".repeat(64), "b".repeat(64))).toEqual({ error: "bad_request" });
  });

  it("goes on in passes, and the alarm finishes what a pass could not", async () => {
    const w = world();
    // More rows than a pass may wipe (PURGE_CALLS): task rows and enrolled devices, with the real ones among them.
    const real = await enrolled(w, "alice@example.test");
    await tunnel(w, real.id);
    await w.send("TASK", real.id, B, 0, "late");
    await seedLog(w, () => ({}), PURGE_CALLS + 10, 2);
    const wiped: string[] = [];
    await w.inTenant(async (inst) => {
      inst.taskStub = (t: string) => ({ wipe: async () => void wiped.push(t) });
    });
    await w.stub.deleteTenant();
    expect(wiped.length).toBeGreaterThan(0);
    expect(wiped.length).toBeLessThanOrEqual(PURGE_CALLS);
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("deleting"))).toBeDefined(); // not finished: the alarm is armed
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.getAlarm())).not.toBeNull();
    for (let i = 0; i < 6 && (await w.inTenant(async (_i, ctx) => ctx.storage.get("deleting"))); i++) await runDurableObjectAlarm(w.stub);
    expect(await w.inTenant(async (_i, ctx) => Object.keys(Object.fromEntries(await ctx.storage.list())))).toEqual([]);
    expect(wiped).toHaveLength(PURGE_CALLS + 11);
    expect(new Set(wiped).size).toBe(PURGE_CALLS + 11);
  });

  it("repeats a step that failed, and finishes", async () => {
    const w = world();
    const a = await enrolled(w, "alice@example.test");
    let down = true;
    await w.inTenant(async (inst) => {
      const real = inst.deviceStub.bind(inst);
      inst.deviceStub = (d: string) => (down ? { revoke: () => Promise.reject(new Error("down")) } : real(d));
    });
    await w.stub.deleteTenant();
    expect(await w.inTenant(async (_i, ctx) => ctx.storage.get("deleting"))).toBeDefined();
    expect(await w.inTenant(async (_i, ctx) => (await ctx.storage.get(`enr:${a.id}`)) !== undefined)).toBe(true); // nothing is forgotten before it is wiped
    down = false;
    await runDurableObjectAlarm(w.stub);
    expect(await w.inTenant(async (_i, ctx) => Object.keys(Object.fromEntries(await ctx.storage.list())))).toEqual([]);
  });
});
