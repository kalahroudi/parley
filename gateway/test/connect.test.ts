// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import { SEALED_MEDIA_TYPE } from "../src/a2a";
import { b64bytes, BINDING_LABEL, CHALLENGE_TTL_MS, CONNECT_LABEL, connectMessage, randomChallenge, verifyBinding, verifyEd25519, type ConnectScope } from "../src/connect";
import type { Env } from "../src/index";
import { CONNECT_TOKEN_TTL_MS, MAX_CHALLENGES_PER_DEVICE, MAX_CONNECT_TOKENS_PER_DEVICE } from "../src/tenant";
import { b64, encodeWire, header, taskBytes, taskHex } from "./wire";

// Durable Object storage writes cost about 24 ms each on Windows runners; tests that make dozens get a longer budget.
const SLOW = 120_000;

const bytesB64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));
const json = async (r: Response) => (await r.json()) as any;
const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  SELF.fetch(`https://gw${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });
const session = async (t: string, role: "admin" | "user", email: string) => {
  const s = await env.TENANT.get(env.TENANT.idFromName(t)).createSession(email, role);
  return `Bearer ps_${t}.${s.secret}`;
};
const sha = async (s: string) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join("");
const te = new TextEncoder();
const u32 = (n: number) => new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const u64 = (n: number) => new Uint8Array(new BigUint64Array([BigInt(n)]).buffer).reverse();
const cat = (...p: Uint8Array[]) => Uint8Array.from(p.flatMap((x) => [...x]));
const field = (s: string | Uint8Array) => { const b = typeof s === "string" ? te.encode(s) : s; return cat(u32(b.length), b); };
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const edKeys = async () => (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
const rawPub = async (k: CryptoKey) => new Uint8Array((await crypto.subtle.exportKey("raw", k)) as ArrayBuffer);
const edSign = async (k: CryptoKey, m: Uint8Array) => bytesB64(await crypto.subtle.sign("Ed25519", k, m));

// internal/binding's encoding, written again here from its documentation, so a mistake in connect.ts does not hide
// behind the same mistake in the test; GO_BINDING below is signed by the Go code itself.
const bindingBytes = (b: { tenant: string; owner: string; device_id: string; key: Uint8Array; version: number; not_after: number }) =>
  cat(field(BINDING_LABEL), field(b.tenant), field(b.owner), field(b.device_id), field(b.key), u64(b.version), u64(b.not_after));

let n = 0;
const YEAR = 365 * 24 * 3600_000;
type Dev = { id: string; key: CryptoKeyPair; sk: string };

// A tenant with its root key registered, and a way to bring devices to "approved with a binding the root signed".
function tenant() {
  const t = `dev${++n}`;
  const admin = session(t, "admin", "admin@example.test");
  const stub = env.TENANT.get(env.TENANT.idFromName(t));
  const call = <T>(fn: (i: any, ctx: DurableObjectState) => Promise<T>) => runInDurableObject(stub, fn);
  const rootReady = (async () => {
    const root = await edKeys();
    const r = await post("/v1/admin/root", { root_public_key: bytesB64(await rawPub(root.publicKey)) }, { Authorization: await admin });
    expect(r.status).toBe(200);
    return root;
  })();
  const enroll = async (opts: { bind?: boolean; decide?: "approved" | "rejected" | false; not_after?: number; version?: number; signer?: CryptoKeyPair; tenantField?: string; skip?: string; owner?: string } = {}): Promise<Dev> => {
    const owner = opts.owner ?? "alice@example.test";
    const { bind = true, decide = "approved", not_after = Math.floor((Date.now() + YEAR) / 1000), version = 1 } = opts;
    const root = opts.signer ?? (await rootReady);
    const key = await edKeys();
    const pub = await rawPub(key.publicKey);
    const sk = bytesB64(pub);
    const { id } = await json(await post("/v1/enroll/request", { name: "laptop", signing_key: sk }, { Authorization: await session(t, "user", owner) }));
    if (decide) await post("/v1/admin/enrollments/decide", { id, decision: decide }, { Authorization: await admin });
    if (bind) {
      const fields = { tenant: opts.tenantField ?? t, owner, device_id: id, key: pub, version, not_after };
      const binding = { tenant: fields.tenant, owner, device_id: id, signing_key: sk, version, not_after: new Date(not_after * 1000).toISOString().replace(".000Z", "Z"), signature: await edSign(root.privateKey, bindingBytes(fields)) };
      expect((await post("/v1/admin/bindings", { id, binding }, { Authorization: await admin })).status).toBe(200);
    }
    return { id, key, sk };
  };
  // A newer binding for the same device and key.
  const rebind = async (d: Dev, version: number) => {
    const root = await rootReady;
    const not_after = Math.floor((Date.now() + YEAR) / 1000);
    const binding = { tenant: t, owner: "alice@example.test", device_id: d.id, signing_key: d.sk, version, not_after: new Date(not_after * 1000).toISOString().replace(".000Z", "Z"), signature: await edSign(root.privateKey, bindingBytes({ tenant: t, owner: "alice@example.test", device_id: d.id, key: await rawPub(d.key.publicKey), version, not_after })) };
    return post("/v1/admin/bindings", { id: d.id, binding }, { Authorization: await admin });
  };
  const challenge = async (d: { id: string }) => (await json(await post("/v1/connect/challenge", { tenant: t, device: d.id }))) as { challenge: string; expires_at: number };
  type Over = { challenge?: string; expires?: number; version?: number; scope?: ConnectScope; signature?: string; tenant?: string; device?: string; signMessage?: Uint8Array };
  // The whole proof: a challenge, a signature over the message for it, the token request.
  const redeem = async (d: Dev, over: Over = {}, scope: ConnectScope = "api") => {
    const ch = over.challenge === undefined ? await challenge(d) : { challenge: over.challenge, expires_at: over.expires ?? 0 };
    const version = over.version ?? 1;
    const signature = over.signature ?? (await edSign(d.key.privateKey, over.signMessage ?? connectMessage(t, d.id, ch.challenge, over.expires ?? ch.expires_at, version, over.scope ?? scope)));
    return post("/v1/connect/token", { tenant: over.tenant ?? t, device: over.device ?? d.id, challenge: ch.challenge, version, scope, signature });
  };
  const token = async (d: Dev, scope: ConnectScope = "api", version = 1) => {
    const r = await redeem(d, { version }, scope);
    expect(r.status).toBe(200);
    return (await json(r)).token as string;
  };
  const revoke = async (devices: string[], version: number) =>
    post("/v1/admin/revocations", { list: { tenant: t, version, revoked: devices, signature: "x" } }, { Authorization: await admin });
  const keys = (prefix: string) => call(async (_i, ctx) => [...(await ctx.storage.list({ prefix })).keys()]);
  return { t, admin, stub, call, enroll, rebind, challenge, redeem, token, revoke, keys, rootReady };
}
const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });
const UNAUTHORIZED = { error: "unauthorized" };
const rpc = (token: string, method = "x") => post("/a2a", { jsonrpc: "2.0", id: 1, method, params: {} }, bearer(token));
const upgrade = (token?: string) => SELF.fetch("https://gw/v1/connect", { headers: { Upgrade: "websocket", ...(token ? bearer(token) : {}) } });

// Signed by internal/binding itself (Go): root seed 0..31, device seed 32..63, tenant t1, version 3, to 2099.
const GO_ROOT = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
const GO_BINDING = { tenant: "t1", owner: "o@x.test", device_id: "abababababababababababababababab", signing_key: "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=", version: 3, not_after: "2099-01-01T00:00:00Z", signature: "KGn10QRdf+BkIMNKGngbve1Ght0Vr10vtWU0zGgELtgmz3aR6PNxe7NpMZuwtT7MbwJm2S/p2Nof3lWn7KDRDA==" };
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

describe("the signed message", () => {
  // The same bytes internal/connect (Go) builds: this vector is checked on both sides.
  it("is the label, the text fields, the expiry and the binding version, then the scope", () => {
    expect(CONNECT_LABEL).toBe("parley/connect/v2");
    const want = "00000011" + "7061726c65792f636f6e6e6563742f7632" + "00000002" + "7431" + "00000003" + "646576" + "00000002" + "6368" + "0000018bcfe56800" + "0000000000000003" + "00000003" + "617069";
    expect(hex(connectMessage("t1", "dev", "ch", 1700000000000, 3, "api"))).toBe(want);
  });

  it("changes with every field", () => {
    const base = hex(connectMessage("ab", "c", "d", 1, 1, "api"));
    for (const other of [connectMessage("a", "bc", "d", 1, 1, "api"), connectMessage("ab", "c", "e", 1, 1, "api"), connectMessage("ab", "c", "d", 2, 1, "api"), connectMessage("ab", "c", "d", 1, 2, "api"), connectMessage("ab", "c", "d", 1, 1, "connect"), connectMessage("ac", "c", "d", 1, 1, "api"), connectMessage("ab", "d", "d", 1, 1, "api")]) {
      expect(hex(other)).not.toBe(base);
    }
  });
});

describe("binding verification (the gateway checks the root's signature itself)", () => {
  const now = Date.parse("2026-11-04T00:00:00Z");
  const root = fromB64(GO_ROOT);

  it("accepts a binding signed by the Go code, and reports its key and version", async () => {
    const ok = await verifyBinding(root, GO_BINDING, "t1", now);
    expect(ok?.version).toBe(3);
    expect(ok?.device).toBe(GO_BINDING.device_id);
    expect(bytesB64(ok!.key)).toBe(GO_BINDING.signing_key);
  });

  it("refuses a change to any field, another root, another tenant, and an expiry that has passed", async () => {
    const bad: Record<string, unknown>[] = [
      { owner: "mallory@x.test" }, { device_id: "ab".repeat(15) + "ac" }, { version: 4 }, { version: 2 }, { not_after: "2099-01-01T00:00:01Z" },
      { signing_key: bytesB64(new Uint8Array(32)) }, { signature: bytesB64(new Uint8Array(64)) }, { tenant: "t2" },
    ];
    for (const over of bad) expect(await verifyBinding(root, { ...GO_BINDING, ...over }, "t1", now), JSON.stringify(over)).toBeNull();
    expect(await verifyBinding(root, GO_BINDING, "t2", now)).toBeNull(); // another tenant's
    expect(await verifyBinding(new Uint8Array(32), GO_BINDING, "t1", now)).toBeNull(); // another root key
    expect(await verifyBinding(root, GO_BINDING, "t1", Date.parse("2099-01-01T00:00:00Z"))).toBeNull(); // expired at not_after
    expect(await verifyBinding(root, GO_BINDING, "t1", Date.parse("2098-12-31T23:59:59Z"))).not.toBeNull();
  });

  it("refuses a version below 1 even when the root signed it", async () => {
    const root = await edKeys();
    const key = new Uint8Array(32).fill(5);
    const sign = async (version: number) => {
      const fields = { tenant: "t1", owner: "o", device_id: "d1", key, version, not_after: 4070908800 };
      return { tenant: "t1", owner: "o", device_id: "d1", signing_key: bytesB64(key), version, not_after: "2099-01-01T00:00:00Z", signature: await edSign(root.privateKey, bindingBytes(fields)) };
    };
    const pub = await rawPub(root.publicKey);
    expect((await verifyBinding(pub, await sign(1), "t1", 0))?.version).toBe(1);
    for (const v of [0, -1]) expect(await verifyBinding(pub, await sign(v), "t1", 0), String(v)).toBeNull();
  });

  it("refuses a malformed binding without throwing", async () => {
    const shaped: unknown[] = [
      undefined, null, "x", 1, [], {}, { ...GO_BINDING, owner: "" }, { ...GO_BINDING, owner: 1 }, { ...GO_BINDING, device_id: "" }, { ...GO_BINDING, device_id: 1 },
      { ...GO_BINDING, version: 0 }, { ...GO_BINDING, version: 1.5 }, { ...GO_BINDING, version: "3" }, { ...GO_BINDING, version: 2 ** 60 },
      { ...GO_BINDING, not_after: undefined }, { ...GO_BINDING, not_after: 4070908800 }, { ...GO_BINDING, not_after: "tomorrow" }, { ...GO_BINDING, not_after: "2099-01-01" },
      { ...GO_BINDING, not_after: [GO_BINDING.not_after] }, { ...GO_BINDING, not_after: "2099-01-01T00:00:00.000Z" }, { ...GO_BINDING, not_after: "2099-01-01T00:00:00+00:00" },
      { ...GO_BINDING, not_after: "2099-01-01T01:00:00+01:00" }, { ...GO_BINDING, not_after: " 2099-01-01T00:00:00Z" }, { ...GO_BINDING, not_after: "2099-01-01T00:00:00Z " },
      { ...GO_BINDING, signing_key: [GO_BINDING.signing_key] }, { ...GO_BINDING, signature: [GO_BINDING.signature] },
      { ...GO_BINDING, signing_key: undefined }, { ...GO_BINDING, signing_key: "!!!" }, { ...GO_BINDING, signing_key: bytesB64(new Uint8Array(31)) },
      { ...GO_BINDING, signature: undefined }, { ...GO_BINDING, signature: "!!!" }, { ...GO_BINDING, signature: bytesB64(new Uint8Array(63)) },
    ];
    for (const b of shaped) expect(await verifyBinding(root, b, "t1", now), JSON.stringify(b)).toBeNull();
  });
});

describe("base64 fields", () => {
  it("are exactly the bytes asked for, and only from a string", () => {
    const k = bytesB64(new Uint8Array(32).fill(7));
    expect(b64bytes(k, 32)).toEqual(new Uint8Array(32).fill(7));
    for (const bad of [[k], new String(k), Symbol("x"), 1, null, undefined, {}, "!!!", "", k.slice(1), bytesB64(new Uint8Array(31))]) expect(b64bytes(bad, 32), String(bad)).toBeNull();
    expect(b64bytes(k, 31)).toBeNull();
  });

  it("are canonical: whitespace, missing padding and stray trailing bits are refused", () => {
    const k = bytesB64(new Uint8Array(32).fill(7)); // 44 characters ending in "="
    expect(b64bytes(k, 32)).not.toBeNull();
    for (const bad of [`${k}\n`, ` ${k}`, `${k.slice(0, 10)} ${k.slice(10)}`, k.slice(0, -1), `${k.slice(0, 42)}B=`]) expect(b64bytes(bad, 32), JSON.stringify(bad)).toBeNull();
  });

  it("a key the runtime cannot import fails the check instead of throwing", async () => {
    expect(await verifyEd25519(new Uint8Array(31), new Uint8Array(64), new Uint8Array(1))).toBe(false);
  });

  it("verify with a key that cannot be exported", async () => {
    const spy = vi.spyOn(crypto.subtle, "importKey");
    try {
      await verifyBinding(fromB64(GO_ROOT), GO_BINDING, "t1", Date.parse("2026-11-04T00:00:00Z"));
      expect(spy).toHaveBeenCalled();
      for (const call of spy.mock.calls) expect(call[3]).toBe(false);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("registering the tenant's root key", () => {
  it("is the admin's, once; the same key again is fine, another is refused", async () => {
    const t = `dev${++n}`;
    const admin = { Authorization: await session(t, "admin", "admin@example.test") };
    const k = bytesB64(await rawPub((await edKeys()).publicKey));
    expect((await post("/v1/admin/root", { root_public_key: k })).status).toBe(401);
    expect((await post("/v1/admin/root", { root_public_key: k }, { Authorization: await session(t, "user", "u@example.test") })).status).toBe(403);
    expect((await post("/v1/admin/root", { root_public_key: k }, admin)).status).toBe(200);
    expect((await post("/v1/admin/root", { root_public_key: k }, admin)).status).toBe(200);
    const other = await post("/v1/admin/root", { root_public_key: bytesB64(await rawPub((await edKeys()).publicKey)) }, admin);
    expect([other.status, await json(other)]).toEqual([409, { error: "root_already_set" }]);
    for (const bad of [{}, { root_public_key: 1 }, { root_public_key: "" }, { root_public_key: "!!!" }, { root_public_key: bytesB64(new Uint8Array(31)) }]) {
      expect((await post("/v1/admin/root", bad, admin)).status).toBe(400);
    }
  });

  it("without one, nothing connects", async () => {
    const x = tenant();
    const d = await x.enroll();
    await x.call(async (_i, ctx) => void (await ctx.storage.delete("root")));
    expect((await x.keys("chal:")).length).toBe(0);
    await x.challenge(d);
    expect((await x.keys("chal:")).length).toBe(0); // decoy
    expect((await x.redeem(d)).status).toBe(401);
  });
});

describe("challenges", () => {
  it("are random, expire in a minute, and are stored by hash only, for devices that may connect", async () => {
    const x = tenant();
    const d = await x.enroll();
    const seen = new Set<string>();
    const c = await x.challenge(d);
    expect(Object.keys(c).sort()).toEqual(["challenge", "expires_at"]);
    expect(c.challenge).toMatch(/^[0-9a-f]{64}$/);
    expect(c.expires_at).toBeGreaterThan(Date.now() + CHALLENGE_TTL_MS - 5000);
    expect(c.expires_at).toBeLessThanOrEqual(Date.now() + CHALLENGE_TTL_MS);
    seen.add(c.challenge);
    seen.add((await x.challenge(d)).challenge);
    expect(seen.size).toBe(2);
    const stored = await x.call(async (_i, ctx) => JSON.stringify([...(await ctx.storage.list({ prefix: "chal:" }))]));
    expect(stored).not.toContain(c.challenge);
    expect(stored).toContain(await sha(c.challenge));
    expect((await x.keys("chal:")).length).toBe(2);
  });

  it("cost no storage for devices that cannot connect, and look the same", async () => {
    const x = tenant();
    const unbound = await x.enroll({ bind: false });
    const pending = await x.enroll({ bind: false, decide: false });
    const rejected = await x.enroll({ bind: false, decide: "rejected" });
    const gone = await x.enroll();
    const lapsed = await x.enroll({ not_after: Math.floor(Date.now() / 1000) - 5 });
    const forged = await x.enroll({ signer: await edKeys() });
    const other = await x.enroll({ tenantField: "elsewhere" });
    await x.revoke([gone.id], 1);
    const real = await x.enroll();
    const shape = async (d: { id: string }) => Object.keys(await x.challenge(d)).sort().join();
    const reference = await shape(real);
    for (const d of [unbound, pending, rejected, gone, lapsed, forged, other, { id: "f".repeat(32) }]) expect(await shape(d)).toBe(reference);
    expect((await x.keys("chal:")).length).toBe(1); // the real device's only
  });

  it("are few per device: the oldest outstanding one goes first", async () => {
    const x = tenant();
    const d = await x.enroll();
    const made: string[] = [];
    for (let i = 0; i < MAX_CHALLENGES_PER_DEVICE + 1; i++) made.push((await x.challenge(d)).challenge);
    expect((await x.keys("chal:")).length).toBe(MAX_CHALLENGES_PER_DEVICE);
    expect((await x.redeem(d, { challenge: made[0]!, expires: 1 })).status).toBe(401); // evicted
    expect((await x.redeem(d)).status).toBe(200); // a fresh one still works
  }, SLOW);

  it("stay at the cap when requested at the same moment", async () => {
    const x = tenant();
    const d = await x.enroll();
    await Promise.all(Array.from({ length: MAX_CHALLENGES_PER_DEVICE * 3 }, () => x.challenge(d)));
    expect((await x.keys("chal:")).length).toBe(MAX_CHALLENGES_PER_DEVICE);
  }, SLOW);

  it("are removed by the alarm once expired", async () => {
    const x = tenant();
    const d = await x.enroll();
    await x.challenge(d);
    await x.challenge(d);
    await x.call(async (_i, ctx) => {
      const [k, v] = [...(await ctx.storage.list<any>({ prefix: "chal:" }))][0]!;
      await ctx.storage.put(k, { ...v, exp: Date.now() - 1 });
    });
    await runDurableObjectAlarm(x.stub);
    expect((await x.keys("chal:")).length).toBe(1);
  });
});

describe("a device proves it holds its bound key and gets a token", () => {
  it("issues a short-lived token for each scope that opens the right door", async () => {
    const x = tenant();
    const d = await x.enroll();
    const r = await x.redeem(d, {}, "connect");
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    const b = await json(r);
    expect(b.token).toMatch(new RegExp(`^pdt_${x.t}\\.${d.id}\\.[0-9a-f]{64}$`));
    expect(Object.keys(b).sort()).toEqual(["expires_at", "token"]);
    expect(b.expires_at).toBeGreaterThan(Date.now() + CONNECT_TOKEN_TTL_MS - 5000);
    expect(b.expires_at).toBeLessThanOrEqual(Date.now() + CONNECT_TOKEN_TTL_MS);

    const ws = (await upgrade(b.token)).webSocket!;
    ws.accept();
    const got = new Promise<any>((res) => ws.addEventListener("message", (e) => res(JSON.parse(e.data as string))));
    ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
    expect((await got).t).toBe("welcome");
    ws.close();

    const api = await x.token(d, "api");
    const answer = await rpc(api, "NoSuchMethod");
    expect(answer.status).toBe(200);
    expect((await json(answer)).error.code).toBe(-32601);
  });

  it("keeps only hashes: no token secret, no challenge", async () => {
    const x = tenant();
    const d = await x.enroll();
    const t = await x.token(d, "api");
    const stored = await x.call(async (_i, ctx) => JSON.stringify([...(await ctx.storage.list())]));
    expect(stored).not.toContain(t.split(".")[2]);
    expect(stored).toContain(await sha(t.split(".")[2]!));
  });

  it("binds the signature to the binding version: version 2 works after the device was re-bound", async () => {
    const x = tenant();
    const d = await x.enroll({ version: 2 });
    expect((await x.redeem(d, { version: 1 })).status).toBe(401);
    expect((await x.redeem(d, { version: 3 })).status).toBe(401);
    expect((await x.redeem(d, { version: 2 })).status).toBe(200);
  });
});

describe("the token step refuses with one answer and no detail", () => {
  const refused = async (r: Response) => {
    expect(r.status).toBe(401);
    expect(await json(r)).toEqual(UNAUTHORIZED);
  };

  it("a signature that is not in canonical base64 is a 400 and does not burn the challenge", async () => {
    const x = tenant();
    const d = await x.enroll();
    const ch = await x.challenge(d);
    const good = await edSign(d.key.privateKey, connectMessage(x.t, d.id, ch.challenge, ch.expires_at, 1, "api"));
    const send = (signature: string) => post("/v1/connect/token", { tenant: x.t, device: d.id, challenge: ch.challenge, version: 1, scope: "api", signature });
    expect((await send(`${good}\n`)).status).toBe(400);
    expect((await send(` ${good}`)).status).toBe(400);
    expect((await send(good)).status).toBe(200);
  }, SLOW);

  it("a signature by another key, or over a message that differs in any one field", async () => {
    const x = tenant();
    const d = await x.enroll();
    const other = await x.enroll();
    const c = async () => await x.challenge(d);
    let ch = await c();
    await refused(await x.redeem(d, { challenge: ch.challenge, expires: ch.expires_at, signature: await edSign(other.key.privateKey, connectMessage(x.t, d.id, ch.challenge, ch.expires_at, 1, "api")) }));
    const variants: Array<(c: { challenge: string; expires_at: number }) => Uint8Array> = [
      (c) => connectMessage("elsewhere", d.id, c.challenge, c.expires_at, 1, "api"),
      (c) => connectMessage(x.t, other.id, c.challenge, c.expires_at, 1, "api"),
      (c) => connectMessage(x.t, d.id, c.challenge + "0", c.expires_at, 1, "api"),
      (c) => connectMessage(x.t, d.id, c.challenge, c.expires_at + 1, 1, "api"),
      (c) => connectMessage(x.t, d.id, c.challenge, c.expires_at, 2, "api"),
      (c) => connectMessage(x.t, d.id, c.challenge, c.expires_at, 1, "connect"), // signed for the tunnel, asked for api
      (c) => te.encode(c.challenge), // no label or lengths
      (c) => connectMessage(x.t, d.id, c.challenge, c.expires_at, 1, "api").slice(1),
    ];
    for (const v of variants) {
      ch = await c();
      await refused(await x.redeem(d, { challenge: ch.challenge, expires: ch.expires_at, signMessage: v(ch) }));
    }
    ch = await c();
    await refused(await x.redeem(d, { challenge: ch.challenge, expires: ch.expires_at, signature: bytesB64(new Uint8Array(64)) }));
  }, SLOW);

  it("a replayed challenge, sequential or simultaneous, and a challenge burned by a failed attempt", async () => {
    const x = tenant();
    const d = await x.enroll();
    const ch = await x.challenge(d);
    const signature = await edSign(d.key.privateKey, connectMessage(x.t, d.id, ch.challenge, ch.expires_at, 1, "api"));
    const again = () => x.redeem(d, { challenge: ch.challenge, expires: ch.expires_at, signature });
    expect((await again()).status).toBe(200);
    await refused(await again());
    const c2 = await x.challenge(d);
    const s2 = await edSign(d.key.privateKey, connectMessage(x.t, d.id, c2.challenge, c2.expires_at, 1, "api"));
    const all = await Promise.all([1, 2, 3, 4].map(() => x.redeem(d, { challenge: c2.challenge, expires: c2.expires_at, signature: s2 })));
    expect(all.map((r) => r.status).sort()).toEqual([200, 401, 401, 401]);
    // A wrong signature spends the challenge: the right one cannot be tried afterwards.
    const c3 = await x.challenge(d);
    await refused(await x.redeem(d, { challenge: c3.challenge, expires: c3.expires_at, signature: bytesB64(new Uint8Array(64)) }));
    await refused(await x.redeem(d, { challenge: c3.challenge, expires: c3.expires_at }));
  });

  it("an expired, unknown, or another device's or tenant's challenge", async () => {
    const x = tenant();
    const y = tenant();
    const d = await x.enroll();
    const e = await x.enroll();
    const ch = await x.challenge(d);
    await x.call(async (_i, ctx) => {
      const [k, v] = [...(await ctx.storage.list<any>({ prefix: "chal:" }))][0]!;
      await ctx.storage.put(k, { ...v, exp: Date.now() - 1 });
    });
    await refused(await x.redeem(d, { challenge: ch.challenge, expires: ch.expires_at })); // validly signed, but expired
    await refused(await x.redeem(d, { challenge: "0".repeat(64), expires: Date.now() + 1000 })); // never issued
    const forE = await x.challenge(e);
    await refused(await x.redeem(d, { challenge: forE.challenge, expires: forE.expires_at })); // issued for e
    const ofY = await y.challenge(await y.enroll());
    await refused(await x.redeem(d, { challenge: ofY.challenge, expires: ofY.expires_at })); // issued by another tenant
  });

  it("devices that are not bound: unknown, pending, rejected, approved without a binding, another tenant's", async () => {
    const x = tenant();
    const unbound = await x.enroll({ bind: false });
    const pending = await x.enroll({ bind: false, decide: false });
    const rejected = await x.enroll({ bind: false, decide: "rejected" });
    for (const d of [unbound, pending, rejected]) await refused(await x.redeem(d, { challenge: "a".repeat(64), expires: 1 }));
    const stranger = await x.enroll();
    await refused(await x.redeem({ ...stranger, id: "f".repeat(32) }, { challenge: "a".repeat(64), expires: 1 }));
    const y = tenant();
    await y.rootReady;
    await refused(await y.redeem(stranger, { challenge: "a".repeat(64), expires: 1 }));
  });

  it("devices whose binding is not good: revoked, expired, root-less signature, another tenant's, key not the enrolled one", async () => {
    const x = tenant();
    const gone = await x.enroll();
    const lapsed = await x.enroll();
    const forged = await x.enroll({ signer: await edKeys() });
    const wrongTenant = await x.enroll({ tenantField: "elsewhere" });
    const fine = await x.enroll();
    const challenges = Object.fromEntries(await Promise.all([gone, lapsed, fine].map(async (d) => [d.id, await x.challenge(d)])));
    await x.revoke([gone.id], 1);
    await x.call(async (_i, ctx) => {
      const rec: any = await ctx.storage.get(`enr:${lapsed.id}`);
      rec.binding.not_after = new Date(Date.now() - 1000).toISOString().replace(".000Z", "Z");
      await ctx.storage.put(`enr:${lapsed.id}`, rec);
    });
    for (const d of [gone, lapsed]) await refused(await x.redeem(d, { challenge: challenges[d.id]!.challenge, expires: challenges[d.id]!.expires_at }));
    for (const d of [forged, wrongTenant]) await refused(await x.redeem(d, { challenge: "a".repeat(64), expires: 1 }));
    expect((await x.redeem(fine, { challenge: challenges[fine.id]!.challenge, expires: challenges[fine.id]!.expires_at })).status).toBe(200);
    // The stored binding altered after the fact (the root did not sign this): it opens nothing.
    await x.call(async (_i, ctx) => {
      const rec: any = await ctx.storage.get(`enr:${fine.id}`);
      rec.binding.owner = "mallory@example.test";
      await ctx.storage.put(`enr:${fine.id}`, rec);
    });
    expect((await x.redeem(fine)).status).toBe(401);
  }, SLOW);

  it("a request that is malformed is a 400 whose code names the part; a wrong method is a 405", async () => {
    const x = tenant();
    const d = await x.enroll();
    const ch = await x.challenge(d);
    const sig = bytesB64(new Uint8Array(64));
    const full = { tenant: x.t, device: d.id, challenge: ch.challenge, version: 1, scope: "api", signature: sig };
    const code = async (path: string, body: unknown) => {
      const r = await post(path, body);
      expect(r.headers.get("content-type")).toBe("application/json");
      expect(r.headers.get("cache-control")).toBe("no-store");
      return [r.status, (await json(r)).error];
    };
    const without = (k: string) => ({ ...full, [k]: undefined });
    const cases: [unknown, string][] = [
      ["not json", "bad_json"], ["null", "bad_json"], ["5", "bad_json"], ['"text"', "bad_json"], ["", "bad_json"], ["{", "bad_json"],
      ["x".repeat(5000), "bad_json"], [JSON.stringify({ ...full, pad: "x".repeat(5000) }), "bad_json"],
      ["[]", "bad_ids"], ["{}", "bad_ids"], [{ ...full, tenant: 1 }, "bad_ids"], [{ ...full, tenant: "a/b" }, "bad_ids"], [{ ...full, tenant: "" }, "bad_ids"],
      [{ ...full, tenant: "t".repeat(65) }, "bad_ids"], [{ ...full, device: "../x" }, "bad_ids"], [{ ...full, device: d.id.toUpperCase() }, "bad_ids"], [without("device"), "bad_ids"],
      [without("challenge"), "bad_challenge"], [{ ...full, challenge: 1 }, "bad_challenge"], [{ ...full, challenge: "x".repeat(129) }, "bad_challenge"],
      [without("version"), "bad_version"], [{ ...full, version: "1" }, "bad_version"], [{ ...full, version: 0 }, "bad_version"], [{ ...full, version: 1.5 }, "bad_version"], [{ ...full, version: 2 ** 60 }, "bad_version"],
      [without("scope"), "bad_scope"], [{ ...full, scope: "admin" }, "bad_scope"], [{ ...full, scope: "API" }, "bad_scope"],
      [without("signature"), "bad_signature"], [{ ...full, signature: 1 }, "bad_signature"], [{ ...full, signature: "!!!" }, "bad_signature"], [{ ...full, signature: [sig] }, "bad_signature"],
      [{ ...full, signature: bytesB64(new Uint8Array(63)) }, "bad_signature"], [{ ...full, signature: bytesB64(new Uint8Array(65)) }, "bad_signature"],
    ];
    for (const [body, want] of cases) expect(await code("/v1/connect/token", body), JSON.stringify(body)?.slice(0, 90)).toEqual([400, want]);
    // The challenge endpoint reads only the ids.
    for (const [body, want] of [["not json", "bad_json"], ["null", "bad_json"], ["[]", "bad_ids"], [{ tenant: x.t }, "bad_ids"], [{ tenant: "a/b", device: d.id }, "bad_ids"], [{ tenant: x.t, device: "x" }, "bad_ids"], [JSON.stringify({ tenant: x.t, device: d.id, pad: "x".repeat(5000) }), "bad_json"]] as [unknown, string][]) {
      expect(await code("/v1/connect/challenge", body), JSON.stringify(body)).toEqual([400, want]);
    }
    // A body of exactly the limit is read; one byte more is not. No content-length to go by: the stream is cut.
    const { default: worker } = await import("../src/index");
    const streamed = new Request("https://gw/v1/connect/challenge", { method: "POST", body: new Blob(["x".repeat(5000)]).stream(), duplex: "half" } as RequestInit);
    const cut = await worker.fetch(streamed, env);
    expect([cut.status, await json(cut)]).toEqual([400, { error: "bad_json" }]);
    const padTo = (n: number) => { const base = JSON.stringify({ tenant: x.t, device: d.id, pad: "" }); return base.replace('"pad":""', `"pad":"${"x".repeat(n - base.length + 0)}"`); };
    expect(padTo(4096).length).toBe(4096);
    expect((await post("/v1/connect/challenge", padTo(4096))).status).toBe(200);
    expect((await post("/v1/connect/challenge", padTo(4097))).status).toBe(400);
    // A challenge of 128 characters is looked up (and not found); one more is refused as malformed.
    expect([(await post("/v1/connect/token", { ...full, challenge: "a".repeat(128) })).status, (await post("/v1/connect/token", { ...full, challenge: "a".repeat(129) })).status]).toEqual([401, 400]);
    // Invalid UTF-8 is not JSON.
    const bad = await SELF.fetch("https://gw/v1/connect/challenge", { method: "POST", body: new Uint8Array([0x7b, 0xff, 0x7d]) });
    expect([bad.status, await json(bad)]).toEqual([400, { error: "bad_json" }]);
    for (const [method, path] of [["GET", "/v1/connect/token"], ["PUT", "/v1/connect/challenge"], ["GET", "/v1/connect/challenge"]]) {
      const r = await SELF.fetch(`https://gw${path}`, { method, body: method === "PUT" ? "{}" : undefined });
      expect([r.status, await json(r)]).toEqual([405, { error: "method_not_allowed" }]);
    }
    expect((await post("/v1/connect/nothing", {})).status).toBe(404);
  });

  it("is rate limited per device, with Retry-After, and refuses when the limiter fails", async () => {
    const x = tenant();
    const d = await x.enroll();
    const { default: worker } = await import("../src/index");
    const limited = { ...env, RATE_CONNECT_DEVICE_PER_MIN: "3" } as Env;
    const ask = (e: Env, path: string, device = d.id, tenantName = x.t) =>
      worker.fetch(new Request(`https://gw${path}`, { method: "POST", body: JSON.stringify({ tenant: tenantName, device, challenge: "a".repeat(64), version: 1, scope: "api", signature: bytesB64(new Uint8Array(64)) }) }), e);
    expect((await ask(limited, "/v1/connect/challenge")).status).toBe(200);
    expect((await ask(limited, "/v1/connect/token")).status).toBe(401);
    expect((await ask(limited, "/v1/connect/challenge")).status).toBe(200);
    const r = await ask(limited, "/v1/connect/token");
    expect([r.status, await json(r)]).toEqual([429, { error: "rate_limited" }]);
    expect(Number(r.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(Number(r.headers.get("retry-after"))).toBeLessThanOrEqual(60); // seconds, not milliseconds
    expect(r.headers.get("content-type")).toBe("application/json");
    const c = await ask(limited, "/v1/connect/challenge");
    expect([c.status, c.headers.get("content-type"), Number(c.headers.get("retry-after")) > 0 && Number(c.headers.get("retry-after")) <= 60]).toEqual([429, "application/json", true]); // one budget for both steps
    expect((await ask(limited, "/v1/connect/challenge", "e".repeat(32))).status).toBe(200); // another device's is its own
    expect((await ask(limited, "/v1/connect/challenge", d.id, "other")).status).toBe(200); // so is another tenant's
    const broken = { ...env, RATE: { get: () => { throw new Error("down"); }, idFromName: () => ({}) } } as unknown as Env;
    expect((await ask(broken, "/v1/connect/challenge")).status).toBe(429);
    expect((await ask(broken, "/v1/connect/token")).status).toBe(429);
  });
});

describe("what a token opens", () => {
  it("nothing without one, with a malformed one, or with a guessed one", async () => {
    const x = tenant();
    const d = await x.enroll();
    const good = await x.token(d, "api");
    const secret = good.split(".")[2]!;
    const bad = [
      undefined, "", "Bearer", "Bearer ", "Basic abc", `Bearer ${good} x`, `Bearer  ${good}`, `bearer ${good}`, `XBearer ${good}`, `Bearer ${good}x`, `Bearer pdt_${x.t}.${d.id}.${secret}0`,
      "Bearer pdt_", `Bearer pdt_${x.t}.${d.id}.${"0".repeat(64)}`,
      `Bearer pdt_${x.t}.${d.id}.${secret.slice(0, 63)}`, `Bearer pdt_${x.t}.${d.id.slice(1)}.${secret}`,
      `Bearer pdt_${x.t}..${secret}`, `Bearer pdt_${x.t}.${d.id}.${secret.toUpperCase()}`,
      `Bearer ps_${x.t}.${secret}`, `Bearer dev:${x.t}:${d.id}`, `Bearer dev-admin:${x.t}`,
    ];
    for (const h of bad) {
      const headers: Record<string, string> = h === undefined ? {} : { Authorization: h };
      expect((await SELF.fetch("https://gw/v1/connect", { headers: { Upgrade: "websocket", ...headers } })).status, String(h)).toBe(401);
      expect((await post("/a2a", { jsonrpc: "2.0", id: 1, method: "x", params: {} }, headers)).status, String(h)).toBe(401);
    }
    expect((await rpc(good)).status).toBe(200); // still good after all that
  });

  it("a token in the query string or a subprotocol is not a credential", async () => {
    const x = tenant();
    const d = await x.enroll();
    const t = await x.token(d, "connect");
    expect((await SELF.fetch(`https://gw/v1/connect?token=${t}&access_token=${t}`, { headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": t } })).status).toBe(401);
    expect((await upgrade(t)).status).toBe(101); // and it was not spent by those
  });

  it("scope: a tunnel token is single use and opens nothing else; an api token serves requests but not the tunnel", async () => {
    const x = tenant();
    const d = await x.enroll();
    const tunnel = await x.token(d, "connect");
    const api = await x.token(d, "api");
    expect((await rpc(tunnel)).status).toBe(401);
    expect((await upgrade(api)).status).toBe(401);
    const first = await upgrade(tunnel);
    expect(first.status).toBe(101);
    first.webSocket!.accept();
    first.webSocket!.close();
    expect((await upgrade(tunnel)).status).toBe(401); // spent
    expect([(await rpc(api)).status, (await rpc(api)).status]).toEqual([200, 200]); // an api token is not
  });

  it("a tunnel token presented at the wrong door is not spent, one presented twice at once opens once", async () => {
    const x = tenant();
    const d = await x.enroll();
    const t = await x.token(d, "connect");
    expect((await rpc(t)).status).toBe(401);
    const both = await Promise.all([upgrade(t), upgrade(t), upgrade(t)]);
    expect(both.map((r) => r.status).sort()).toEqual([101, 401, 401]);
  });

  it("only the device and tenant it was issued to", async () => {
    const x = tenant();
    const y = tenant();
    const a = await x.enroll();
    const b = await x.enroll();
    const ta = await x.token(a, "api");
    const secret = ta.split(".")[2]!;
    expect((await rpc(ta)).status).toBe(200);
    expect((await rpc(`pdt_${x.t}.${b.id}.${secret}`)).status).toBe(401); // a's secret, b's name
    expect((await rpc(`pdt_${y.t}.${a.id}.${secret}`)).status).toBe(401); // another tenant
    expect((await upgrade(`pdt_${x.t}.${b.id}.${secret}`)).status).toBe(401);
  });

  it("routes the tunnel to the token's own Device DO and nobody else's", async () => {
    const x = tenant();
    const a = await x.enroll();
    const b = await x.enroll();
    const wsA = (await upgrade(await x.token(a, "connect"))).webSocket!;
    wsA.accept();
    const ready = new Promise((res) => wsA.addEventListener("message", res, { once: true }));
    wsA.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
    await ready;
    const status = (tenantName: string, d: string) => (env.DEVICE.get(env.DEVICE.idFromName(`${tenantName}:${d}`)) as any).status();
    expect((await status(x.t, a.id)).connected).toBe(true);
    expect((await status(x.t, b.id)).connected).toBe(false);
    expect((await status("other", a.id)).connected).toBe(false);
    wsA.close();
  });

  it("a task sent with one device's token reaches the tunnel another device opened", async () => {
    const x = tenant();
    const caller = await x.enroll();
    const target = await x.enroll();
    const ws = (await upgrade(await x.token(target, "connect"))).webSocket!;
    ws.accept();
    const inbox: any[] = [];
    ws.addEventListener("message", (e) => inbox.push(JSON.parse(e.data as string)));
    ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
    for (let i = 0; i < 100 && !inbox.length; i++) await new Promise((r) => setTimeout(r, 10));
    expect(inbox[0].t).toBe("welcome");
    const part = { raw: b64(encodeWire({ header: header("TASK", { tenant: x.t, sender: caller.id, target: target.id, task: taskBytes("one") }) })), mediaType: SEALED_MEDIA_TYPE };
    const send = (token: string) => post("/a2a", { jsonrpc: "2.0", id: 1, method: "SendMessage", params: { message: { messageId: "m1", role: "ROLE_USER", parts: [part] } } }, bearer(token));
    // The sender in the signed header must be the token's device: the target's token cannot send as the caller.
    expect((await json(await send(await x.token(target, "api")))).error).toBeDefined();
    const r = await json(await send(await x.token(caller, "api")));
    expect(r.result.task.status.state).toBe("TASK_STATE_SUBMITTED");
    expect(r.result.task.id).toBe(taskHex("one"));
    for (let i = 0; i < 100 && inbox.length < 2; i++) await new Promise((r2) => setTimeout(r2, 10));
    expect(inbox[1].t).toBe("event");
    ws.close();
  });

  // The connect path must not depend on the tenant's retention mode, and the token flow keeps only what
  // specs/parley-mvp/connect-tokens.md documents: hashes and metadata, never the secret, the challenge or the signature.
  for (const mode of ["strict", "queued"]) {
    it(`works in ${mode} retention and stores only the documented metadata`, async () => {
      const x = tenant();
      expect((await post("/v1/admin/retention/put", { mode }, { Authorization: await x.admin })).status).toBe(200);
      const caller = await x.enroll();
      const target = await x.enroll();
      const ws = (await upgrade(await x.token(target, "connect"))).webSocket!;
      ws.accept();
      const inbox: any[] = [];
      ws.addEventListener("message", (e) => inbox.push(JSON.parse(e.data as string)));
      ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
      for (let i = 0; i < 100 && !inbox.length; i++) await new Promise((r) => setTimeout(r, 10));
      expect(inbox[0].t).toBe("welcome");

      const ch = await x.challenge(caller);
      const signature = await edSign(caller.key.privateKey, connectMessage(x.t, caller.id, ch.challenge, ch.expires_at, 1, "api"));
      const issued = await json(await post("/v1/connect/token", { tenant: x.t, device: caller.id, challenge: ch.challenge, version: 1, scope: "api", signature }));
      const secret = (issued.token as string).split(".")[2]!;
      const part = { raw: b64(encodeWire({ header: header("TASK", { tenant: x.t, sender: caller.id, target: target.id, task: taskBytes(`m-${mode}`) }) })), mediaType: SEALED_MEDIA_TYPE };
      const r = await json(await post("/a2a", { jsonrpc: "2.0", id: 1, method: "SendMessage", params: { message: { messageId: "m1", role: "ROLE_USER", parts: [part] } } }, bearer(issued.token)));
      expect(r.result.task.status.state).toBe("TASK_STATE_SUBMITTED");
      for (let i = 0; i < 100 && inbox.length < 2; i++) await new Promise((r2) => setTimeout(r2, 10));
      expect(inbox[1].t).toBe("event");

      const stored = await x.call(async (_i, ctx) => [...(await ctx.storage.list()).entries()]);
      const dump = JSON.stringify(stored);
      for (const leaked of [secret, ch.challenge, signature]) expect(dump).not.toContain(leaked);
      for (const [k] of stored) expect(k, k).toMatch(/^(aud:|auds$|dtk:|enr:|retention$|root$|ses:)/);
      // Strict keeps no ciphertext for the task the token sent; the connect path adds nothing of its own to it.
      const held = await runInDurableObject(env.TASK.get(env.TASK.idFromName(`${x.t}:${taskHex(`m-${mode}`)}`)), async (_i, ctx) => [...(await ctx.storage.list({ prefix: "q:" })).keys()]);
      if (mode === "strict") expect(held).toEqual([]);
      ws.close();
    });
  }
});

describe("a token stops working when its device does", () => {
  it("at once on revocation, not at expiry", async () => {
    const x = tenant();
    const a = await x.enroll();
    const b = await x.enroll();
    const [ta, tb, tunnel] = [await x.token(a, "api"), await x.token(b, "api"), await x.token(a, "connect")];
    expect([(await rpc(ta)).status, (await rpc(tb)).status]).toEqual([200, 200]);
    expect((await x.revoke([a.id], 1)).status).toBe(200);
    expect([(await rpc(ta)).status, (await rpc(tb)).status]).toEqual([401, 200]);
    expect((await upgrade(tunnel)).status).toBe(401);
    expect(await x.keys(`dtk:${a.id}:`)).toEqual([]); // gone from storage, not just refused
  });

  it("when a newer binding replaces the one it was issued for", async () => {
    const x = tenant();
    const d = await x.enroll();
    const t = await x.token(d, "api");
    expect((await rpc(t)).status).toBe(200);
    expect((await x.rebind(d, 2)).status).toBe(200);
    expect((await rpc(t)).status).toBe(401);
    expect((await rpc(await x.token(d, "api", 2))).status).toBe(200);
  });

  it("when its binding expires", async () => {
    const x = tenant();
    const d = await x.enroll();
    const t = await x.token(d, "api");
    await x.call(async (_i, ctx) => {
      const rec: any = await ctx.storage.get(`enr:${d.id}`);
      rec.binding.not_after = new Date(Date.now() - 1000).toISOString().replace(".000Z", "Z");
      await ctx.storage.put(`enr:${d.id}`, rec);
    });
    expect((await rpc(t)).status).toBe(401);
  });

  it("when it expires; the alarm removes expired tokens but not live ones", async () => {
    const x = tenant();
    const d = await x.enroll();
    const old = await x.token(d, "api");
    const live = await x.token(d, "api");
    const aged = await x.token(d, "api");
    await x.call(async (_i, ctx) => {
      for (const [k, v] of await ctx.storage.list<any>({ prefix: "dtk:" })) {
        if (k.endsWith(`:${await sha(old.split(".")[2]!)}`)) await ctx.storage.put(k, { ...v, exp: Date.now() - 1 });
        if (k.endsWith(`:${await sha(aged.split(".")[2]!)}`)) await ctx.storage.put(k, { ...v, exp: Date.now() - 1 });
      }
    });
    expect((await rpc(old)).status).toBe(401); // refused, and deleted, even before the alarm
    await runDurableObjectAlarm(x.stub);
    expect((await x.keys("dtk:")).length).toBe(1);
    expect((await rpc(live)).status).toBe(200);
  });

  it("keeps a device to its most recent tokens", async () => {
    const x = tenant();
    const d = await x.enroll();
    const tokens: string[] = [];
    for (let i = 0; i < MAX_CONNECT_TOKENS_PER_DEVICE + 2; i++) tokens.push(await x.token(d, "api"));
    const statuses = [];
    for (const t of tokens) statuses.push((await rpc(t)).status);
    expect(statuses.slice(0, 2)).toEqual([401, 401]);
    expect(statuses.slice(2).every((s) => s === 200)).toBe(true);
  }, SLOW);
});

// T412: the prekey relay. A caller asks a target for a one-time prekey, and the target answers, through the
// gateway, which forwards the frame, names the sender it authenticated, counts every frame against the
// sender's allowance before delivering it, and creates and stores nothing. Everything below goes through the
// real Worker with real connect tokens. (The same frames are built by internal/frames, in Go.)
describe("the prekey relay", () => {
  const NONCE = btoa("0123456789abcdef");
  const BLOB = btoa("a signed prekey, opaque to the gateway");
  const request = (id: string, to: string) => ({ t: "prekey_request", id, to, nonce: NONCE, expires_at: Date.now() + 900_000 });
  const reply = (id: string, to: string) => ({ t: "prekey_reply", id, to, prekey: BLOB });

  // An enrolled device with a card the whole tenant may see: what a daemon that takes requests has.
  const enr = async (x: ReturnType<typeof tenant>, card: Record<string, unknown> = {}, owner?: string) => {
    const d = await x.enroll({ owner });
    expect(await x.call((i) => i.publishCard(d.id, { name: "bot", description: "a bot", visibility: "tenant", ...card }))).toEqual({ id: expect.any(String) });
    return d;
  };

  // A daemon on the tunnel: frames out (numbered), events in.
  async function daemon(x: ReturnType<typeof tenant>, d: Dev, headers: Record<string, string> = {}) {
    const res = await SELF.fetch("https://gw/v1/connect", { headers: { Upgrade: "websocket", ...bearer(await x.token(d, "connect")), ...headers } });
    const ws = res.webSocket!;
    ws.accept();
    const inbox: any[] = [];
    ws.addEventListener("message", (e) => {
      if (e.data !== "pong") inbox.push(JSON.parse(e.data as string));
    });
    ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
    let seq = 0;
    const events = () => inbox.filter((m) => m.t === "event").map((m) => JSON.parse(m.body));
    const acks = () => inbox.filter((m) => m.t === "ack").length;
    const settle = async (n: number) => {
      for (let i = 0; i < 200 && acks() < n; i++) await new Promise((r) => setTimeout(r, 5));
      await new Promise((r) => setTimeout(r, 30)); // anything the relay delivers after the ack
    };
    for (let i = 0; i < 200 && !inbox.length; i++) await new Promise((r) => setTimeout(r, 5));
    return {
      ws,
      events,
      // Sends a frame and waits for the gateway's acknowledgment of it (and a moment for what it relays).
      send: async (body: unknown, again = false) => {
        if (!again) seq++;
        ws.send(JSON.stringify({ t: "frame", seq, body: typeof body === "string" ? body : JSON.stringify(body) }));
        await settle(seq);
      },
    };
  }

  // The Device DO reads its limits from its own env; a test lowers this device's prekey budget there.
  async function lowerBudget(t: string, device: string, perMin: string) {
    const stub: DurableObjectStub = env.DEVICE.get(env.DEVICE.idFromName(`${t}:${device}`));
    await runInDurableObject(stub, async (inst) => {
      const holder = inst as unknown as { env: Record<string, unknown> };
      holder.env = { ...holder.env, RATE_PREKEY_PER_MIN: perMin };
    });
  }

  async function pair() {
    const x = tenant();
    const a = await enr(x);
    const b = await enr(x);
    return { x, a, b, A: await daemon(x, a), B: await daemon(x, b) };
  }

  it("forwards a request to the target as an event naming the authenticated sender, and the answer back", async () => {
    const { a, b, A, B } = await pair();
    await A.send(request("r1", b.id));
    expect(B.events()).toEqual([{ t: "prekey_request", id: "r1", nonce: NONCE, expires_at: expect.any(Number), from: a.id }]);
    await B.send(reply("r1", a.id));
    expect(A.events()).toEqual([{ t: "prekey_reply", id: "r1", prekey: BLOB, from: b.id }]);
    await B.send({ t: "prekey_refused", id: "r2", to: a.id });
    expect(A.events().at(-1)).toEqual({ t: "prekey_refused", id: "r2", from: b.id, reason: "refused" });
    A.ws.close();
    B.ws.close();
  });

  it("answers the requester with a refusal when the target is not connected", async () => {
    const x = tenant();
    const a = await enr(x);
    const off = await enr(x);
    const A = await daemon(x, a);
    await A.send(request("r1", off.id));
    expect(A.events()).toEqual([{ t: "prekey_refused", id: "r1", from: off.id, reason: "offline" }]);
    await A.send(request("r2", "nobody-by-that-name"));
    expect(A.events().at(-1)).toMatchObject({ id: "r2", reason: "offline" });
    A.ws.close();
  });

  it("never lets a sender claim to be someone else, and ignores identity headers from the client", async () => {
    const x = tenant();
    const a = await enr(x);
    const b = await enr(x);
    const evil = await enr(x);
    const B = await daemon(x, b);
    // The client sends the headers the Worker uses to tell the Device DO who it is; the Worker overwrites them.
    const E = await daemon(x, evil, { "x-parley-tenant": x.t, "x-parley-device": a.id });
    await E.send({ ...request("r1", b.id), from: a.id }); // a claimed sender is not a field of the frame
    expect(B.events()).toEqual([]);
    await E.send(request("r2", b.id));
    expect(B.events()).toEqual([{ t: "prekey_request", id: "r2", nonce: NONCE, expires_at: expect.any(Number), from: evil.id }]);
    B.ws.close();
    E.ws.close();
  });

  it("relays only to devices of the sender's own tenant", async () => {
    const x = tenant();
    const y = tenant();
    const a = await enr(x);
    const other = await enr(y);
    const A = await daemon(x, a);
    const O = await daemon(y, other);
    await A.send(request("r1", other.id));
    expect(O.events()).toEqual([]);
    expect(A.events()).toEqual([{ t: "prekey_refused", id: "r1", from: other.id, reason: "offline" }]);
    A.ws.close();
    O.ws.close();
  });

  it("relays a frame once, however often the daemon retransmits it, and ignores frames it does not understand", async () => {
    const { b, A, B } = await pair();
    const body = JSON.stringify(request("r1", b.id));
    await A.send(body);
    await A.send(body, true); // the same frame seq again, as after a reconnect
    expect(B.events()).toHaveLength(1);
    for (const junk of ["a", "{}", '{"t":"prekey_request"}', '{"t":"prekey_other","id":"r","to":"x"}', '{"t":"prekey_', "[]", JSON.stringify({ ...request("r9", b.id), extra: 1 })]) await A.send(junk);
    await A.send(request("r3", "a".repeat(65)));
    expect(B.events()).toHaveLength(1);
    expect(A.events()).toEqual([]); // nothing came back for them either
    A.ws.close();
    B.ws.close();
  });

  it("does not relay a frame addressed to the sender itself, and not from a socket the Worker did not open", async () => {
    const { a, A } = await pair();
    await A.send(request("r1", a.id));
    expect(A.events()).toEqual([]);
    A.ws.close();
    // A socket opened on the Device DO directly has no identity: its frames are acknowledged and ignored.
    const stub = env.DEVICE.get(env.DEVICE.idFromName("nowhere:dev")) as any;
    const raw = (await stub.fetch("https://do/", { headers: { Upgrade: "websocket" } })).webSocket!;
    raw.accept();
    const got: any[] = [];
    raw.addEventListener("message", (e: MessageEvent) => got.push(JSON.parse(e.data as string)));
    raw.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
    for (let i = 0; i < 100 && !got.length; i++) await new Promise((r) => setTimeout(r, 5));
    raw.send(JSON.stringify({ t: "frame", seq: 1, body: JSON.stringify(request("r1", "someone")) }));
    for (let i = 0; i < 100 && got.length < 2; i++) await new Promise((r) => setTimeout(r, 5));
    expect(got.map((m) => m.t)).toEqual(["welcome", "ack"]);
    // Headers that are not valid ids are not an identity either.
    const bad = (await stub.fetch("https://do/", { headers: { Upgrade: "websocket", "x-parley-tenant": "a b", "x-parley-device": "d" } })).webSocket!;
    expect(bad).toBeDefined();
    bad.accept();
    bad.close();
    raw.close();
  });

  it("counts every frame against the sender's allowance before delivering it: a flood is refused at the gateway and never reaches the target", async () => {
    const x = tenant();
    const a = await enr(x);
    const b = await enr(x);
    const honest = await enr(x);
    const A = await daemon(x, a);
    const B = await daemon(x, b);
    const H = await daemon(x, honest);
    await lowerBudget(x.t, a.id, "3");
    await lowerBudget(x.t, honest.id, "3");
    for (let i = 0; i < 12; i++) await A.send(request(`f${i}`, b.id));
    expect(B.events()).toHaveLength(3); // the budget, and not one more
    const refusals = A.events().filter((e) => e.t === "prekey_refused");
    expect(refusals).toHaveLength(9);
    expect(refusals[0]).toMatchObject({ from: b.id, reason: "rate_limited", retry_after_ms: expect.any(Number) });
    expect(refusals[0].retry_after_ms).toBeGreaterThan(0);
    // The answers a device sends count too: a flood of replies is cut off the same way.
    for (let i = 0; i < 6; i++) await A.send(reply(`g${i}`, b.id));
    expect(B.events().filter((e) => e.t === "prekey_reply")).toHaveLength(0); // A is already out of budget
    expect(A.events().filter((e) => e.t === "prekey_refused")).toHaveLength(9); // and a refused answer is not "refused" back to anyone
    // Another device of the same tenant is served.
    await H.send(request("h1", b.id));
    expect(B.events().at(-1)).toMatchObject({ id: "h1", from: honest.id });
    A.ws.close();
    B.ws.close();
    H.ws.close();
  });

  it("tells nobody when an answer cannot be delivered, only the requester when a request cannot", async () => {
    const x = tenant();
    const a = await enr(x);
    const off = await enr(x);
    const A = await daemon(x, a);
    await A.send(reply("r1", off.id));
    await A.send({ t: "prekey_refused", id: "r2", to: off.id });
    expect(A.events()).toEqual([]);
    await A.send(request("r3", off.id));
    expect(A.events()).toEqual([{ t: "prekey_refused", id: "r3", from: off.id, reason: "offline" }]);
    A.ws.close();
  });

  it("relays only for a socket the Worker opened with a complete, valid identity", async () => {
    const x = tenant();
    const b = await enr(x);
    const d1 = await enr(x);
    const B = await daemon(x, b);
    const open = async (headers: Record<string, string>) => {
      const stub = env.DEVICE.get(env.DEVICE.idFromName(`${x.t}:direct${Object.keys(headers).join("")}${Object.values(headers).join("")}`)) as any;
      const ws = (await stub.fetch("https://do/", { headers: { Upgrade: "websocket", ...headers } })).webSocket!;
      ws.accept();
      const got: any[] = [];
      ws.addEventListener("message", (e: MessageEvent) => {
        got.push(JSON.parse(e.data as string));
      });
      ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
      for (let i = 0; i < 100 && !got.length; i++) await new Promise((r) => setTimeout(r, 5));
      ws.send(JSON.stringify({ t: "frame", seq: 1, body: JSON.stringify(request("r1", b.id)) }));
      for (let i = 0; i < 100 && got.length < 2; i++) await new Promise((r) => setTimeout(r, 5));
      await new Promise((r) => setTimeout(r, 30));
      ws.close();
      return got.map((m) => m.t);
    };
    const T = "x-parley-tenant";
    const D = "x-parley-device";
    const incomplete: Record<string, string>[] = [{}, { [T]: x.t }, { [D]: "d1" }, { [T]: "bad tenant", [D]: "d1" }, { [T]: x.t, [D]: "bad device" }, { [T]: "", [D]: "d1" }, { [T]: x.t, [D]: "" }];
    for (const headers of incomplete) expect(await open(headers), JSON.stringify(headers)).toEqual(["welcome", "ack"]); // nothing relayed, nothing refused back
    expect(B.events()).toEqual([]);
    await open({ [T]: x.t, [D]: d1.id });
    expect(B.events()).toEqual([{ t: "prekey_request", id: "r1", nonce: NONCE, expires_at: expect.any(Number), from: d1.id }]);
    B.ws.close();
  });

  it("stores nothing: the Device DOs hold no frame body, key or nonce afterwards", async () => {
    const x = tenant();
    const a = await enr(x);
    const b = await enr(x);
    const A = await daemon(x, a);
    const B = await daemon(x, b);
    await A.send(request("r1", b.id));
    await B.send(reply("r1", a.id));
    for (const d of [a, b]) {
      const stub = env.DEVICE.get(env.DEVICE.idFromName(`${x.t}:${d.id}`)) as any;
      const dump = await runInDurableObject(stub, async (_i, ctx) => JSON.stringify([...(await ctx.storage.list()).entries()]));
      expect(dump).not.toContain(NONCE);
      expect(dump).not.toContain(BLOB);
      expect(dump).not.toContain("prekey");
    }
    A.ws.close();
    B.ws.close();
  });

  it("refuses a request for a target none of whose cards the sender may see, or that is not enrolled, and allows one with no card", async () => {
    const x = tenant();
    expect(await x.call((i) => i.putGroup("ops", ["bob@example.test"]))).toMatchObject({ name: "ops" });
    const a = await enr(x);
    const hidden = await enr(x, { visibility: "groups", groups: ["ops"] }, "carol@example.test");
    const cardless = await x.enroll();
    const A = await daemon(x, a);
    const H = await daemon(x, hidden);
    const C = await daemon(x, cardless);
    await A.send(request("r1", hidden.id));
    await A.send(request("r3", "a".repeat(32)));
    expect(A.events().map((e) => [e.id, e.reason])).toEqual([["r1", "offline"], ["r3", "offline"]]);
    expect(H.events()).toEqual([]);
    // No card, nothing for the directory to hide: only enrollment decides.
    await A.send(request("r2", cardless.id));
    expect(C.events()).toEqual([{ t: "prekey_request", id: "r2", nonce: NONCE, expires_at: expect.any(Number), from: a.id }]);
    // Visible to any one of the group's members: the same target is served for bob's device.
    const bobDev = await enr(x, {}, "bob@example.test");
    const Bob = await daemon(x, bobDev);
    await Bob.send(request("r4", hidden.id));
    expect(H.events()).toEqual([{ t: "prekey_request", id: "r4", nonce: NONCE, expires_at: expect.any(Number), from: bobDev.id }]);
    Bob.ws.close();
    A.ws.close();
    H.ws.close();
    C.ws.close();
  });

  it("answers need no card: a target replies to a requester that has none", async () => {
    const x = tenant();
    const a = await x.enroll();
    const b = await enr(x);
    const A = await daemon(x, a);
    const B = await daemon(x, b);
    await A.send(request("r1", b.id));
    expect(B.events()).toHaveLength(1);
    await B.send(reply("r1", a.id));
    expect(A.events()).toEqual([{ t: "prekey_reply", id: "r1", prekey: BLOB, from: b.id }]);
    A.ws.close();
    B.ws.close();
  });

  it("stops relaying for a device the moment it is revoked, though its socket is still open, in both directions", async () => {
    const x = tenant();
    const a = await enr(x);
    const b = await enr(x);
    const A = await daemon(x, a);
    const B = await daemon(x, b);
    expect((await x.revoke([a.id], 1)).status).toBe(200);
    await A.send(request("r1", b.id));
    await A.send(reply("r2", b.id));
    expect(B.events()).toEqual([]);
    await B.send(reply("r3", a.id)); // and nothing reaches a revoked device
    expect(A.events().map((e) => [e.id, e.reason])).toEqual([["r1", "offline"]]); // and r3 never reached a revoked device
    await B.send(request("r4", a.id)); // a revoked target is refused to the requester
    expect(B.events().at(-1)).toEqual({ t: "prekey_refused", id: "r4", from: a.id, reason: "offline" });
    A.ws.close();
    B.ws.close();
  });

  it("gives a target a budget of its own: one flooding caller is cut off by its own, and callers together cannot spend more than the target's", async () => {
    const x = tenant();
    const t = await enr(x);
    const other = await enr(x);
    const T = await daemon(x, t);
    const O = await daemon(x, other);
    const callers = [];
    for (let i = 0; i < 5; i++) {
      const c = await enr(x);
      await lowerBudget(x.t, c.id, "2"); // the target's budget is 3 times this: 6
      callers.push({ c, D: await daemon(x, c) });
    }
    // One caller floods: it passes 2, and the target has 4 left for everybody else.
    for (let i = 0; i < 10; i++) await callers[0]!.D.send(request(`a${i}`, t.id));
    expect(T.events()).toHaveLength(2);
    // Others are served up to what is left (4), then refused: the tradeoff of a per-target budget, bounded by it.
    for (const [i, { D }] of callers.slice(1).entries()) for (let j = 0; j < 2; j++) await D.send(request(`b${i}${j}`, t.id));
    expect(T.events()).toHaveLength(6);
    expect(callers[4]!.D.events().filter((e) => e.reason === "rate_limited")).toHaveLength(2);
    expect(callers[4]!.D.events()[0]).toMatchObject({ from: t.id, retry_after_ms: expect.any(Number) });
    // The budget is per target: the same callers are served for another one.
    const fresh = await enr(x);
    const F = await daemon(x, fresh);
    await lowerBudget(x.t, fresh.id, "2");
    await F.send(request("c1", other.id));
    expect(O.events()).toHaveLength(1);
    F.ws.close();
    // Answers are not requests: the target can still answer all of them.
    await T.send(reply("a0", callers[0]!.c.id));
    expect(callers[0]!.D.events().at(-1)).toMatchObject({ t: "prekey_reply", id: "a0" });
    for (const { D } of callers) D.ws.close();
    T.ws.close();
    O.ws.close();
  });

  it("treats a target that cannot be reached as offline, and does not fail the sender's frame", async () => {
    const x = tenant();
    const a = await enr(x);
    const b = await enr(x);
    const A = await daemon(x, a);
    await runInDurableObject(env.DEVICE.get(env.DEVICE.idFromName(`${x.t}:${a.id}`)), async (inst) => {
      const holder = inst as unknown as { env: Record<string, unknown> };
      holder.env = { ...holder.env, DEVICE: { idFromName: (n: string) => n, get: () => ({ deliver: () => Promise.reject(new Error("overloaded")) }) } };
    });
    await A.send(request("r1", b.id));
    expect(A.events()).toEqual([{ t: "prekey_refused", id: "r1", from: b.id, reason: "offline" }]);
    A.ws.close();
  });
});

// Each byte is two hex digits, so a byte under 0x10 keeps its leading zero and a challenge is always 64 characters.
describe("randomChallenge", () => {
  it("zero-pads every byte", () => {
    const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation(((a: Uint8Array) => {
      a.fill(0);
      a[0] = 0x0a;
      a[1] = 0x01;
      a[31] = 0xff;
      return a;
    }) as any);
    try {
      expect(randomChallenge()).toBe("0a01" + "00".repeat(29) + "ff");
    } finally {
      spy.mockRestore();
    }
  });
  it("is 64 lowercase hex characters and fresh each time", () => {
    const a = randomChallenge();
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(randomChallenge()).not.toBe(a);
  });
});
