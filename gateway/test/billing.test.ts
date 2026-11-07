// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T502: Stripe billing (journey K): webhook signatures, what a subscription event changes, the seat limit that applies
// when an admin approves a device, the 7-day grace period, and the Checkout and Portal calls. Events are signed with the
// test webhook secret exactly as Stripe signs them; Stripe's API is replaced by a spy on fetch.

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  EVENT_TTL_MS,
  FREE_SEATS,
  GRACE_MS,
  MAX_EVENT_IDS,
  MAX_SEATS,
  MAX_WEBHOOK_BYTES,
  WEBHOOK_TOLERANCE_S,
  handleBilling,
  keyMode,
  limitOf,
  parseEvent,
  reduce,
  remember,
  returnUrl,
  verifySignature,
  type Billing,
  type SubUpdate,
} from "../src/billing";
import type { Env } from "../src/index";
import { DECIDED_RETENTION_MS } from "../src/tenant";
import { gw } from "./wire";

afterEach(() => vi.restoreAllMocks());

// Stand-in credentials are assembled at run time so no key-shaped literal sits in the source.
const fake = (kind: string, mode: string, tail: string) => [kind, mode, tail].join("_");
const SECRET = fake("whsec", "test", "secret");
const PRICE = "price_seat";
const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const mac = async (secret: string, data: string) => {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
};
const nowS = () => Math.floor(Date.now() / 1000);
const header = async (body: string, t = nowS(), secret = SECRET) => `t=${t},v1=${await mac(secret, `${t}.${body}`)}`;

describe("webhook signature", () => {
  const body = '{"id":"evt_1"}';
  const now = 1_800_000_000;
  it("accepts Stripe's format", async () => {
    expect(await verifySignature(body, await header(body, now), SECRET, now)).toBe(true);
  });
  it("accepts when any v1 matches (secret rotation sends two)", async () => {
    const good = await mac(SECRET, `${now}.${body}`);
    expect(await verifySignature(body, `t=${now}, v1=${"0".repeat(64)}, v1=${good}`, SECRET, now)).toBe(true);
    expect(await verifySignature(body, `t=${now},v1=${good},v1=${"0".repeat(64)}`, SECRET, now)).toBe(true);
  });
  it("refuses a wrong secret, a changed body, a changed time and a v0 scheme", async () => {
    expect(await verifySignature(body, await header(body, now, fake("whsec", "other", "")), SECRET, now)).toBe(false);
    expect(await verifySignature(body + " ", await header(body, now), SECRET, now)).toBe(false);
    const h = await header(body, now);
    expect(await verifySignature(body, h.replace(`t=${now}`, `t=${now + 1}`), SECRET, now)).toBe(false);
    expect(await verifySignature(body, `t=${now},v0=${await mac(SECRET, `${now}.${body}`)}`, SECRET, now)).toBe(false);
  });
  it("takes a time of digits only, and a header up to 512 characters", async () => {
    for (const bad of [`x${now}`, `${now}x`, `${now} 1`, "1".repeat(13)]) {
      expect(await verifySignature(body, `t=${bad},v1=${await mac(SECRET, `${bad}.${body}`)}`, SECRET, now)).toBe(false);
    }
    const base = `t=${now},v1=${await mac(SECRET, `${now}.${body}`)},x=`;
    expect(await verifySignature(body, base + "y".repeat(512 - base.length), SECRET, now)).toBe(true);
    expect(await verifySignature(body, base + "y".repeat(513 - base.length), SECRET, now)).toBe(false);
  });
  it("imports the secret as a key that cannot be extracted, and sends it nowhere", async () => {
    const h = await header(body, now);
    const spy = vi.spyOn(crypto.subtle, "importKey");
    await verifySignature(body, h, SECRET, now);
    expect(spy.mock.calls[0]![4]).toEqual(["verify"]);
    expect(spy.mock.calls[0]![3]).toBe(false);
  });
  it("refuses a delivery outside the tolerance, either side", async () => {
    for (const skew of [WEBHOOK_TOLERANCE_S + 1, -WEBHOOK_TOLERANCE_S - 1]) expect(await verifySignature(body, await header(body, now - skew), SECRET, now)).toBe(false);
    for (const skew of [WEBHOOK_TOLERANCE_S, -WEBHOOK_TOLERANCE_S]) expect(await verifySignature(body, await header(body, now - skew), SECRET, now)).toBe(true);
  });
  it("refuses malformed headers", async () => {
    const good = await mac(SECRET, `${now}.${body}`);
    const bad: (string | null)[] = [
      null,
      "",
      `v1=${good}`, // no time
      `t,v1=${good}`, // a time without a value
      `t=${now},t=${now},v1=${good}`, // two times
      `t=abc,v1=${good}`,
      `t=${"1".repeat(13)},v1=${good}`,
      `t=${now}`, // no signature
      `t=${now},v1=${good.slice(1)}`, // short
      `t=${now},v1=${good}0`, // long
      `t=${now},v1=${"zz".repeat(32)}`, // not hex
      `t=${now},v1`, // no value
      `t=${now},v1=${good},${"x=y,".repeat(200)}`, // longer than any real header
    ];
    for (const h of bad) expect(await verifySignature(body, h, SECRET, now)).toBe(false);
  });
});

const sub = (over: Partial<Record<string, unknown>> = {}, items: unknown = [{ price: { id: PRICE }, quantity: 5 }]) => ({
  id: "evt_1",
  type: "customer.subscription.updated",
  livemode: false,
  created: 1_800_000_000,
  data: { object: { id: "sub_1", customer: "cus_1", status: "active", metadata: { tenant: "bil1" }, items: { data: items }, ...over } },
});

describe("parseEvent", () => {
  it("reads a subscription event", () => {
    expect(parseEvent(sub(), PRICE, false)).toEqual({ event: "evt_1", tenant: "bil1", customer: "cus_1", subscription: "sub_1", status: "active", seats: 5, created: 1_800_000_000_000 });
  });
  it("counts only our price, summed", () => {
    const items = [{ price: { id: PRICE }, quantity: 2 }, { price: { id: "price_addon" }, quantity: 50 }, { price: { id: PRICE }, quantity: 3 }, null, { price: null, quantity: 1 }, { price: { id: PRICE }, quantity: 1.5 }, { price: { id: PRICE }, quantity: 0 }, { price: { id: PRICE } }];
    expect(parseEvent(sub({}, items), PRICE, false)?.seats).toBe(5);
  });
  it("takes every type of subscription event and no other", () => {
    for (const type of ["customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"]) expect(parseEvent({ ...sub(), type }, PRICE, false)).not.toBeNull();
    for (const type of ["invoice.paid", "checkout.session.completed", "customer.subscription.trial_will_end", 7]) expect(parseEvent({ ...sub(), type }, PRICE, false)).toBeNull();
  });
  it("takes events of one mode only", () => {
    expect(parseEvent({ ...sub(), livemode: true }, PRICE, false)).toBeNull();
    expect(parseEvent({ ...sub(), livemode: true }, PRICE, true)).not.toBeNull();
    expect(parseEvent(sub(), PRICE, true)).toBeNull();
    const { livemode: _, ...none } = sub();
    expect(parseEvent(none, PRICE, false)).toBeNull();
  });
  it("takes every status Stripe has, and a time of 0, and one seat", () => {
    for (const status of ["active", "trialing", "past_due", "unpaid", "canceled", "incomplete", "incomplete_expired", "paused"]) expect(parseEvent(sub({ status }), PRICE, false)?.status).toBe(status);
    expect(parseEvent({ ...sub(), created: 0 }, PRICE, false)?.created).toBe(0);
    expect(parseEvent(sub({}, [{ price: { id: PRICE }, quantity: 1 }]), PRICE, false)?.seats).toBe(1);
  });
  it("never lets a negative or zero quantity lower the count", () => {
    expect(parseEvent(sub({}, [{ price: { id: PRICE }, quantity: 4 }, { price: { id: PRICE }, quantity: -3 }, { price: { id: PRICE }, quantity: 0 }]), PRICE, false)?.seats).toBe(4);
  });
  it("refuses events that are not shaped as expected", () => {
    const e = sub();
    const cases: unknown[] = [
      null,
      "x",
      [],
      { ...e, data: null },
      { ...e, data: { object: null } },
      { ...e, data: { object: [] } },
      { ...e, id: 5 },
      { ...e, id: "sub_1" },
      { ...e, id: "evt_" },
      { ...e, id: ["evt_1"] },
      { ...e, id: "xevt_1" },
      { ...e, id: "evt_a b" },
      { ...e, id: `evt_${"a".repeat(65)}` },
      { ...e, id: undefined },
      { ...e, created: -1 },
      { ...e, created: 1.5 },
      { ...e, created: "1" },
      sub({ id: 5 }),
      sub({ id: "evt_1" }),
      sub({ id: ["sub_1"] }),
      sub({ id: "xsub_1" }),
      sub({ id: "sub_1 " }),
      sub({ customer: ["cus_1"] }),
      sub({ customer: "xcus_1" }),
      sub({ customer: "cus_1 " }),
      sub({ metadata: { tenant: ["bil1"] } }),
      sub({ id: "sub_" }),
      sub({ id: `sub_${"a".repeat(65)}` }),
      sub({ customer: { id: "cus_1" } }),
      sub({ customer: "x_1" }),
      sub({ metadata: null }),
      sub({ metadata: {} }),
      sub({ metadata: { tenant: 5 } }),
      sub({ metadata: { tenant: "has space" } }),
      sub({ metadata: { tenant: "" } }),
      sub({ metadata: { tenant: "a".repeat(65) } }),
      sub({ status: "mystery" }),
      sub({ status: 5 }),
      sub({ items: null }),
      sub({ items: { data: "x" } }),
      sub({}, []),
      sub({}, [{ price: { id: "price_other" }, quantity: 3 }]),
      sub({}, [{ price: { id: PRICE }, quantity: MAX_SEATS + 1 }]),
      sub({}, [{ price: { id: PRICE }, quantity: MAX_SEATS }, { price: { id: PRICE }, quantity: 1 }]),
    ];
    for (const c of cases) expect(parseEvent(c, PRICE, false)).toBeNull();
    expect(parseEvent(sub({}, [{ price: { id: PRICE }, quantity: MAX_SEATS }]), PRICE, false)?.seats).toBe(MAX_SEATS);
    expect(parseEvent({ ...e, id: `evt_${"a".repeat(64)}` }, PRICE, false)).not.toBeNull();
    expect(parseEvent(sub({ id: `sub_${"a".repeat(64)}`, metadata: { tenant: "a".repeat(64) } }), PRICE, false)).not.toBeNull();
  });
});

const T0 = 1_800_000_000_000;
const upd = (over: Partial<SubUpdate> = {}): SubUpdate => ({ event: "evt_1", tenant: "t", customer: "cus_1", subscription: "sub_1", status: "active", seats: 10, created: T0, ...over });
const rec = (over: Partial<Billing> = {}): Billing => ({ customer: "cus_1", subscription: "sub_1", status: "active", seats: 10, as_of: T0, ...over });

describe("remember", () => {
  it("keeps an id for 7 days", () => expect(EVENT_TTL_MS).toBe(604_800_000));
  it("adds an id, and says null for one it already holds", () => {
    expect(remember(undefined, "evt_a", T0)).toEqual([["evt_a", T0]]);
    const one = remember(undefined, "evt_a", T0)!;
    expect(remember(one, "evt_a", T0 + 1)).toBeNull();
    expect(remember(one, "evt_b", T0 + 1)).toEqual([["evt_a", T0], ["evt_b", T0 + 1]]);
  });
  it("forgets an id when its time to live is over, to the millisecond, and then takes it again", () => {
    const one = remember(undefined, "evt_a", T0)!;
    expect(remember(one, "evt_a", T0 + EVENT_TTL_MS - 1)).toBeNull();
    expect(remember(one, "evt_a", T0 + EVENT_TTL_MS)).toEqual([["evt_a", T0 + EVENT_TTL_MS]]);
    expect(remember([["evt_a", T0], ["evt_b", T0 + 10]], "evt_c", T0 + EVENT_TTL_MS)).toEqual([["evt_b", T0 + 10], ["evt_c", T0 + EVENT_TTL_MS]]); // the expired one is dropped
  });
  it("drops the oldest first at the cap, and the dropped id is then taken again", () => {
    let seen = remember(undefined, "evt_1", T0, 3)!;
    for (const id of ["evt_2", "evt_3"]) seen = remember(seen, id, T0 + 1, 3)!;
    expect(seen.map(([e]) => e)).toEqual(["evt_1", "evt_2", "evt_3"]);
    seen = remember(seen, "evt_4", T0 + 2, 3)!;
    expect(seen.map(([e]) => e)).toEqual(["evt_2", "evt_3", "evt_4"]);
    expect(remember(seen, "evt_2", T0 + 3, 3)).toBeNull();
    expect(remember(seen, "evt_1", T0 + 3, 3)?.map(([e]) => e)).toEqual(["evt_3", "evt_4", "evt_1"]);
  });
  it("holds MAX_EVENT_IDS by default, and a full list stays small enough for one storage value", () => {
    let seen: ReturnType<typeof remember> = undefined as any;
    for (let i = 0; i < MAX_EVENT_IDS + 5; i++) seen = remember(seen ?? undefined, `evt_${String(i).padStart(64, "0")}`, T0 + i)!;
    expect(seen).toHaveLength(MAX_EVENT_IDS);
    expect(JSON.stringify(seen).length).toBeLessThan(128 * 1024);
  });
});

describe("limitOf", () => {
  it("is not limited for a tenant that never had a subscription", () => expect(limitOf(undefined, T0)).toBe(Infinity));
  it("is the paid seats while active or trialing, never below the free ones", () => {
    expect(limitOf(rec(), T0)).toBe(10);
    expect(limitOf(rec({ status: "trialing" }), T0)).toBe(10);
    expect(limitOf(rec({ seats: 1 }), T0)).toBe(FREE_SEATS);
  });
  it("keeps the paid seats until the grace period ends, then the free ones", () => {
    const lapsed = rec({ status: "past_due", grace_until: T0 + GRACE_MS });
    expect(limitOf(lapsed, T0 + GRACE_MS - 1)).toBe(10);
    expect(limitOf(lapsed, T0 + GRACE_MS)).toBe(FREE_SEATS);
    expect(limitOf(rec({ status: "canceled" }), T0)).toBe(FREE_SEATS); // no grace recorded
    expect(limitOf(rec({ status: "incomplete" }), T0)).toBe(FREE_SEATS);
  });
});

describe("reduce", () => {
  it("records a first subscription", () => expect(reduce(undefined, upd())).toEqual(rec()));
  it("gives a first event that is already lapsed no grace", () => expect(reduce(undefined, upd({ status: "past_due" }))).toEqual(rec({ status: "past_due" })));
  it("starts the grace period at Stripe's time when good standing ends, and never extends it", () => {
    const lapsed = reduce(rec(), upd({ status: "past_due", created: T0 + 1000 }))!;
    expect(lapsed).toEqual(rec({ status: "past_due", as_of: T0 + 1000, grace_until: T0 + 1000 + GRACE_MS }));
    const worse = reduce(lapsed, upd({ status: "unpaid", created: T0 + 5000 }))!;
    expect(worse.grace_until).toBe(T0 + 1000 + GRACE_MS);
    expect(reduce(worse, upd({ status: "canceled", created: T0 + 9000 }))!.grace_until).toBe(T0 + 1000 + GRACE_MS);
  });
  it("clears the grace period when payment succeeds", () => {
    const back = reduce(rec({ status: "past_due", grace_until: T0 + GRACE_MS }), upd({ created: T0 + 10 }));
    expect(back).toEqual(rec({ as_of: T0 + 10 }));
    expect("grace_until" in back!).toBe(false);
  });
  it("applies seat changes at once, up and down", () => {
    expect(reduce(rec(), upd({ seats: 4, created: T0 + 1 }))?.seats).toBe(4);
    expect(reduce(rec(), upd({ seats: 40, created: T0 + 1 }))?.seats).toBe(40);
  });
  it("ignores an older event and takes one of the same time again", () => {
    expect(reduce(rec(), upd({ status: "canceled", created: T0 - 1 }))).toBeNull();
    expect(reduce(rec(), upd())).toEqual(rec());
  });
  it("in the same second, a lapse wins over a good standing whatever the arrival order", () => {
    const lapsedAt = rec({ status: "canceled", as_of: T0, grace_until: T0 + GRACE_MS });
    expect(reduce(lapsedAt, upd({ created: T0 }))).toBeNull(); // a stale "active" arriving after the cancel
    expect(reduce(lapsedAt, upd({ created: T0 + 1 }))?.status).toBe("active"); // a later one still applies
    expect(reduce(rec({ as_of: T0 }), upd({ status: "canceled", created: T0 }))?.status).toBe("canceled"); // the cancel after an active
  });
  it("ignores another customer's claim on the same subscription", () => expect(reduce(rec(), upd({ customer: "cus_2", created: T0 + 1 }))).toBeNull());
  it("ignores a second subscription while the first is in good standing", () => {
    expect(reduce(rec(), upd({ subscription: "sub_2", customer: "cus_2", created: T0 + 1 }))).toBeNull();
    expect(reduce(rec({ status: "trialing" }), upd({ subscription: "sub_2", created: T0 + 1 }))).toBeNull();
  });
  it("lets a new subscription in good standing replace a lapsed one, grace period or not, and nothing else does", () => {
    const old = rec({ status: "past_due", grace_until: T0 + GRACE_MS });
    expect(reduce(old, upd({ subscription: "sub_2", customer: "cus_2", seats: 6, created: T0 + 1 }))).toEqual({ customer: "cus_2", subscription: "sub_2", status: "active", seats: 6, as_of: T0 + 1 });
    expect(reduce(old, upd({ subscription: "sub_2", status: "past_due", created: T0 + 1 }))).toBeNull();
    expect(reduce(rec({ status: "canceled" }), upd({ subscription: "sub_2", customer: "cus_2", created: T0 + 1 }))?.subscription).toBe("sub_2");
  });
  it("gives a lapse of an unseen subscription over a lapsed one no grace", () => {
    expect(reduce(rec({ status: "canceled" }), upd({ subscription: "sub_2", status: "past_due", created: T0 + 1 }))).toBeNull();
  });
});

describe("keyMode and returnUrl", () => {
  it("accepts test keys, and live keys only when allowed", () => {
    expect(keyMode((fake("sk", "test", "abcdefgh1234")), false)).toBe("test");
    expect(keyMode((fake("rk", "test", "abcdefgh1234")), true)).toBe("test");
    expect(keyMode((fake("sk", "live", "abcdefgh1234")), false)).toBeNull();
    expect(keyMode((fake("sk", "live", "abcdefgh1234")), true)).toBe("live");
    expect(keyMode((fake("rk", "live", "abcdefgh1234")), true)).toBe("live");
    for (const k of [("x" + fake("sk", "live", "abcdefgh1234")), (fake("sk", "live", "abcdefgh1234!")), (fake("sk", "live", "short")), (fake("sk", "live", ""))]) expect(keyMode(k, true)).toBeNull();
    for (const k of [undefined, "", (fake("sk", "test", "")), (fake("sk", "test", "short")), (fake("pk", "test", "abcdefgh1234")), fake("whsec", "abcdefgh1234", ""), ("x" + fake("sk", "test", "abcdefgh1234")), (fake("sk", "test", "abcdefgh1234\n"))]) {
      expect(keyMode(k, true)).toBeNull();
    }
  });
  it("accepts https, and http only on the loopback", () => {
    expect(returnUrl("https://dash.example.test/billing")).toBe("https://dash.example.test/billing");
    expect(returnUrl("http://localhost:8788/billing")).toBe("http://localhost:8788/billing");
    expect(returnUrl("http://127.0.0.1/x")).toBe("http://127.0.0.1/x");
    for (const u of [undefined, "", "not a url", "http://dash.example.test/", "javascript:alert(1)", "ftp://localhost/"]) expect(returnUrl(u)).toBeNull();
  });
});

// ---- through the gateway ----

let n = 0;
const fresh = () => {
  const t = `bil${++n}`;
  const stub = env.TENANT.get(env.TENANT.idFromName(t));
  const session = (role: "admin" | "user", email = "admin@example.test") => stub.createSession(email, role).then((s) => ({ auth: `Bearer ps_${t}.${s.secret}`, csrf: s.csrf, secret: s.secret }));
  const admin = session("admin");
  const post = async (path: string, body: unknown, who: ReturnType<typeof session> = admin, extra: Record<string, string> = {}) => {
    const s = await who;
    return SELF.fetch(`https://gw${path}`, { method: "POST", headers: { Authorization: s.auth, ...extra }, body: typeof body === "string" ? body : JSON.stringify(body) });
  };
  const events = { n: 0 };
  // A webhook delivery as Stripe sends it: the tenant is in the subscription's metadata.
  const hook = async (over: Partial<Record<string, unknown>> = {}, o: { id?: string; created?: number; type?: string; items?: unknown; sig?: string; raw?: string } = {}) => {
    const e = sub(over, o.items);
    e.id = o.id ?? `evt_${++events.n}`;
    e.created = o.created ?? nowS();
    e.type = o.type ?? "customer.subscription.updated";
    (e.data.object as any).metadata = { tenant: t };
    const raw = o.raw ?? JSON.stringify(e);
    return SELF.fetch("https://gw/v1/stripe/webhook", { method: "POST", headers: { "stripe-signature": o.sig ?? (await header(raw)) }, body: raw });
  };
  const enroll = async (owner: string) => {
    const user = await session("user", owner);
    const r = await SELF.fetch("https://gw/v1/enroll/request", {
      method: "POST",
      headers: { Authorization: user.auth, "x-csrf-token": user.csrf },
      body: JSON.stringify({ name: "laptop", signing_key: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))) }),
    });
    return ((await r.json()) as any).id as string;
  };
  const decide = async (id: string, decision = "approved") => {
    const a = await admin;
    return SELF.fetch("https://gw/v1/admin/enrollments/decide", { method: "POST", headers: { Authorization: a.auth, "x-csrf-token": a.csrf }, body: JSON.stringify({ id, decision }) });
  };
  const view = async () => {
    const a = await admin;
    return (await (await SELF.fetch("https://gw/v1/admin/billing", { method: "POST", headers: { Authorization: a.auth, "x-csrf-token": a.csrf }, body: "{}" })).json()) as any;
  };
  const adminPost = async (path: string, body: unknown) => {
    const a = await admin;
    return SELF.fetch(`https://gw${path}`, { method: "POST", headers: { Authorization: a.auth, "x-csrf-token": a.csrf }, body: JSON.stringify(body) });
  };
  return { t, stub, session, post, hook, enroll, decide, view, adminPost };
};
type World = ReturnType<typeof fresh>;
// A tenant that once had a subscription, long lapsed: the only kind that is metered, at the free seats.
const lapsed = async (w: World) => {
  expect(await json(await w.hook({ status: "canceled" }, { created: nowS() - 90 * 86400 }))).toMatchObject({ applied: true });
  return w;
};
const json = async (r: Response) => (await r.json()) as any;
const storageOf = (w: World) => runInDurableObject(w.stub, async (_i, ctx) => Object.fromEntries(await ctx.storage.list()));
const approveN = async (w: World, count: number) => {
  const ids: string[] = [];
  for (let i = 0; i < count; i++) {
    const id = await w.enroll(`u${i}@example.test`);
    expect((await w.decide(id)).status).toBe(200);
    ids.push(id);
  }
  return ids;
};

describe("the webhook endpoint", () => {
  it("applies a signed subscription event and shows it to the admin", async () => {
    const w = fresh();
    expect(await w.view()).toEqual({ status: "none", limit: null, used: 0, subscribed: false });
    const r = await w.hook();
    expect(r.status).toBe(200);
    expect(await json(r)).toEqual({ received: true, applied: true });
    expect(await w.view()).toEqual({ status: "active", limit: 5, used: 0, subscribed: true });
    // The record holds ids and counts, and the change is in the admin audit.
    expect((await storageOf(w)).billing).toMatchObject({ customer: "cus_1", subscription: "sub_1", status: "active", seats: 5 });
    const csv = await (await w.adminPost("/v1/admin/audit/csv", { kind: "admin" })).text();
    expect(csv).toContain("billing.put");
  });

  it("refuses a missing, wrong or stale signature without touching the tenant", async () => {
    const w = fresh();
    const raw = JSON.stringify({ x: 1 });
    const stale = nowS() - WEBHOOK_TOLERANCE_S - 5;
    for (const sig of ["", "t=1,v1=00", await header(raw, nowS(), fake("whsec", "other", "")), await header(raw, stale), await header("{}")]) {
      const r = await SELF.fetch("https://gw/v1/stripe/webhook", { method: "POST", headers: sig ? { "stripe-signature": sig } : {}, body: raw });
      expect(r.status).toBe(400);
      expect(await json(r)).toEqual({ error: "bad_signature" });
    }
    const r = await w.hook({}, { sig: "t=1,v1=00" });
    expect(r.status).toBe(400);
    expect(await w.view()).toMatchObject({ status: "none" });
  });

  it("refuses signed bodies that are not JSON, and oversized ones unread", async () => {
    const raw = "not json";
    const r = await SELF.fetch("https://gw/v1/stripe/webhook", { method: "POST", headers: { "stripe-signature": await header(raw) }, body: raw });
    expect(r.status).toBe(400);
    expect(await json(r)).toEqual({ error: "bad_request" });
    for (const body of ["x".repeat(MAX_WEBHOOK_BYTES + 1), new Uint8Array([0xff, 0xfe, 0xfd])]) {
      const big = await SELF.fetch("https://gw/v1/stripe/webhook", { method: "POST", headers: { "stripe-signature": await header("x") }, body });
      expect(big.status).toBe(413);
      expect(await json(big)).toEqual({ error: "too_large" });
    }
  });

  it("answers 200 to events it does not act on, so Stripe stops retrying them", async () => {
    const w = fresh();
    const nameless = JSON.stringify({ ...sub({ metadata: {} }), created: nowS() });
    const signed = await SELF.fetch("https://gw/v1/stripe/webhook", { method: "POST", headers: { "stripe-signature": await header(nameless) }, body: nameless });
    for (const r of [await w.hook({}, { type: "invoice.paid" }), signed, await w.hook({}, { items: [] }), await w.hook({ status: "mystery" })]) {
      expect(r.status).toBe(200);
      expect(await json(r)).toEqual({ received: true, applied: false });
    }
    expect(await w.view()).toMatchObject({ status: "none" });
  });

  it("takes only POST, and refuses a test deployment's live-mode events", async () => {
    const get = await SELF.fetch("https://gw/v1/stripe/webhook");
    expect(get.status).toBe(405);
    expect(await json(get)).toEqual({ error: "method_not_allowed" });
    expect(get.headers.get("content-type")).toBe("application/json");
    expect(get.headers.get("cache-control")).toBe("no-store");
    const w = fresh();
    const e = JSON.stringify({ ...sub({ metadata: { tenant: w.t } }), livemode: true });
    const r = await SELF.fetch("https://gw/v1/stripe/webhook", { method: "POST", headers: { "stripe-signature": await header(e) }, body: e });
    expect(await json(r)).toEqual({ received: true, applied: false });
    expect(await w.view()).toMatchObject({ status: "none" });
  });

  it("expects test-mode events from a test key (or no key), and live-mode ones only from a live key that is allowed", async () => {
    const send = async (over: Record<string, unknown>, livemode: boolean) => {
      const w = fresh();
      const e = JSON.stringify({ ...sub({ metadata: { tenant: w.t } }), livemode });
      const r = await handleBilling(new Request("https://gw/v1/stripe/webhook", { method: "POST", headers: { "stripe-signature": await header(e) }, body: e }), { ...env, ...over } as unknown as Env);
      expect(r.status).toBe(200);
      return (await json(r)).applied as boolean;
    };
    const live = { STRIPE_SECRET_KEY: (fake("sk", "live", "abcdefgh12345678")) };
    expect(await send({}, false)).toBe(true);
    expect(await send({}, true)).toBe(false);
    expect(await send({ STRIPE_SECRET_KEY: undefined }, false)).toBe(true);
    expect(await send(live, false)).toBe(true); // a live key that is not allowed counts as no live mode
    expect(await send(live, true)).toBe(false);
    expect(await send({ ...live, STRIPE_ALLOW_LIVE: "1" }, true)).toBe(true);
    expect(await send({ ...live, STRIPE_ALLOW_LIVE: "1" }, false)).toBe(false);
    expect(await send({ STRIPE_ALLOW_LIVE: "1" }, false)).toBe(true); // allowed, but the key is a test key
  });

  it("is not available until the webhook secret and the price are configured", async () => {
    for (const gone of ["STRIPE_WEBHOOK_SECRET", "STRIPE_PRICE_ID"]) {
      const r = await handleBilling(new Request("https://gw/v1/stripe/webhook", { method: "POST", body: "{}" }), { ...env, [gone]: undefined } as unknown as Env);
      expect(r.status).toBe(503);
      expect(await json(r)).toEqual({ error: "billing_not_configured" });
    }
  });

  const audits = async (w: World) => (await (await w.adminPost("/v1/admin/audit/csv", { kind: "admin" })).text()).split("billing.put").length - 1;

  it("applies deliveries in Stripe's order, not arrival order", async () => {
    const w = fresh();
    const t = nowS();
    expect(await json(await w.hook({ status: "past_due" }, { created: t }))).toEqual({ received: true, applied: true });
    expect(await json(await w.hook({}, { created: t - 100 }))).toEqual({ received: true, applied: false }); // older, arrived later
    expect(await json(await w.hook({}, { created: t + 100 }))).toEqual({ received: true, applied: true });
    expect(await json(await w.hook({ status: "canceled" }, { created: t + 50 }))).toEqual({ received: true, applied: false }); // older than the last applied
    expect(await w.view()).toMatchObject({ status: "active", limit: 5 });
    expect(await audits(w)).toBe(2);
  });

  it("makes a redelivered event id a no-op whatever its content or time, and does not audit it", async () => {
    const w = fresh();
    const t = nowS();
    expect(await json(await w.hook({}, { id: "evt_R1", created: t }))).toEqual({ received: true, applied: true });
    expect(await json(await w.hook({}, { id: "evt_R1", created: t }))).toEqual({ received: true, applied: false, duplicate: true });
    // The same id with another status and a later time is still the one event: by id, not by timestamp.
    expect(await json(await w.hook({ status: "canceled" }, { id: "evt_R1", created: t + 1000 }))).toEqual({ received: true, applied: false, duplicate: true });
    expect(await w.view()).toMatchObject({ status: "active", limit: 5 });
    expect(await audits(w)).toBe(1);
    // A new id with the same content changes nothing and is not audited either, but it is not a duplicate.
    expect(await json(await w.hook({}, { id: "evt_R2", created: t }))).toEqual({ received: true, applied: false });
    expect(await audits(w)).toBe(1);
  });

  it("remembers the id of an event that was ignored as stale, so its replay is a no-op by id", async () => {
    const w = fresh();
    const t = nowS();
    await w.hook({}, { id: "evt_N", created: t });
    expect(await json(await w.hook({ status: "canceled" }, { id: "evt_S", created: t - 500 }))).toEqual({ received: true, applied: false });
    expect(await json(await w.hook({ status: "canceled" }, { id: "evt_S", created: t - 500 }))).toEqual({ received: true, applied: false, duplicate: true });
  });

  it("counts two deliveries of one event at once as one", async () => {
    const w = fresh();
    const t = nowS();
    const results = await Promise.all(Array.from({ length: 6 }, () => w.hook({ status: "past_due" }, { id: "evt_C", created: t }).then(json)));
    expect(results.filter((r) => r.applied)).toHaveLength(1);
    expect(results.filter((r) => r.duplicate)).toHaveLength(5);
    expect(await audits(w)).toBe(1);
    expect(await w.view()).toEqual({ status: "past_due", limit: FREE_SEATS, used: 0, subscribed: false }); // a first event already lapsed grants no grace
  });

  it("holds the ids in the tenant's storage, bounded: once the cap evicts an id its replay is no longer caught by id, and the order rule still keeps it from doing anything", async () => {
    const w = fresh();
    const t = nowS();
    await w.hook({ status: "past_due" }, { id: "evt_OLD", created: t - 100 });
    expect(((await storageOf(w)).billing_events as [string, number][]).map(([id]) => id)).toEqual(["evt_OLD"]);
    // Fill the list to the cap with other ids; the next event pushes the oldest out.
    await runInDurableObject(w.stub, (_i, ctx) => ctx.storage.put("billing_events", [["evt_OLD", Date.now()], ...Array.from({ length: MAX_EVENT_IDS - 1 }, (_, i) => [`evt_F${i}`, Date.now()])]));
    expect(await json(await w.hook({}, { id: "evt_NEW", created: t }))).toEqual({ received: true, applied: true });
    const ids = ((await storageOf(w)).billing_events as [string, number][]).map(([id]) => id);
    expect(ids).toHaveLength(MAX_EVENT_IDS);
    expect(ids).not.toContain("evt_OLD");
    expect(ids.at(-1)).toBe("evt_NEW");
    // The replay of the evicted one is not a duplicate by id, and does nothing: it is older than the state.
    expect(await json(await w.hook({ status: "past_due" }, { id: "evt_OLD", created: t - 100 }))).toEqual({ received: true, applied: false });
    expect(await w.view()).toMatchObject({ status: "active", limit: 5 });
    expect(await audits(w)).toBe(2);
  });

  it("does not apply events to a tenant that is being deleted", async () => {
    const w = fresh();
    await runInDurableObject(w.stub, (_i, ctx) => ctx.storage.put("deleting", Date.now()));
    expect(await json(await w.hook())).toMatchObject({ applied: false });
    expect((await storageOf(w)).billing).toBeUndefined();
  });
});

describe("seat enforcement at enrollment", () => {
  it("does not meter a tenant that never had a subscription (self-hosted, development, tests)", async () => {
    const w = fresh();
    await approveN(w, FREE_SEATS + 7);
    expect(await w.view()).toEqual({ status: "none", limit: null, used: FREE_SEATS + 7, subscribed: false });
  });

  it("allows the free seats and refuses the next approval, leaving the request pending", async () => {
    const w = await lapsed(fresh());
    await approveN(w, FREE_SEATS);
    const extra = await w.enroll("late@example.test");
    const r = await w.decide(extra);
    expect(r.status).toBe(402);
    expect(await json(r)).toEqual({ error: "seat_limit" });
    expect((await json(await w.adminPost("/v1/admin/enrollments", {}))).pending.map((p: any) => p.id)).toEqual([extra]);
    expect(await w.view()).toMatchObject({ limit: FREE_SEATS, used: FREE_SEATS });
  });

  it("opens more seats when the subscription pays for them, and the same request can then be approved", async () => {
    const w = await lapsed(fresh());
    await approveN(w, FREE_SEATS);
    const extra = await w.enroll("late@example.test");
    expect((await w.decide(extra)).status).toBe(402);
    await w.hook({}, { items: [{ price: { id: PRICE }, quantity: 4 }] });
    expect((await w.decide(extra)).status).toBe(200);
    const fifth = await w.enroll("fifth@example.test");
    expect((await w.decide(fifth)).status).toBe(402); // 4 paid, 4 used
    expect(await w.view()).toMatchObject({ limit: 4, used: 4 });
  });

  it("never blocks rejecting, repeating a decision, or a device that already holds a seat", async () => {
    const w = await lapsed(fresh());
    const ids = await approveN(w, FREE_SEATS);
    const extra = await w.enroll("late@example.test");
    expect((await w.decide(extra, "rejected")).status).toBe(200);
    expect((await w.decide(ids[0]!)).status).toBe(200);
    expect((await w.decide(ids[0]!, "rejected")).status).toBe(409);
  });

  it("frees a seat when a device is revoked", async () => {
    const w = await lapsed(fresh());
    const ids = await approveN(w, FREE_SEATS);
    const extra = await w.enroll("late@example.test");
    expect((await w.decide(extra)).status).toBe(402);
    const r = await w.adminPost("/v1/admin/revocations", { list: { tenant: w.t, version: 1, revoked: [ids[0]], signature: "x" } });
    expect(r.status).toBe(200);
    expect(await w.view()).toMatchObject({ used: FREE_SEATS - 1 });
    expect((await w.decide(extra)).status).toBe(200);
  });

  it("keeps counting an approved device after the enrollment retention, and drops a revoked one", async () => {
    const w = await lapsed(fresh());
    const ids = await approveN(w, FREE_SEATS);
    await w.adminPost("/v1/admin/revocations", { list: { tenant: w.t, version: 1, revoked: [ids[0]], signature: "x" } });
    vi.useFakeTimers({ now: Date.now() + DECIDED_RETENTION_MS + 1000, toFake: ["Date"] });
    try {
      await runDurableObjectAlarm(w.stub);
    } finally {
      vi.useRealTimers();
    }
    const keys = Object.keys(await storageOf(w)).filter((k) => k.startsWith("enr:"));
    expect(keys.sort()).toEqual([`enr:${ids[1]}`, `enr:${ids[2]}`].sort());
    // The alarm also purged the admin session; sign in again.
    const a = await w.session("admin");
    const call = (path: string, body: unknown) => SELF.fetch(`https://gw${path}`, { method: "POST", headers: { Authorization: a.auth, "x-csrf-token": a.csrf }, body: JSON.stringify(body) });
    expect(await json(await call("/v1/admin/billing", {}))).toMatchObject({ used: FREE_SEATS - 1 });
    // The two seats still held are still counted: one approval fits, the next is refused.
    const decide = async (owner: string) => (await call("/v1/admin/enrollments/decide", { id: await w.enroll(owner), decision: "approved" })).status;
    expect(await decide("x@example.test")).toBe(200);
    expect(await decide("y@example.test")).toBe(402);
  });

  it("does not let two approvals share the last seat", async () => {
    const w = await lapsed(fresh());
    await approveN(w, FREE_SEATS - 1);
    const [a, b] = [await w.enroll("a@example.test"), await w.enroll("b@example.test")];
    const codes = (await Promise.all([w.decide(a), w.decide(b)])).map((r) => r.status).sort();
    expect(codes).toEqual([200, 402]);
  });

  it("keeps the paid seats for 7 days after payment fails, then falls back to the free ones; devices already approved stay", async () => {
    const w = fresh();
    const t = nowS();
    await w.hook({}, { created: t - 20 * 86400, items: [{ price: { id: PRICE }, quantity: 6 }] });
    const ids = await approveN(w, 5);
    // Payment failed one day ago: the paid seats still apply.
    await w.hook({ status: "past_due" }, { created: t - 86400, items: [{ price: { id: PRICE }, quantity: 6 }] });
    expect(await w.view()).toMatchObject({ status: "past_due", limit: 6, used: 5, subscribed: false, grace_until: (t - 86400) * 1000 + GRACE_MS });
    expect((await w.decide(await w.enroll("sixth@example.test"))).status).toBe(200);
    // Later events do not extend it, and a new approval is refused once it ends: the clock is Stripe's time of the first failure.
    const w2 = fresh();
    await w2.hook({}, { created: t - 30 * 86400, items: [{ price: { id: PRICE }, quantity: 6 }] });
    await approveN(w2, 5);
    await w2.hook({ status: "past_due" }, { created: t - 8 * 86400 });
    await w2.hook({ status: "unpaid" }, { created: t - 1 * 86400 });
    expect(await w2.view()).toMatchObject({ status: "unpaid", limit: FREE_SEATS, used: 5 });
    expect((await w2.decide(await w2.enroll("sixth@example.test"))).status).toBe(402);
    expect(ids).toHaveLength(5);
  });

  it("returns to the paid seats when payment succeeds again", async () => {
    const w = fresh();
    const t = nowS();
    await w.hook({}, { created: t - 40 * 86400 });
    await w.hook({ status: "canceled" }, { created: t - 20 * 86400 });
    expect(await w.view()).toMatchObject({ limit: FREE_SEATS });
    await w.hook({ status: "active" }, { created: t - 10 });
    expect(await w.view()).toMatchObject({ limit: 5, subscribed: true });
    expect("grace_until" in (await w.view())).toBe(false);
  });

  it("never cuts what is live: lowering the seats refuses new approvals only", async () => {
    const w = fresh();
    await w.hook({}, { created: nowS() - 100, items: [{ price: { id: PRICE }, quantity: 8 }] });
    const ids = await approveN(w, 6);
    await w.hook({}, { created: nowS(), items: [{ price: { id: PRICE }, quantity: 4 }] });
    expect(await w.view()).toMatchObject({ limit: 4, used: 6 });
    expect((await w.decide(await w.enroll("new@example.test"))).status).toBe(402);
    expect((await w.decide(ids[5]!)).status).toBe(200);
    const stored = await storageOf(w);
    expect(Object.keys(stored).filter((k) => k.startsWith("enr:") && (stored[k] as any).status === "approved")).toHaveLength(6);
  });

  it("counts a tenant's seats apart from every other tenant's", async () => {
    const a = fresh();
    const b = fresh();
    await approveN(a, FREE_SEATS);
    expect((await b.decide(await b.enroll("x@example.test"))).status).toBe(200);
    expect(await b.view()).toMatchObject({ used: 1 });
  });

  it("is part of the tenant export", async () => {
    const w = fresh();
    await w.hook();
    const r = await json(await w.adminPost("/v1/admin/export", { section: "settings" }));
    expect(r.items[0].billing).toMatchObject({ customer: "cus_1", status: "active", seats: 5 });
  });
});

describe("journeys A and K: a lapsed tenant on the free seats, a subscription, a lapse again", () => {
  // A tunnel the test holds open, as a daemon does; `closed` is set if the gateway ever closes it.
  async function tunnel(w: World, device: string) {
    const res = await gw("https://gw/v1/connect", { headers: { Upgrade: "websocket", Authorization: `Bearer dev:${w.t}:${device}` } });
    const ws = res.webSocket!;
    ws.accept();
    const state = { closed: false };
    ws.addEventListener("close", () => (state.closed = true));
    const welcomed = new Promise<void>((r) => ws.addEventListener("message", (e) => JSON.parse(e.data as string).t === "welcome" && r()));
    ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
    await welcomed;
    return { ws, state };
  }

  it("refuses a fourth device on the free seats, a subscription raises the limit, and no live tunnel is cut when the subscription lapses", async () => {
    const w = await lapsed(fresh());
    const t = nowS();
    const ids = await approveN(w, FREE_SEATS);
    const live = await Promise.all(ids.map((id) => tunnel(w, id)));

    const fourth = await w.enroll("fourth@example.test");
    expect((await w.decide(fourth)).status).toBe(402);
    await w.hook({}, { created: t - 40 * 86400, items: [{ price: { id: PRICE }, quantity: 5 }] });
    expect((await w.decide(fourth)).status).toBe(200);
    live.push(await tunnel(w, fourth));

    // The subscription is canceled and its grace period has long ended: the limit is the free one again.
    await w.hook({ status: "canceled" }, { created: t - 30 * 86400 });
    expect(await w.view()).toMatchObject({ limit: FREE_SEATS, used: 4 });
    expect((await w.decide(await w.enroll("fifth@example.test"))).status).toBe(402);

    // Every tunnel is still open, and the gateway still answers on it.
    await new Promise((r) => setTimeout(r, 50));
    for (const { ws, state } of live) {
      expect(state.closed).toBe(false);
      expect(ws.readyState).toBe(WebSocket.OPEN);
    }
    const answered = new Promise<string>((r) => live[0]!.ws.addEventListener("message", (e) => r(String(e.data))));
    live[0]!.ws.send("ping");
    expect(await answered).toBe("pong");
  });
});

describe("Checkout and Portal", () => {
  const stripe = (reply: () => Response | Promise<Response> = () => Response.json({ url: "https://checkout.stripe.com/c/pay/cs_test_1" })) => {
    const real = globalThis.fetch;
    const calls: { url: string; init: RequestInit }[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      if (!url.startsWith("https://api.stripe.com/")) return real(input as any, init);
      calls.push({ url, init: init ?? {} });
      return reply();
    });
    return calls;
  };

  it("creates a Checkout session for this tenant only, with the seat count the admin chose", async () => {
    const w = fresh();
    const calls = stripe();
    const r = await w.adminPost("/v1/admin/billing/checkout", { seats: 12 });
    expect(r.status).toBe(200);
    expect(await json(r)).toEqual({ url: "https://checkout.stripe.com/c/pay/cs_test_1" });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://api.stripe.com/v1/checkout/sessions");
    const h = calls[0]!.init.headers as Record<string, string>;
    expect(calls[0]!.init.method).toBe("POST");
    expect(h["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(h.authorization).toBe(`Bearer ${fake("sk", "test", "abcdefgh12345678")}`);
    const form = calls[0]!.init.body as URLSearchParams;
    expect(Object.fromEntries(form)).toEqual({
      mode: "subscription",
      "line_items[0][price]": PRICE,
      "line_items[0][quantity]": "12",
      client_reference_id: w.t,
      "subscription_data[metadata][tenant]": w.t,
      success_url: "https://dash.example.test/billing",
      cancel_url: "https://dash.example.test/billing",
    });
  });

  it("refuses a second subscription while one is in good standing, and allows one after a lapse", async () => {
    const w = fresh();
    stripe();
    await w.hook();
    const r = await w.adminPost("/v1/admin/billing/checkout", { seats: 5 });
    expect(r.status).toBe(409);
    expect(await json(r)).toEqual({ error: "already_subscribed" });
    await w.hook({ status: "canceled" }, { created: nowS() + 1 });
    expect((await w.adminPost("/v1/admin/billing/checkout", { seats: 5 })).status).toBe(200);
  });

  it("takes one seat and the most there can be", async () => {
    const w = fresh();
    const calls = stripe();
    for (const seats of [1, MAX_SEATS]) expect((await w.adminPost("/v1/admin/billing/checkout", { seats })).status).toBe(200);
    expect(calls.map((c) => (c.init.body as URLSearchParams).get("line_items[0][quantity]"))).toEqual(["1", String(MAX_SEATS)]);
  });

  it("rejects bad seat counts and unknown fields", async () => {
    const w = fresh();
    const calls = stripe();
    for (const body of [{}, { seats: 0 }, { seats: -1 }, { seats: 1.5 }, { seats: "5" }, { seats: MAX_SEATS + 1 }, { seats: 5, price: "price_cheap" }, [], "x", null]) {
      const r = await w.adminPost("/v1/admin/billing/checkout", body);
      expect(r.status, JSON.stringify(body)).toBe(400);
      expect(await json(r)).toEqual({ error: "bad_request" });
    }
    const a = await w.session("admin");
    const raw = (body: BodyInit) => SELF.fetch("https://gw/v1/admin/billing/checkout", { method: "POST", headers: { Authorization: a.auth }, body });
    const bad = await raw("{");
    expect([bad.status, await json(bad)]).toEqual([400, { error: "bad_json" }]);
    for (const big of [`{"seats":3,"pad":"${"x".repeat(300)}"}`, new Uint8Array([0xff, 0xfe])]) {
      const r = await raw(big);
      expect([r.status, await json(r)]).toEqual([413, { error: "too_large" }]);
    }
    for (const path of ["/v1/admin/billing", "/v1/admin/billing/portal"]) {
      for (const body of [{ seats: 5 }, { customer: "cus_other" }]) expect((await w.adminPost(path, body)).status).toBe(400);
    }
    expect(calls).toHaveLength(0);
  });

  it("opens the Portal for the customer a subscription event named, and for no other", async () => {
    const w = fresh();
    const calls = stripe(() => Response.json({ url: "https://billing.stripe.com/p/session/test_1" }));
    const none = await w.adminPost("/v1/admin/billing/portal", {});
    expect(none.status).toBe(409);
    expect(await json(none)).toEqual({ error: "no_subscription" });
    await w.hook({ customer: "cus_77" });
    const r = await w.adminPost("/v1/admin/billing/portal", {});
    expect(await json(r)).toEqual({ url: "https://billing.stripe.com/p/session/test_1" });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://api.stripe.com/v1/billing_portal/sessions");
    expect(Object.fromEntries(calls[0]!.init.body as URLSearchParams)).toEqual({ customer: "cus_77", return_url: "https://dash.example.test/billing" });
  });

  it("reports a Stripe failure without relaying what Stripe said", async () => {
    const w = fresh();
    const replies: (() => Response | Promise<Response>)[] = [
      () => Response.json({ error: { message: `secret detail ${fake("sk", "test", "leak")}` } }, { status: 402 }),
      () => Response.json({ url: "https://evil.example.test/steal" }),
      () => Response.json({ url: "https://notstripe.com/x" }),
      () => Response.json({ url: "http://checkout.stripe.com/x" }),
      () => Response.json({ url: "not a url" }),
      () => Response.json({}),
      () => new Response("<html>", { status: 200 }),
      () => Response.json({ url: "https://checkout.stripe.com/x" }, { status: 500 }),
      () => {
        throw new Error("network down");
      },
    ];
    for (const reply of replies) {
      vi.restoreAllMocks();
      stripe(reply);
      const r = await w.adminPost("/v1/admin/billing/checkout", { seats: 3 });
      expect(r.status).toBe(502);
      const text = await r.text();
      expect(JSON.parse(text)).toEqual({ error: "billing_unavailable" });
      expect(text).not.toContain("leak");
    }
    vi.restoreAllMocks();
    stripe(() => Response.json({ url: "https://stripe.com/x" }));
    expect((await w.adminPost("/v1/admin/billing/checkout", { seats: 3 })).status).toBe(200);
    vi.restoreAllMocks();
    stripe(() => Response.json({}, { status: 500 }));
    await w.hook();
    const portal = await w.adminPost("/v1/admin/billing/portal", {});
    expect(portal.status).toBe(502);
    expect(await json(portal)).toEqual({ error: "billing_unavailable" });
  });

  it("is not available without a test-mode key, the price and a return page", async () => {
    const w = fresh();
    const calls = stripe();
    const a = await w.session("admin");
    const call = (over: Record<string, unknown>) =>
      handleBilling(new Request("https://gw/v1/admin/billing/checkout", { method: "POST", headers: { Authorization: a.auth, "x-csrf-token": a.csrf }, body: '{"seats":3}' }), { ...env, ...over } as unknown as Env);
    for (const over of [{ STRIPE_SECRET_KEY: undefined }, { STRIPE_SECRET_KEY: (fake("sk", "live", "abcdefgh12345678")) }, { STRIPE_PRICE_ID: undefined }, { BILLING_RETURN_URL: undefined }, { BILLING_RETURN_URL: "http://dash.example.test/" }]) {
      const r = await call(over);
      expect(r.status, JSON.stringify(over)).toBe(503);
      expect(await json(r)).toEqual({ error: "billing_not_configured" });
    }
    expect((await call({ STRIPE_SECRET_KEY: (fake("sk", "live", "abcdefgh12345678")), STRIPE_ALLOW_LIVE: "1" })).status).toBe(200);
    expect(calls).toHaveLength(1);
  });

  it("needs an admin session with the CSRF token, takes only POST, and is rate limited per tenant", async () => {
    const w = fresh();
    const calls = stripe();
    const user = await w.session("user", "u@example.test");
    const a = await w.session("admin");
    const url = "https://gw/v1/admin/billing/checkout";
    const body = '{"seats":3}';
    const refused = async (r: Promise<Response>, status: number, error: string) => {
      const x = await r;
      expect([x.status, await json(x)]).toEqual([status, { error }]);
    };
    await refused(SELF.fetch(url, { method: "POST", body }), 401, "unauthorized");
    await refused(SELF.fetch(url, { method: "POST", headers: { Authorization: user.auth, "x-csrf-token": user.csrf }, body }), 403, "forbidden");
    const cookie = `__Host-parley_session=ps_${w.t}.${a.secret}`;
    await refused(SELF.fetch(url, { method: "POST", headers: { cookie, origin: "https://gw" }, body }), 403, "csrf"); // no CSRF token
    await refused(SELF.fetch(url, { method: "POST", headers: { cookie, origin: "https://evil.test", "x-csrf-token": a.csrf }, body }), 403, "csrf");
    expect((await SELF.fetch(url, { method: "POST", headers: { cookie, origin: "https://gw", "x-csrf-token": a.csrf }, body })).status).toBe(200);
    await refused(SELF.fetch(url, { headers: { Authorization: a.auth } }), 405, "method_not_allowed");
    expect(calls).toHaveLength(1); // only the cookie request with its token reached Stripe

    const limited = { ...env, RATE_BILLING_PER_MIN: "2" } as unknown as Env;
    const w2 = fresh();
    const b = await w2.session("admin");
    const hit = () => handleBilling(new Request("https://gw/v1/admin/billing", { method: "POST", headers: { Authorization: b.auth, "x-csrf-token": b.csrf }, body: "{}" }), limited);
    expect([(await hit()).status, (await hit()).status, (await hit()).status]).toEqual([200, 200, 429]);
  });
});
