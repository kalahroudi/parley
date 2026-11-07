// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T502: the Stripe event payloads the billing code reads, kept as fixtures (test/fixtures/stripe/*.json). Each carries its
// source URLs, API version and date. They are composed from Stripe's published API reference (the events page for the
// envelope and the types, the OpenAPI specification for each object's properties and which of them are required): there
// is no Stripe CLI or account in this repository's CI, so none is captured from a live account. T510 runs the same flows
// against real Stripe test events (tests/pending-t509.test.mjs). A fixture that lacks a property the reference marks
// required fails here, so a fixture cannot drift from the reference unnoticed.

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { GRACE_MS, limitOf, parseEvent, reduce, type Billing } from "../src/billing";
import created from "./fixtures/stripe/customer.subscription.created.json?raw";
import deleted from "./fixtures/stripe/customer.subscription.deleted.json?raw";
import pastDue from "./fixtures/stripe/customer.subscription.updated.past_due.json?raw";
import seats from "./fixtures/stripe/customer.subscription.updated.seats.json?raw";
import invoicePaid from "./fixtures/stripe/invoice.paid.json?raw";
import invoiceFailed from "./fixtures/stripe/invoice.payment_failed.json?raw";
import checkout from "./fixtures/stripe/checkout.session.completed.json?raw";
import customerDeleted from "./fixtures/stripe/customer.deleted.json?raw";
import requiredRaw from "./fixtures/stripe/required.json?raw";

type Json = Record<string, any>;
const FILES: Record<string, string> = {
  "customer.subscription.created": created,
  "customer.subscription.updated.past_due": pastDue,
  "customer.subscription.updated.seats": seats,
  "customer.subscription.deleted": deleted,
  "invoice.paid": invoicePaid,
  "invoice.payment_failed": invoiceFailed,
  "checkout.session.completed": checkout,
  "customer.deleted": customerDeleted,
};
const fx = (name: string): { _fixture: Json; event: Json } => JSON.parse(FILES[name]!);
const REQUIRED = JSON.parse(requiredRaw) as Record<string, any>;
const SUB_FILES = ["customer.subscription.created", "customer.subscription.updated.seats", "customer.subscription.updated.past_due", "customer.subscription.deleted"];
const OTHER_FILES = ["invoice.paid", "invoice.payment_failed", "checkout.session.completed", "customer.deleted"];
const PRICE = "price_1Seat";

// Every property named required for the envelope, the object and the objects nested in it that the code reads.
function missing(f: { event: Json }): string[] {
  const out: string[] = [];
  const need = (what: string, o: Json | undefined, schema: string) => {
    for (const k of REQUIRED[schema] as string[]) if (!o || !(k in o)) out.push(`${what}.${k}`);
  };
  const e = f.event;
  need("event", e, "event");
  const obj = e.data?.object as Json | undefined;
  const type = obj?.object === "customer" ? "deleted_customer" : (obj?.object as string);
  need(`data.object(${type})`, obj, type);
  if (type === "subscription") {
    for (const [i, it] of ((obj!.items?.data ?? []) as Json[]).entries()) {
      need(`items[${i}]`, it, "subscription_item");
      need(`items[${i}].price`, it.price, "price");
    }
    if (!obj!.items?.data?.length) out.push("items.data");
  }
  return out;
}

describe("the Stripe fixtures", () => {
  it("each names its sources, API version and date", () => {
    for (const name of Object.keys(FILES)) {
      const m = fx(name)._fixture;
      expect(m.source, name).toEqual(expect.arrayContaining([expect.stringMatching(/^https:\/\/(docs\.stripe\.com|raw\.githubusercontent\.com\/stripe\/openapi)\//)]));
      for (const u of m.source) expect(u).toMatch(/^https:\/\//);
      expect(m.api_version, name).toMatch(/^\d{4}-\d{2}-\d{2}\.[a-z]+$/);
      expect(m.recorded, name).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(typeof m.kind === "string" && m.kind.length > 0 && typeof m.note === "string" && m.note.length > 0, name).toBe(true);
      expect(fx(name).event.api_version, name).toBe(m.api_version);
      expect(fx(name).event.type, name).toBe(name.replace(/\.(past_due|seats)$/, ""));
    }
    expect(REQUIRED._fixture.source).toMatch(/^https:\/\//);
    expect(REQUIRED._fixture.api_version).toBe(fx("invoice.paid")._fixture.api_version);
  });

  it("cover every event type the billing flow involves", () => {
    const types = new Set(Object.keys(FILES).map((n) => fx(n).event.type));
    expect([...types].sort()).toEqual(["checkout.session.completed", "customer.deleted", "customer.subscription.created", "customer.subscription.deleted", "customer.subscription.updated", "invoice.paid", "invoice.payment_failed"]);
  });

  it("lack no property the API reference marks required", () => {
    for (const name of Object.keys(FILES)) expect(missing(fx(name)), name).toEqual([]);
  });

  it("fail the check when a required property is missing (the check itself is tested)", () => {
    const f = fx("customer.subscription.created");
    delete f.event.pending_webhooks;
    delete f.event.data.object.metadata;
    delete f.event.data.object.items.data[0].price.currency;
    delete f.event.data.object.items.data[0].current_period_end;
    expect(missing(f)).toEqual(["event.pending_webhooks", "data.object(subscription).metadata", "items[0].current_period_end", "items[0].price.currency"]);
    const g = fx("customer.subscription.created");
    g.event.data.object.items.data = [];
    expect(missing(g)).toEqual(["items.data"]);
    const h = fx("customer.deleted");
    delete h.event.data.object.deleted;
    expect(missing(h)).toEqual(["data.object(deleted_customer).deleted"]);
  });
});

const update = (name: string, price = PRICE) => parseEvent(fx(name).event, price, false);
const T = (name: string) => fx(name).event.created * 1000;

describe("the billing state machine, driven by the fixtures", () => {
  it("reads each subscription fixture", () => {
    expect(update("customer.subscription.created")).toEqual({ event: "evt_1Created", tenant: "acme", customer: "cus_1Acme", subscription: "sub_1Acme", status: "active", seats: 5, created: T("customer.subscription.created") });
    expect(update("customer.subscription.updated.seats")).toMatchObject({ status: "active", seats: 8 });
    expect(update("customer.subscription.updated.past_due")).toMatchObject({ status: "past_due", seats: 5 });
    expect(update("customer.subscription.deleted")).toMatchObject({ status: "canceled", seats: 5 });
    expect(update("customer.subscription.created", "price_other")).toBeNull(); // not our price
  });

  it("acts on none of the other event types: the subscription events carry the state", () => {
    for (const name of OTHER_FILES) expect(update(name), name).toBeNull();
  });

  it("follows a subscription through creation, a seat change, a failed payment and the cancel, with its grace period", () => {
    let b: Billing | undefined;
    const apply = (name: string) => (b = reduce(b, update(name)!) ?? b);
    apply("customer.subscription.created");
    expect(limitOf(b, T("customer.subscription.created") + 1)).toBe(5);
    apply("customer.subscription.updated.seats");
    expect(limitOf(b, T("customer.subscription.updated.seats"))).toBe(8);
    apply("customer.subscription.updated.past_due"); // the seat count in this event is 5: the later state wins
    const graceEnds = T("customer.subscription.updated.past_due") + GRACE_MS;
    expect(b).toMatchObject({ status: "past_due", seats: 5, grace_until: graceEnds });
    expect(limitOf(b, graceEnds - 1)).toBe(5);
    expect(limitOf(b, graceEnds)).toBe(3);
    apply("customer.subscription.deleted"); // the cancel does not extend the grace period
    expect(b).toMatchObject({ status: "canceled", grace_until: graceEnds });
    expect(limitOf(b, graceEnds - 1)).toBe(5);
    expect(limitOf(b, graceEnds)).toBe(3);
  });

  it("ends in the same state whatever order the four subscription events arrive in", () => {
    const perms = (a: string[]): string[][] => (a.length < 2 ? [a] : a.flatMap((x, i) => perms([...a.slice(0, i), ...a.slice(i + 1)]).map((p) => [x, ...p])));
    const all = perms(SUB_FILES);
    expect(all).toHaveLength(24);
    for (const order of all) {
      let b: Billing | undefined;
      for (const name of order) b = reduce(b, update(name)!) ?? b;
      expect(b, order.join(" > ")).toMatchObject({ status: "canceled", seats: 5, as_of: T("customer.subscription.deleted"), subscription: "sub_1Acme", customer: "cus_1Acme" });
    }
  });
});

// ---- through the webhook ----

const enc = new TextEncoder();
const sign = async (body: string, t: number) => {
  const k = await crypto.subtle.importKey("raw", enc.encode(env.STRIPE_WEBHOOK_SECRET!), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const v1 = [...new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(`${t}.${body}`)))].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `t=${t},v1=${v1}`;
};
let n = 100;
const tenant = () => {
  const t = `bil${++n}`;
  return { t, stub: env.TENANT.get(env.TENANT.idFromName(t)) };
};
// The fixture as Stripe would deliver it for this tenant and our configured price.
const deliver = async (name: string, t: string) => {
  const e = fx(name).event;
  if (e.data.object.object === "subscription") {
    e.data.object.metadata.tenant = t;
    for (const it of e.data.object.items.data) it.price.id = env.STRIPE_PRICE_ID;
  }
  const raw = JSON.stringify(e);
  const res = await SELF.fetch("https://gw/v1/stripe/webhook", { method: "POST", headers: { "stripe-signature": await sign(raw, Math.floor(Date.now() / 1000)) }, body: raw });
  return { status: res.status, body: (await res.json()) as Json };
};
const billing = (t: { stub: unknown }) => runInDurableObject(t.stub as any, (_i, ctx) => ctx.storage.get<Billing>("billing"));

describe("the webhook with the fixtures", () => {
  it("applies each subscription fixture and acknowledges, and ignores, the others", async () => {
    const x = tenant();
    expect(await deliver("customer.subscription.created", x.t)).toEqual({ status: 200, body: { received: true, applied: true } });
    expect(await billing(x)).toMatchObject({ status: "active", seats: 5, customer: "cus_1Acme", subscription: "sub_1Acme" });
    for (const name of OTHER_FILES) expect(await deliver(name, x.t), name).toEqual({ status: 200, body: { received: true, applied: false } });
    expect(await billing(x)).toMatchObject({ status: "active", seats: 5 });
    expect(await deliver("customer.subscription.updated.seats", x.t)).toMatchObject({ body: { applied: true } });
    expect(await billing(x)).toMatchObject({ status: "active", seats: 8 });
    expect(await deliver("customer.subscription.updated.past_due", x.t)).toMatchObject({ body: { applied: true } });
    expect(await billing(x)).toMatchObject({ status: "past_due", seats: 5 });
    expect(await deliver("customer.subscription.deleted", x.t)).toMatchObject({ body: { applied: true } });
    expect(await billing(x)).toMatchObject({ status: "canceled" });
  });

  it("takes the fixtures replayed, whole and in any order, as the same events", async () => {
    const x = tenant();
    for (const name of [...SUB_FILES].reverse()) await deliver(name, x.t);
    expect(await billing(x)).toMatchObject({ status: "canceled", seats: 5 });
    for (const name of SUB_FILES) expect(await deliver(name, x.t), name).toEqual({ status: 200, body: { received: true, applied: false, duplicate: true } });
  });

  it("holds no card data or Stripe objects: only ids, status, seats and times", async () => {
    const x = tenant();
    await deliver("customer.subscription.created", x.t);
    expect(Object.keys((await billing(x))!).sort()).toEqual(["as_of", "customer", "seats", "status", "subscription"]);
    const stored = JSON.stringify(await runInDurableObject(x.stub, async (_i, ctx) => Object.fromEntries(await ctx.storage.list())));
    for (const leak of ["price_1Seat", "prod_Seat", "unit_amount", "payment_method", "card", "success_url"]) expect(stored).not.toContain(leak);
  });
});
