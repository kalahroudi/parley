// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { readBounded } from "./a2a";
import type { Env } from "./index";
import { limitAdmin } from "./ratelimit";
import { csrfOk, principal } from "./session";
import { tenantStub } from "./tenant";

// Flat per-device seats through Stripe (journey K). The seat limit is checked when an admin approves a device
// (Tenant.decide) and nowhere else: a tunnel that is open is never cut. Stripe holds the money and the tenant mapping
// (the tenant name travels in the subscription's metadata, which only this Worker sets when it creates the Checkout
// session); this file holds the three decisions that matter, each a pure function: is a webhook genuine, what does an
// event change, and how many devices may the tenant approve now.

// What a tenant keeps once a subscription it had has lapsed and its grace period is over.
export const FREE_SEATS = 3;
// A subscription that lapses (payment failed, canceled, unpaid) keeps its paid seat count for this long, counted from
// the time Stripe says it lapsed, so a missed card payment does not stop the next hire from enrolling.
export const GRACE_MS = 7 * 24 * 3600_000;
export const MAX_SEATS = 10_000;
export const WEBHOOK_TOLERANCE_S = 300;
export const MAX_WEBHOOK_BYTES = 256 * 1024;
const MAX_SIGNATURE_HEADER = 512;
const STRIPE_TIMEOUT_MS = 10_000;
const TENANT = /^[A-Za-z0-9_-]{1,64}$/;
const SUB = /^sub_[A-Za-z0-9]{1,64}$/;
const CUS = /^cus_[A-Za-z0-9]{1,64}$/;

export type SubStatus = "active" | "trialing" | "past_due" | "unpaid" | "canceled" | "incomplete" | "incomplete_expired" | "paused";
const STATUSES: readonly string[] = ["active", "trialing", "past_due", "unpaid", "canceled", "incomplete", "incomplete_expired", "paused"];
const entitled = (s: SubStatus) => s === "active" || s === "trialing";

// The tenant's subscription as last reported by Stripe. Ids and counts only. `as_of` is the Stripe event time (ms)
// of the newest event applied, and `grace_until` (ms) is set once, when a paid subscription lapses.
export interface Billing {
  customer: string;
  subscription: string;
  status: SubStatus;
  seats: number;
  as_of: number;
  grace_until?: number;
}

// What one subscription event says about one tenant.
export interface SubUpdate {
  tenant: string;
  customer: string;
  subscription: string;
  status: SubStatus;
  seats: number;
  created: number; // Stripe event time, ms
}

// How many devices the tenant may have approved at `now`. A tenant that has never had a subscription is not metered at
// all (self-hosted, development and test tenants: no billing record, no limit); once Stripe has reported one, the paid
// seats while it is in good standing or inside its grace period, and otherwise the free ones. Never fewer than the free ones.
export function limitOf(b: Billing | undefined, now: number): number {
  if (!b) return Infinity;
  const paid = entitled(b.status) || now < (b.grace_until ?? 0);
  return paid ? Math.max(b.seats, FREE_SEATS) : FREE_SEATS;
}

// The record after `u`, or null when the event changes nothing: an older event than the one already applied (Stripe
// does not deliver in order), another customer's claim on the same subscription, or a second subscription while the
// first is in good standing (the tenant would hold two; the portal is where an existing one is changed). A new one
// that is in good standing replaces a lapsed one, grace period or not.
export function reduce(cur: Billing | undefined, u: SubUpdate): Billing | null {
  const same = cur?.subscription === u.subscription;
  // Stripe's event time has one-second resolution and event ids carry no order, so of two events in the same second the
  // one that leaves the subscription lapsed wins whatever order they arrive in: a stale "active" cannot undo a lapse.
  if (cur && same && (u.customer !== cur.customer || u.created < cur.as_of || (u.created === cur.as_of && entitled(u.status) && !entitled(cur.status)))) return null;
  if (cur && !same && !(entitled(u.status) && !entitled(cur.status))) return null;
  // The grace period starts when a subscription we saw in good standing stops being so, at Stripe's time, and is never
  // extended by the events that follow (past_due, then unpaid, then canceled). An event for a subscription we never saw
  // in good standing grants none.
  const grace = entitled(u.status) || !cur || !same ? undefined : entitled(cur.status) ? u.created + GRACE_MS : cur.grace_until;
  return { customer: u.customer, subscription: u.subscription, status: u.status, seats: u.seats, as_of: u.created, ...(grace === undefined ? {} : { grace_until: grace }) };
}

const SUB_EVENTS = ["customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"];
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

// The subscription update an event carries, or null for an event of another type, one from the other mode (test or
// live), or one that is not shaped as expected or names no tenant, or none of our price. `seats` is the quantity of our
// price only, so an item added in the portal cannot raise it.
export function parseEvent(raw: unknown, priceId: string, live: boolean): SubUpdate | null {
  if (!isObj(raw) || !SUB_EVENTS.includes(raw.type as string) || raw.livemode !== live) return null;
  const sub = isObj(raw.data) ? raw.data.object : undefined;
  if (!isObj(sub) || typeof sub.id !== "string" || !SUB.test(sub.id) || typeof sub.customer !== "string" || !CUS.test(sub.customer)) return null;
  const tenant = isObj(sub.metadata) ? sub.metadata.tenant : undefined;
  const items = isObj(sub.items) ? sub.items.data : null;
  if (!Array.isArray(items) || typeof tenant !== "string" || !TENANT.test(tenant) || !STATUSES.includes(sub.status as string)) return null;
  if (!Number.isSafeInteger(raw.created) || (raw.created as number) < 0) return null;
  let seats = 0;
  for (const it of items) {
    if (isObj(it) && isObj(it.price) && it.price.id === priceId && Number.isSafeInteger(it.quantity)) seats += Math.max(0, it.quantity as number);
  }
  if (seats < 1 || seats > MAX_SEATS) return null;
  return { tenant, customer: sub.customer, subscription: sub.id, status: sub.status as SubStatus, seats, created: (raw.created as number) * 1000 };
}

const unhex = (s: string) => Uint8Array.from({ length: Math.ceil(s.length / 2) }, (_, i) => parseInt(s.slice(2 * i, 2 * i + 2), 16));

// Stripe's webhook signature: the header `t=<unix s>,v1=<hex>[,v1=<hex>]`, where v1 is HMAC-SHA256 of `${t}.${body}`
// under the endpoint's secret. The time must be within WEBHOOK_TOLERANCE_S of now (a captured delivery cannot be
// replayed later), and the comparison is the one WebCrypto's verify makes, which does not leak where a mismatch is.
// A v1 that is not 32 bytes of hex decodes to something else and simply fails the comparison.
export async function verifySignature(payload: string, header: string | null, secret: string, nowS: number): Promise<boolean> {
  if (!header || header.length > MAX_SIGNATURE_HEADER) return false;
  const fields = header.split(",").map((p) => {
    const at = p.indexOf("=");
    return [p.slice(0, at).trim(), p.slice(at + 1).trim()] as const;
  });
  const times = fields.filter(([k]) => k === "t");
  const t = times[0]?.[1];
  if (times.length !== 1 || !/^\d{1,12}$/.test(t as string) || Math.abs(nowS - Number(t)) > WEBHOOK_TOLERANCE_S) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const data = new TextEncoder().encode(`${t}.${payload}`);
  let ok = false;
  for (const [k, v] of fields) if (k === "v1") ok = (await crypto.subtle.verify("HMAC", key, unhex(v), data)) || ok;
  return ok;
}

// "test" for Stripe's test-mode keys; "live" only when the operator has said so (STRIPE_ALLOW_LIVE=1), so a live key
// pasted into a test deployment is refused instead of used; null for anything else.
export function keyMode(key: string | undefined, allowLive: boolean): "test" | "live" | null {
  if (/^[sr]k_test_[A-Za-z0-9]{8,}$/.test(key as string)) return "test";
  return allowLive && /^[sr]k_live_[A-Za-z0-9]{8,}$/.test(key as string) ? "live" : null;
}

// The page Stripe sends the admin to afterwards: fixed in configuration, never taken from a request.
export function returnUrl(v: string | undefined): string | null {
  try {
    const u = new URL(v as string);
    return u.protocol === "https:" || (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) ? u.href : null;
  } catch {
    return null;
  }
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

// One POST to Stripe's API, returning the hosted page's URL, or null on any failure (the reason is Stripe's and is not
// relayed or logged: it can carry request details). The URL must be on stripe.com.
async function stripePage(key: string, path: string, form: Record<string, string>): Promise<string | null> {
  try {
    const res = await fetch(`https://api.stripe.com/v1/${path}`, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form),
      signal: AbortSignal.timeout(STRIPE_TIMEOUT_MS),
    });
    const url = new URL(((await res.json()) as { url: string }).url);
    return res.ok && url.protocol === "https:" && (url.hostname === "stripe.com" || url.hostname.endsWith(".stripe.com")) ? url.href : null;
  } catch {
    return null;
  }
}

async function webhook(req: Request, env: Env): Promise<Response> {
  if (!env.STRIPE_WEBHOOK_SECRET || !env.STRIPE_PRICE_ID) return json(503, { error: "billing_not_configured" });
  const text = await readBounded(req, MAX_WEBHOOK_BYTES).catch(() => null);
  if (text === null) return json(413, { error: "too_large" });
  // Genuine first, parsed after: nothing in the body is looked at until the signature has held.
  if (!(await verifySignature(text, req.headers.get("stripe-signature"), env.STRIPE_WEBHOOK_SECRET, Date.now() / 1000))) return json(400, { error: "bad_signature" });
  let event: unknown;
  try {
    event = JSON.parse(text);
  } catch {
    return json(400, { error: "bad_request" });
  }
  const update = parseEvent(event, env.STRIPE_PRICE_ID, keyMode(env.STRIPE_SECRET_KEY, env.STRIPE_ALLOW_LIVE === "1") === "live");
  // 200 for anything we do not act on, so Stripe does not retry it; a failure inside throws and becomes a 500, which it does retry.
  return json(200, { received: true, applied: update ? await tenantStub(env, update.tenant).applyBilling(update) : false });
}

// The admin's side: the plan and seats in use, and the two hosted pages (Checkout to subscribe, the Portal to change
// the card, the seat count or cancel). Every route is an admin POST with a JSON body, like the other admin routes.
export async function handleBilling(req: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(req.url);
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
  if (pathname === "/v1/stripe/webhook") return webhook(req, env);
  const p = await principal(req, env);
  if (!p) return json(401, { error: "unauthorized" });
  if (!csrfOk(req, p)) return json(403, { error: "csrf" });
  if (p.role !== "admin") return json(403, { error: "forbidden" });
  const refused = await limitAdmin(env, p.tenant, "billing");
  if (refused) return refused;
  const text = await readBounded(req, 256).catch(() => null);
  if (text === null) return json(413, { error: "too_large" });
  let b: unknown;
  try {
    b = JSON.parse(text);
  } catch {
    return json(400, { error: "bad_json" });
  }
  // Only Checkout takes a field, and only `seats`.
  const checkout = pathname === "/v1/admin/billing/checkout";
  if (!isObj(b) || Object.keys(b).some((k) => !(checkout && k === "seats"))) return json(400, { error: "bad_request" });
  const stub = tenantStub(env, p.tenant);

  if (pathname === "/v1/admin/billing") return json(200, await stub.billingView());

  const key = env.STRIPE_SECRET_KEY;
  const back = returnUrl(env.BILLING_RETURN_URL);
  if (!key || !back || !env.STRIPE_PRICE_ID || !keyMode(key, env.STRIPE_ALLOW_LIVE === "1")) return json(503, { error: "billing_not_configured" });

  if (checkout) {
    if (!Number.isSafeInteger(b.seats) || (b.seats as number) < 1 || (b.seats as number) > MAX_SEATS) return json(400, { error: "bad_request" });
    if ((await stub.billingView()).subscribed) return json(409, { error: "already_subscribed" });
    const url = await stripePage(key, "checkout/sessions", {
      mode: "subscription",
      "line_items[0][price]": env.STRIPE_PRICE_ID,
      "line_items[0][quantity]": String(b.seats),
      client_reference_id: p.tenant,
      "subscription_data[metadata][tenant]": p.tenant,
      success_url: back,
      cancel_url: back,
    });
    return url !== null ? json(200, { url }) : json(502, { error: "billing_unavailable" });
  }

  const customer = await stub.customerId();
  if (!customer) return json(409, { error: "no_subscription" });
  const url = await stripePage(key, "billing_portal/sessions", { customer, return_url: back });
  return url !== null ? json(200, { url }) : json(502, { error: "billing_unavailable" });
}
