// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index";

// A fixed-window counter in a Durable Object, one object per (scope, source or tenant). It stores two numbers (the
// window start and the count) and an alarm that deletes them when the window ends, so storage is bounded and holds
// no content; the object name is a hash, so no address or tenant name is kept either. A refusal does not extend the
// window, so waiting it out always works.
interface Win {
  start: number;
  n: number;
  windowMs: number;
}

// One request against a window. A window that has ended starts afresh; a refusal changes nothing, so it never
// extends the window; the wait is clamped to one window, so a clock that jumped back cannot promise a longer one.
export function advance(w: Win | undefined, limit: number, windowMs: number, now: number): { w: Win; ok: boolean; retryAfterS: number } {
  const cur = !w || w.start + windowMs <= now ? { start: now, n: 0, windowMs } : { ...w };
  const ok = cur.n < limit;
  if (ok) cur.n++;
  return { w: cur, ok, retryAfterS: Math.min(Math.ceil(windowMs / 1000), Math.max(1, Math.ceil((cur.start + windowMs - now) / 1000))) };
}

// When the alarm should fire again: the end of a window that is still open, else null (delete the row).
export const reArm = (w: Win | undefined, now: number): number | null => (w && w.start + w.windowMs > now ? w.start + w.windowMs : null);

export class RateLimit extends DurableObject<Env> {
  async hit(limit: number, windowMs: number): Promise<{ ok: boolean; retryAfterS: number }> {
    const r = advance(await this.ctx.storage.get<Win>("w"), limit, windowMs, Date.now());
    await this.ctx.storage.put("w", r.w);
    await this.ctx.storage.setAlarm(r.w.start + windowMs);
    return { ok: r.ok, retryAfterS: r.retryAfterS };
  }

  async alarm() {
    const at = reArm(await this.ctx.storage.get<Win>("w"), Date.now());
    if (at !== null) return this.ctx.storage.setAlarm(at);
    await this.ctx.storage.deleteAll();
  }
}

const WINDOW_MS = 60_000;
const DEFAULTS = { auth: 30, tenant: 120, session: 120 } as const;
const ID = /^[A-Za-z0-9_-]{1,64}$/;

export const limitFor = (v: string | undefined, dflt: number) => {
  const n = Number(v); // undefined is NaN, so it falls to the default like any other nonsense
  return Number.isInteger(n) && n > 0 ? n : dflt;
};

async function name(scope: string, key: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)));
  return `${scope}:${[...d.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

// null when the request may go on, else the seconds to wait. Any failure of the limiter itself refuses (fail closed).
async function count(env: Env, scope: string, key: string, limit: number): Promise<number | null> {
  try {
    const r = await env.RATE.get(env.RATE.idFromName(await name(scope, key))).hit(limit, WINDOW_MS);
    return r.ok ? null : r.retryAfterS;
  } catch {
    return WINDOW_MS / 1000;
  }
}

async function take(env: Env, scope: string, key: string, limit: number): Promise<Response | null> {
  const wait = await count(env, scope, key, limit);
  return wait === null ? null : tooMany(wait);
}

const tooMany = (retryAfterS: number) =>
  new Response(JSON.stringify({ error: "rate_limited" }), {
    status: 429,
    headers: { "content-type": "application/json", "cache-control": "no-store", "retry-after": String(retryAfterS) },
  });

// Login and session endpoints are limited per source (the connecting address) and a login also per tenant it asks
// for, each over a one-minute window. The limits can be raised with RATE_AUTH_PER_MIN, RATE_TENANT_LOGIN_PER_MIN
// and RATE_SESSION_PER_MIN. Without the address header every request shares one "unknown" source, which only makes
// the limit tighter.
export async function limitAuth(req: Request, env: Env): Promise<Response | null> {
  const url = new URL(req.url);
  const source = req.headers.get("CF-Connecting-IP") ?? "unknown";
  if (url.pathname.startsWith("/auth/")) {
    const refused = await take(env, "auth", source, limitFor(env.RATE_AUTH_PER_MIN, DEFAULTS.auth));
    if (refused) return refused;
    const tenant = url.pathname.endsWith("/login") ? url.searchParams.get("tenant") : null;
    if (tenant && ID.test(tenant)) return take(env, "tenant", tenant.toLowerCase(), limitFor(env.RATE_TENANT_LOGIN_PER_MIN, DEFAULTS.tenant));
    return null;
  }
  return take(env, "session", source, limitFor(env.RATE_SESSION_PER_MIN, DEFAULTS.session));
}

// Requests that name a device (A2A sends, status, GetTask, CancelTask, directory search; prekey requests join
// when the gateway relays them, T412) are counted per scope against two budgets in the same RateLimit DO:
//  - the device's own, in a bucket named by a hash salted with the tenant, so the same device id in another
//    tenant has its own and no name or id is stored;
//  - the tenant's, TENANT_FACTOR times the device's, which caps what a tenant's devices cost the Worker together.
// The device budget is spent first and the tenant's only when it passes, so a flooding device is refused by its own
// budget and burns at most that much of the tenant's: it takes TENANT_FACTOR devices flooding at once (all of them
// enrolled and approved) to lock out the tenant's honest ones. Buckets never cross tenants: the tenant is part of
// every name and comes from the verified credential. Returns null to go on, else the wait in milliseconds.
export type Scope = "task" | "message" | "find";
const SCOPES: Record<Scope, { env: "RATE_TASK_PER_MIN" | "RATE_MESSAGE_PER_MIN" | "RATE_FIND_PER_MIN"; dflt: number }> = {
  task: { env: "RATE_TASK_PER_MIN", dflt: 30 }, // new tasks
  message: { env: "RATE_MESSAGE_PER_MIN", dflt: 300 }, // status, replies, cancels, GetTask
  find: { env: "RATE_FIND_PER_MIN", dflt: 60 }, // directory searches
};
export const TENANT_FACTOR = 10;

export async function limitDevice(env: Env, tenant: string, device: string, scope: Scope): Promise<number | null> {
  const { env: v, dflt } = SCOPES[scope];
  const per = limitFor(env[v], dflt);
  const mine = await count(env, `dev-${scope}`, `${tenant.length}:${tenant}${device}`, per);
  const wait = mine ?? (await count(env, `ten-${scope}`, tenant, per * TENANT_FACTOR));
  return wait === null ? null : wait * 1000;
}
