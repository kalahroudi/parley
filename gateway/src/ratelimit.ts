// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index";

// A fixed-window counter in a Durable Object, one object per (scope, source or tenant). It stores two numbers (the
// window start and the count) and an alarm that deletes them when the window ends, so storage is bounded and holds
// no content; the object name is a hash, so no address or tenant name is kept either. A refusal does not extend the
// window, so waiting it out always works.
export class RateLimit extends DurableObject<Env> {
  async hit(limit: number, windowMs: number): Promise<{ ok: boolean; retryAfterS: number }> {
    const now = Date.now();
    let w = await this.ctx.storage.get<{ start: number; n: number; windowMs: number }>("w");
    if (!w || w.start + windowMs <= now) w = { start: now, n: 0, windowMs };
    const ok = w.n < limit;
    if (ok) w.n++;
    await this.ctx.storage.put("w", w);
    await this.ctx.storage.setAlarm(w.start + windowMs);
    return { ok, retryAfterS: Math.max(1, Math.ceil((w.start + windowMs - now) / 1000)) };
  }

  async alarm() {
    const w = await this.ctx.storage.get<{ start: number; n: number; windowMs?: number }>("w");
    if (w && w.start + (w.windowMs ?? 0) > Date.now()) return this.ctx.storage.setAlarm(w.start + w.windowMs!);
    await this.ctx.storage.deleteAll();
  }
}

const WINDOW_MS = 60_000;
const DEFAULTS = { auth: 30, tenant: 120, session: 120 } as const;
const ID = /^[A-Za-z0-9_-]{1,64}$/;

const limitFor = (v: string | undefined, dflt: number) => {
  const n = Number(v);
  return v !== undefined && Number.isInteger(n) && n > 0 ? n : dflt;
};

async function name(scope: string, key: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)));
  return `${scope}:${[...d.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

// null when the request may go on. Any failure of the limiter itself refuses (fail closed).
async function take(env: Env, scope: string, key: string, limit: number): Promise<Response | null> {
  try {
    const r = await env.RATE.get(env.RATE.idFromName(await name(scope, key))).hit(limit, WINDOW_MS);
    if (r.ok) return null;
    return tooMany(r.retryAfterS);
  } catch {
    return tooMany(WINDOW_MS / 1000);
  }
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
