// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import type { Env } from "./index";
import { SESSION_TTL_MS, type Role, type Tenant } from "./tenant";

export const COOKIE = "parley_session";
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const SECRET = /^[0-9a-f]{64}$/;
const json = (status: number, body: unknown, headers: HeadersInit = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });

export type Principal = { role: Role; tenant: string; email: string; csrf: string; secret: string; via: "cookie" | "bearer" };

const tenantStub = (env: Env, tenant: string) => env.TENANT.get(env.TENANT.idFromName(tenant)) as DurableObjectStub<Tenant>;
const token = (tenant: string, secret: string) => `ps_${tenant}.${secret}`;

// ADMINS is a comma-separated list of `tenant:email` pairs. Anyone not listed
// for the tenant is refused an admin session, whatever the IdP says.
export function isAdmin(env: Env, tenant: string, email: string): boolean {
  const want = `${tenant}:${email.toLowerCase()}`;
  return (env.ADMINS ?? "").split(",").some((e) => e.trim().toLowerCase() === want);
}

function sessionCookie(req: Request, value: string, maxAgeS: number): string {
  const secure = new URL(req.url).protocol === "https:" ? "; Secure" : "";
  return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeS}${secure}`;
}

// Called by the OIDC callback with a verified identity. The token goes only in
// the HttpOnly cookie; the body carries what the page needs (the CSRF token).
export async function issueSession(req: Request, env: Env, tenant: string, role: Role, email: string): Promise<Response> {
  if (!ID.test(tenant)) return json(400, { error: "bad_request" });
  if (role === "admin" && !isAdmin(env, tenant, email)) return json(403, { error: "not_admin" });
  const s = await tenantStub(env, tenant).createSession(email, role);
  return json(200, { role, tenant, email, csrf: s.csrf, expires_at: s.expires_at }, { "set-cookie": sessionCookie(req, token(tenant, s.secret), SESSION_TTL_MS / 1000) });
}

// A session arrives as the cookie (a browser; needs CSRF and Origin checks) or
// as `Authorization: Bearer ps_...` (a program that holds the token itself; not
// ambient, so no CSRF risk). Nothing else is accepted.
export async function principal(req: Request, env: Env): Promise<Principal | null> {
  const auth = req.headers.get("Authorization");
  let raw: string | undefined;
  let via: Principal["via"] = "bearer";
  if (auth !== null) raw = /^Bearer (ps_\S+)$/.exec(auth)?.[1];
  else {
    raw = new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`).exec(req.headers.get("cookie") ?? "")?.[1];
    via = "cookie";
  }
  const m = /^ps_([^.]+)\.(.+)$/.exec(raw ?? "");
  if (!m || !ID.test(m[1]!) || !SECRET.test(m[2]!)) return null;
  const s = await tenantStub(env, m[1]!).getSession(m[2]!);
  return s ? { role: s.role, tenant: m[1]!, email: s.email, csrf: s.csrf, secret: m[2]!, via } : null;
}

// State-changing requests made with the cookie need the session's CSRF token in
// a header and an Origin that is this gateway's own.
export function csrfOk(req: Request, p: Principal): boolean {
  if (p.via === "bearer") return true;
  if (req.headers.get("Origin") !== new URL(req.url).origin) return false;
  const got = req.headers.get("X-CSRF-Token") ?? "";
  if (got.length !== p.csrf.length) return false;
  let d = 0;
  for (let i = 0; i < got.length; i++) d |= got.charCodeAt(i) ^ p.csrf.charCodeAt(i);
  return d === 0;
}

// POST /v1/session reports the current session; /v1/session/logout ends it on the server.
export async function handleSession(req: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(req.url);
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
  const p = await principal(req, env);
  if (!p) return json(401, { error: "unauthorized" });
  if (pathname === "/v1/session") return json(200, { role: p.role, tenant: p.tenant, email: p.email, csrf: p.csrf });
  // The only other route the Worker sends here is /v1/session/logout.
  if (!csrfOk(req, p)) return json(403, { error: "csrf" });
  await tenantStub(env, p.tenant).endSession(p.secret);
  return json(200, { ok: true }, { "set-cookie": sessionCookie(req, "", 0) });
}
