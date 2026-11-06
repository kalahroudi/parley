// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import type { Env } from "./index";
import { confirmPage } from "./login";
import { fold } from "./text";
import { SESSION_TTL_MS, type Role, tenantStub } from "./tenant";

// Over HTTPS the cookie is `__Host-` prefixed: the browser then refuses it unless it is Secure, has Path=/ and no
// Domain, so a sibling subdomain cannot plant or overwrite it. Plain http (local development) cannot use the prefix.
export const COOKIE = "parley_session";
const cookieName = (req: Request) => (new URL(req.url).protocol === "https:" ? `__Host-${COOKIE}` : COOKIE);
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const SECRET = /^[0-9a-f]{64}$/;
const json = (status: number, body: unknown, headers: HeadersInit = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });

export type Principal = { role: Role; tenant: string; email: string; csrf: string; secret: string; via: "cookie" | "bearer" };

const token = (tenant: string, secret: string) => `ps_${tenant}.${secret}`;

// ADMINS is a comma-separated list of `tenant:email` pairs. Anyone not listed
// for the tenant is refused an admin session, whatever the IdP says.
export function isAdmin(env: Env, tenant: string, email: string): boolean {
  const want = `${tenant}:${fold(email)}`;
  return (env.ADMINS ?? "").split(",").some((e) => fold(e.trim()) === want);
}

// A user session needs the tenant to say who may have one, or it is refused. USERS is `tenant:email` pairs and
// USER_DOMAINS is `tenant:domain` pairs, both comma-separated like ADMINS. An email matches USERS exactly (a
// `+tag` address is a different entry) and USER_DOMAINS by its whole domain: `acme.test` admits `a@acme.test` and
// `a+x@acme.test` but not `a@evil.acme.test`, `a@acme.test.evil.com` or an address with a second `@`.
// Admins are governed by ADMINS alone; an admin who also needs a user session is listed in USERS.
export function isUser(env: Env, tenant: string, email: string): boolean {
  const e = fold(email.trim());
  const at = e.indexOf("@");
  if (at < 1 || at !== e.lastIndexOf("@") || at === e.length - 1) return false;
  const t = fold(tenant);
  const listed = (v: string | undefined) => (v ?? "").split(",").map((x) => fold(x.trim()));
  if (listed(env.USERS).includes(`${t}:${e}`)) return true;
  return listed(env.USER_DOMAINS).includes(`${t}:${e.slice(at + 1)}`);
}

function sessionCookie(req: Request, value: string, maxAgeS: number): string {
  const secure = new URL(req.url).protocol === "https:" ? "; Secure" : "";
  return `${cookieName(req)}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeS}${secure}`;
}

// Called by the OIDC callback with a verified identity. The token goes only in
// the HttpOnly cookie; the body carries what the page needs (the CSRF token).
export async function issueSession(req: Request, env: Env, tenant: string, role: Role, email: string, device?: string): Promise<Response> {
  if (!ID.test(tenant)) return json(400, { error: "bad_request" });
  // One answer for every refusal (no such tenant, not an admin, not an allowed user), so a login cannot probe which
  // exist. Admins come from ADMINS and users from USERS or USER_DOMAINS; with none of them set nobody gets a session.
  if (!(role === "admin" ? isAdmin(env, tenant, email) : isUser(env, tenant, email))) return json(403, { error: "not_admin" });
  // A login started by a device (src/login.ts) ends in a confirmation page, not a cookie.
  if (device !== undefined) return confirmPage(env, tenant, email, device);
  // Rotation: a login never reuses a session. The one this browser already presented, if any, ends now.
  const old = await principal(req, env);
  if (old) await tenantStub(env, old.tenant).endSession(old.secret);
  const s = await tenantStub(env, tenant).createSession(email, role);
  return json(200, { role, tenant, email, csrf: s.csrf, expires_at: s.expires_at }, { "set-cookie": sessionCookie(req, token(tenant, s.secret), SESSION_TTL_MS / 1000) });
}

// A session arrives as the cookie (a browser; needs CSRF and Origin checks) or
// as `Authorization: Bearer ps_...` (a program that holds the token itself; not
// ambient, so no CSRF risk). Nothing else is accepted. Why the exemption is safe: a
// cross-site page cannot set Authorization without a CORS preflight, which the gateway never
// grants; the login flow puts the token only in an HttpOnly cookie, so no browser script can
// learn it to use as a bearer; and the two forms never mix: with an Authorization header the
// cookie is ignored, without one only the cookie is read.
export async function principal(req: Request, env: Env): Promise<Principal | null> {
  const auth = req.headers.get("Authorization");
  let raw: string | undefined;
  let via: Principal["via"] = "bearer";
  if (auth !== null) raw = /^Bearer (ps_\S+)$/.exec(auth)?.[1];
  else {
    raw = new RegExp(`(?:^|;\\s*)${cookieName(req)}=([^;]+)`).exec(req.headers.get("cookie") ?? "")?.[1];
    via = "cookie";
  }
  const m = /^ps_([^.]+)\.(.+)$/.exec(raw ?? "");
  if (!m || !ID.test(m[1]!) || !SECRET.test(m[2]!)) return null;
  const s = await tenantStub(env, m[1]!).getSession(m[2]!);
  // The allowlist is checked on every request, so removing someone from ADMINS ends their admin sessions now, not at expiry.
  if (s?.role === "admin" && !isAdmin(env, m[1]!, s.email)) return null;
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
