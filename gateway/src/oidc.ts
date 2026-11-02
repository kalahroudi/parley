// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// OIDC login (authorization code + PKCE S256) for Google and Microsoft Entra.
// Uses only web-standard APIs (fetch, crypto.subtle) so it runs in a Worker and
// in Node. Login state is stateless: a signed `flow` value (kept by the browser
// in an HttpOnly cookie) carries the state, nonce and PKCE verifier.

export type Provider = {
  name: string;
  issuer: string;
  clientId: string;
  clientSecret?: string;
  scopes: string[];
  // Entra: the only directory whose users may sign in (checked against `tid`).
  tenantId?: string;
  // Google: Workspace domain the user must belong to (checked against `hd`).
  hostedDomain?: string;
  // Google asserts email_verified; Entra emails are admin-controlled and not
  // asserted, so only the tenant check vouches for them.
  requireVerifiedEmail: boolean;
};

export type Identity = { provider: string; issuer: string; sub: string; email: string; tenantId?: string };

export class OidcError extends Error {
  code: string;
  constructor(code: string, message = code) {
    super(message);
    this.code = code;
  }
}

type Opts = { clientId: string; clientSecret?: string; issuer?: string };

export const google = (o: Opts & { hostedDomain?: string }): Provider => ({
  name: "google",
  issuer: o.issuer ?? "https://accounts.google.com",
  clientId: o.clientId,
  clientSecret: o.clientSecret,
  scopes: ["openid", "email"],
  hostedDomain: o.hostedDomain,
  requireVerifiedEmail: true,
});

export const entra = (o: Opts & { tenantId: string }): Provider => ({
  name: "entra",
  issuer: o.issuer ?? `https://login.microsoftonline.com/${o.tenantId}/v2.0`,
  clientId: o.clientId,
  clientSecret: o.clientSecret,
  scopes: ["openid", "email", "profile"],
  tenantId: o.tenantId,
  requireVerifiedEmail: false,
});

export const FLOW_TTL_MS = 10 * 60_000;
const enc = new TextEncoder();
const b64u = (b: ArrayBuffer | Uint8Array) => {
  const u = b instanceof Uint8Array ? b : new Uint8Array(b);
  let s = "";
  for (const c of u) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64u = (s: string) => {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const rand = (n: number) => b64u(crypto.getRandomValues(new Uint8Array(n)));
const parseJson = (b: Uint8Array) => JSON.parse(new TextDecoder().decode(b));

const hmacKey = (secret: string) =>
  crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

async function seal(secret: string, payload: object): Promise<string> {
  const body = b64u(enc.encode(JSON.stringify(payload)));
  return `${body}.${b64u(await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(body)))}`;
}

async function unseal(secret: string, flow: string): Promise<Record<string, unknown>> {
  const [body, sig, extra] = flow.split(".");
  if (!body || !sig || extra !== undefined) throw new OidcError("bad_flow");
  let ok = false;
  try {
    ok = await crypto.subtle.verify("HMAC", await hmacKey(secret), unb64u(sig), enc.encode(body));
  } catch {
    // malformed base64 falls through to the rejection below
  }
  if (!ok) throw new OidcError("bad_flow");
  return parseJson(unb64u(body));
}

export type Fetch = typeof fetch;
export type Ctx = { flowSecret: string; fetch?: Fetch; now?: () => number };

// Discovery documents and JWKS are cached per Provider object for the life of
// the isolate; an unknown kid triggers one JWKS refetch to follow key rotation.
type Meta = { authorization_endpoint: string; token_endpoint: string; jwks_uri: string };
const metaCache = new WeakMap<Provider, Meta>();
const jwksCache = new WeakMap<Provider, { keys: (JsonWebKey & { kid?: string })[] }>();

async function getJson(f: Fetch, url: string, init?: RequestInit) {
  const res = await f(url, init);
  if (!res.ok) throw new OidcError("idp_error", `${new URL(url).pathname} returned ${res.status}`);
  return res.json() as Promise<any>;
}

async function discover(p: Provider, f: Fetch): Promise<Meta> {
  const hit = metaCache.get(p);
  if (hit) return hit;
  const doc = await getJson(f, `${p.issuer}/.well-known/openid-configuration`);
  if (doc.issuer !== p.issuer) throw new OidcError("issuer_mismatch");
  for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    if (typeof doc[k] !== "string") throw new OidcError("idp_error", `discovery lacks ${k}`);
  }
  metaCache.set(p, doc);
  return doc;
}

export async function startLogin(
  ctx: Ctx,
  p: Provider,
  redirectUri: string,
  loginHint?: string,
): Promise<{ url: string; flow: string }> {
  const f = ctx.fetch ?? fetch;
  const now = (ctx.now ?? Date.now)();
  const meta = await discover(p, f);
  const state = rand(16);
  const nonce = rand(16);
  const verifier = rand(32);
  const challenge = b64u(await crypto.subtle.digest("SHA-256", enc.encode(verifier)));
  const url = new URL(meta.authorization_endpoint);
  const q: Record<string, string> = {
    response_type: "code",
    client_id: p.clientId,
    redirect_uri: redirectUri,
    scope: p.scopes.join(" "),
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  };
  if (loginHint) q.login_hint = loginHint;
  if (p.hostedDomain) q.hd = p.hostedDomain;
  for (const [k, v] of Object.entries(q)) url.searchParams.set(k, v);
  const flow = await seal(ctx.flowSecret, { p: p.name, state, nonce, verifier, redirectUri, exp: now + FLOW_TTL_MS });
  return { url: url.toString(), flow };
}

async function verifyIdToken(p: Provider, f: Fetch, meta: Meta, jwt: string, nonce: string, nowMs: number) {
  const [h, c, s, extra] = jwt.split(".");
  if (!h || !c || !s || extra !== undefined) throw new OidcError("bad_token");
  let header: any, claims: any;
  try {
    header = parseJson(unb64u(h));
    claims = parseJson(unb64u(c));
  } catch {
    throw new OidcError("bad_token");
  }
  if (header.alg !== "RS256") throw new OidcError("bad_token", "unsupported alg");
  let jwk = jwksCache.get(p)?.keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    const set = await getJson(f, meta.jwks_uri);
    jwksCache.set(p, set);
    jwk = set.keys?.find((k: any) => k.kid === header.kid && (!k.use || k.use === "sig"));
  }
  if (!jwk) throw new OidcError("bad_token", "unknown signing key");
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, unb64u(s), enc.encode(`${h}.${c}`));
  if (!valid) throw new OidcError("bad_signature");

  const nowS = nowMs / 1000;
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== p.issuer) throw new OidcError("issuer_mismatch");
  if (!aud.includes(p.clientId) || (aud.length > 1 && claims.azp !== p.clientId)) throw new OidcError("audience_mismatch");
  if (typeof claims.exp !== "number" || claims.exp + 60 < nowS) throw new OidcError("token_expired");
  if (typeof claims.iat === "number" && claims.iat - 60 > nowS) throw new OidcError("bad_token", "iat in the future");
  if (claims.nonce !== nonce) throw new OidcError("nonce_mismatch");
  if (typeof claims.sub !== "string" || !claims.sub) throw new OidcError("bad_token", "no sub");
  return claims;
}

export async function completeLogin(
  ctx: Ctx,
  p: Provider,
  flow: string | undefined,
  query: URLSearchParams,
): Promise<Identity> {
  const f = ctx.fetch ?? fetch;
  const nowMs = (ctx.now ?? Date.now)();
  if (!flow) throw new OidcError("bad_flow");
  const fl = await unseal(ctx.flowSecret, flow);
  if (fl.p !== p.name || typeof fl.exp !== "number" || fl.exp < nowMs) throw new OidcError("bad_flow");
  const state = query.get("state");
  if (!state || state !== fl.state) throw new OidcError("state_mismatch");
  // Error responses carry the state too, so check it first. Only the code is
  // surfaced, never IdP-supplied text.
  if (query.get("error")) throw new OidcError("idp_denied", query.get("error")!.replace(/[^\w.-]/g, "").slice(0, 64));
  const code = query.get("code");
  if (!code) throw new OidcError("bad_request", "no code");

  const meta = await discover(p, f);
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: String(fl.redirectUri),
    client_id: p.clientId,
    code_verifier: String(fl.verifier),
  });
  if (p.clientSecret) form.set("client_secret", p.clientSecret);
  const tok = await getJson(f, meta.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form,
  });
  if (typeof tok.id_token !== "string") throw new OidcError("idp_error", "no id_token");

  const claims = await verifyIdToken(p, f, meta, tok.id_token, String(fl.nonce), nowMs);
  if (p.tenantId && claims.tid !== p.tenantId) throw new OidcError("tenant_mismatch");
  if (p.hostedDomain && claims.hd !== p.hostedDomain) throw new OidcError("tenant_mismatch");
  const email = String(claims.email ?? claims.preferred_username ?? "").toLowerCase();
  if (!/^[^@\s]+@[^@\s]+$/.test(email)) throw new OidcError("no_email");
  if (p.requireVerifiedEmail && claims.email_verified !== true) throw new OidcError("email_unverified");
  return { provider: p.name, issuer: p.issuer, sub: claims.sub, email, tenantId: p.tenantId };
}
