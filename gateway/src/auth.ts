// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { completeLogin, entra, google, OidcError, startLogin, type Provider } from "./oidc.ts";

export type AuthEnv = {
  FLOW_SECRET: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GOOGLE_HOSTED_DOMAIN?: string;
  ENTRA_TENANT_ID?: string;
  ENTRA_CLIENT_ID?: string;
  ENTRA_CLIENT_SECRET?: string;
  // Test/dev only: point either provider at a mock IdP.
  GOOGLE_ISSUER?: string;
  ENTRA_ISSUER?: string;
};

// oidc.ts caches discovery and JWKS per Provider object, and a Worker may hand
// us a different env object on each request. Keep one Provider per distinct
// config (module-level, in memory only) so those caches survive across requests.
const providerCache = new Map<string, Provider>();
const cached = (config: unknown[], make: () => Provider): Provider => {
  const key = JSON.stringify(config);
  let p = providerCache.get(key);
  if (!p) providerCache.set(key, (p = make()));
  return p;
};

export function providers(env: AuthEnv): Record<string, Provider> {
  const out: Record<string, Provider> = {};
  if (env.GOOGLE_CLIENT_ID) {
    const c = [env.GOOGLE_CLIENT_ID, env.GOOGLE_CLIENT_SECRET, env.GOOGLE_HOSTED_DOMAIN, env.GOOGLE_ISSUER];
    out.google = cached(["google", ...c], () =>
      google({
        clientId: env.GOOGLE_CLIENT_ID!,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        hostedDomain: env.GOOGLE_HOSTED_DOMAIN,
        issuer: env.GOOGLE_ISSUER,
      }),
    );
  }
  if (env.ENTRA_CLIENT_ID && env.ENTRA_TENANT_ID) {
    const c = [env.ENTRA_CLIENT_ID, env.ENTRA_CLIENT_SECRET, env.ENTRA_TENANT_ID, env.ENTRA_ISSUER];
    out.entra = cached(["entra", ...c], () =>
      entra({
        clientId: env.ENTRA_CLIENT_ID!,
        clientSecret: env.ENTRA_CLIENT_SECRET,
        tenantId: env.ENTRA_TENANT_ID!,
        issuer: env.ENTRA_ISSUER,
      }),
    );
  }
  return out;
}

const COOKIE = "parley_flow";
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

// /auth/:provider/login redirects to the IdP; /auth/:provider/callback finishes
// the flow. Session and connect-token issuance build on the returned identity
// in later tasks (enrollment); here the callback reports the verified identity.
// Nothing about the user goes in URLs or logs.
export async function handle(req: Request, env: AuthEnv, fetchFn?: typeof fetch): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === "/healthz") return json(200, { ok: true });
  const m = /^\/auth\/([a-z]+)\/(login|callback)$/.exec(url.pathname);
  const [, name, action] = m ?? [];
  if (!name || req.method !== "GET") return json(404, { error: "not_found" });
  const p = providers(env)[name];
  if (!p) return json(404, { error: "unknown_provider" });
  const ctx = { flowSecret: env.FLOW_SECRET, fetch: fetchFn };
  const redirectUri = `${url.origin}/auth/${p.name}/callback`;
  const cookieAttrs = `Path=/auth/${p.name}/callback; HttpOnly; SameSite=Lax; Max-Age=600${url.protocol === "https:" ? "; Secure" : ""}`;
  try {
    if (action === "login") {
      const { url: to, flow } = await startLogin(ctx, p, redirectUri);
      return new Response(null, { status: 302, headers: { location: to, "set-cookie": `${COOKIE}=${flow}; ${cookieAttrs}` } });
    }
    const flow = /(?:^|;\s*)parley_flow=([^;]+)/.exec(req.headers.get("cookie") ?? "")?.[1];
    const id = await completeLogin(ctx, p, flow, url.searchParams);
    return json(200, id, { "set-cookie": `${COOKIE}=; ${cookieAttrs.replace("Max-Age=600", "Max-Age=0")}`, "cache-control": "no-store" });
  } catch (e) {
    if (e instanceof OidcError) return json(e.code === "idp_error" ? 502 : 401, { error: e.code });
    return json(500, { error: "server_error" });
  }
}
