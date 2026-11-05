// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Optional cross-check (T111): the gateway's Entra login scenarios run against node-oidc-provider
// (https://github.com/panva/node-oidc-provider, an OpenID-certified server written independently of this
// repository), configured Entra-shaped: issuer `<base>/<tenant guid>/v2.0`, tid, oid and preferred_username claims
// in the id_token. It stops us testing only against our own assumptions about what an OIDC server does.
//
// It is skipped unless ENTRA_CROSSCHECK_DIR names a directory whose node_modules holds oidc-provider (CI:
// .github/workflows/entra-crosscheck.yml, an optional workflow outside the required checks, installs the version pinned in
// tests/crosscheck/package-lock.json; locally, `npm ci --ignore-scripts --prefix tests/crosscheck`; nothing is added to
// the gateway's or the daemon's dependencies). Once the variable is set, a missing module or a failing scenario fails the run.
//
// What it does not cover: Entra's path layout (/oauth2/v2.0/authorize ...) and the multi-tenant `{tenantid}` issuer,
// AADSTS errors and key rollover; node-oidc-provider has none of these, so tests/gateway-entra.test.mjs covers them
// against the simulator, whose shapes come from Microsoft's published reference.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { completeLogin, entra, OidcError, startLogin } from "../gateway/src/oidc.ts";

const dir = process.env.ENTRA_CROSSCHECK_DIR;
const skip = dir ? false : "set ENTRA_CROSSCHECK_DIR to a directory with oidc-provider installed (see the header of this file)";
const ctx = { flowSecret: "test-secret" };
const REDIRECT = "http://127.0.0.1:8787/auth/entra/callback";
const TENANT = "5f4d3c2b-1a09-4e8d-9c7b-6a5f4e3d2c1b";
const OTHER_TENANT = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof OidcError && e.code === code, code);

async function startProvider() {
  const { default: Provider } = await import(pathToFileURL(join(dir, "node_modules", "oidc-provider", "lib", "index.js")).href);
  let handler;
  const server = createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const prefix = `/${TENANT}/v2.0`;
  const oid = (login) => `00000000-0000-4000-8000-${Buffer.from(login).toString("hex").padEnd(12, "0").slice(0, 12)}`;
  const accounts = {
    // login name -> directory the account belongs to
    alice: { tid: TENANT, upn: "Alice@Corp.test" },
    mallory: { tid: OTHER_TENANT, upn: "alice@corp.test" },
  };
  const provider = new Provider(`${base}${prefix}`, {
    clients: ["cid", "other-app"].map((client_id) => ({ client_id, redirect_uris: [REDIRECT], token_endpoint_auth_method: "none", application_type: "native", grant_types: ["authorization_code"], response_types: ["code"] })),
    pkce: { required: () => true },
    claims: { openid: ["sub", "tid", "oid", "ver"], profile: ["preferred_username", "name"], email: [] },
    conformIdTokenClaims: false,
    ttl: { IdToken: 1, AuthorizationCode: 60, Session: 600, Interaction: 600, Grant: 600 },
    findAccount: async (_c, id) => {
      const a = accounts[id];
      return a && { accountId: id, claims: async () => ({ sub: `sub-${id}`, tid: a.tid, oid: oid(id), ver: "2.0", preferred_username: a.upn, name: id }) };
    },
    // auto-consent for the test client, as Entra does for a pre-consented application
    loadExistingGrant: async (ctx) => {
      const grant = new provider.Grant({ clientId: ctx.oidc.client.clientId, accountId: ctx.oidc.session.accountId });
      grant.addOIDCScope("openid profile email");
      await grant.save();
      return grant;
    },
  });
  const cb = provider.callback();
  handler = (req, res) => {
    req.originalUrl = req.url;
    req.url = req.url.slice(prefix.length) || "/";
    cb(req, res);
  };
  return { provider, server, base, close: () => new Promise((r) => (server.closeAllConnections(), server.close(r))) };
}

// Plays the browser: follows redirects with a cookie jar, signs in as `login` on the library's dev interaction pages,
// and returns the callback query the gateway would receive.
async function browse(url, login) {
  const jar = new Map();
  const send = async (u, init = {}) => {
    const r = await fetch(u, { redirect: "manual", ...init, headers: { ...init.headers, cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") } });
    for (const c of r.headers.getSetCookie()) {
      const [kv] = c.split(";");
      const i = kv.indexOf("=");
      jar.set(kv.slice(0, i), kv.slice(i + 1));
    }
    return r;
  };
  let u = url;
  for (let hops = 0; hops < 12; hops++) {
    const r = await send(u);
    if (r.status >= 300 && r.status < 400) {
      u = new URL(r.headers.get("location"), u).toString();
      if (u.startsWith(REDIRECT)) return new URL(u).searchParams;
      continue;
    }
    if (u.includes("/interaction/")) {
      // dev interactions: the login form, then (if asked) the consent form; both post to the interaction URL
      const html = await r.text();
      const step = html.includes('name="login"') ? "login" : "confirm";
      const post = await send(u, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: step === "login" ? new URLSearchParams({ prompt: "login", login, password: "x" }) : new URLSearchParams({ prompt: "consent" }) });
      u = new URL(post.headers.get("location"), u).toString();
      continue;
    }
    throw new Error(`unexpected response ${r.status} at ${u}: ${await r.text()}`);
  }
  throw new Error("too many redirects");
}

async function withProvider(fn) {
  const idp = await startProvider();
  try {
    const p = (clientId = "cid") => entra({ clientId, tenantId: TENANT, issuer: `${idp.base}/${TENANT}/v2.0` });
    await fn(idp, p);
  } finally {
    await idp.close();
  }
}

test("cross-check: login completes against an independent OIDC server with a tenant issuer", { skip }, () =>
  withProvider(async (idp, p) => {
    const { url, flow } = await startLogin(ctx, p(), REDIRECT);
    const id = await completeLogin(ctx, p(), flow, await browse(url, "alice"));
    assert.equal(id.provider, "entra");
    assert.equal(id.issuer, `${idp.base}/${TENANT}/v2.0`);
    assert.equal(id.tenantId, TENANT);
    assert.equal(id.sub, "alice"); // the server sets sub to the account id
    assert.equal(id.email, "alice@corp.test");
  }));

test("cross-check: a user from another directory with the same address is refused by tid", { skip }, () =>
  withProvider(async (idp, p) => {
    const { url, flow } = await startLogin(ctx, p(), REDIRECT);
    await rejects(completeLogin(ctx, p(), flow, await browse(url, "mallory")), "tenant_mismatch");
  }));

test("cross-check: a code issued to another application cannot be redeemed here", { skip }, () =>
  withProvider(async (idp, p) => {
    const { url, flow } = await startLogin(ctx, p(), REDIRECT);
    const swapped = new URL(url);
    swapped.searchParams.set("client_id", "other-app");
    // the server itself refuses the redemption (code bound to other-app); the gateway reports an IdP error
    await rejects(completeLogin(ctx, p(), flow, await browse(swapped.toString(), "alice")), "idp_error");
  }));

test("cross-check: a replayed authorization code is refused by the server and by the gateway", { skip }, () =>
  withProvider(async (idp, p) => {
    const { url, flow } = await startLogin(ctx, p(), REDIRECT);
    const q = await browse(url, "alice");
    assert.equal((await completeLogin(ctx, p(), flow, q)).tenantId, TENANT);
    await rejects(completeLogin(ctx, p(), flow, q), "idp_error");
  }));

test("cross-check: an expired id_token is refused", { skip }, () =>
  withProvider(async (idp, p) => {
    const { url, flow } = await startLogin(ctx, p(), REDIRECT);
    const q = await browse(url, "alice");
    const late = { ...ctx, now: () => Date.now() + 120_000 }; // id_token ttl is 1 s; the gateway allows 60 s of skew
    await rejects(completeLogin(late, p(), flow, q), "token_expired");
  }));

test("cross-check: a different tenant's issuer is refused at discovery", { skip }, () =>
  withProvider(async (idp) => {
    // the server's discovery document names TENANT; a gateway configured for another tenant at the same URL refuses it
    const wrong = entra({ clientId: "cid", tenantId: OTHER_TENANT, issuer: `${idp.base}/${TENANT}/v2.0/` });
    await rejects(startLogin(ctx, wrong, REDIRECT), "idp_error"); // that path is not a discovery document
  }));
