// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Gateway OIDC login against the Entra-shaped mock IdP (T111). The generic mock covers the protocol; this file
// covers what is particular to Microsoft Entra v2.0: tenant-scoped issuers, tid and oid, preferred_username,
// the multi-tenant endpoints, key rollover, AADSTS errors and the groups overage pointer.
// The same scenarios run against an independent OIDC server in tests/entra-crosscheck.test.mjs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { startMockOidc, MULTI_TENANT } from "./harness/oidc.mjs";
import { completeLogin, entra, OidcError, startLogin } from "../gateway/src/oidc.ts";
import { handle } from "../gateway/src/auth.ts";
import { pending } from "./harness/pending.mjs";

const ctx = { flowSecret: "test-secret" };
const REDIRECT = "http://127.0.0.1:8787/auth/entra/callback";
const TENANT = "5f4d3c2b-1a09-4e8d-9c7b-6a5f4e3d2c1b";
const OTHER_TENANT = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const PERSONAL = "9188040d-6c67-4c5b-b112-36a304b66dad"; // Microsoft's personal-account tenant

async function withIdp(fn, o = {}) {
  const idp = await startMockOidc({ profile: "entra", tenantId: TENANT, ...o });
  try {
    await fn(idp, entra({ clientId: "cid", tenantId: TENANT, issuer: idp.issuer }));
  } finally {
    await idp.close();
  }
}
const browse = async (url) => {
  const r = await fetch(url, { redirect: "manual" });
  assert.equal(r.status, 302);
  return new URL(r.headers.get("location")).searchParams;
};
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof OidcError && e.code === code, code);
const login = async (p, c = ctx, hint) => {
  const { url, flow } = await startLogin(c, p, REDIRECT, hint);
  return completeLogin(c, p, flow, await browse(url));
};
const attempt = async (p, c = ctx) => {
  const { url, flow } = await startLogin(c, p, REDIRECT);
  return [flow, await browse(url)];
};
const claimsOf = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());

test("v2.0 discovery and the tenant issuer: login completes and the identity is bound to tid and the pairwise sub", () =>
  withIdp(async (idp, p) => {
    assert.equal(p.issuer, `${idp.base}/${TENANT}/v2.0`);
    const { url, flow } = await startLogin(ctx, p, REDIRECT, "Alice@Corp.test");
    const u = new URL(url);
    assert.equal(u.pathname, `/${TENANT}/oauth2/v2.0/authorize`);
    assert.equal(u.searchParams.get("scope"), "openid email profile");
    assert.equal(u.searchParams.get("code_challenge_method"), "S256");
    let token;
    const spy = async (a, i) => {
      const res = await fetch(a, i);
      if (String(a).endsWith("/token")) token = (await res.clone().json()).id_token;
      return res;
    };
    const id = await completeLogin({ ...ctx, fetch: spy }, p, flow, await browse(url));
    const c = claimsOf(token);
    assert.deepEqual(id, { provider: "entra", issuer: p.issuer, sub: c.sub, email: "alice@corp.test", tenantId: TENANT });
    assert.notEqual(id.sub, c.oid); // the identity key is the pairwise sub, not the cross-app oid
    assert.equal(c.tid, TENANT);
    assert.equal(c.ver, "2.0");
  }));

test("the gateway's default Entra issuer has the documented shape", () => {
  assert.equal(entra({ clientId: "c", tenantId: TENANT }).issuer, `https://login.microsoftonline.com/${TENANT}/v2.0`);
});

test("preferred_username alone identifies the user; the id_token carries no email claim or email_verified", () =>
  withIdp(async (idp, p) => {
    const id = await login(p, ctx, "Bob@Corp.test");
    assert.equal(id.email, "bob@corp.test");
    // the Entra profile never asserts a verified email, so only tid vouches for it
    assert.equal(p.requireVerifiedEmail, false);
  }));

test("an unverified email claim, whether equal to preferred_username or not, is accepted only inside the right tenant", () =>
  withIdp(async (idp, p) => {
    idp.tweak.emailClaim = "Alice@Corp.test";
    assert.equal((await login(p)).email, "alice@corp.test");
    // A different tenant's user claiming our user's email: refused by tid, whatever the email says.
    idp.tweak.emailClaim = "alice@example.test";
    idp.tweak.claims = { tid: OTHER_TENANT };
    await rejects(login(p), "tenant_mismatch");
  }));

pending(
  "Entra identity is not taken from a mutable, unasserted email claim when it differs from preferred_username",
  "spec001-entra-identity-claim",
  "today the gateway reads `email` before `preferred_username` for Entra; Microsoft documents both as mutable and `email` as 'not guaranteed to be correct'. Decide which claim (or xms_edov, or oid with an admin-bound mapping) identifies the user, then assert a differing email claim cannot select another Parley user",
);

test("wrong tenant: a foreign tid, a foreign or personal-account issuer, and a missing tid are all refused", () =>
  withIdp(async (idp, p) => {
    for (const [code, claims] of [
      ["tenant_mismatch", { tid: OTHER_TENANT }],
      ["tenant_mismatch", { tid: undefined }],
      ["issuer_mismatch", { iss: `${idp.base}/${OTHER_TENANT}/v2.0`, tid: OTHER_TENANT }],
      ["issuer_mismatch", { iss: `${idp.base}/${PERSONAL}/v2.0`, tid: PERSONAL }],
      ["issuer_mismatch", { iss: `${idp.base}/${TENANT}/`, tid: TENANT }],
    ]) {
      idp.tweak.claims = claims;
      const [flow, q] = await attempt(p);
      await rejects(completeLogin(ctx, p, flow, q), code);
    }
    idp.tweak.claims = {};
    assert.equal((await login(p)).tenantId, TENANT);
  }));

test("multi-tenant endpoints (common, organizations, consumers) are refused: their issuer is the literal {tenantid}", async () => {
  for (const seg of MULTI_TENANT) {
    await withIdp(async (idp) => {
      const p = entra({ clientId: "cid", tenantId: seg, issuer: `${idp.base}/${seg}/v2.0` });
      await rejects(startLogin(ctx, p, REDIRECT), "issuer_mismatch");
      // pointing the issuer at the discovery URL's own advertised template does not help: nothing signs with it
      const tpl = entra({ clientId: "cid", tenantId: seg, issuer: `${idp.base}/{tenantid}/v2.0` });
      await assert.rejects(startLogin(ctx, tpl, REDIRECT), (e) => e instanceof OidcError);
    });
  }
});

test("worker route: ENTRA_TENANT_ID=common fails closed at login, with no redirect to the IdP", () =>
  withIdp(async (idp) => {
    const env = { FLOW_SECRET: "s", ENTRA_CLIENT_ID: "cid", ENTRA_TENANT_ID: "common", ENTRA_ISSUER: `${idp.base}/common/v2.0` };
    const res = await handle(new Request("http://gw.test/auth/entra/login"), env);
    assert.equal(res.status, 401);
    assert.deepEqual(await res.json(), { error: "issuer_mismatch" });
    assert.equal(res.headers.get("location"), null);
    assert.equal(res.headers.get("set-cookie"), null);
  }));

test("worker route: Entra login and callback end to end", () =>
  withIdp(async (idp) => {
    const env = { FLOW_SECRET: "s", ENTRA_CLIENT_ID: "cid", ENTRA_TENANT_ID: TENANT, ENTRA_ISSUER: idp.issuer };
    const l = await handle(new Request("http://gw.test/auth/entra/login"), env);
    assert.equal(l.status, 302);
    const q = await browse(l.headers.get("location"));
    const cb = await handle(new Request(`http://gw.test/auth/entra/callback?${q}`, { headers: { cookie: l.headers.get("set-cookie").split(";")[0] } }), env);
    assert.equal(cb.status, 200);
    const id = await cb.json();
    assert.equal(id.provider, "entra");
    assert.equal(id.tenantId, TENANT);
  }));

test("key rotation: an unknown kid causes one JWKS refetch and the login succeeds; retired keys are gone", () =>
  withIdp(async (idp, p) => {
    let hits = 0;
    const c = { ...ctx, fetch: (u, i) => (String(u).endsWith("/discovery/v2.0/keys") && hits++, fetch(u, i)) };
    await login(p, c);
    await login(p, c);
    assert.equal(hits, 1, "second login uses the cached key set");
    idp.rotateKey();
    assert.equal((await login(p, c)).tenantId, TENANT);
    assert.equal(hits, 2, "kid miss, then one refetch");
    await login(p, c);
    assert.equal(hits, 2);
    idp.rotateKey({ retire: true });
    assert.equal((await login(p, c)).tenantId, TENANT);
    assert.equal(hits, 3);
  }));

test("key rotation: a kid the IdP never published is refused after exactly one refetch", () =>
  withIdp(async (idp, p) => {
    let hits = 0;
    const forged = async (u, i) => {
      String(u).endsWith("/discovery/v2.0/keys") && hits++;
      const res = await fetch(u, i);
      if (!String(u).endsWith("/token")) return res;
      const body = await res.json();
      const [h, ...rest] = body.id_token.split(".");
      const head = { ...JSON.parse(Buffer.from(h, "base64url")), kid: "not-published" };
      return Response.json({ ...body, id_token: [Buffer.from(JSON.stringify(head)).toString("base64url"), ...rest].join(".") });
    };
    const [flow, q] = await attempt(p);
    await rejects(completeLogin({ ...ctx, fetch: forged }, p, flow, q), "bad_token");
    assert.equal(hits, 1);
  }));

test("a token signed by a key that is not the IdP's is refused", () =>
  withIdp(async (idp, p) => {
    idp.tweak.badSignature = true;
    const [flow, q] = await attempt(p);
    await rejects(completeLogin(ctx, p, flow, q), "bad_signature");
  }));

test("expired and wrong-audience tokens are refused", () =>
  withIdp(async (idp, p) => {
    const now = Math.floor(Date.now() / 1000);
    for (const [code, claims] of [
      ["token_expired", { exp: now - 3600, iat: now - 7200, nbf: now - 7200 }],
      ["audience_mismatch", { aud: "00000000-0000-4000-8000-000000000000" }],
      ["audience_mismatch", { aud: ["cid", "other-app"], azp: "other-app" }],
    ]) {
      idp.tweak.claims = claims;
      const [flow, q] = await attempt(p);
      await rejects(completeLogin(ctx, p, flow, q), code);
    }
    // sign-in through another application registered in the same tenant: the IdP issues aud=that client, which this
    // gateway must not accept
    idp.tweak.claims = {};
    const { url, flow } = await startLogin(ctx, p, REDIRECT);
    const swapped = new URL(url);
    swapped.searchParams.set("client_id", "other-app");
    await rejects(completeLogin(ctx, p, flow, await browse(swapped)), "audience_mismatch");
  }));

test("a replayed authorization code is refused (AADSTS54005) and the IdP's text never reaches the caller", () =>
  withIdp(async (idp, p) => {
    const [flow, q] = await attempt(p);
    assert.equal((await completeLogin(ctx, p, flow, q)).tenantId, TENANT);
    await assert.rejects(completeLogin(ctx, p, flow, q), (e) => {
      assert.ok(e instanceof OidcError);
      assert.equal(e.code, "idp_error");
      assert.doesNotMatch(e.message, /AADSTS|redeemed/);
      return true;
    });
  }));

test("groups overage: login ignores the pointer, never calls the endpoint, and carries no group data", () =>
  withIdp(async (idp, p) => {
    idp.tweak.overage = true;
    const calls = [];
    const real = globalThis.fetch;
    globalThis.fetch = (u, i) => (calls.push(String(u)), real(u, i));
    let id;
    try {
      id = await login(p);
    } finally {
      globalThis.fetch = real;
    }
    assert.ok(calls.length > 0);
    for (const u of calls) assert.ok(u.startsWith(idp.base), `unexpected request to ${u}`);
    assert.deepEqual(Object.keys(id).sort(), ["email", "issuer", "provider", "sub", "tenantId"]);
  }));

test("an unknown tenant in the issuer path is an IdP error, not a login", () =>
  withIdp(async (idp) => {
    const p = entra({ clientId: "cid", tenantId: OTHER_TENANT, issuer: `${idp.base}/${OTHER_TENANT}/v2.0` });
    await rejects(startLogin(ctx, p, REDIRECT), "idp_error");
  }));
