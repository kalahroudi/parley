// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { startMockOidc } from "./harness/oidc.mjs";
import { completeLogin, entra, google, OidcError, startLogin } from "../gateway/src/oidc.ts";
import { handle, providers } from "../gateway/src/auth.ts";

const ctx = { flowSecret: "test-secret" };
const REDIRECT = "http://127.0.0.1:8787/auth/x/callback";

async function withIdp(fn) {
  const idp = await startMockOidc();
  try {
    await fn(idp);
  } finally {
    await idp.close();
  }
}

// Follows the authorize redirect the way a browser would and returns the
// callback query the gateway would receive.
async function browse(url) {
  const r = await fetch(url, { redirect: "manual" });
  assert.equal(r.status, 302);
  return new URL(r.headers.get("location")).searchParams;
}

const rejects = (p, code) => assert.rejects(p, (e) => e instanceof OidcError && e.code === code, code);

for (const [name, make] of [
  ["google", (issuer) => google({ clientId: "cid", issuer })],
  ["entra", (issuer) => entra({ clientId: "cid", tenantId: "t1", issuer })],
]) {
  test(`${name}: login completes against the mock IdP`, () =>
    withIdp(async (idp) => {
      idp.tweak.claims = { tid: "t1" };
      const p = make(idp.issuer);
      const { url, flow } = await startLogin(ctx, p, REDIRECT);
      const u = new URL(url);
      assert.equal(u.searchParams.get("code_challenge_method"), "S256");
      assert.equal(u.searchParams.get("client_id"), "cid");
      const id = await completeLogin(ctx, p, flow, await browse(url));
      assert.equal(id.email, "alice@example.test");
      assert.equal(id.provider, name);
      assert.equal(id.issuer, idp.issuer);
    }));
}

test("presets point at the real endpoints", () => {
  assert.equal(google({ clientId: "c" }).issuer, "https://accounts.google.com");
  assert.equal(entra({ clientId: "c", tenantId: "t" }).issuer, "https://login.microsoftonline.com/t/v2.0");
});

test("flow: state mismatch, tampering, other provider, wrong secret, expiry, missing cookie", () =>
  withIdp(async (idp) => {
    const p = google({ clientId: "cid", issuer: idp.issuer });
    const { url, flow } = await startLogin(ctx, p, REDIRECT);
    const q = await browse(url);
    const bad = new URLSearchParams(q);
    bad.set("state", "other");
    await rejects(completeLogin(ctx, p, flow, bad), "state_mismatch");
    await rejects(completeLogin(ctx, p, flow, new URLSearchParams({ code: q.get("code") })), "state_mismatch");
    await rejects(completeLogin(ctx, p, undefined, q), "bad_flow");
    await rejects(completeLogin(ctx, p, flow.slice(0, -2) + "AA", q), "bad_flow");
    await rejects(completeLogin(ctx, p, "garbage", q), "bad_flow");
    await rejects(completeLogin(ctx, p, `${flow}.x`, q), "bad_flow");
    await rejects(completeLogin({ flowSecret: "other" }, p, flow, q), "bad_flow");
    const asEntra = entra({ clientId: "cid", tenantId: "t1", issuer: idp.issuer });
    await rejects(completeLogin(ctx, asEntra, flow, q), "bad_flow");
    const late = { ...ctx, now: () => Date.now() + 11 * 60_000 };
    await rejects(completeLogin(late, p, flow, q), "bad_flow");
    // none of the rejected attempts reached the IdP, so the code still works
    assert.equal((await completeLogin(ctx, p, flow, q)).email, "alice@example.test");
  }));

test("idp error response and missing code", () =>
  withIdp(async (idp) => {
    const p = google({ clientId: "cid", issuer: idp.issuer });
    const { url, flow } = await startLogin(ctx, p, REDIRECT);
    const state = new URL(url).searchParams.get("state");
    await rejects(completeLogin(ctx, p, flow, new URLSearchParams({ state, error: "access_denied" })), "idp_denied");
    await rejects(completeLogin(ctx, p, flow, new URLSearchParams({ state })), "bad_request");
  }));

test("id_token validation rejects forged or mismatched tokens", () =>
  withIdp(async (idp) => {
    const cases = [
      ["bad_signature", { badSignature: true }],
      ["issuer_mismatch", { claims: { iss: "http://evil.test" } }],
      ["audience_mismatch", { claims: { aud: "someone-else" } }],
      ["token_expired", { claims: { exp: 1000 } }],
      ["nonce_mismatch", { claims: { nonce: "replayed" } }],
      ["email_unverified", { claims: { email_verified: false } }],
      ["no_email", { claims: { email: "" } }],
    ];
    for (const [code, t] of cases) {
      idp.tweak.claims = t.claims ?? {};
      idp.tweak.badSignature = !!t.badSignature;
      const p = google({ clientId: "cid", issuer: idp.issuer });
      const { url, flow } = await startLogin(ctx, p, REDIRECT);
      await rejects(completeLogin(ctx, p, flow, await browse(url)), code);
    }
  }));

test("entra: tenant must match; google: hosted domain must match", () =>
  withIdp(async (idp) => {
    idp.tweak.claims = { tid: "other-tenant" };
    const e = entra({ clientId: "cid", tenantId: "t1", issuer: idp.issuer });
    let r = await startLogin(ctx, e, REDIRECT);
    await rejects(completeLogin(ctx, e, r.flow, await browse(r.url)), "tenant_mismatch");

    idp.tweak.claims = { hd: "evil.test" };
    const g = google({ clientId: "cid", issuer: idp.issuer, hostedDomain: "corp.test" });
    r = await startLogin(ctx, g, REDIRECT);
    assert.equal(new URL(r.url).searchParams.get("hd"), "corp.test");
    await rejects(completeLogin(ctx, g, r.flow, await browse(r.url)), "tenant_mismatch");

    idp.tweak.claims = { hd: "corp.test" };
    r = await startLogin(ctx, g, REDIRECT);
    assert.equal((await completeLogin(ctx, g, r.flow, await browse(r.url))).email, "alice@example.test");
  }));

test("entra: falls back to preferred_username and lowercases", () =>
  withIdp(async (idp) => {
    idp.tweak.claims = { tid: "t1", email: undefined, preferred_username: "Bob@Example.TEST" };
    const p = entra({ clientId: "cid", tenantId: "t1", issuer: idp.issuer });
    const { url, flow } = await startLogin(ctx, p, REDIRECT);
    assert.equal((await completeLogin(ctx, p, flow, await browse(url))).email, "bob@example.test");
  }));

test("discovery issuer mismatch is refused", () =>
  withIdp(async (idp) => {
    const p = google({ clientId: "cid", issuer: idp.issuer });
    const f = async (u, i) => Response.json({ ...(await (await fetch(u, i)).json()), issuer: "http://evil.test" });
    await rejects(startLogin({ ...ctx, fetch: f }, p, REDIRECT), "issuer_mismatch");
  }));

test("idp failures surface as idp_error", () =>
  withIdp(async (idp) => {
    const p = google({ clientId: "cid", issuer: idp.issuer });
    const { url, flow } = await startLogin(ctx, p, REDIRECT);
    const state = new URL(url).searchParams.get("state");
    await rejects(completeLogin(ctx, p, flow, new URLSearchParams({ state, code: "bogus" })), "idp_error");
  }));

test("JWKS is cached across logins", () =>
  withIdp(async (idp) => {
    const p = google({ clientId: "cid", issuer: idp.issuer });
    let jwksHits = 0;
    const c = { ...ctx, fetch: (u, i) => (String(u).endsWith("/jwks") && jwksHits++, fetch(u, i)) };
    for (let i = 0; i < 2; i++) {
      const { url, flow } = await startLogin(c, p, REDIRECT);
      await completeLogin(c, p, flow, await browse(url));
    }
    assert.equal(jwksHits, 1);
  }));

test("worker routes: login redirects, callback returns identity, errors are generic", () =>
  withIdp(async (idp) => {
    idp.tweak.claims = { tid: "t1" };
    const env = {
      FLOW_SECRET: "s",
      GOOGLE_CLIENT_ID: "cid",
      GOOGLE_ISSUER: idp.issuer,
      ENTRA_CLIENT_ID: "cid",
      ENTRA_TENANT_ID: "t1",
      ENTRA_ISSUER: idp.issuer,
    };
    assert.deepEqual(Object.keys(providers(env)).sort(), ["entra", "google"]);
    for (const name of ["google", "entra"]) {
      const login = await handle(new Request(`http://gw.test/auth/${name}/login`), env);
      assert.equal(login.status, 302);
      const cookie = login.headers.get("set-cookie");
      assert.match(cookie, /HttpOnly/);
      assert.match(cookie, /SameSite=Lax/);
      const q = await browse(login.headers.get("location"));
      const cb = await handle(
        new Request(`http://gw.test/auth/${name}/callback?${q}`, { headers: { cookie: cookie.split(";")[0] } }),
        env,
      );
      assert.equal(cb.status, 200);
      assert.equal((await cb.json()).provider, name);
      assert.match(cb.headers.get("set-cookie"), /Max-Age=0/);

      const noCookie = await handle(new Request(`http://gw.test/auth/${name}/callback?${q}`), env);
      assert.equal(noCookie.status, 401);
      assert.deepEqual(await noCookie.json(), { error: "bad_flow" });
    }
    assert.equal((await handle(new Request("http://gw.test/auth/okta/login"), env)).status, 404);
    assert.equal((await handle(new Request("http://gw.test/auth/google/login"), { FLOW_SECRET: "s" })).status, 404);
    assert.equal((await handle(new Request("http://gw.test/auth/google/login", { method: "POST" }), env)).status, 404);
    assert.equal((await handle(new Request("http://gw.test/healthz"), env)).status, 200);

    const idpDown = await handle(new Request("http://gw.test/auth/google/login"), { ...env, GOOGLE_CLIENT_ID: "uncached" }, async () => new Response("x", { status: 503 }));
    assert.equal(idpDown.status, 502);
    const boom = await handle(new Request("http://gw.test/auth/entra/login"), { ...env, ENTRA_CLIENT_ID: "uncached" }, async () => {
      throw new TypeError("net");
    });
    assert.equal(boom.status, 500);
    assert.deepEqual(await boom.json(), { error: "server_error" });
  }));

test("worker routes reuse discovery and JWKS across requests with distinct env objects", () =>
  withIdp(async (idp) => {
    const hits = [];
    const f = (u, i) => (hits.push(String(u)), fetch(u, i));
    for (let i = 0; i < 2; i++) {
      // a fresh env object per request, as a Worker may provide
      const env = { FLOW_SECRET: "s", GOOGLE_CLIENT_ID: "cid", GOOGLE_ISSUER: idp.issuer };
      const login = await handle(new Request("http://gw.test/auth/google/login"), env, f);
      const q = await browse(login.headers.get("location"));
      const cookie = login.headers.get("set-cookie").split(";")[0];
      const cb = await handle(new Request(`http://gw.test/auth/google/callback?${q}`, { headers: { cookie } }), env, f);
      assert.equal(cb.status, 200);
    }
    assert.equal(hits.filter((u) => u.endsWith("/.well-known/openid-configuration")).length, 1);
    assert.equal(hits.filter((u) => u.endsWith("/jwks")).length, 1);
  }));

// Rewrites the id_token the mock IdP returns, to hit the token parser's edges.
const rewriteToken = (fn) => async (u, i) => {
  const res = await fetch(u, i);
  if (!String(u).endsWith("/token")) return res;
  const body = await res.json();
  return Response.json({ ...body, id_token: fn(body.id_token) });
};
const segs = (jwt) => jwt.split(".").slice(0, 2).map((s) => JSON.parse(Buffer.from(s, "base64url").toString()));

test("id_token parser: malformed tokens, unsupported alg, unknown key, odd claims", () =>
  withIdp(async (idp) => {
    const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const cases = [
      ["bad_token", (t) => "only.two", "segment count"],
      ["bad_token", (t) => `${t}.extra`, "extra segment"],
      ["bad_token", (t) => `!!!.${t.split(".")[1]}.${t.split(".")[2]}`, "undecodable header"],
      ["bad_token", (t) => `${Buffer.from("not json").toString("base64url")}.${t.split(".")[1]}.${t.split(".")[2]}`, "header is not JSON"],
      ["bad_token", (t) => { const [h] = segs(t); return `${enc({ ...h, alg: "none" })}.${t.split(".").slice(1).join(".")}`; }, "alg"],
      ["bad_token", (t) => { const [h] = segs(t); return `${enc({ ...h, kid: "unknown" })}.${t.split(".").slice(1).join(".")}`; }, "unknown key"],
    ];
    for (const [code, fn, what] of cases) {
      const p = google({ clientId: "cid", issuer: idp.issuer });
      const { url, flow } = await startLogin(ctx, p, REDIRECT);
      await rejects(completeLogin({ ...ctx, fetch: rewriteToken(fn) }, p, flow, await browse(url)), code);
    }
    // Claims the mock IdP can mint directly.
    const claimCases = [
      ["bad_token", { iat: Math.floor(Date.now() / 1000) + 3600 }],
      ["bad_token", { sub: "" }],
      ["audience_mismatch", { aud: ["cid", "other"], azp: "other" }],
      ["audience_mismatch", { aud: ["other"] }],
      ["token_expired", { exp: "never" }],
    ];
    for (const [code, claims] of claimCases) {
      idp.tweak.claims = claims;
      const p = google({ clientId: "cid", issuer: idp.issuer });
      const { url, flow } = await startLogin(ctx, p, REDIRECT);
      await rejects(completeLogin(ctx, p, flow, await browse(url)), code);
    }
    // An audience list that names this client and sets azp to it is fine.
    idp.tweak.claims = { aud: ["cid", "other"], azp: "cid" };
    const p = google({ clientId: "cid", issuer: idp.issuer });
    const { url, flow } = await startLogin(ctx, p, REDIRECT);
    assert.equal((await completeLogin(ctx, p, flow, await browse(url))).email, "alice@example.test");
  }));

test("flow cookie with an undecodable signature is rejected, not thrown", () =>
  withIdp(async (idp) => {
    const p = google({ clientId: "cid", issuer: idp.issuer });
    const { url, flow } = await startLogin(ctx, p, REDIRECT);
    const q = await browse(url);
    await rejects(completeLogin(ctx, p, `${flow.split(".")[0]}.!!!`, q), "bad_flow");
  }));

test("token endpoint reply without an id_token, and discovery without endpoints", () =>
  withIdp(async (idp) => {
    const p = google({ clientId: "cid", issuer: idp.issuer });
    const { url, flow } = await startLogin(ctx, p, REDIRECT);
    const noToken = async (u, i) => {
      const res = await fetch(u, i);
      return String(u).endsWith("/token") ? Response.json({ access_token: "x" }) : res;
    };
    await rejects(completeLogin({ ...ctx, fetch: noToken }, p, flow, await browse(url)), "idp_error");

    const q2 = google({ clientId: "cid", issuer: idp.issuer });
    const stripped = async (u, i) => {
      const doc = await (await fetch(u, i)).json();
      delete doc.token_endpoint;
      return Response.json(doc);
    };
    await rejects(startLogin({ ...ctx, fetch: stripped }, q2, REDIRECT), "idp_error");
  }));

test("login_hint is forwarded to the IdP and scopes differ per provider", () =>
  withIdp(async (idp) => {
    const p = entra({ clientId: "cid", tenantId: "t1", issuer: idp.issuer });
    const { url } = await startLogin(ctx, p, REDIRECT, "bob@example.test");
    assert.equal(new URL(url).searchParams.get("login_hint"), "bob@example.test");
    assert.equal(new URL(url).searchParams.get("scope"), "openid email profile");
  }));

test("callback over https sets a Secure cookie; unknown paths are 404", () =>
  withIdp(async (idp) => {
    const env = { FLOW_SECRET: "s", GOOGLE_CLIENT_ID: "cid", GOOGLE_ISSUER: idp.issuer };
    const login = await handle(new Request("https://gw.test/auth/google/login"), env);
    assert.match(login.headers.get("set-cookie"), /; Secure/);
    assert.equal((await handle(new Request("https://gw.test/other"), env)).status, 404);
    // The IdP reporting an error is relayed as a generic 401 and never as IdP text.
    const state = new URL(login.headers.get("location")).searchParams.get("state");
    const cookie = login.headers.get("set-cookie").split(";")[0];
    const cb = await handle(new Request(`https://gw.test/auth/google/callback?state=${state}&error=access_denied`, { headers: { cookie } }), env);
    assert.equal(cb.status, 401);
  }));
