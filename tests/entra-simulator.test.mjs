// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// The Entra profile of the mock IdP against the fixtures recorded from Microsoft's published reference
// (tests/fixtures/entra), so the simulator cannot drift from what Microsoft documents.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { startMockOidc, MULTI_TENANT } from "./harness/oidc.mjs";

const fx = (n) => JSON.parse(readFileSync(new URL(`./fixtures/entra/${n}.json`, import.meta.url), "utf8"));
const discovery = fx("discovery");
const claimsFx = fx("claims");
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const claimsOf = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());
async function login(idp, seg = idp.tenantId, { client = "cid", hint } = {}) {
  const u = new URL(`${idp.base}/${seg}/oauth2/v2.0/authorize`);
  u.search = new URLSearchParams({ client_id: client, redirect_uri: "http://127.0.0.1/cb", nonce: "n1", ...(hint && { login_hint: hint }) });
  const r = await fetch(u, { redirect: "manual" });
  const code = new URL(r.headers.get("location")).searchParams.get("code");
  return { code, redeem: () => fetch(`${idp.base}/${seg}/oauth2/v2.0/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: client }) }) };
}
async function withIdp(fn, o) {
  const idp = await startMockOidc({ profile: "entra", ...o });
  try {
    await fn(idp);
  } finally {
    await idp.close();
  }
}

test("discovery: tenant issuer, endpoints and key set match Microsoft's document", () =>
  withIdp(async (idp) => {
    assert.equal(idp.issuer, `${idp.base}/${idp.tenantId}/v2.0`);
    const doc = await (await fetch(`${idp.issuer}/.well-known/openid-configuration`)).json();
    assert.deepEqual(Object.keys(doc).sort(), [...discovery.keys].sort());
    assert.equal(doc.issuer, idp.issuer);
    assert.equal(doc.authorization_endpoint, `${idp.base}/${idp.tenantId}${discovery.paths.authorization_endpoint.replace("/{tenant}", "")}`);
    assert.equal(doc.token_endpoint, `${idp.base}/${idp.tenantId}${discovery.paths.token_endpoint.replace("/{tenant}", "")}`);
    assert.equal(doc.jwks_uri, `${idp.base}/${idp.tenantId}${discovery.paths.jwks_uri.replace("/{tenant}", "")}`);
    assert.deepEqual(doc.subject_types_supported, discovery.subject_types_supported);
    assert.deepEqual(doc.id_token_signing_alg_values_supported, discovery.id_token_signing_alg_values_supported);
    assert.equal((await fetch(doc.jwks_uri)).status, 200);
    // another tenant's path is not this tenant
    const other = await fetch(`${idp.base}/${"0".repeat(8)}-0000-4000-8000-${"0".repeat(12)}/v2.0/.well-known/openid-configuration`);
    assert.equal(other.status, 400);
    assert.match((await other.json()).error_description, /^AADSTS90002/);
    assert.equal((await fetch(`${idp.base}/nope`)).status, 404);
  }));

test("discovery: multi-tenant endpoints advertise the literal {tenantid} issuer", () =>
  withIdp(async (idp) => {
    for (const seg of MULTI_TENANT) {
      const doc = await (await fetch(`${idp.base}/${seg}/v2.0/.well-known/openid-configuration`)).json();
      assert.equal(doc.issuer, discovery.multi_tenant_issuer.replace("{base}", idp.base));
      assert.equal(doc.jwks_uri, `${idp.base}/${seg}/discovery/v2.0/keys`);
    }
  }));

test("id_token: carries the documented v2.0 claims and none of the Google ones", () =>
  withIdp(async (idp) => {
    const body = await (await (await login(idp, undefined, { hint: "Bob@Corp.test" })).redeem()).json();
    const c = claimsOf(body.id_token);
    assert.deepEqual(Object.keys(c).filter((k) => k !== "nonce").sort(), [...claimsFx.v2_default].sort());
    for (const k of claimsFx.never_present) assert.equal(k in c, false, k);
    assert.equal(c.ver, claimsFx.formats.ver);
    assert.equal(c.iss, `${idp.base}/${c.tid}/v2.0`);
    assert.equal(c.tid, idp.tenantId);
    assert.match(c.tid, GUID);
    assert.match(c.oid, GUID);
    assert.equal(c.preferred_username, "Bob@Corp.test");
    assert.equal(c.aud, "cid");
    assert.equal(c.nonce, "n1");
    assert.notEqual(c.sub, c.oid);
    assert.equal(JSON.parse(Buffer.from(body.id_token.split(".")[0], "base64url")).typ, "JWT");
  }));

test("id_token: sub is pairwise per application, oid is the same, both differ per tenant", () =>
  withIdp(async (idp) => {
    const get = async (client, seg) => claimsOf((await (await (await login(idp, seg, { client })).redeem()).json()).id_token);
    const a = await get("app-a");
    const b = await get("app-b");
    assert.notEqual(a.sub, b.sub);
    assert.equal(a.oid, b.oid);
    assert.equal((await get("app-a")).sub, a.sub);
    idp.tweak.tenant = "22222222-2222-4222-8222-222222222222";
    const other = await get("app-a", "organizations");
    assert.equal(other.tid, idp.tweak.tenant);
    assert.equal(other.iss, `${idp.base}/${other.tid}/v2.0`);
    assert.notEqual(other.oid, a.oid);
    assert.notEqual(other.sub, a.sub);
  }));

test("id_token: email and overage appear only when asked for, shaped as documented", () =>
  withIdp(async (idp) => {
    idp.tweak.emailClaim = "mallory@evil.test";
    idp.tweak.overage = true;
    const c = claimsOf((await (await (await login(idp)).redeem()).json()).id_token);
    assert.equal(c.email, "mallory@evil.test");
    assert.deepEqual(c._claim_names, claimsFx.overage._claim_names);
    assert.equal(c._claim_sources.src1.endpoint, claimsFx.overage._claim_sources.src1.endpoint.replace("{oid}", c.oid));
    assert.equal("groups" in c, false);
  }));

test("token endpoint: a replayed code gets AADSTS54005, an unknown code a plain invalid_grant", () =>
  withIdp(async (idp) => {
    const l = await login(idp);
    assert.equal((await l.redeem()).status, 200);
    const again = await l.redeem();
    assert.equal(again.status, 400);
    const e = await again.json();
    assert.equal(e.error, "invalid_grant");
    assert.deepEqual(e.error_codes, [54005]);
    assert.match(e.error_description, /^AADSTS54005: OAuth2 Authorization code was already redeemed/);
    const unknown = { ...l, code: "bogus" };
    const r = await fetch(`${idp.base}/${idp.tenantId}/oauth2/v2.0/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code: unknown.code }) });
    assert.deepEqual(await r.json(), { error: "invalid_grant" });
  }));

test("key rotation: new kid signs, old key stays in the set until retired", () =>
  withIdp(async (idp) => {
    const kids = async () => (await (await fetch(`${idp.issuer}/../discovery/v2.0/keys`)).json()).keys.map((k) => k.kid);
    const [k0] = await kids();
    idp.rotateKey();
    const both = await kids();
    assert.equal(both.length, 2);
    assert.ok(both.includes(k0));
    const head = JSON.parse(Buffer.from((await (await (await login(idp)).redeem()).json()).id_token.split(".")[0], "base64url"));
    assert.equal(head.kid, both[0]);
    idp.rotateKey({ retire: true });
    assert.equal((await kids()).length, 1);
    assert.ok(!(await kids()).includes(k0));
  }));
