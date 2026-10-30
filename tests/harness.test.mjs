// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey, createVerify } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { start } from "./harness/harness.mjs";
import { startMockOidc } from "./harness/oidc.mjs";

// Mirrors `make test-go`: skip locally without Go, fail under CI.
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const needsGo = haveGo ? {} : { skip: process.env.CI ? false : "go not installed" };

const REDIRECT = "http://127.0.0.1/cb";

async function authorize(issuer, params = {}) {
  const auth = new URL(`${issuer}/authorize`);
  auth.search = new URLSearchParams({
    client_id: "parley",
    redirect_uri: REDIRECT,
    state: "s1",
    nonce: "n1",
    ...params,
  });
  return fetch(auth, { redirect: "manual" });
}

const exchange = (issuer, form) =>
  fetch(`${issuer}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form),
  });

const codeFrom = (r) => new URL(r.headers.get("location")).searchParams.get("code");

async function withOidc(fn) {
  const oidc = await startMockOidc();
  try {
    await fn(oidc.issuer);
  } finally {
    await oidc.close();
  }
}

test("oidc: authorization-code flow yields a signed id_token", () =>
  withOidc(async (issuer) => {
    const cfg = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
    assert.equal(cfg.issuer, issuer);
    const { keys } = await (await fetch(cfg.jwks_uri)).json();
    assert.equal(keys.length, 1);

    const r = await authorize(issuer, { login_hint: "bob@example.test" });
    assert.equal(r.status, 302);
    assert.equal(new URL(r.headers.get("location")).searchParams.get("state"), "s1");
    const code = codeFrom(r);
    const tok = await (await exchange(issuer, { grant_type: "authorization_code", code })).json();

    const [head, body, sig] = tok.id_token.split(".");
    const header = JSON.parse(Buffer.from(head, "base64url"));
    assert.equal(header.alg, "RS256");
    assert.equal(header.kid, keys[0].kid);
    const verify = createVerify("RSA-SHA256").update(`${head}.${body}`);
    assert.ok(verify.verify(createPublicKey({ key: keys[0], format: "jwk" }), Buffer.from(sig, "base64url")));

    const claims = JSON.parse(Buffer.from(body, "base64url"));
    assert.equal(claims.email, "bob@example.test");
    assert.equal(claims.nonce, "n1");
    assert.equal(claims.iss, issuer);
    assert.equal(claims.aud, "parley");
    assert.ok(claims.exp > Date.now() / 1000);

    const again = await exchange(issuer, { grant_type: "authorization_code", code });
    assert.equal(again.status, 400, "code is single use");
  }));

test("oidc: bad or missing redirect_uri is rejected and the server survives", () =>
  withOidc(async (issuer) => {
    for (const redirect_uri of ["not a url", ""]) {
      assert.equal((await authorize(issuer, { redirect_uri })).status, 400);
    }
    const noParam = new URL(`${issuer}/authorize`);
    assert.equal((await fetch(noParam, { redirect: "manual" })).status, 400);
    assert.equal((await authorize(issuer)).status, 302, "still serving");
  }));

test("oidc: token endpoint rejects unknown codes and other grant types", () =>
  withOidc(async (issuer) => {
    assert.equal((await exchange(issuer, { grant_type: "authorization_code", code: "nope" })).status, 400);
    const code = codeFrom(await authorize(issuer));
    const r = await exchange(issuer, { grant_type: "password", code });
    assert.equal(r.status, 400);
    assert.equal((await r.json()).error, "unsupported_grant_type");
  }));

test("oidc: PKCE S256 is enforced when a challenge is sent", () =>
  withOidc(async (issuer) => {
    const verifier = "v".repeat(48);
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const pkce = { code_challenge: challenge, code_challenge_method: "S256" };
    const grant = { grant_type: "authorization_code" };

    const bad = codeFrom(await authorize(issuer, pkce));
    assert.equal((await exchange(issuer, { ...grant, code: bad, code_verifier: "wrong" })).status, 400);

    const good = codeFrom(await authorize(issuer, pkce));
    assert.equal((await exchange(issuer, { ...grant, code: good, code_verifier: verifier })).status, 200);

    assert.equal((await authorize(issuer, { code_challenge: challenge })).status, 400, "plain not supported");
  }));

test("harness boots gateway, mock OIDC and N daemons, then stops", needsGo, async () => {
  const h = await start({ daemons: 3, quiet: true });
  try {
    assert.equal(h.daemons.length, 3);
    for (const d of h.daemons) assert.equal(d.child.exitCode, null, `${d.name} running`);
    assert.equal((await fetch(`${h.gatewayUrl}/healthz`)).status, 200);
    assert.equal((await fetch(`${h.oidcIssuer}/jwks`)).status, 200);
  } finally {
    await h.stop();
    await h.stop(); // idempotent
  }
  for (const d of h.daemons) assert.notEqual(d.child.exitCode ?? d.child.signalCode, null);
  await assert.rejects(fetch(`${h.gatewayUrl}/healthz`));
});

test("harness rejects invalid daemon counts", async () => {
  for (const daemons of [0, -1, 1.5, NaN]) {
    await assert.rejects(start({ daemons, quiet: true }), /daemons must be an integer/);
  }
});

test("harness fails fast and cleans up when the gateway command dies", async () => {
  const prev = process.env.PARLEY_GATEWAY_CMD;
  process.env.PARLEY_GATEWAY_CMD = 'node -e "process.exit(3)"';
  try {
    await assert.rejects(start({ daemons: 1, quiet: true }), /gateway exited unexpectedly/);
  } finally {
    if (prev === undefined) delete process.env.PARLEY_GATEWAY_CMD;
    else process.env.PARLEY_GATEWAY_CMD = prev;
  }
});

test("harness honours PARLEY_GATEWAY_CMD and stops its whole process tree", needsGo, async () => {
  const prev = process.env.PARLEY_GATEWAY_CMD;
  const stub = fileURLToPath(new URL("./harness/stub-gateway.mjs", import.meta.url));
  // The shell wrapper makes the real server a grandchild of the spawned process.
  process.env.PARLEY_GATEWAY_CMD = `node "${stub}"; true`;
  let h;
  try {
    h = await start({ daemons: 1, quiet: true });
    assert.equal((await fetch(`${h.gatewayUrl}/healthz`)).status, 200);
  } finally {
    if (prev === undefined) delete process.env.PARLEY_GATEWAY_CMD;
    else process.env.PARLEY_GATEWAY_CMD = prev;
    await h?.stop();
  }
  await assert.rejects(fetch(`${h.gatewayUrl}/healthz`), "grandchild released the port");
});
