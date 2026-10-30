// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { start } from "./harness/harness.mjs";

test("harness boots gateway, mock OIDC and N daemons, then stops", async () => {
  const h = await start({ daemons: 3, quiet: true });
  try {
    assert.equal(h.daemons.length, 3);
    for (const d of h.daemons) assert.equal(d.child.exitCode, null, `${d.name} running`);
    assert.equal((await fetch(`${h.gatewayUrl}/healthz`)).status, 200);

    const cfg = await (await fetch(`${h.oidcIssuer}/.well-known/openid-configuration`)).json();
    assert.equal(cfg.issuer, h.oidcIssuer);
    const { keys } = await (await fetch(cfg.jwks_uri)).json();
    assert.equal(keys.length, 1);

    // Authorization-code flow yields an id_token for the requested user.
    const auth = new URL(cfg.authorization_endpoint);
    auth.search = new URLSearchParams({
      client_id: "parley",
      redirect_uri: "http://127.0.0.1/cb",
      state: "s1",
      nonce: "n1",
      login_hint: "bob@example.test",
    });
    const r = await fetch(auth, { redirect: "manual" });
    assert.equal(r.status, 302);
    const back = new URL(r.headers.get("location"));
    assert.equal(back.searchParams.get("state"), "s1");
    const code = back.searchParams.get("code");
    const tokenReq = () =>
      fetch(cfg.token_endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code }),
      });
    const tok = await (await tokenReq()).json();
    const claims = JSON.parse(Buffer.from(tok.id_token.split(".")[1], "base64url"));
    assert.equal(claims.email, "bob@example.test");
    assert.equal(claims.nonce, "n1");
    assert.equal(claims.iss, h.oidcIssuer);
    assert.equal((await tokenReq()).status, 400, "code is single use");
  } finally {
    await h.stop();
  }
  for (const d of h.daemons) assert.notEqual(d.child.exitCode ?? d.child.signalCode, null);
  await assert.rejects(fetch(`${h.gatewayUrl}/healthz`));
});
