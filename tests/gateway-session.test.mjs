// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T001 (dashboard spec): admin sessions end to end. The real gateway Worker runs
// under `wrangler dev` with a mock OIDC provider; a user signs in through the
// login redirect, as a browser would. Unit-level cases (expiry, caps, the
// allowlist) are in gateway/test/session.test.ts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startGateway } from "./harness/gateway.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const skip = !existsSync(join(root, "gateway", "node_modules", ".bin")) && "gateway dependencies not installed (cd gateway && npm ci)";
const needs = skip && !process.env.CI ? { skip } : {};

test("admin sessions: sign in through OIDC, cookie, CSRF, sign-out", needs, async () => {
  const gw = await startGateway({ admins: "acme:root@example.test", userDomains: "acme:example.test" });
  try {
    const post = (path, { cookie, bearer, origin, csrf, body = {} } = {}) =>
      fetch(`${gw.url}${path}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(cookie ? { cookie: `parley_session=${cookie}` } : {}),
          ...(bearer ? { authorization: bearer } : {}),
          ...(origin ? { origin } : {}),
          ...(csrf ? { "x-csrf-token": csrf } : {}),
        },
        body: JSON.stringify(body),
      });

    // No session, and the old development credentials, are refused.
    assert.equal((await post("/v1/admin/enrollments")).status, 401);
    for (const bearer of ["Bearer dev-admin:acme", "Bearer dev-user:acme:root@example.test"]) {
      assert.equal((await post("/v1/admin/enrollments", { bearer })).status, 401, bearer);
    }

    // A listed admin signs in: HttpOnly, SameSite=Strict cookie (no Secure over http), CSRF token in the body.
    const admin = await gw.signIn({ tenant: "acme", role: "admin", email: "root@example.test" });
    assert.equal(admin.status, 200);
    const cookie = admin.setCookies.find((c) => c.startsWith("parley_session="));
    assert.match(cookie, /; HttpOnly/);
    assert.match(cookie, /; SameSite=Strict/);
    assert.match(cookie, /; Max-Age=28800/);
    assert.doesNotMatch(JSON.stringify(admin.body), new RegExp(admin.token));
    assert.match(admin.csrf, /^[0-9a-f]{32}$/);

    // Cookie requests need the CSRF token and the gateway's own Origin.
    const ok = { cookie: admin.token, origin: gw.url, csrf: admin.csrf, body: { owner: "svc" } };
    assert.equal((await post("/v1/admin/enrollment-tokens", { ...ok, csrf: undefined })).status, 403);
    assert.equal((await post("/v1/admin/enrollment-tokens", { ...ok, csrf: "0".repeat(32) })).status, 403);
    assert.equal((await post("/v1/admin/enrollment-tokens", { ...ok, origin: "https://evil.example" })).status, 403);
    assert.equal((await post("/v1/admin/enrollment-tokens", ok)).status, 201);
    assert.equal((await post("/v1/session", { cookie: admin.token })).status, 200);

    // A signed-in user who is not an admin is refused; so is an admin of another tenant.
    const bob = await gw.signIn({ tenant: "acme", role: "user", email: "bob@example.test" });
    assert.equal(bob.status, 200);
    assert.equal((await post("/v1/admin/enrollments", { bearer: `Bearer ${bob.token}` })).status, 403);
    for (const [tenant, email] of [["acme", "bob@example.test"], ["other", "root@example.test"]]) {
      const denied = await gw.signIn({ tenant, role: "admin", email });
      assert.equal(denied.status, 403, `${tenant} ${email}`);
      assert.equal(denied.token, undefined);
    }

    // Sign-out ends the session on the server: the same cookie no longer works.
    assert.equal((await post("/v1/session/logout", { cookie: admin.token, origin: gw.url })).status, 403); // needs CSRF
    const out = await post("/v1/session/logout", { cookie: admin.token, origin: gw.url, csrf: admin.csrf });
    assert.equal(out.status, 200);
    assert.match(out.headers.get("set-cookie"), /Max-Age=0/);
    assert.equal((await post("/v1/session", { cookie: admin.token })).status, 401);
    assert.equal((await post("/v1/admin/enrollments", { bearer: `Bearer ${admin.token}` })).status, 401);
  } finally {
    await gw.close();
  }
});
