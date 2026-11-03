// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109: the Google login check (google.mjs) with every Cloudflare and network call faked,
// plus the redacted summary the login Worker keeps (summary.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { CLIENT_ID, EXPECTED_REDIRECT, NAME, SECRET, redirectUri, run } from "./google.mjs";
import { secretCommand } from "../cf/safety.mjs";
import { REFUSED_PAGE, SIGNED_IN_PAGE, summarize } from "./summary.ts";

const ORIGIN = "https://parley-test-login.hello-891.workers.dev";
const goodLocation = (over = {}) => {
  const u = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  const q = { response_type: "code", client_id: CLIENT_ID, redirect_uri: redirectUri(ORIGIN), scope: "openid email", state: "s", nonce: "n", code_challenge: "c", code_challenge_method: "S256", ...over };
  for (const [k, v] of Object.entries(q)) u.searchParams.set(k, v);
  return u.toString();
};

// A fake world: records every call, and lets a test script what the Worker returns.
function world({ secrets = [SECRET], result = { ok: true, status: 200, provider: "google", issuer: "https://accounts.google.com", emailDomain: "example.com", personalAccount: false, hasSub: true, hostedDomainChecked: false, at: 1 }, loginStatus = 302, location = goodLocation(), failDeploy = false, failDestroy = false, results } = {}) {
  const w = { calls: [], logs: [], clock: 0, secrets: [...secrets], polls: 0 };
  const log = (c) => w.calls.push(c);
  w.deps = {
    verifyAccount: () => log("verify"),
    deploy: async (name, vars) => { log(`deploy ${name}`); w.vars = vars; if (failDeploy) throw new Error("deploy failed"); return ORIGIN; },
    destroy: (name) => { log(`destroy ${name}`); if (failDestroy) throw new Error("boom"); },
    removeConfig: () => log("removeConfig"),
    remaining: () => (log("remaining"), []),
    secretNames: () => w.secrets,
    secretCommand: (n, s) => secretCommand(n, s),
    fetch: async (url, init = {}) => {
      if (url.endsWith("/healthz")) return { ok: true };
      if (url.endsWith("/auth/google/login")) return { status: loginStatus, headers: { get: () => location } };
      if (url.endsWith("/__login-result")) {
        w.polls++;
        w.probeHeader = init.headers["x-probe-token"];
        const r = results ? results(w.polls) : result;
        return { json: async () => ({ result: r }) };
      }
      throw new Error(`unexpected fetch ${url}`);
    },
    sleep: async (ms) => { w.clock += ms; if (w.secrets.length === 0 && w.clock > 8000) w.secrets.push(SECRET); },
    now: () => w.clock,
    log: (...a) => w.logs.push(a.join(" ")),
    open: (url) => log(`open ${url}`),
  };
  return w;
}

test("the fixed name and redirect URI are what the runbook says", () => {
  assert.equal(NAME, "parley-test-login");
  assert.equal(redirectUri(ORIGIN), "https://parley-test-login.hello-891.workers.dev/auth/google/callback");
  assert.match(CLIENT_ID, /^221774361645-4isrhvs33j1eft8133hsk239s831d33r\.apps\.googleusercontent\.com$/);
});

test("a completed sign-in passes, and the Worker is deleted and listed afterwards", async () => {
  const w = world();
  const r = await run({ deps: w.deps });
  assert.equal(r.passed, true);
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.remaining, []);
  assert.equal(w.calls[0], "verify");
  assert.ok(w.calls.some((c) => c === `open ${ORIGIN}/auth/google/login`));
  const tail = w.calls.slice(-3);
  assert.deepEqual(tail, [`destroy ${NAME}`, "removeConfig", "remaining"]);
  assert.equal(w.vars.GOOGLE_CLIENT_ID, CLIENT_ID);
  assert.equal(w.vars.LOGIN_CHECK, "1");
  assert.ok(!(SECRET in w.vars), "the secret is never a deploy variable");
  assert.equal(w.probeHeader, w.vars.PROBE_TOKEN);
});

test("it waits for the secret, printing the exact command, and carries on once it is set", async () => {
  const w = world({ secrets: [] });
  const r = await run({ deps: w.deps });
  assert.equal(r.passed, true);
  const text = w.logs.join("\n");
  assert.match(text, /GOOGLE_CLIENT_SECRET is not set/);
  assert.match(text, /npx wrangler secret put GOOGLE_CLIENT_SECRET --name parley-test-login --config "[^"]+wrangler\.jsonc"/);
  assert.match(text, /GOOGLE_CLIENT_SECRET is set/);
});

test("a secret that never arrives fails after the wait and still cleans up", async () => {
  const w = world({ secrets: [] });
  w.deps.sleep = async (ms) => { w.clock += ms; };
  const r = await run({ waitMs: 20_000, deps: w.deps });
  assert.equal(r.passed, false);
  assert.match(r.problems.join(), /was not set in time/);
  assert.ok(w.calls.includes(`destroy ${NAME}`) && w.calls.includes("remaining"));
});

test("the expected redirect and client id are exactly the registered ones", () => {
  assert.equal(EXPECTED_REDIRECT, "https://parley-test-login.hello-891.workers.dev/auth/google/callback");
  assert.equal(CLIENT_ID, "221774361645-4isrhvs33j1eft8133hsk239s831d33r.apps.googleusercontent.com");
  assert.equal(redirectUri(ORIGIN), EXPECTED_REDIRECT);
});

test("a Worker on another host, or a different client id, is caught before anyone clicks", async () => {
  for (const [label, location, re] of [
    ["other host", goodLocation({ redirect_uri: "https://parley-test-login.other-123.workers.dev/auth/google/callback" }), /redirect_uri is (wrong|not exactly)/],
    ["a different client", goodLocation({ client_id: "000000000000-someotherclient.apps.googleusercontent.com" }), /client_id is (wrong|not exactly)/],
    ["other path", goodLocation({ redirect_uri: `${ORIGIN}/auth/google/other` }), /redirect_uri is (wrong|not exactly)/],
  ]) {
    const w = world({ location });
    const r = await run({ deps: w.deps });
    assert.equal(r.passed, false, label);
    assert.match(r.problems.join(), re, label);
    assert.ok(!w.calls.some((c) => c.startsWith("open ")), `${label}: nobody was asked to click`);
    assert.ok(w.calls.includes(`destroy ${NAME}`), `${label}: cleaned up`);
  }
});

test("a Worker deployed to an unexpected host fails the exact-callback check even if its redirect is self-consistent", async () => {
  const other = "https://parley-test-login.other-123.workers.dev";
  const w = world({ location: goodLocation({ redirect_uri: `${other}/auth/google/callback` }) });
  w.deps.deploy = async () => other;
  const r = await run({ deps: w.deps });
  assert.equal(r.passed, false);
  assert.match(r.problems.join(), /redirect_uri is not exactly https:\/\/parley-test-login\.hello-891/);
});

test("a wrong login redirect stops before anyone is asked to click, and cleans up", async () => {
  const w = world({ location: goodLocation({ client_id: "someone-else" }) });
  const r = await run({ deps: w.deps });
  assert.equal(r.passed, false);
  assert.match(r.problems.join(), /client_id is wrong/);
  assert.ok(!w.calls.some((c) => c.startsWith("open ")));
  assert.ok(w.calls.includes(`destroy ${NAME}`));
});

test("a refusal by the gateway is reported with its code and is not a pass", async () => {
  const w = world({ result: { ok: false, status: 401, error: "tenant_mismatch", hostedDomainChecked: true, at: 1 } });
  const r = await run({ hostedDomain: "example.com", deps: w.deps });
  assert.equal(r.passed, false);
  assert.match(w.logs.join("\n"), /REFUSED .*tenant_mismatch/);
  assert.equal(w.vars.GOOGLE_HOSTED_DOMAIN, "example.com");
});

test("waiting for the person polls until a result exists, then stops", async () => {
  const w = world({ results: (n) => (n < 4 ? null : { ok: true, status: 200, provider: "google", emailDomain: "gmail.com", personalAccount: true, hasSub: true, hostedDomainChecked: false }) });
  const r = await run({ deps: w.deps });
  assert.equal(r.passed, true);
  assert.equal(w.polls, 4);
});

test("no sign-in in time fails, and every failure path deletes the Worker", async () => {
  const w = world({ results: () => null });
  const r = await run({ waitMs: 10_000, deps: w.deps });
  assert.equal(r.passed, false);
  assert.match(r.problems.join(), /no sign-in was completed in time/);
  assert.ok(w.calls.includes(`destroy ${NAME}`));

  const d = world({ failDeploy: true });
  const r2 = await run({ deps: d.deps });
  assert.match(r2.problems.join(), /deploy failed/);
  assert.ok(d.calls.includes(`destroy ${NAME}`), "a failed deploy may leave a partial Worker, so delete anyway");
});

test("a failed delete is reported loudly, never swallowed", async () => {
  const w = world({ failDestroy: true });
  const r = await run({ deps: w.deps });
  assert.match(r.problems.join(), /delete failed: boom/);
  assert.ok(w.calls.includes("remaining"), "the listing still runs so the leftover is visible");
});

test("output never carries the email, the subject id, tokens or the secret", async () => {
  const w = world({ result: { ok: true, status: 200, provider: "google", issuer: "https://accounts.google.com", emailDomain: "example.com", hasSub: true, email: "alice@example.com", sub: "123456789", hostedDomainChecked: false } });
  await run({ deps: w.deps });
  const text = w.logs.join("\n");
  assert.doesNotMatch(text, /alice|123456789/);
  assert.doesNotMatch(text, new RegExp(w.vars.PROBE_TOKEN));
  assert.doesNotMatch(text, new RegExp(w.vars.FLOW_SECRET));
});

test("summary: a 200 keeps the domain and flags only, never the email or sub", () => {
  const s = summarize(200, { provider: "google", issuer: "https://accounts.google.com", sub: "123", email: "Alice@Example.com" }, undefined);
  assert.deepEqual(s, { ok: true, status: 200, provider: "google", issuer: "https://accounts.google.com", emailDomain: "example.com", hasSub: true, personalAccount: false, hostedDomainChecked: false });
  assert.doesNotMatch(JSON.stringify(s), /alice|123/i);
  assert.equal(summarize(200, { provider: "google", email: "x@gmail.com", sub: "1" }, "corp.example").personalAccount, true);
  assert.equal(summarize(200, { provider: "google", email: "x@gmail.com", sub: "1" }, "corp.example").hostedDomainChecked, true);
});

test("summary: refusals keep only a well-formed code; anything else is 'unknown'", () => {
  assert.deepEqual(summarize(401, { error: "tenant_mismatch" }, "a.example"), { ok: false, status: 401, error: "tenant_mismatch", hostedDomainChecked: true });
  assert.equal(summarize(502, { error: "Some <script> text" }, undefined).error, "unknown");
  assert.equal(summarize(500, null, undefined).error, "unknown");
  assert.equal(summarize(200, { provider: "google" }, undefined).ok, false, "no email means no identity");
  assert.equal(summarize(200, "not an object", undefined).ok, false);
  assert.match(SIGNED_IN_PAGE, /Signed in/);
  assert.match(REFUSED_PAGE, /refused/);
});
