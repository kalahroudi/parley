// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109: a real Google sign-in against the gateway deployed to Cloudflare, end to end,
// then a clean delete. Everything runs under the fixed throwaway Worker name
// `parley-test-login` on the pinned account, so the redirect URI can be registered once
// on the existing Google client:
//
//   https://parley-test-login.hello-891.workers.dev/auth/google/callback
//
// Two things only the owner of the client can do (see reality-check-1.md, "Google"):
// add that URI under Authorized redirect URIs, and type the client secret into
// wrangler's prompt when this script asks. The secret never passes through this
// script, a file or the output. Then:
//
//   node tests/reality/logins/google.mjs [--no-open] [--wait-minutes 10]
//   node tests/reality/logins/google.mjs cleanup     (delete the Worker if a run was abandoned)
//
// The run: verify the account, deploy the gateway plus the measurement wrapper
// (tests/reality/cf/worker/entry.ts) with the public client id as a plain var, wait for
// the secret, check the login redirect, open the login URL, wait for you to click
// through Google's consent once, read the redacted result, and delete the Worker in a
// finally block (then list `parley-test-*` Workers to show none remain). The gateway's
// own callback validates the id token's signature, issuer, audience, nonce, expiry,
// state and PKCE and, if GOOGLE_HOSTED_DOMAIN is set, the `hd` claim; PASS means all of
// that held. The email and subject id are never stored, printed or shown in the browser.
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { checkLoginRedirect } from "../lib.mjs";
import { configPath, deployAsync, destroy, remaining, removeConfig, secretCommand, secretNames, verifyAccount } from "../cf/safety.mjs";

export const NAME = "parley-test-login";
export const CLIENT_ID = "221774361645-4isrhvs33j1eft8133hsk239s831d33r.apps.googleusercontent.com"; // public
export const SECRET = "GOOGLE_CLIENT_SECRET";
export const redirectUri = (origin) => `${origin}/auth/google/callback`;
// The URI the owner of the client registers (account workers.dev subdomain `hello-891`).
// The first check compares the live login redirect to exactly this and exactly CLIENT_ID.
export const EXPECTED_REDIRECT = "https://parley-test-login.hello-891.workers.dev/auth/google/callback";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const realDeps = {
  verifyAccount,
  deploy: deployAsync,
  destroy,
  removeConfig,
  remaining,
  secretNames,
  secretCommand,
  configPath,
  fetch: (...a) => fetch(...a),
  sleep,
  now: Date.now,
  log: (...a) => console.log(...a),
  open: (url) => {
    const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
    const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
    spawn(cmd, args, { stdio: "ignore", detached: true }).on("error", () => {}).unref();
  },
};

// Returns { passed, result, problems }. The Worker is always deleted, whatever happens.
export async function run({ open = true, waitMs = 10 * 60_000, hostedDomain, deps = realDeps } = {}) {
  const d = { ...realDeps, ...deps };
  const probeToken = randomBytes(24).toString("hex");
  const vars = { PROBE_TOKEN: probeToken, FLOW_SECRET: randomBytes(32).toString("hex"), GOOGLE_CLIENT_ID: CLIENT_ID, LOGIN_CHECK: "1" };
  if (hostedDomain) vars.GOOGLE_HOSTED_DOMAIN = hostedDomain;
  const out = { passed: false, result: null, problems: [] };
  try {
    d.verifyAccount();
    d.log(`account verified; deploying ${NAME}`);
    const origin = await d.deploy(NAME, vars);
    d.log(`redirect URI that must be registered on the Google client:\n  ${redirectUri(origin)}`);

    // The gateway answers once the route is live (a new workers.dev route can lag a few seconds).
    const t0 = d.now();
    for (;;) {
      const h = await d.fetch(`${origin}/healthz`).catch(() => null);
      if (h?.ok) break;
      if (d.now() - t0 > 90_000) throw new Error("the Worker did not answer /healthz within 90 s");
      await d.sleep(3000);
    }

    // The secret is set by the person, in their own terminal, with wrangler's prompt.
    if (!d.secretNames(NAME).includes(SECRET)) {
      d.log(`\n${SECRET} is not set. In another terminal, run this and type the secret at the prompt:\n  ${d.secretCommand(NAME, SECRET)}\n(waiting up to ${Math.round(waitMs / 60000)} minutes)`);
      for (const end = d.now() + waitMs; !d.secretNames(NAME).includes(SECRET); await d.sleep(4000)) {
        if (d.now() > end) throw new Error(`${SECRET} was not set in time`);
      }
      d.log(`${SECRET} is set`);
    }

    // First check, before asking anyone to click: the login redirect must go to Google and
    // name exactly this client id and exactly the registered callback. A Worker that landed
    // on another host, or a wrong client id, fails here and not on Google's error page.
    const login = await d.fetch(`${origin}/auth/google/login`, { redirect: "manual" });
    const loc = login.headers.get("location");
    const redirect = login.status === 302 && loc ? checkLoginRedirect("google", loc, { clientId: CLIENT_ID, gatewayOrigin: origin }) : { ok: false, problems: [`status ${login.status}`] };
    const problems = [...redirect.problems];
    if (login.status === 302 && loc) {
      let q;
      try {
        q = new URL(loc).searchParams;
      } catch {}
      if (q?.get("client_id") !== CLIENT_ID) problems.push(`client_id is not exactly ${CLIENT_ID}`);
      if (q?.get("redirect_uri") !== EXPECTED_REDIRECT) problems.push(`redirect_uri is not exactly ${EXPECTED_REDIRECT} (the Worker is at ${origin})`);
    }
    if (problems.length) {
      out.problems.push(`login redirect: ${[...new Set(problems)].join("; ")}`);
      throw new Error("the login redirect is wrong");
    }
    d.log(`login redirect checked: Google, client ${CLIENT_ID}, callback ${EXPECTED_REDIRECT}, PKCE S256, state and nonce`);

    const url = `${origin}/auth/google/login`;
    d.log(`\nopen this URL and click through Google's consent once:\n  ${url}`);
    if (open) d.open(url);

    for (const end = d.now() + waitMs; ; await d.sleep(2000)) {
      const r = await d
        .fetch(`${origin}/__login-result`, { method: "POST", headers: { "x-probe-token": probeToken, "content-type": "application/json" }, body: "{}" })
        .then((x) => x.json())
        .catch(() => null);
      if (r?.result) {
        out.result = r.result;
        break;
      }
      if (d.now() > end) throw new Error("no sign-in was completed in time");
    }
    out.passed = out.result.ok === true;
    d.log(out.passed ? `PASS ${JSON.stringify(redacted(out.result))}` : `REFUSED ${JSON.stringify(redacted(out.result))}`);
  } catch (err) {
    out.problems.push(err.message);
    d.log(`FAILED: ${err.message}`);
  } finally {
    d.log(`cleanup: deleting ${NAME}`);
    try {
      d.destroy(NAME);
    } catch (err) {
      out.problems.push(`delete failed: ${err.message}`);
      d.log(`delete failed: ${err.message}`);
    }
    d.removeConfig(NAME);
    try {
      out.remaining = d.remaining();
      d.log(`remaining parley-test-* workers: ${JSON.stringify(out.remaining)}`);
    } catch (err) {
      out.problems.push(`listing failed: ${err.message}`);
    }
  }
  return out;
}

// Only fields that identify nothing: no email, no subject id, no timestamps of the person.
const redacted = ({ ok, status, error, provider, issuer, emailDomain, personalAccount, hasSub, hostedDomainChecked }) => ({
  ok, status, error, provider, issuer, emailDomain, personalAccount, hasSub, hostedDomainChecked,
});

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const argv = process.argv.slice(2);
  if (argv[0] === "cleanup") {
    verifyAccount();
    try {
      destroy(NAME);
    } catch (err) {
      console.log(`delete: ${err.message.split("\n")[0]}`);
    }
    removeConfig(NAME);
    console.log(`remaining parley-test-* workers: ${JSON.stringify(remaining())}`);
  } else {
    const i = argv.indexOf("--wait-minutes");
    const res = await run({
      open: !argv.includes("--no-open"),
      waitMs: (i >= 0 ? Number(argv[i + 1]) : 10) * 60_000,
      hostedDomain: process.env.GOOGLE_HOSTED_DOMAIN,
    });
    process.exit(res.passed && res.problems.length === 0 ? 0 : 1);
  }
}
