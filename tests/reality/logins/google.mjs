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
//   node tests/reality/logins/google.mjs --domain hostjab.com --mode positive   (a hostjab.com account)
//   node tests/reality/logins/google.mjs --domain example.com --mode negative   (any account not of example.com)
//   node tests/reality/logins/google.mjs cleanup     (delete the Worker if a run was abandoned)
//
// Hosted-domain (Workspace) runs: the domain is given with --domain or GOOGLE_HOSTED_DOMAIN and
// the script sets it as the Worker's GOOGLE_HOSTED_DOMAIN variable in the generated config
// (no manual wrangler edit). The mode says what the sign-in must do:
//   positive  sign in with an account of that Workspace domain: PASS with hostedDomainChecked true
//   negative  sign in with an account NOT of that domain: must be REFUSED as tenant_mismatch, with no
//             identity issued. Either a personal gmail.com account (it has no hd claim) or a Workspace
//             account of another domain (its hd is not the required one), for example the hostjab.com
//             account with --domain example.com
// The `hd` parameter in the authorization request is only a hint to Google's account chooser.
// The gateway enforces the domain on the `hd` claim of the verified id token.
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
export const DOMAIN = /^(?=.{4,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
export const IDENTITY_FIELDS = ["provider", "issuer", "emailDomain", "hasSub", "personalAccount"];

// Command line and environment to run options. A domain needs a mode and a mode needs a domain,
// so a run can never be ambiguous about whether it expects a pass or a refusal.
export function parseArgs(argv, env = {}) {
  const flag = (n) => {
    const i = argv.indexOf(n);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const raw = flag("--domain") ?? env.GOOGLE_HOSTED_DOMAIN;
  const mode = flag("--mode");
  const hostedDomain = raw ? raw.trim().toLowerCase() : undefined;
  if (hostedDomain && !DOMAIN.test(hostedDomain)) throw new Error(`not a domain name: ${JSON.stringify(raw)}`);
  if (mode !== undefined && mode !== "positive" && mode !== "negative") throw new Error("--mode must be positive or negative");
  if (hostedDomain && !mode) throw new Error("a domain needs --mode positive (sign in with an account of that domain) or --mode negative (sign in with an account that is not)");
  if (mode && !hostedDomain) throw new Error(`--mode ${mode} needs a domain (--domain or GOOGLE_HOSTED_DOMAIN)`);
  const w = flag("--wait-minutes");
  return { open: !argv.includes("--no-open"), waitMs: (w === undefined ? 10 : Number(w)) * 60_000, mode, hostedDomain };
}

// What the sign-in has to look like for the run to count. Anything else is reported plainly:
// a negative run that is accepted means enforcement failed; one that fails for another reason
// (consent denied, wrong account type) proves nothing about the domain check.
export function judge(result, mode, hostedDomain) {
  const identity = IDENTITY_FIELDS.filter((k) => result[k] !== undefined);
  if (!mode) return result.ok === true ? { met: true, text: "PASS" } : { met: false, text: `REFUSED ${result.error ?? ""}`.trim() };
  if (mode === "positive") {
    if (result.ok === true && result.hostedDomainChecked === true) return { met: true, text: `PASS (positive): an account of ${hostedDomain} was accepted and the hd claim was checked` };
    if (result.ok === true) return { met: false, text: "UNEXPECTED: accepted, but the hosted-domain check did not run" };
    return { met: false, text: `NOT MET (positive): refused with ${result.error}; sign in with an account of ${hostedDomain}` };
  }
  if (result.ok === true) return { met: false, text: `ENFORCEMENT FAILED: an account was accepted although GOOGLE_HOSTED_DOMAIN=${hostedDomain}; if that account is not of that domain, the gateway let it in` };
  if (result.error !== "tenant_mismatch") return { met: false, text: `NOT PROVEN (negative): refused with ${result.error}, not tenant_mismatch, so the domain check was not what stopped it; sign in with an account that is not of ${hostedDomain} and click Allow` };
  if (identity.length) return { met: false, text: `UNEXPECTED: refused, but the result carries identity fields (${identity.join(", ")})` };
  return { met: true, text: `REFUSED as expected (negative): tenant_mismatch, hd did not match ${hostedDomain}; no identity was issued` };
}

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
export async function run({ open = true, waitMs = 10 * 60_000, hostedDomain, mode, deps = realDeps } = {}) {
  if (hostedDomain && !DOMAIN.test(hostedDomain)) throw new Error(`not a domain name: ${JSON.stringify(hostedDomain)}`);
  if (!!mode !== !!hostedDomain) throw new Error("a hosted domain and a mode go together");
  const d = { ...realDeps, ...deps };
  const probeToken = randomBytes(24).toString("hex");
  const vars = { PROBE_TOKEN: probeToken, FLOW_SECRET: randomBytes(32).toString("hex"), GOOGLE_CLIENT_ID: CLIENT_ID, LOGIN_CHECK: "1" };
  if (hostedDomain) vars.GOOGLE_HOSTED_DOMAIN = hostedDomain;
  const out = { passed: false, result: null, problems: [], mode: mode ?? null, verdict: null };
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
      // The domain reached the Worker as its GOOGLE_HOSTED_DOMAIN variable if the hint carries it.
      if ((q?.get("hd") ?? undefined) !== hostedDomain) problems.push(`hd hint is ${q?.get("hd") === null ? "missing" : JSON.stringify(q?.get("hd"))}, expected ${hostedDomain === undefined ? "none" : JSON.stringify(hostedDomain)}: GOOGLE_HOSTED_DOMAIN did not reach the Worker`);
    }
    if (problems.length) {
      out.problems.push(`login redirect: ${[...new Set(problems)].join("; ")}`);
      throw new Error("the login redirect is wrong");
    }
    d.log(`login redirect checked: Google, client ${CLIENT_ID}, callback ${EXPECTED_REDIRECT}, PKCE S256, state and nonce${hostedDomain ? `, hd hint ${hostedDomain}` : ""}`);

    const url = `${origin}/auth/google/login`;
    const who = mode === "positive" ? `an account of ${hostedDomain}` : mode === "negative" ? `an account that is NOT of ${hostedDomain} (a personal gmail.com account, or an account of another domain)` : "your account";
    d.log(`\nsign in with ${who}; open this URL and click through Google's consent once:\n  ${url}`);
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
    const v = judge(out.result, mode, hostedDomain);
    out.verdict = v.text;
    out.passed = v.met;
    d.log(`${v.text}\n  ${JSON.stringify(redacted(out.result))}`);
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
    let opts;
    try {
      opts = parseArgs(argv, process.env);
    } catch (err) {
      console.error(err.message);
      process.exit(2);
    }
    const res = await run(opts);
    process.exit(res.passed && res.problems.length === 0 ? 0 : 1);
  }
}
