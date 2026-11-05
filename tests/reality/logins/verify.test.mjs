// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109: tests/reality/logins/verify.mjs against the mock IdP, so the script is known
// to work before anyone spends time on a real Google or Entra sign-in.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { startMockOidc } from "../../harness/oidc.mjs";

const script = fileURLToPath(new URL("./verify.mjs", import.meta.url));
const freePort = () => new Promise((res) => { const s = createServer().listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => res(port)); }); });

async function run(env, args, drive) {
  const port = await freePort();
  const child = spawn(process.execPath, [script, ...args], { env: { ...process.env, ...env, PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  const code = new Promise((r) => child.on("exit", r));
  if (drive) {
    while (!out.includes("open http")) await new Promise((r) => setTimeout(r, 20));
    await drive(`http://127.0.0.1:${port}`);
  }
  return { code: await code, out };
}

// Follows the login redirect through the IdP the way a browser would.
async function browse(base, provider) {
  const login = await fetch(`${base}/auth/${provider}/login`, { redirect: "manual" });
  const cookie = login.headers.get("set-cookie").split(";")[0];
  const back = await fetch(login.headers.get("location"), { redirect: "manual" });
  return fetch(back.headers.get("location"), { headers: { cookie } });
}

test("verify: a Google login completes and prints only a redacted summary", async () => {
  const idp = await startMockOidc();
  try {
    const { code, out } = await run({ GOOGLE_CLIENT_ID: "cid", GOOGLE_CLIENT_SECRET: "super-secret-value", GOOGLE_ISSUER: idp.issuer }, ["google"], async (base) => {
      idp.tweak.claims = { email_verified: true };
      const r = await browse(base, "google");
      assert.equal(r.status, 200);
      assert.doesNotMatch(await r.text(), /alice/, "the browser is not shown the identity");
    });
    assert.equal(code, 0);
    assert.match(out, /PASS .*"provider":"google".*"emailDomain":"example\.test"/);
    assert.doesNotMatch(out, /alice@|super-secret-value/);
  } finally {
    await idp.close();
  }
});

test("verify: an Entra login from the wrong tenant is refused and exits non-zero", async () => {
  const idp = await startMockOidc();
  try {
    const { code, out } = await run({ ENTRA_TENANT_ID: "t1", ENTRA_CLIENT_ID: "cid", ENTRA_CLIENT_SECRET: "s", ENTRA_ISSUER: idp.issuer }, ["entra"], async (base) => {
      idp.tweak.claims = { tid: "someone-else" };
      assert.equal((await browse(base, "entra")).status, 401);
    });
    assert.equal(code, 1);
    assert.match(out, /REFUSED status=401 .*tenant_mismatch/);
  } finally {
    await idp.close();
  }
});

test("verify: REDIRECT_HOST decides the redirect URI the IdP is given", async () => {
  const idp = await startMockOidc();
  try {
    let sent;
    const { code } = await run({ GOOGLE_CLIENT_ID: "cid", GOOGLE_CLIENT_SECRET: "s", GOOGLE_ISSUER: idp.issuer, REDIRECT_HOST: "localhost" }, ["google"], async (base) => {
      const login = await fetch(`${base.replace("127.0.0.1", "localhost")}/auth/google/login`, { redirect: "manual" });
      sent = new URL(login.headers.get("location")).searchParams.get("redirect_uri");
      assert.match(sent, /^http:\/\/localhost:\d+\/auth\/google\/callback$/);
      const back = await fetch(login.headers.get("location"), { redirect: "manual" });
      await fetch(back.headers.get("location"), { headers: { cookie: login.headers.get("set-cookie").split(";")[0] } });
    });
    assert.equal(code, 0);
  } finally {
    await idp.close();
  }
});

test("verify: missing configuration and unknown providers exit 2 without starting a server", async () => {
  assert.equal((await run({ GOOGLE_CLIENT_ID: "", GOOGLE_CLIENT_SECRET: "" }, ["google"])).code, 2);
  assert.equal((await run({}, ["okta"])).code, 2);
});
