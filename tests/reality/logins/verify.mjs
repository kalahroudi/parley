// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109 (pending the user): a real Google or Microsoft Entra login, end to end, with
// the gateway's own OIDC code (gateway/src/auth.ts) listening on loopback. It needs
// no Cloudflare account: register http://127.0.0.1:8787/auth/<provider>/callback as
// the redirect URI (see specs/parley-mvp/reality-check-1.md, "Real logins").
//
//   GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... [GOOGLE_HOSTED_DOMAIN=example.com] \
//     node tests/reality/logins/verify.mjs google
//   ENTRA_TENANT_ID=... ENTRA_CLIENT_ID=... ENTRA_CLIENT_SECRET=... REDIRECT_HOST=localhost \
//     node tests/reality/logins/verify.mjs entra
//
// It prints the login URL, waits for you to sign in, and reports PASS or the
// refusal code. The credentials are read from the environment and never printed;
// of the identity it prints only the provider, the issuer, the email's domain and
// whether the tenant matched, and the browser is shown "signed in" without the
// identity. Run it once per case in the runbook (expected result in the table).
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { handle } from "../../../gateway/src/auth.ts";

const provider = process.argv[2];
const port = Number(process.env.PORT ?? 8787);
if (!["google", "entra"].includes(provider)) {
  console.error("usage: verify.mjs google|entra");
  process.exit(2);
}
const need = provider === "google" ? ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"] : ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"];
const missing = need.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`missing environment: ${missing.join(", ")}`);
  process.exit(2);
}
const env = { FLOW_SECRET: randomBytes(32).toString("hex"), ...process.env };
// Entra accepts an http redirect URI only on localhost, so Entra runs use REDIRECT_HOST=localhost.
const base = `http://${process.env.REDIRECT_HOST ?? "127.0.0.1"}:${port}`;

export const summarize = (id) => ({
  provider: id.provider,
  issuer: id.issuer,
  emailDomain: String(id.email).split("@")[1],
  hasSub: Boolean(id.sub),
  tenantChecked: id.tenantId !== undefined,
});

const server = createServer(async (req, res) => {
  const r = await handle(new Request(base + req.url, { method: req.method, headers: req.headers }), env);
  const isCallback = new URL(base + req.url).pathname.endsWith("/callback");
  let body = Buffer.from(await r.arrayBuffer());
  const headers = Object.fromEntries(r.headers);
  if (isCallback) {
    if (r.status === 200) {
      console.log(`PASS ${JSON.stringify(summarize(JSON.parse(body.toString())))}`);
      body = Buffer.from("Signed in. You can close this tab and return to the terminal.");
      headers["content-type"] = "text/plain";
    } else {
      console.log(`REFUSED status=${r.status} ${body.toString()}`);
    }
    res.writeHead(r.status, headers).end(body);
    setTimeout(() => server.close(() => process.exit(r.status === 200 ? 0 : 1)), 200);
    return;
  }
  res.writeHead(r.status, headers).end(body);
});
server.listen(port, "127.0.0.1", () => {
  console.log(`open ${base}/auth/${provider}/login in a browser and sign in (Ctrl-C to cancel)`);
});
