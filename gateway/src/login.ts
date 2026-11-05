// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import type { Env } from "./index";
import { tenantStub } from "./tenant";

// Sign-in for `parley-cli login` (the device flow). Three steps, each a POST:
//   /v1/login/start   the CLI sends the hashes of the session secret and a poll secret it made; gets an id and a code
//   (browser)         /auth/<provider>/login?tenant=T&role=user&device=<id>; after the IdP, a page shows the code
//   /v1/login/confirm the page's form, posted by the user who compared the code with the terminal's
//   /v1/login/poll    the CLI learns the session now exists; its token is `ps_<tenant>.<session secret>`
// No secret is stored or relayed: the gateway only ever sees hashes of the two the CLI keeps.
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const DEVICE = /^[0-9a-f]{32}$/;
const MAX_BODY = 2048;
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const bad = () => json(400, { error: "bad_request" });
const notFound = () => json(404, { error: "not_found" });
// Whether a JSON field is a string of the expected shape; anything else (absent, a number, an object) is not.
const is = (re: RegExp, v: unknown): v is string => typeof v === "string" && re.test(v);

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const EXPIRED = "<h1>This sign-in has expired</h1><p>Run <code>parley-cli login</code> again.</p>";
const page = (status: number, inner: string) =>
  new Response(`<!doctype html><meta charset="utf-8"><title>Parley sign-in</title><body style="font-family:system-ui;max-width:32em;margin:3em auto">${inner}`, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
    },
  });

// The page after a successful IdP login for a device login: shows the code and asks for confirmation.
export async function confirmPage(env: Env, tenant: string, email: string, device: string): Promise<Response> {
  const r = DEVICE.test(device) ? await tenantStub(env, tenant).loginAuth(device, email) : null;
  if (!r) return page(410, EXPIRED);
  return page(
    200,
    `<h1>Sign in a device</h1><p>Signed in as <b>${esc(email)}</b>.</p><p>Does the terminal show this code?</p><p style="font-size:2em"><b>${esc(r.code)}</b></p>` +
      `<form method="post" action="/v1/login/confirm"><input type="hidden" name="tenant" value="${esc(tenant)}"><input type="hidden" name="id" value="${esc(device)}">` +
      `<input type="hidden" name="confirm" value="${esc(r.confirm)}"><button>Yes, it matches</button></form><p>If you did not start this, close this window.</p>`,
  );
}

export async function handleLogin(req: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(req.url);
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
  if (Number(req.headers.get("content-length")) > MAX_BODY) return bad(); // refuse before reading it
  const raw = await req.arrayBuffer(); // not .text(): a form body is not "text" to the runtime
  if (raw.byteLength > MAX_BODY) return bad();
  const text = new TextDecoder().decode(raw);

  if (pathname === "/v1/login/confirm") {
    // A form post from the page above: it must come from this gateway's own origin.
    const f = new URLSearchParams(text);
    const tenant = String(f.get("tenant"));
    if (req.headers.get("Origin") !== new URL(req.url).origin || !ID.test(tenant) || !DEVICE.test(String(f.get("id")))) {
      return page(400, "<h1>Not accepted</h1>");
    }
    const ok = await tenantStub(env, tenant).loginConfirm(String(f.get("id")), String(f.get("confirm")));
    return ok ? page(200, "<h1>Done</h1><p>You can close this window and go back to the terminal.</p>") : page(410, EXPIRED);
  }

  let b: Record<string, unknown> | null = null;
  try {
    b = JSON.parse(text);
  } catch {
    // not JSON: it has no tenant, so it is refused below
  }
  const tenant = b?.tenant;
  if (!is(ID, tenant)) return bad();
  const stub = tenantStub(env, tenant);
  const routes: Record<string, () => Promise<Response>> = {
    "/v1/login/start": async () => {
      const r = await stub.loginStart(b!.session_hash as string, b!.poll_hash as string); // the Tenant checks their shape
      return "error" in r ? json(r.error === "too_many" ? 429 : 400, { error: r.error }) : json(201, r);
    },
    "/v1/login/poll": async () => {
      const state = is(DEVICE, b!.id) ? await stub.loginPoll(b!.id, b!.poll as string) : null;
      return state ? json(200, { state }) : notFound();
    },
  };
  return (routes[pathname] ?? (async () => notFound()))();
}
