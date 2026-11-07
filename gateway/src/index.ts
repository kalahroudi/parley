// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { handleAdmin } from "./admin";
import { handleBilling } from "./billing";
import { agentCard, handleA2A } from "./a2a";
import { authenticate, handleConnectAuth } from "./connect";
import { handle as handleAuth, type AuthEnv } from "./auth.ts";
import { handleSession, issueSession } from "./session";
import { Device, IDENTITY_DEVICE, IDENTITY_TENANT } from "./device";
import { handleDirectory } from "./directory";
import { handleEnroll } from "./enroll";
import { handleLogin } from "./login";
import { Task } from "./task";
import { limitAuth, RateLimit } from "./ratelimit";
import { Tenant } from "./tenant";

export { Device, RateLimit, Task, Tenant };

export interface Env extends AuthEnv {
  DEVICE: DurableObjectNamespace<Device>;
  TENANT: DurableObjectNamespace<Tenant>;
  TASK: DurableObjectNamespace<Task>;
  RATE: DurableObjectNamespace<RateLimit>;
  // Per-minute limits for the login and session endpoints (see ratelimit.ts); defaults apply when unset.
  RATE_AUTH_PER_MIN?: string;
  RATE_TENANT_LOGIN_PER_MIN?: string;
  RATE_SESSION_PER_MIN?: string;
  // Per-minute limits for a tenant's admin export and audit CSV (RATE_ADMIN_PER_MIN) and its deletion tries (RATE_DELETE_PER_MIN).
  RATE_ADMIN_PER_MIN?: string;
  RATE_DELETE_PER_MIN?: string;
  // Per-minute limit for a tenant's Checkout and Portal calls.
  RATE_BILLING_PER_MIN?: string;
  // Stripe (src/billing.ts), all set as secrets or variables on the deployment: the API key (test-mode `sk_test_`/`rk_test_`;
  // a live key is refused unless STRIPE_ALLOW_LIVE is "1"), the webhook endpoint's signing secret, the id of the per-device
  // seat price, and the fixed page Stripe returns the admin to.
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  STRIPE_PRICE_ID?: string;
  STRIPE_ALLOW_LIVE?: string;
  BILLING_RETURN_URL?: string;
  // Per-minute limits per device for new tasks, other task messages and directory searches (the tenant's are ten times these).
  RATE_TASK_PER_MIN?: string;
  RATE_MESSAGE_PER_MIN?: string;
  RATE_FIND_PER_MIN?: string;
  // Per-minute limit per device for prekey frames it sends through the relay (requests and answers).
  RATE_PREKEY_PER_MIN?: string;
  // Comma-separated `tenant:email` pairs allowed to hold an admin session.
  ADMINS?: string;
  // Comma-separated `tenant:email` pairs and `tenant:domain` pairs allowed to hold a user session. With neither set
  // for a tenant, user logins to it are refused.
  USERS?: string;
  USER_DOMAINS?: string;
  // Per-minute limits for the connect challenge and token endpoints (src/connect.ts): per source address, and per device.
  RATE_CONNECT_PER_MIN?: string;
  RATE_CONNECT_DEVICE_PER_MIN?: string;
}

// Devices authenticate with a connect token (src/connect.ts); with none, or a bad one, nothing opens.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Identifiers travel in the Authorization header and frames, never in the URL.
    const { pathname } = new URL(request.url);
    if (pathname === "/healthz") return Response.json({ ok: true, service: "gateway" });
    if (pathname.startsWith("/auth/") || pathname === "/v1/session" || pathname === "/v1/session/logout" || pathname.startsWith("/v1/connect/") || pathname.startsWith("/v1/login/")) {
      const refused = await limitAuth(request, env);
      if (refused) return refused;
    }
    if (pathname.startsWith("/auth/")) return handleAuth(request, env, undefined, issueSession.bind(null, request, env));
    if (pathname === "/v1/connect/challenge" || pathname === "/v1/connect/token") return handleConnectAuth(request, env);
    if (pathname.startsWith("/v1/login/")) return handleLogin(request, env);
    if (pathname === "/v1/session" || pathname === "/v1/session/logout") return handleSession(request, env);
    if (pathname === "/v1/stripe/webhook" || pathname === "/v1/admin/billing" || pathname === "/v1/admin/billing/checkout" || pathname === "/v1/admin/billing/portal") return handleBilling(request, env);
    if (pathname === "/v1/admin/export" || pathname === "/v1/admin/audit/csv" || pathname === "/v1/admin/tenant/delete") return handleAdmin(request, env);
    if (pathname.startsWith("/v1/admin/groups") || pathname === "/v1/admin/audit" || pathname.startsWith("/v1/admin/retention") || pathname.startsWith("/v1/cards/") || pathname.startsWith("/v1/directory/")) return handleDirectory(request, env, (req) => authenticate(req, env, "api"));
    if (pathname.startsWith("/v1/enroll/") || pathname.startsWith("/v1/admin/") || pathname === "/v1/revocations" || pathname === "/v1/root") return handleEnroll(request, env);
    if (pathname === "/.well-known/agent-card.json") {
      return request.method === "GET" ? Response.json(agentCard(new URL(request.url).origin)) : new Response("method not allowed", { status: 405 });
    }
    if (pathname === "/a2a") {
      const who = await authenticate(request, env, "api");
      return who ? handleA2A(request, env, who) : new Response("unauthorized", { status: 401 });
    }
    if (pathname !== "/v1/connect") return new Response("not found", { status: 404 });
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }
    const who = await authenticate(request, env, "connect");
    if (!who) return new Response("unauthorized", { status: 401 });
    // The Device DO learns who it is from the Worker, which has just verified the token: these headers are
    // set here, overwriting whatever the client sent, and a DO is not reachable any other way.
    const forwarded = new Request(request);
    forwarded.headers.set(IDENTITY_TENANT, who.tenant);
    forwarded.headers.set(IDENTITY_DEVICE, who.device);
    return env.DEVICE.get(env.DEVICE.idFromName(`${who.tenant}:${who.device}`)).fetch(forwarded);
  },
} satisfies ExportedHandler<Env>;
