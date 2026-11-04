// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { agentCard, handleA2A } from "./a2a";
import { authenticate, handleConnectAuth } from "./connect";
import { handle as handleAuth, type AuthEnv } from "./auth.ts";
import { handleSession, issueSession } from "./session";
import { Device } from "./device";
import { handleDirectory } from "./directory";
import { handleEnroll } from "./enroll";
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
  // Per-minute limits per device for new tasks, other task messages and directory searches (the tenant's are ten times these).
  RATE_TASK_PER_MIN?: string;
  RATE_MESSAGE_PER_MIN?: string;
  RATE_FIND_PER_MIN?: string;
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
    if (pathname.startsWith("/auth/") || pathname === "/v1/session" || pathname === "/v1/session/logout" || pathname.startsWith("/v1/connect/")) {
      const refused = await limitAuth(request, env);
      if (refused) return refused;
    }
    if (pathname.startsWith("/auth/")) return handleAuth(request, env, undefined, issueSession.bind(null, request, env));
    if (pathname === "/v1/connect/challenge" || pathname === "/v1/connect/token") return handleConnectAuth(request, env);
    if (pathname === "/v1/session" || pathname === "/v1/session/logout") return handleSession(request, env);
    if (pathname.startsWith("/v1/admin/groups") || pathname === "/v1/admin/audit" || pathname.startsWith("/v1/admin/retention") || pathname.startsWith("/v1/cards/") || pathname.startsWith("/v1/directory/")) return handleDirectory(request, env);
    if (pathname.startsWith("/v1/enroll/") || pathname.startsWith("/v1/admin/") || pathname === "/v1/revocations") return handleEnroll(request, env);
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
    return who ? env.DEVICE.get(env.DEVICE.idFromName(`${who.tenant}:${who.device}`)).fetch(request) : new Response("unauthorized", { status: 401 });
  },
} satisfies ExportedHandler<Env>;
