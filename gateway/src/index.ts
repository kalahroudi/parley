// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { agentCard } from "./a2a";
import { handle as handleAuth, type AuthEnv } from "./auth.ts";
import { handleSession, issueSession } from "./session";
import { Device } from "./device";
import { handleDirectory } from "./directory";
import { handleEnroll } from "./enroll";
import { Task } from "./task";
import { Tenant } from "./tenant";

export { Device, Task, Tenant };

export interface Env extends AuthEnv {
  DEVICE: DurableObjectNamespace<Device>;
  TENANT: DurableObjectNamespace<Tenant>;
  TASK: DurableObjectNamespace<Task>;
  // Comma-separated `tenant:email` pairs allowed to hold an admin session.
  ADMINS?: string;
  // Comma-separated `tenant:email` or `tenant:@domain` entries allowed to hold a user session.
  USERS?: string;
}

// Fails closed until connect tokens land: no credential opens a device connection.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Identifiers travel in the Authorization header and frames, never in the URL.
    const { pathname } = new URL(request.url);
    if (pathname === "/healthz") return Response.json({ ok: true, service: "gateway" });
    if (pathname.startsWith("/auth/")) return handleAuth(request, env, undefined, issueSession.bind(null, request, env));
    if (pathname === "/v1/session" || pathname === "/v1/session/logout") return handleSession(request, env);
    if (pathname.startsWith("/v1/admin/groups") || pathname === "/v1/admin/audit" || pathname.startsWith("/v1/cards/") || pathname.startsWith("/v1/directory/")) return handleDirectory(request, env);
    if (pathname.startsWith("/v1/enroll/") || pathname.startsWith("/v1/admin/") || pathname === "/v1/revocations") return handleEnroll(request, env);
    if (pathname === "/.well-known/agent-card.json") {
      return request.method === "GET" ? Response.json(agentCard(new URL(request.url).origin)) : new Response("method not allowed", { status: 405 });
    }
    // Closed like /v1/connect: the development bearer is gone and device tokens are not here yet.
    if (pathname === "/a2a") return new Response("unauthorized", { status: 401 });
    if (pathname !== "/v1/connect") return new Response("not found", { status: 404 });
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }
    return new Response("unauthorized", { status: 401 });
  },
} satisfies ExportedHandler<Env>;
