// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { handle as handleAuth, type AuthEnv } from "./auth.ts";
import { Device } from "./device";
import { handleEnroll } from "./enroll";
import { Task } from "./task";
import { Tenant } from "./tenant";

export { Device, Task, Tenant };

export interface Env extends AuthEnv {
  DEVICE: DurableObjectNamespace<Device>;
  TENANT: DurableObjectNamespace<Tenant>;
  TASK: DurableObjectNamespace<Task>;
  // "1" enables the development bearer token `dev:<tenant>:<device>`. Never set in production.
  DEV_AUTH?: string;
}

interface Identity {
  tenant: string;
  device: string;
}

const ID = /^[A-Za-z0-9_-]{1,64}$/;

// Placeholder until connect tokens land. Fails closed:
// without DEV_AUTH every request is unauthenticated.
function authenticate(request: Request, env: Env): Identity | null {
  if (env.DEV_AUTH !== "1") return null;
  const m = /^Bearer dev:([^:]+):([^:]+)$/.exec(request.headers.get("Authorization") ?? "");
  if (!m || !ID.test(m[1]!) || !ID.test(m[2]!)) return null;
  return { tenant: m[1]!, device: m[2]! };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Identifiers travel in the Authorization header and frames, never in the URL.
    const { pathname } = new URL(request.url);
    if (pathname === "/healthz") return Response.json({ ok: true, service: "gateway" });
    if (pathname.startsWith("/auth/")) return handleAuth(request, env);
    if (pathname.startsWith("/v1/enroll/") || pathname.startsWith("/v1/admin/") || pathname === "/v1/revocations") return handleEnroll(request, env);
    if (pathname !== "/v1/connect") return new Response("not found", { status: 404 });
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }
    const id = authenticate(request, env);
    if (!id) return new Response("unauthorized", { status: 401 });
    // The tenant id is part of the name, so one tenant can never reach another's device.
    return env.DEVICE.get(env.DEVICE.idFromName(`${id.tenant}:${id.device}`)).fetch(request);
  },
} satisfies ExportedHandler<Env>;
