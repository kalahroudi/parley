// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { agentCard, handleA2A } from "./a2a";
import { handle as handleAuth, type AuthEnv } from "./auth.ts";
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

// Sign-in endpoints are open to anyone, so they are limited per client address
// (login scope, src/ratelimit.ts). The address is hashed before it becomes a
// Durable Object name, and each address gets its own object, whose bucket is
// deleted once it refills. The "~" cannot occur in a tenant id (ID above), so
// these objects never collide with a tenant's. A request with no address (not
// possible behind Cloudflare) shares one bucket.
async function loginLimited(request: Request, env: Env): Promise<Response | null> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "none";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip));
  const name = `~login:${[...new Uint8Array(digest).slice(0, 16)].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
  const r = await (env.TENANT.get(env.TENANT.idFromName(name)) as DurableObjectStub<Tenant>).rateLimit("login", "ip");
  if (r.ok) return null;
  return new Response(JSON.stringify({ error: "rate_limited", retry_after_ms: r.retry_after_ms }), {
    status: 429,
    headers: { "content-type": "application/json", "cache-control": "no-store", "retry-after": String(Math.ceil(r.retry_after_ms / 1000)) },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Identifiers travel in the Authorization header and frames, never in the URL.
    const { pathname } = new URL(request.url);
    if (pathname === "/healthz") return Response.json({ ok: true, service: "gateway" });
    if (pathname.startsWith("/auth/")) return (await loginLimited(request, env)) ?? handleAuth(request, env);
    if (pathname.startsWith("/v1/admin/groups") || pathname === "/v1/admin/audit" || pathname.startsWith("/v1/cards/") || pathname.startsWith("/v1/directory/")) return handleDirectory(request, env);
    if (pathname.startsWith("/v1/enroll/") || pathname.startsWith("/v1/admin/") || pathname === "/v1/revocations") return handleEnroll(request, env);
    if (pathname === "/.well-known/agent-card.json") {
      return request.method === "GET" ? Response.json(agentCard(new URL(request.url).origin)) : new Response("method not allowed", { status: 405 });
    }
    if (pathname === "/a2a") {
      const who = authenticate(request, env);
      return who ? handleA2A(request, env, who) : new Response("unauthorized", { status: 401 });
    }
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
