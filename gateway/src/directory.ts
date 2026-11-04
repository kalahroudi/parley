// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { isCardId, isDeviceId, validatePage } from "./acl";
import type { Env } from "./index";
import { limitDevice } from "./ratelimit";
import { csrfOk, principal } from "./session";
import type { DirectoryError, Tenant } from "./tenant";

const ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_BODY_BYTES = 16384;
const MAX_GROUP_BODY_BYTES = 65536; // a full group: up to 60,000 characters of members
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

const STATUS: Record<DirectoryError, number> = {
  not_enrolled: 403,
  bad_card: 400,
  secret_detected: 422,
  too_many_cards: 429,
  bad_query: 400,
  bad_group: 400,
  bad_members: 400,
  too_many_groups: 429,
};
const limitedResponse = (retryAfterMs: number) =>
  new Response(JSON.stringify({ error: "rate_limited", retry_after_ms: retryAfterMs }), {
    status: 429,
    headers: { "content-type": "application/json", "cache-control": "no-store", "retry-after": String(Math.ceil(retryAfterMs / 1000)) },
  });
const fail = (r: { error: DirectoryError; field?: string }) => json(STATUS[r.error], r.field ? { error: r.error, field: r.field } : { error: r.error });

// An admin is a session. A device has no credential until connect tokens land,
// so device routes fail closed unless a resolver is injected (tests do).
export type DeviceAuth = (req: Request) => Promise<{ tenant: string; device: string } | null>;
type Identity = { admin: boolean; tenant: string; device?: string };

async function identity(req: Request, env: Env, device?: DeviceAuth): Promise<Identity | { forbidden: true } | null> {
  const p = await principal(req, env);
  if (p) {
    if (p.role !== "admin") return null;
    return csrfOk(req, p) ? { admin: true, tenant: p.tenant } : { forbidden: true };
  }
  const d = device && (await device(req));
  return d && ID.test(d.tenant) && isDeviceId(d.device) ? { admin: false, tenant: d.tenant, device: d.device } : null;
}

async function body(req: Request, max: number): Promise<Record<string, unknown> | null> {
  if (req.method !== "POST" || Number(req.headers.get("content-length") ?? 0) > max) return null;
  try {
    const text = await req.text();
    if (text.length > max) return null;
    const b = JSON.parse(text);
    return b && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

// Every route is a POST with a JSON body (no identifier in a URL). Devices
// publish, remove and find cards; the admin manages groups.
export async function handleDirectory(req: Request, env: Env, deviceAuth?: DeviceAuth): Promise<Response> {
  const { pathname } = new URL(req.url);
  const b = await body(req, pathname === "/v1/admin/groups/put" ? MAX_GROUP_BODY_BYTES : MAX_BODY_BYTES);
  if (!b) return json(req.method === "POST" ? 400 : 405, { error: req.method === "POST" ? "bad_request" : "method_not_allowed" });
  const id = await identity(req, env, deviceAuth);
  if (!id) return json(401, { error: "unauthorized" });
  if ("forbidden" in id) return json(403, { error: "csrf" });
  const stub = env.TENANT.get(env.TENANT.idFromName(id.tenant)) as DurableObjectStub<Tenant>;
  const page = validatePage(b);

  if (pathname.startsWith("/v1/admin/groups")) {
    if (!id.admin) return json(401, { error: "unauthorized" });
    if (pathname === "/v1/admin/groups") return page ? json(200, await stub.groups(page)) : fail({ error: "bad_query" });
    if (pathname === "/v1/admin/groups/get") {
      const g = page && (await stub.group(b.name, page));
      return g ? json(200, g) : json(page ? 404 : 400, { error: page ? "not_found" : "bad_query" });
    }
    if (pathname === "/v1/admin/groups/put") {
      const r = await stub.putGroup(b.name, b.members);
      return "error" in r ? fail(r) : json(200, r);
    }
    if (pathname === "/v1/admin/groups/delete") return (await stub.deleteGroup(b.name)) ? json(200, { ok: true }) : json(404, { error: "not_found" });
    return json(404, { error: "not_found" });
  }
  if (pathname === "/v1/admin/audit") {
    if (!id.admin) return json(401, { error: "unauthorized" });
    return page ? json(200, await stub.auditLog(page)) : fail({ error: "bad_query" });
  }

  if (id.admin || !id.device) return json(401, { error: "unauthorized" });
  if (pathname === "/v1/cards/publish") {
    const r = await stub.publishCard(id.device, b.card);
    return "error" in r ? fail(r) : json(200, r);
  }
  if (pathname === "/v1/cards/remove") return (await stub.removeCard(id.device, isCardId(b.id) ? b.id : "")) ? json(200, { ok: true }) : json(404, { error: "not_found" });
  if (pathname === "/v1/directory/find") {
    if (!page) return fail({ error: "bad_query" });
    const wait = await limitDevice(env, id.tenant, id.device, "find");
    if (wait !== null) return limitedResponse(wait);
    const r = await stub.find(id.device, b.query, page);
    return "error" in r ? fail(r) : json(200, r);
  }
  return json(404, { error: "not_found" });
}
