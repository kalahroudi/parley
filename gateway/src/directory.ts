// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import type { Env } from "./index";
import type { DirectoryError, Tenant } from "./tenant";

const ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_BODY_BYTES = 16384;
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
const fail = (r: { error: DirectoryError; field?: string }) => json(STATUS[r.error], r.field ? { error: r.error, field: r.field } : { error: r.error });

// Placeholders until sessions and connect tokens land; both fail closed without
// DEV_AUTH. `Bearer dev:<tenant>:<device>` is an enrolled device (the same
// bearer as /v1/connect); `Bearer dev-admin:<tenant>` is a tenant admin.
function identity(req: Request, env: Env): { admin: boolean; tenant: string; device?: string } | null {
  if (env.DEV_AUTH !== "1") return null;
  const h = req.headers.get("Authorization") ?? "";
  let m = /^Bearer dev-admin:([^:]+)$/.exec(h);
  if (m && ID.test(m[1]!)) return { admin: true, tenant: m[1]! };
  m = /^Bearer dev:([^:]+):([^:]+)$/.exec(h);
  if (m && ID.test(m[1]!) && ID.test(m[2]!)) return { admin: false, tenant: m[1]!, device: m[2]! };
  return null;
}

async function body(req: Request): Promise<Record<string, unknown> | null> {
  if (req.method !== "POST" || Number(req.headers.get("content-length") ?? 0) > MAX_BODY_BYTES) return null;
  try {
    const text = await req.text();
    if (text.length > MAX_BODY_BYTES) return null;
    const b = JSON.parse(text);
    return b && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

// Every route is a POST with a JSON body (no identifier in a URL). Devices
// publish, remove and find cards; the admin manages groups.
export async function handleDirectory(req: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(req.url);
  const b = await body(req);
  if (!b) return json(req.method === "POST" ? 400 : 405, { error: req.method === "POST" ? "bad_request" : "method_not_allowed" });
  const id = identity(req, env);
  if (!id) return json(401, { error: "unauthorized" });
  const stub = env.TENANT.get(env.TENANT.idFromName(id.tenant)) as DurableObjectStub<Tenant>;
  const str = (v: unknown) => (typeof v === "string" ? v : "");

  if (pathname.startsWith("/v1/admin/groups")) {
    if (!id.admin) return json(401, { error: "unauthorized" });
    if (pathname === "/v1/admin/groups") return json(200, { groups: await stub.groups() });
    if (pathname === "/v1/admin/groups/put") {
      const r = await stub.putGroup(b.name, b.members);
      return "error" in r ? fail(r) : json(200, r);
    }
    if (pathname === "/v1/admin/groups/delete") return (await stub.deleteGroup(str(b.name))) ? json(200, { ok: true }) : json(404, { error: "not_found" });
    return json(404, { error: "not_found" });
  }

  if (id.admin || !id.device) return json(401, { error: "unauthorized" });
  if (pathname === "/v1/cards/publish") {
    const r = await stub.publishCard(id.device, b.card);
    return "error" in r ? fail(r) : json(200, r);
  }
  if (pathname === "/v1/cards/remove") return (await stub.removeCard(id.device, str(b.id))) ? json(200, { ok: true }) : json(404, { error: "not_found" });
  if (pathname === "/v1/directory/find") {
    const r = await stub.find(id.device, b.query);
    return "error" in r ? fail(r) : json(200, r);
  }
  return json(404, { error: "not_found" });
}
