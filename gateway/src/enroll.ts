// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import type { Env } from "./index";
import type { Tenant } from "./tenant";

const ID = /^[A-Za-z0-9_-]{1,64}$/;
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

// Placeholder until sessions land (like the device connect token): fails closed
// without DEV_AUTH. `Bearer dev-admin:<tenant>` is a tenant admin and
// `Bearer dev-user:<tenant>:<email>` a signed-in user.
function devIdentity(req: Request, env: Env): { role: "admin" | "user"; tenant: string; email?: string } | null {
  if (env.DEV_AUTH !== "1") return null;
  const h = req.headers.get("Authorization") ?? "";
  let m = /^Bearer dev-admin:([^:]+)$/.exec(h);
  if (m && ID.test(m[1]!)) return { role: "admin", tenant: m[1]! };
  m = /^Bearer dev-user:([^:]+):([^:]+)$/.exec(h);
  if (m && ID.test(m[1]!)) return { role: "user", tenant: m[1]!, email: m[2]! };
  return null;
}

const tenantStub = (env: Env, tenant: string) => env.TENANT.get(env.TENANT.idFromName(tenant)) as DurableObjectStub<Tenant>;

async function body(req: Request): Promise<Record<string, unknown> | null> {
  if (req.method !== "POST") return null;
  try {
    const b = await req.json();
    return b && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

// Every route is a POST with a JSON body, so no identifier or secret appears in
// a URL. Admin routes need an admin identity; the enrollment routes need an SSO
// identity or a pod token.
export async function handleEnroll(req: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(req.url);
  const b = await body(req);
  if (!b) return json(req.method === "POST" ? 400 : 405, { error: req.method === "POST" ? "bad_request" : "method_not_allowed" });

  if (pathname === "/v1/enroll/request") {
    const token = str(b.token);
    const id = devIdentity(req, env);
    let tenant: string | undefined;
    let user: string | undefined;
    if (token !== undefined) {
      tenant = str(b.tenant);
    } else if (id?.role === "user") {
      tenant = id.tenant;
      user = id.email;
    } else {
      return json(401, { error: "unauthorized" });
    }
    if (!tenant || !ID.test(tenant)) return json(400, { error: "bad_request" });
    const r = await tenantStub(env, tenant).request({ user, token, name: str(b.name) ?? "", signing_key: str(b.signing_key) ?? "" });
    if ("error" in r) return json(r.error === "bad_token" ? 401 : r.error === "queue_full" || r.error === "owner_full" ? 429 : 400, { error: r.error });
    return json(202, r);
  }

  if (pathname === "/v1/enroll/status") {
    const tenant = str(b.tenant);
    if (!tenant || !ID.test(tenant)) return json(400, { error: "bad_request" });
    const e = await tenantStub(env, tenant).status(str(b.id) ?? "", str(b.poll) ?? "");
    return e ? json(200, { status: e.status, fingerprint: e.fingerprint }) : json(404, { error: "not_found" });
  }

  const admin = devIdentity(req, env);
  if (admin?.role !== "admin") return json(401, { error: "unauthorized" });
  const stub = tenantStub(env, admin.tenant);

  if (pathname === "/v1/admin/enrollment-tokens") {
    const ttl = b.ttl_s === undefined ? undefined : Number(b.ttl_s) * 1000;
    const t = await stub.mintToken(str(b.owner) ?? "", ttl);
    return t ? json(201, t) : json(400, { error: "bad_request" });
  }
  if (pathname === "/v1/admin/enrollments") return json(200, { pending: await stub.pending() });
  if (pathname === "/v1/admin/enrollments/decide") {
    const d = b.decision;
    if (d !== "approved" && d !== "rejected") return json(400, { error: "bad_request" });
    const r = await stub.decide(str(b.id) ?? "", d);
    if (r === null) return json(404, { error: "not_found" });
    return r === "conflict" ? json(409, { error: "already_decided" }) : json(200, r);
  }
  return json(404, { error: "not_found" });
}
