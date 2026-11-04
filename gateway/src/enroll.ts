// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import type { Env } from "./index";
import { csrfOk, principal, tenantStub, type Principal } from "./session";
import { MAX_LIST_BYTES, MAX_SIGNED_BYTES, type SignedBinding, type SignedList, type Tenant } from "./tenant";

const MAX_BODY_BYTES = MAX_LIST_BYTES + 1024;
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

async function body(req: Request): Promise<Record<string, unknown> | null> {
  if (req.method !== "POST") return null;
  // Bound what is buffered before parsing; the largest legitimate body is a
  // revocation list plus a little framing.
  if (Number(req.headers.get("content-length") ?? 0) > MAX_BODY_BYTES) return null;
  try {
    const text = await req.text();
    if (text.length > MAX_BODY_BYTES) return null;
    const b = JSON.parse(text);
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
    let tenant: string | undefined;
    let user: string | undefined;
    if (token !== undefined) {
      tenant = str(b.tenant);
    } else {
      const id = await principal(req, env);
      if (!id) return json(401, { error: "unauthorized" });
      if (!csrfOk(req, id)) return json(403, { error: "csrf" });
      if (id.role !== "user") return json(403, { error: "forbidden" });
      tenant = id.tenant;
      user = id.email;
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
    return e ? json(200, { status: e.status, fingerprint: e.fingerprint, binding: e.binding }) : json(404, { error: "not_found" });
  }

  // The signed list is public and verified by every daemon against the pinned
  // root, so reading it needs no identity. It lists device ids only (metadata).
  if (pathname === "/v1/revocations") {
    const tenant = str(b.tenant);
    if (!tenant || !ID.test(tenant)) return json(400, { error: "bad_request" });
    const l = await tenantStub(env, tenant).revocations();
    return l ? json(200, l) : json(404, { error: "not_found" });
  }

  const admin: Principal | null = await principal(req, env);
  if (!admin) return json(401, { error: "unauthorized" });
  if (!csrfOk(req, admin)) return json(403, { error: "csrf" });
  if (admin.role !== "admin") return json(403, { error: "forbidden" });
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
  if (pathname === "/v1/admin/bindings") {
    const sb = signed(b.binding);
    if (!sb || typeof sb.device_id !== "string" || typeof sb.signing_key !== "string" || !Number.isSafeInteger(sb.version) || (sb.version as number) < 1) {
      return json(400, { error: "bad_request" });
    }
    const r = await stub.putBinding(str(b.id) ?? "", sb as SignedBinding);
    if (r === "not_found") return json(404, { error: "not_found" });
    if (r === "not_approved" || r === "mismatch" || r === "rollback") return json(409, { error: r });
    return json(200, { ok: true });
  }
  if (pathname === "/v1/admin/revocations") {
    const l = signed(b.list, MAX_LIST_BYTES);
    if (!l || l.tenant !== admin.tenant || !Number.isSafeInteger(l.version) || (l.version as number) < 1) return json(400, { error: "bad_request" });
    return (await stub.putRevocations(l as SignedList)) === "ok" ? json(200, { ok: true }) : json(409, { error: "rollback" });
  }
  return json(404, { error: "not_found" });
}

// A small JSON object posted by the admin's daemon.
function signed(v: unknown, max = MAX_SIGNED_BYTES): Record<string, unknown> | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  return JSON.stringify(v).length <= max ? (v as Record<string, unknown>) : null;
}
