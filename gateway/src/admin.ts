// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { readBounded } from "./a2a";
import { validatePage } from "./acl";
import type { Env } from "./index";
import { csrfOk, principal, sessionCookie } from "./session";
import { CSV_PAGE_DEFAULT, CSV_PAGE_MAX, EXPORT_SECTIONS, tenantStub, type CsvKind, type ExportSection } from "./tenant";

const MAX_BODY_BYTES = 2048;
const json = (status: number, body: unknown, headers: HeadersInit = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });

const KEYS: Record<string, readonly string[]> = {
  "/v1/admin/export": ["section", "limit", "cursor"],
  "/v1/admin/audit/csv": ["kind", "limit", "cursor"],
  "/v1/admin/tenant/delete": ["confirm"],
};

// The security team's views of the tenant (journey L): the metadata audit CSV, the tenant export and tenant
// deletion. Admin only, every route a POST with a JSON body (no identifier in a URL), and the CSRF rules of every
// other admin route. Content is not here to be shown: the gateway holds none.
export async function handleAdmin(req: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(req.url);
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
  const p = await principal(req, env);
  if (!p) return json(401, { error: "unauthorized" });
  if (!csrfOk(req, p)) return json(403, { error: "csrf" });
  if (p.role !== "admin") return json(403, { error: "forbidden" });

  let b: unknown;
  try {
    b = JSON.parse((await readBounded(req, MAX_BODY_BYTES)) ?? "");
  } catch {
    return json(400, { error: "bad_request" });
  }
  if (typeof b !== "object" || b === null || Array.isArray(b) || !Object.keys(b).every((k) => KEYS[pathname]!.includes(k))) return json(400, { error: "bad_request" });
  const body = b as Record<string, unknown>;
  const stub = tenantStub(env, p.tenant);

  if (pathname === "/v1/admin/tenant/delete") {
    // Type the name: the request must carry the tenant's own name, so a stray click or a replayed form cannot delete it.
    if (body.confirm !== p.tenant) return json(400, { error: "confirm_mismatch" });
    await stub.deleteTenant();
    return json(200, { deleted: true }, { "set-cookie": sessionCookie(req, "", 0) });
  }

  if (pathname === "/v1/admin/export") {
    const page = validatePage(body);
    if (!page || !EXPORT_SECTIONS.includes(body.section as ExportSection)) return json(400, { error: "bad_request" });
    return json(200, await stub.exportSection(body.section as ExportSection, page));
  }

  // The audit CSV. A page of up to CSV_PAGE_MAX rows; the header row is on the first page only.
  const limit = body.limit === undefined ? CSV_PAGE_DEFAULT : body.limit;
  const page = validatePage({ cursor: body.cursor });
  if (!page || (body.kind !== "admin" && body.kind !== "tasks") || !Number.isSafeInteger(limit) || (limit as number) < 1 || (limit as number) > CSV_PAGE_MAX) return json(400, { error: "bad_request" });
  const r = await stub.auditCsv(body.kind as CsvKind, { ...page, limit: limit as number });
  return new Response(r.csv, {
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": `attachment; filename="parley-${body.kind}-audit.csv"`,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...(r.next_cursor ? { "x-next-cursor": r.next_cursor } : {}),
    },
  });
}
