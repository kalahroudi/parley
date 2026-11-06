// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T308 measurement Worker, deployed only as a throwaway `parley-test-*` Worker by tests/reality/cf/retention-run.mjs
// (and run under `wrangler dev` by tests/reality/cf/retention.test.mjs). It holds no product code: a SQLite-backed
// Durable Object `Vault` shaped like the Task DO's storage (key-value rows, an alarm that deletes a held row), and an
// R2 bucket, both behind /__vault and /__r2 (guarded by PROBE_TOKEN). Bodies are random test strings.
import { DurableObject } from "cloudflare:workers";

interface Env {
  VAULT: DurableObjectNamespace<Vault>;
  BUCKET: R2Bucket;
  PROBE_TOKEN: string;
}

export class Vault extends DurableObject<Env> {
  async put(key: string, value: string): Promise<void> {
    await this.ctx.storage.put(key, value);
  }

  async putSql(id: string, body: string): Promise<void> {
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS held (id TEXT PRIMARY KEY, body TEXT NOT NULL)");
    this.ctx.storage.sql.exec("INSERT OR REPLACE INTO held (id, body) VALUES (?, ?)", id, body);
  }

  async del(key: string): Promise<void> {
    await this.ctx.storage.delete(key);
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS held (id TEXT PRIMARY KEY, body TEXT NOT NULL)");
    this.ctx.storage.sql.exec("DELETE FROM held WHERE id = ?", key);
  }

  // The product's TTL path: an alarm deletes the held row.
  async holdWithTtl(key: string, value: string, ttlMs: number): Promise<void> {
    await this.ctx.storage.put(key, value);
    await this.ctx.storage.put("ttl:key", key);
    await this.ctx.storage.setAlarm(Date.now() + ttlMs);
  }

  override async alarm(): Promise<void> {
    const key = await this.ctx.storage.get<string>("ttl:key");
    if (key) await this.ctx.storage.delete([key, "ttl:key"]);
  }

  async wipe(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }

  async read(): Promise<{ kv: Record<string, string>; sql: Record<string, string> }> {
    const kv = Object.fromEntries(await this.ctx.storage.list<string>());
    const sql: Record<string, string> = {};
    try {
      for (const r of this.ctx.storage.sql.exec<{ id: string; body: string }>("SELECT id, body FROM held")) sql[r.id] = r.body;
    } catch {
      // no table yet: nothing was ever put with putSql
    }
    return { kv, sql };
  }

  async bookmark(): Promise<string> {
    return this.ctx.storage.getCurrentBookmark();
  }

  async bookmarkAt(ms: number): Promise<string> {
    return this.ctx.storage.getBookmarkForTime(ms);
  }

  // Restores the object to a bookmark: the restore applies when the object next starts, so the object is reset.
  async restore(bookmark: string): Promise<never> {
    await this.ctx.storage.onNextSessionRestoreBookmark(bookmark);
    this.ctx.abort("restore");
    throw new Error("unreachable");
  }
}

type VaultOp = { name: string; op: string; args?: unknown[] };
type R2Op = { op: string; key?: string; keys?: string[]; body?: string; prefix?: string; parts?: number };

const NAME = /^[A-Za-z0-9_-]{1,64}$/;
const KEY = /^[A-Za-z0-9_./-]{1,200}$/;
const PART = 5 * 1024 * 1024; // R2's minimum size for every part but the last

async function r2(env: Env, b: R2Op): Promise<unknown> {
  const key = b.key ?? "";
  if (b.op !== "list" && b.op !== "delete" && !KEY.test(key)) throw new Error("bad key");
  switch (b.op) {
    case "put": {
      const o = await env.BUCKET.put(key, b.body ?? "");
      return { etag: o?.etag, size: o?.size };
    }
    case "head": {
      const o = await env.BUCKET.head(key);
      return o ? { size: o.size, etag: o.etag } : null;
    }
    case "get": {
      const o = await env.BUCKET.get(key);
      return o ? { body: await o.text() } : null;
    }
    case "list": {
      const l = await env.BUCKET.list({ prefix: b.prefix ?? "", limit: 1000 });
      return { keys: l.objects.map((o) => o.key), truncated: l.truncated };
    }
    case "delete": {
      const keys = b.keys ?? [key];
      if (!keys.every((k) => KEY.test(k))) throw new Error("bad key");
      await env.BUCKET.delete(keys);
      return { deleted: keys.length };
    }
    case "multipart": {
      // Two parts: one at the minimum part size and a short last one.
      const mpu = await env.BUCKET.createMultipartUpload(key);
      const first = await mpu.uploadPart(1, new Uint8Array(PART).fill(97));
      const last = await mpu.uploadPart(2, new TextEncoder().encode(b.body ?? "tail"));
      const o = await mpu.complete([first, last]);
      return { size: o.size };
    }
    case "multipart-abort": {
      const mpu = await env.BUCKET.createMultipartUpload(key);
      await mpu.uploadPart(1, new Uint8Array(PART).fill(98));
      await mpu.abort();
      return { aborted: true };
    }
    default:
      throw new Error("unknown op");
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === "/healthz") return new Response("ok");
    if (!env.PROBE_TOKEN || request.headers.get("x-probe-token") !== env.PROBE_TOKEN) return new Response("unauthorized", { status: 401 });
    try {
      if (pathname === "/__r2") return Response.json({ result: await r2(env, (await request.json()) as R2Op) });
      if (pathname === "/__vault") {
        const b = (await request.json()) as VaultOp;
        if (!NAME.test(b.name)) return new Response("bad name", { status: 400 });
        const stub = env.VAULT.get(env.VAULT.idFromName(b.name)) as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
        if (!["put", "putSql", "del", "holdWithTtl", "wipe", "read", "bookmark", "bookmarkAt", "restore"].includes(b.op)) return new Response("unknown op", { status: 400 });
        try {
          return Response.json({ result: (await stub[b.op]!(...(b.args ?? []))) ?? null });
        } catch (err) {
          // restore resets the object, which fails the call that asked for it; that is the expected outcome.
          if (b.op === "restore") return Response.json({ result: "reset" });
          throw err;
        }
      }
    } catch (err) {
      return Response.json({ error: String((err as Error).message ?? err) }, { status: 500 });
    }
    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
