// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109 measurement build of the gateway, deployed only as a throwaway
// `parley-test-*` Worker by tests/reality/cf/run.mjs. It re-exports the real
// gateway and adds, to the Device DO, only what the measurements need:
//   - a `{"t":"probe"}` frame answered with the object's boot id, its boot count
//     (kept in storage, so every wake is counted) and its age, which shows
//     whether it hibernated and what woke it;
//   - RPC methods behind /__push, /__drop and /__counters (guarded by PROBE_TOKEN)
//     that stand in for a peer pushing events, a forced disconnect and a read of
//     the counters. Bodies are test strings; nothing here is in the product.
import { Device as BaseDevice, Tenant } from "../../../../gateway/src/index";
import gateway, { type Env } from "../../../../gateway/src/index";
import { REFUSED_PAGE, SIGNED_IN_PAGE, summarize } from "../../logins/summary.ts";

export { Tenant };

interface ProbeEnv extends Env {
  PROBE_TOKEN: string;
  // "1" in the `parley-test-login` Worker only: the Google callback result is kept
  // as a redacted summary (see ../../logins/summary.ts) and read back through /__login-result.
  LOGIN_CHECK?: string;
}

export class Device extends BaseDevice {
  private readonly boot = crypto.randomUUID();
  private readonly startedAt = Date.now();
  private boots = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    void ctx.blockConcurrencyWhile(async () => {
      this.boots = ((await ctx.storage.get<number>("boots")) ?? 0) + 1;
      await ctx.storage.put("boots", this.boots);
    });
  }

  override async webSocketMessage(ws: WebSocket, data: string | ArrayBuffer): Promise<void> {
    if (data === '{"t":"probe"}') {
      ws.send(JSON.stringify({ t: "probe", boot: this.boot, boots: this.boots, ageMs: Date.now() - this.startedAt }));
      return;
    }
    return super.webSocketMessage(ws, data);
  }

  // Pushes bodies in order and stops at the first one that is not delivered.
  async pushBatch(bodies: string[]): Promise<{ statuses: string[] }> {
    const statuses: string[] = [];
    for (const b of bodies) {
      const r = await this.deliver(b);
      statuses.push(r.status);
      if (r.status !== "delivered") break;
    }
    return { statuses };
  }

  async setLoginResult(r: unknown): Promise<void> {
    await this.ctx.storage.put("login", r);
  }

  async getLoginResult(): Promise<unknown> {
    return (await this.ctx.storage.get("login")) ?? null;
  }

  drop(code: number): number {
    const sockets = this.ctx.getWebSockets();
    for (const ws of sockets) ws.close(code, "probe");
    return sockets.length;
  }

  async counters(): Promise<{ boots: number; boot: string; ageMs: number; session?: unknown }> {
    return { boots: this.boots, boot: this.boot, ageMs: Date.now() - this.startedAt, session: (await this.status()).session };
  }
}

const ID = /^[A-Za-z0-9_-]{1,64}$/;

export default {
  async fetch(request: Request, env: ProbeEnv): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (env.LOGIN_CHECK === "1" && pathname === "/auth/google/callback") {
      const res = await gateway.fetch(request, env);
      const body: unknown = await res
        .clone()
        .json()
        .catch(() => ({}));
      const summary = summarize(res.status, body, env.GOOGLE_HOSTED_DOMAIN);
      const stub = env.DEVICE.get(env.DEVICE.idFromName("login:result")) as unknown as DurableObjectStub<Device>;
      await stub.setLoginResult({ ...summary, at: Date.now() });
      // The browser is shown a plain page, not the identity; the gateway's cookie clearing is kept.
      const headers = new Headers({ "content-type": "text/plain", "cache-control": "no-store" });
      const cookie = res.headers.get("set-cookie");
      if (cookie) headers.set("set-cookie", cookie);
      return new Response(summary.ok ? SIGNED_IN_PAGE : REFUSED_PAGE, { status: res.status, headers });
    }
    if (!pathname.startsWith("/__")) return gateway.fetch(request, env);
    if (!env.PROBE_TOKEN || request.headers.get("x-probe-token") !== env.PROBE_TOKEN) return new Response("unauthorized", { status: 401 });
    if (pathname === "/__login-result") {
      const stub = env.DEVICE.get(env.DEVICE.idFromName("login:result")) as unknown as DurableObjectStub<Device>;
      return Response.json({ result: await stub.getLoginResult() });
    }
    const b = (await request.json()) as { tenant: string; device: string; bodies?: string[]; code?: number };
    if (!ID.test(b.tenant) || !ID.test(b.device)) return new Response("bad id", { status: 400 });
    const stub = env.DEVICE.get(env.DEVICE.idFromName(`${b.tenant}:${b.device}`)) as unknown as DurableObjectStub<Device>;
    if (pathname === "/__push") return Response.json(await stub.pushBatch(b.bodies ?? []));
    if (pathname === "/__drop") return Response.json({ closed: await stub.drop(b.code ?? 1012) });
    if (pathname === "/__counters") return Response.json(await stub.counters());
    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<ProbeEnv>;
