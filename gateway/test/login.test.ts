// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { confirmPage } from "../src/login";
import { LOGIN_TTL_MS, MAX_PENDING_LOGINS } from "../src/tenant";

const hex = (b: ArrayBuffer | Uint8Array) => [...(b instanceof Uint8Array ? b : new Uint8Array(b))].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha = async (s: string) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
const rnd = () => hex(crypto.getRandomValues(new Uint8Array(32)));
let n = 0;
const tenant = () => `lg${++n}`;
const stub = (t: string) => env.TENANT.get(env.TENANT.idFromName(t));
const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  SELF.fetch(`https://gw${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });
const form = (f: Record<string, string>, origin: string | null = "https://gw") =>
  SELF.fetch("https://gw/v1/login/confirm", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...(origin ? { Origin: origin } : {}) }, body: new URLSearchParams(f).toString() });

// Starts a login the way the CLI does and returns what it keeps.
async function start(t: string) {
  const session = rnd();
  const poll = rnd();
  const r = await post("/v1/login/start", { tenant: t, session_hash: await sha(session), poll_hash: await sha(poll) });
  expect(r.status).toBe(201);
  return { session, poll, ...((await r.json()) as { id: string; code: string; expires_at: number }) };
}
const page = async (t: string, id: string, email = "alice@acme.test") => {
  const res = await confirmPage(env as never, t, email, id);
  return { res, html: await res.text() };
};
const bodyOf = async (r: Response) => ({ status: r.status, json: await r.json() });
const BAD = { error: "bad_request" };
const NOT_FOUND = { error: "not_found" };
// A start request padded with an unused field to exactly `n` bytes.
const padded = async (t: string, n: number) => {
  const base = JSON.stringify({ tenant: t, session_hash: await sha("a"), poll_hash: await sha("b"), pad: "" });
  return base.replace('"pad":""', `"pad":"${"x".repeat(n - base.length)}"`);
};
const field = (html: string, name: string) => new RegExp(`name="${name}" value="([^"]*)"`).exec(html)![1]!;

describe("device login", () => {
  it("runs start, IdP login, confirmation and poll, and only then is the CLI's session valid", async () => {
    const t = tenant();
    const l = await start(t);
    expect(l.code).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}$/);
    expect(l.expires_at).toBeGreaterThan(Date.now());
    expect(await (await post("/v1/login/poll", { tenant: t, id: l.id, poll: l.poll })).json()).toEqual({ state: "pending" });
    expect(await stub(t).getSession(l.session)).toBeNull();

    const { res, html } = await page(t, l.id);
    expect(res.status).toBe(200);
    expect(html).toContain(l.code);
    expect(html).toContain("alice@acme.test");
    expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(res.headers.get("content-security-policy")).toBe("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(html).toContain("<title>Parley sign-in</title>");
    expect(html).toContain("Does the terminal show this code?");
    // Authenticating alone gives the CLI nothing.
    expect(await stub(t).getSession(l.session)).toBeNull();
    expect(await (await post("/v1/login/poll", { tenant: t, id: l.id, poll: l.poll })).json()).toEqual({ state: "pending" });

    const body = { tenant: field(html, "tenant"), id: field(html, "id"), confirm: field(html, "confirm") };
    const done = await form(body);
    expect(done.status).toBe(200);
    expect(done.headers.get("cache-control")).toBe("no-store");
    expect(await done.text()).toContain("<h1>Done</h1><p>You can close this window and go back to the terminal.</p>");
    expect(await stub(t).getSession(l.session)).toMatchObject({ email: "alice@acme.test", role: "user" });
    // The poll answer is given once; the secret itself never passed through the gateway.
    expect(await (await post("/v1/login/poll", { tenant: t, id: l.id, poll: l.poll })).json()).toEqual({ state: "done" });
    expect((await post("/v1/login/poll", { tenant: t, id: l.id, poll: l.poll })).status).toBe(404);
    const replay = await form(body);
    expect(replay.status).toBe(410); // a confirmation is not replayable
    expect(await replay.text()).toContain("<h1>This sign-in has expired</h1><p>Run <code>parley-cli login</code> again.</p>");
  });

  it("refuses bad starts and polls", async () => {
    const t = tenant();
    const ok = { session_hash: await sha("a"), poll_hash: await sha("b") };
    const arrayHash = { tenant: t, ...ok, session_hash: [ok.session_hash] };
    const bads = [{ tenant: t }, { tenant: t, ...ok, session_hash: "xyz" }, { tenant: t, ...ok, poll_hash: 5 }, arrayHash, { tenant: "a/b", ...ok }, { tenant: 5, ...ok }, {}, [], "nope", "null", "5", "0", '"s"', "{"];
    for (const b of bads) expect(await bodyOf(await post("/v1/login/start", b))).toEqual({ status: 400, json: BAD });
    const refused = await post("/v1/login/start", { tenant: t });
    expect(refused.headers.get("content-type")).toBe("application/json");
    expect(refused.headers.get("cache-control")).toBe("no-store");
    const l = await start(t);
    for (const poll of [{ tenant: t, id: l.id, poll: rnd() }, { tenant: t, id: "short", poll: l.poll }, { tenant: t, id: 5, poll: l.poll }, { tenant: t, poll: l.poll }, { tenant: tenant(), id: l.id, poll: l.poll }]) {
      expect(await bodyOf(await post("/v1/login/poll", poll))).toEqual({ status: 404, json: NOT_FOUND }); // wrong secret, bad id, another tenant
    }
    expect(await bodyOf(await post("/v1/login/other", { tenant: t }))).toEqual({ status: 404, json: NOT_FOUND });
    expect(await bodyOf(await post("/v1/login/constructor", { tenant: t }))).toEqual({ status: 404, json: NOT_FOUND });
    expect(await bodyOf(await SELF.fetch("https://gw/v1/login/start"))).toEqual({ status: 405, json: { error: "method_not_allowed" } });
  });

  it("caps the request body at 2048 bytes, announced or not", async () => {
    const t = tenant();
    const send = (body: BodyInit, headers: Record<string, string> = {}) => SELF.fetch("https://gw/v1/login/start", { method: "POST", headers, body, duplex: "half" } as RequestInit);
    const stream = (text: string) => new ReadableStream({ start: (c) => { c.enqueue(new TextEncoder().encode(text)); c.close(); } });
    expect((await send(await padded(t, 2048))).status).toBe(201);
    expect(await bodyOf(await send(await padded(t, 2049)))).toEqual({ status: 400, json: BAD });
    // No announced length: the size is checked after reading.
    expect((await send(stream(await padded(t, 2048)))).status).toBe(201);
    expect(await bodyOf(await send(stream(await padded(t, 2049))))).toEqual({ status: 400, json: BAD });
    // Multi-byte text counts in bytes, not characters.
    expect((await send(stream((await padded(t, 2000)).replace("x".repeat(50), "é".repeat(50))))).status).toBe(400);
    // An announced length over the cap is refused without reading: the body here is fine.
    expect((await send(await padded(t, 300), { "content-length": "2049" })).status).toBe(400);
    expect((await send(await padded(t, 300), { "content-length": "2048" })).status).not.toBe(400);
  });

  it("confirms only a code that was shown, from this origin, once", async () => {
    const t = tenant();
    const l = await start(t);
    expect((await form({ tenant: t, id: l.id, confirm: "0".repeat(32) })).status).toBe(410); // not authenticated yet
    const html = (await page(t, l.id)).html;
    const good = { tenant: t, id: l.id, confirm: field(html, "confirm") };
    expect((await form({ ...good, confirm: "0".repeat(32) })).status).toBe(410);
    const refusedForm = await form(good, "https://evil.example");
    expect(refusedForm.status).toBe(400);
    expect(await refusedForm.text()).toContain("<h1>Not accepted</h1>");
    expect((await form(good, null)).status).toBe(400);
    expect((await form({ ...good, id: "x" })).status).toBe(400);
    expect((await form({ ...good, id: `z${l.id}` })).status).toBe(400); // the id is exactly 32 hex characters
    expect((await form({ ...good, id: `${l.id}z` })).status).toBe(400);
    expect((await form({ ...good, id: l.id.toUpperCase() })).status).toBe(400);
    expect((await form({ ...good, tenant: "a/b" })).status).toBe(400);
    expect((await form({ tenant: t, id: l.id })).status).toBe(410); // no confirm field
    expect((await page(t, l.id)).res.status).toBe(410); // authenticated only once
    expect((await form(good)).status).toBe(200);
    expect(await stub(t).getSession(l.session)).not.toBeNull();
  });

  it("answers an expired or unknown login with a page, and escapes what it shows", async () => {
    const t = tenant();
    expect((await page(t, "f".repeat(32))).res.status).toBe(410);
    expect((await page(t, "not-an-id")).res.status).toBe(410);
    const l = await start(t);
    const { html } = await page(t, l.id, `a&b'c"d<e>@x.test`);
    expect(html).toContain("a&#38;b&#39;c&#34;d&#60;e&#62;@x.test");
    const l2 = await start(t);
    await runInDurableObject(stub(t), async (_i, state) => {
      const r = (await state.storage.get<{ exp: number }>(`lgn:${l2.id}`))!;
      await state.storage.put(`lgn:${l2.id}`, { ...r, exp: Date.now() - 1 });
    });
    expect((await page(t, l2.id)).res.status).toBe(410);
    expect((await post("/v1/login/poll", { tenant: t, id: l2.id, poll: l2.poll })).status).toBe(404);
    await runDurableObjectAlarm(stub(t));
    await runInDurableObject(stub(t), async (_i, state) => expect(await state.storage.get(`lgn:${l2.id}`)).toBeUndefined());
  });

  it("caps pending logins per tenant and frees the room when they expire", async () => {
    const t = tenant();
    for (let i = 0; i < MAX_PENDING_LOGINS; i++) await stub(t).loginStart(await sha(`s${i}`), await sha(`p${i}`));
    expect(await bodyOf(await post("/v1/login/start", { tenant: t, session_hash: await sha("s"), poll_hash: await sha("p") }))).toEqual({ status: 429, json: { error: "too_many" } });
    await runInDurableObject(stub(t), async (_i, state) => {
      for (const [k, v] of await state.storage.list<{ exp: number }>({ prefix: "lgn:" })) await state.storage.put(k, { ...v, exp: Date.now() - LOGIN_TTL_MS });
    });
    expect((await post("/v1/login/start", { tenant: t, session_hash: await sha("s"), poll_hash: await sha("p") })).status).toBe(201);
  });

  it("will not let a login take over an existing session's hash", async () => {
    const t = tenant();
    const existing = await stub(t).createSession("victim@acme.test", "user");
    const r = (await stub(t).loginStart(await sha(existing.secret), await sha("p"))) as { id: string };
    const { html } = await page(t, r.id, "attacker@acme.test");
    expect((await form({ tenant: t, id: r.id, confirm: field(html, "confirm") })).status).toBe(410);
    expect((await stub(t).getSession(existing.secret))!.email).toBe("victim@acme.test");
  });
});
