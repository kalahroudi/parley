// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Starts the real gateway Worker under `wrangler dev` next to a mock OIDC
// server, and signs users in through it. This is how tests get a session: the
// gateway has no development bypass, so a test logs in the way a person does.

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startMockOidc } from "./oidc.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..", "..");

const freePort = () =>
  new Promise((resolve, reject) => {
    const s = createServer().once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

function kill(child) {
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else process.kill(-child.pid, "SIGKILL");
  } catch {}
}

// `admins` is the gateway's ADMINS setting (`tenant:email,...`); `users` and `userDomains` are USERS and
// USER_DOMAINS (`tenant:email` / `tenant:domain`), without which no user can sign in. The login rate limits are
// raised out of the way (tests sign in dozens of times from one address); `extra` overrides any variable.
export async function startGateway({ admins = "", users = "", userDomains = "", extra = {} } = {}) {
  const idp = await startMockOidc();
  const port = await freePort();
  const vars = { FLOW_SECRET: "test-flow-secret", GOOGLE_CLIENT_ID: "parley", GOOGLE_ISSUER: idp.issuer, ADMINS: admins, USERS: users, USER_DOMAINS: userDomains, RATE_AUTH_PER_MIN: "100000", RATE_TENANT_LOGIN_PER_MIN: "100000", RATE_SESSION_PER_MIN: "100000", ...extra };
  // Own state directory and inspector port, so several gateways can run side by side (node --test runs files in parallel).
  const args = ["wrangler", "dev", "--port", String(port), "--inspector-port", String(await freePort()), "--persist-to", mkdtempSync(join(tmpdir(), "parley-gw-"))];
  for (const [k, v] of Object.entries(vars)) if (v) args.push("--var", `${k}:${v}`);
  const gw = spawn("npx", args, {
    cwd: join(root, "gateway"),
    stdio: "ignore",
    shell: process.platform === "win32",
    detached: process.platform !== "win32",
  });
  const url = `http://127.0.0.1:${port}`;
  const close = async () => {
    kill(gw);
    await idp.close();
  };
  try {
    const end = Date.now() + 60000;
    for (;;) {
      if (gw.exitCode !== null) throw new Error("wrangler dev exited early");
      if (await fetch(`${url}/healthz`).then((r) => r.ok, () => false)) break;
      if (Date.now() > end) throw new Error("gateway did not start");
      await new Promise((r) => setTimeout(r, 200));
    }
  } catch (e) {
    await close();
    throw e;
  }
  return { url, idp, close, signIn: (o) => signIn(url, o) };
}

// Runs the login the way a browser does (without one) and returns the callback
// response plus, on success, the session cookie value (usable as
// `Authorization: Bearer <token>`) and the CSRF token.
export async function signIn(url, { tenant, role, email }) {
  const qs = new URLSearchParams({ tenant, role, login_hint: email });
  const jar = new Map();
  const keep = (res) => {
    for (const c of res.headers.getSetCookie()) {
      const [kv, ...attrs] = c.split(";");
      const [k, ...v] = kv.split("=");
      if (v.join("=") === "" || /max-age=0/i.test(attrs.join(";"))) jar.delete(k);
      else jar.set(k, v.join("="));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(`${url}/auth/google/login?${qs}`, { redirect: "manual" });
  keep(res);
  res = await fetch(res.headers.get("location"), { redirect: "manual" }); // the mock IdP approves at once
  const back = new URL(res.headers.get("location"));
  res = await fetch(`${url}${back.pathname}${back.search}`, { headers: { cookie: cookie() }, redirect: "manual" });
  const setCookies = res.headers.getSetCookie();
  const body = await res.json();
  const session = setCookies.find((c) => c.startsWith("parley_session="));
  return { status: res.status, body, setCookies, token: session?.split(";")[0].split("=")[1], csrf: body.csrf };
}
