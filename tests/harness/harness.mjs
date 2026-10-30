// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Local harness: boots the gateway, a mock OIDC server and N daemons.
// Run with `make dev` (see CONTRIBUTING.md); tests import start() directly.
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startMockOidc } from "./oidc.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const repo = join(here, "..", "..");

function freePort() {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function waitFor(fn, what, ms = 15000) {
  const end = Date.now() + ms;
  for (;;) {
    try {
      if (await fn()) return;
    } catch {}
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

function stopChild(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    child.once("exit", resolve);
    child.kill("SIGTERM");
    setTimeout(() => child.kill("SIGKILL"), 3000).unref();
  });
}

export async function start({ daemons = 2, quiet = false } = {}) {
  const children = [];
  const dir = mkdtempSync(join(tmpdir(), "parley-dev-"));
  const stdio = quiet ? "ignore" : "inherit";
  const stop = async () => {
    await Promise.all(children.map(stopChild));
    await oidc?.close();
    rmSync(dir, { recursive: true, force: true });
  };
  let oidc;
  try {
    oidc = await startMockOidc();

    const gwPort = await freePort();
    const gatewayUrl = `http://127.0.0.1:${gwPort}`;
    const env = { ...process.env, PORT: String(gwPort) };
    const cmd = process.env.PARLEY_GATEWAY_CMD;
    const gateway = cmd
      ? spawn(cmd, { shell: true, cwd: join(repo, "gateway"), env, stdio })
      : spawn(process.execPath, [join(here, "stub-gateway.mjs")], { env, stdio });
    children.push(gateway);
    await waitFor(async () => (await fetch(`${gatewayUrl}/healthz`)).ok, "gateway");

    const bin = join(dir, process.platform === "win32" ? "parleyd.exe" : "parleyd");
    const build = spawnSync("go", ["build", "-o", bin, "./cmd/parleyd"], { cwd: repo, stdio });
    if (build.status !== 0) throw new Error("go build ./cmd/parleyd failed");

    const procs = [];
    for (let i = 1; i <= daemons; i++) {
      const home = join(dir, `daemon-${i}`);
      const child = spawn(bin, [], {
        stdio,
        env: {
          ...process.env,
          PARLEY_HOME: home,
          PARLEY_GATEWAY_URL: gatewayUrl,
          PARLEY_OIDC_ISSUER: oidc.issuer,
        },
      });
      children.push(child);
      procs.push({ name: `daemon-${i}`, home, child });
    }
    await new Promise((r) => setTimeout(r, 200));
    for (const p of procs) {
      if (p.child.exitCode !== null) throw new Error(`${p.name} exited early`);
    }
    return { gatewayUrl, oidcIssuer: oidc.issuer, daemons: procs, stop };
  } catch (err) {
    await stop();
    throw err;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const n = Number(process.env.N ?? 2);
  const h = await start({ daemons: n });
  console.log(`gateway  ${h.gatewayUrl}\noidc     ${h.oidcIssuer}\ndaemons  ${n}\nCtrl-C to stop`);
  const bye = () => h.stop().then(() => process.exit(0));
  process.on("SIGINT", bye);
  process.on("SIGTERM", bye);
}
