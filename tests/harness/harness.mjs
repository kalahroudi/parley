// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Local harness: boots the gateway, a mock OIDC server and N daemons.
// Run with `make dev` (see CONTRIBUTING.md); tests import start() directly.
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { startMockOidc } from "./oidc.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const repo = join(here, "..", "..");
const isWindows = process.platform === "win32";

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

async function waitFor(fn, what, { ms = 15000, abort = () => false } = {}) {
  const end = Date.now() + ms;
  let last;
  while (!abort()) {
    try {
      if (await fn()) return;
    } catch (err) {
      last = err;
    }
    if (Date.now() > end) {
      throw new Error(`timed out waiting for ${what}${last ? ` (${last.cause?.code ?? last.message})` : ""}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

const hasExited = (child) => child.exitCode !== null || child.signalCode !== null;

// Signals the child, or its whole process group/tree: a gateway started
// through a shell (PARLEY_GATEWAY_CMD) has grandchildren that hold its port.
function signal(child, sig) {
  try {
    if (isWindows) {
      spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    } else if (child.groupLeader) {
      process.kill(-child.pid, sig);
    } else {
      child.kill(sig);
    }
  } catch {}
}

function stopChild(child) {
  return new Promise((resolve) => {
    if (hasExited(child)) return resolve();
    const timer = setTimeout(() => signal(child, "SIGKILL"), 3000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    signal(child, "SIGTERM");
  });
}

export async function start({ daemons = 2, quiet = false, onUnexpectedExit } = {}) {
  if (!Number.isInteger(daemons) || daemons < 1) {
    throw new Error(`daemons must be an integer >= 1, got ${daemons}`);
  }
  const children = [];
  const dir = mkdtempSync(join(tmpdir(), "parley-dev-"));
  const stdio = quiet ? "ignore" : "inherit";
  let oidc;
  let stopping = false;
  let stopped;

  // Rejects start() if any child fails to spawn or dies while we are booting.
  let fail;
  const dead = new Promise((_, reject) => (fail = reject));
  dead.catch(() => {});
  const watch = (name, child) => {
    children.push(child);
    child.once("error", (err) => fail(new Error(`${name} failed to start: ${err.message}`)));
    child.once("exit", (code, sig) => {
      if (stopping) return;
      const err = new Error(`${name} exited unexpectedly (${sig ?? `code ${code}`})`);
      fail(err);
      onUnexpectedExit?.(name, err);
    });
  };

  const stop = () => {
    stopped ??= (async () => {
      stopping = true;
      await Promise.all(children.map(stopChild));
      await oidc?.close();
      try {
        rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
      } catch {}
    })();
    return stopped;
  };

  try {
    oidc = await startMockOidc();

    const gwPort = await freePort();
    const gatewayUrl = `http://127.0.0.1:${gwPort}`;
    const env = { ...process.env, PORT: String(gwPort) };
    const cmd = process.env.PARLEY_GATEWAY_CMD;
    const detached = !isWindows;
    const gateway = cmd
      ? spawn(cmd, { shell: true, cwd: join(repo, "gateway"), env, stdio, detached })
      : spawn(process.execPath, [join(here, "stub-gateway.mjs")], { env, stdio, detached });
    gateway.groupLeader = detached;
    watch("gateway", gateway);
    await Promise.race([
      waitFor(async () => (await fetch(`${gatewayUrl}/healthz`)).ok, "gateway", { abort: () => stopping }),
      dead,
    ]);

    const bin = join(dir, isWindows ? "parleyd.exe" : "parleyd");
    const build = spawnSync("go", ["build", "-o", bin, "./cmd/parleyd"], {
      cwd: repo,
      stdio: quiet ? ["ignore", "ignore", "pipe"] : "inherit",
      encoding: "utf8",
    });
    if (build.error) {
      throw new Error(
        build.error.code === "ENOENT"
          ? "go not found on PATH (needed to build parleyd)"
          : `go build failed to run: ${build.error.message}`,
      );
    }
    if (build.status !== 0) {
      throw new Error(`go build ./cmd/parleyd failed${build.stderr ? `:\n${build.stderr}` : ""}`);
    }

    const procs = [];
    const spawned = [];
    for (let i = 1; i <= daemons; i++) {
      const name = `daemon-${i}`;
      const home = join(dir, name);
      const child = spawn(bin, [], {
        stdio,
        env: {
          ...process.env,
          PARLEY_HOME: home,
          PARLEY_GATEWAY_URL: gatewayUrl,
          PARLEY_OIDC_ISSUER: oidc.issuer,
        },
      });
      watch(name, child);
      spawned.push(new Promise((r) => child.once("spawn", r)));
      procs.push({ name, home, child });
    }
    // Wait for every process to start, then give early crashes a moment to show.
    await Promise.race([Promise.all(spawned), dead]);
    await Promise.race([new Promise((r) => setTimeout(r, 200)), dead]);
    return { gatewayUrl, oidcIssuer: oidc.issuer, daemons: procs, stop };
  } catch (err) {
    await stop();
    throw err;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const arg = process.argv.find((a) => a.startsWith("--daemons="));
  const n = Number(arg ? arg.slice("--daemons=".length) : (process.env.N ?? 2));
  let h;
  const bye = (code) => () => h.stop().then(() => process.exit(code));
  try {
    h = await start({
      daemons: n,
      onUnexpectedExit: (name, err) => {
        console.error(err.message);
        if (h) bye(1)();
      },
    });
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
  console.log(`gateway  ${h.gatewayUrl}\noidc     ${h.oidcIssuer}\ndaemons  ${n}\nCtrl-C to stop`);
  process.on("SIGINT", bye(0));
  process.on("SIGTERM", bye(0));
}
