// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Starts the real gateway under `wrangler dev` for a test, safely beside other
// tests (node --test runs test files in parallel, and CI runs three OSes).
//
// What used to collide, and what this does about it:
//   - the main port: allocated by the OS (listen on 0), never a fixed number;
//   - the inspector port: wrangler defaults it to 9229, so two wrangler devs
//     started together fought over it (the Linux flake). It is allocated here too;
//   - the two ports of one gateway could come back equal, or be taken between
//     being picked and bound by another test: both are held open together until
//     chosen, and a start that fails for any reason before /healthz answers is
//     retried with fresh ports (not only when the log says "in use");
//   - Durable Object state: wrangler persists under gateway/.wrangler/state by
//     default, which every run and every parallel test shared. Each start gets
//     its own state directory;
//   - wrangler's own logs and registry: per-start directories, so one run never
//     reads or truncates another's.
import { spawn } from "node:child_process";
import { killTree } from "./killtree.mjs";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

const isWindows = process.platform === "win32";
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// n distinct free ports, all held open until every one is known.
export async function freePorts(n) {
  const servers = [];
  try {
    const ports = [];
    for (let i = 0; i < n; i++) {
      const s = createServer();
      await new Promise((resolve, reject) => {
        s.once("error", reject);
        s.listen(0, "127.0.0.1", resolve);
      });
      servers.push(s);
      ports.push(s.address().port);
    }
    return ports;
  } finally {
    await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
  }
}

export function stopTree(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    const timer = setTimeout(() => kill("SIGKILL"), 8000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    function kill(sig) {
      try {
        if (isWindows) killTree(child);
        else process.kill(-child.pid, sig);
      } catch {}
    }
    kill("SIGTERM");
  });
}

// Starts the gateway in `gatewayDir` and resolves once /healthz answers.
// Returns { port, url, state, logs, output(), stop() }. `stop()` ends the whole
// process tree (state is flushed to disk by then) and removes nothing: the
// caller owns `scratch`, or lets stop({ clean: true }) remove it.
export async function startGateway(gatewayDir, { vars = [], scratch, attempts = 5, startTimeoutMs = 60000 } = {}) {
  const wrangler = join(gatewayDir, "node_modules", ".bin", isWindows ? "wrangler.cmd" : "wrangler");
  const own = scratch === undefined;
  const base = scratch ?? mkdtempSync(join(tmpdir(), "parley-gw-"));
  let lastLog = "";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const run = join(base, `run${attempt}`);
    const state = join(run, "state");
    const logs = join(run, "wrangler-logs");
    const registry = join(run, "registry");
    for (const d of [state, logs, registry]) mkdirSync(d, { recursive: true });
    const [port, inspector] = await freePorts(2);
    const chunks = [];
    const flags = vars.map((v) => `--var ${v}`).join(" ");
    const child = spawn(
      `"${wrangler}" dev --port ${port} --inspector-port ${inspector} --ip 127.0.0.1 ${flags} --persist-to "${state}"`,
      {
        cwd: gatewayDir,
        shell: true,
        detached: !isWindows,
        env: {
          ...process.env,
          WRANGLER_LOG_PATH: logs,
          WRANGLER_REGISTRY_PATH: registry,
          WRANGLER_SEND_METRICS: "false",
          CI: "1",
        },
      },
    );
    child.stdout.on("data", (d) => chunks.push(d));
    child.stderr.on("data", (d) => chunks.push(d));
    const output = () => Buffer.concat(chunks).toString();
    const deadline = Date.now() + startTimeoutMs;
    let up = false;
    while (child.exitCode === null && Date.now() < deadline) {
      try {
        if ((await fetch(`http://127.0.0.1:${port}/healthz`)).ok) {
          up = true;
          break;
        }
      } catch {}
      await sleep(200);
    }
    if (up) {
      return {
        port,
        url: `http://127.0.0.1:${port}`,
        state,
        logs,
        output,
        async stop({ clean = false } = {}) {
          await stopTree(child);
          if (clean && own) rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
        },
      };
    }
    lastLog = output();
    await stopTree(child);
  }
  if (own) rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  throw new Error(`gateway did not start after ${attempts} attempts; last output:\n${lastLog}`);
}
