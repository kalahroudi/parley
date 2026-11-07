// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Ends a child process started by a test, with its descendants, on Windows (where there are no process groups).
// `taskkill /pid N /T /F` ends whatever process holds the pid N now, and Windows reuses a pid as soon as its process
// has gone. So: a child that has exited is never killed, the image behind the pid is read first and logged, and a
// pid that now belongs to a Parley program is refused with a loud message (it is not the child this test started).
import { spawnSync } from "node:child_process";

const parley = /^parley(d|-cli)\.exe$/i;

export function killTree(child, log = (m) => process.stderr.write(m + "\n")) {
  if (child.exitCode !== null || child.signalCode !== null) return false;
  const pid = String(child.pid);
  const q = spawnSync("tasklist", ["/FI", `PID eq ${pid}`, "/FO", "CSV", "/NH"], { encoding: "utf8" });
  const image = (q.stdout ?? "").trim().split(",")[0]?.replace(/"/g, "") ?? "";
  if (parley.test(image)) {
    log(`[harness] REFUSED to taskkill pid ${pid}: it is ${image}, not the process this test started`);
    return false;
  }
  log(`[harness] taskkill pid ${pid} (${image || "no such process"})`);
  spawnSync("taskkill", ["/pid", pid, "/T", "/F"], { stdio: "ignore" });
  return true;
}
