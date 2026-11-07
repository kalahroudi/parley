// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Ends a child process started by a test, with its descendants, on Windows (where there are no process groups).
// A child that has already exited is never killed: its pid may belong to another process by now, and Windows reuses
// pids at once. Every kill is logged with the image behind the pid and what taskkill reports it ended (it names each
// process of the tree), so that a process that dies for no visible reason can be matched to a kill by its time.
import { spawnSync } from "node:child_process";

export function killTree(child, log = (m) => process.stderr.write(m + "\n")) {
  if (child.exitCode !== null || child.signalCode !== null) return false;
  const pid = String(child.pid);
  const q = spawnSync("tasklist", ["/FI", `PID eq ${pid}`, "/FO", "CSV", "/NH"], { encoding: "utf8" });
  const image = (q.stdout ?? "").trim().split(",")[0]?.replace(/"/g, "") ?? "";
  const k = spawnSync("taskkill", ["/pid", pid, "/T", "/F"], { encoding: "utf8" });
  log(`[harness] taskkill pid ${pid} (${image || "no such process"}): ${(k.stdout ?? "").replace(/\s+/g, " ").trim()}`);
  return true;
}
