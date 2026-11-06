// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// The bot of the walking-skeleton test: a program the CLI adapter runs once per task and talks to in the
// parley-bot/1 line protocol (internal/adapter/doc.go). What the task text says picks what it does:
//   "echo X"  answers "bot heard: X"
//   "ask"     asks "which colour?" (INPUT_REQUIRED) and answers "colour: <the answer>"
//   "slow X"  sends a status, then answers "bot heard: X" once the file <dir>/release-X exists (the test decides when)
//   "snoop <parley-cli> <home>"  waits until another task waits for the owner's approval, then tries to approve and to
//             deny it with the owner's command (a bot has no terminal, and the daemon refuses callers that belong to a
//             bot), writes what happened to <dir>/result-snoop.json and answers "snooped"
//   "hang"    sends a status and then waits for ever, until the daemon ends it (cancel or expiry)
// It records its process id in <dir>/<first word>-<its pid>.pid, so the test can see that a task that ended took its
// process with it.

import { execFile } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";

const dir = process.argv[2];
const b64 = (s) => Buffer.from(s).toString("base64");
const send = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);

let waiting = null; // resolves with the caller's answer
const lines = createInterface({ input: process.stdin });
lines.on("line", async (line) => {
  const m = JSON.parse(line);
  if (m.type === "answer" && waiting) return waiting(Buffer.from(m.content, "base64").toString());
  if (m.type !== "task") return;
  const text = Buffer.from(m.content, "base64").toString();
  const [verb, ...rest] = text.split(" ");
  writeFileSync(join(dir, `${verb}-${process.pid}.pid`), String(process.pid));
  if (verb === "ask") {
    send({ type: "question", content: b64("which colour?") });
    const answer = await new Promise((r) => (waiting = r));
    return send({ type: "result", content: b64(`colour: ${answer}`) });
  }
  if (verb === "slow") {
    send({ type: "status", content: b64("working") });
    while (!existsSync(join(dir, `release-${rest[0]}`))) await new Promise((r) => setTimeout(r, 100));
    return send({ type: "result", content: b64(`bot heard: ${rest[0]}`) });
  }
  if (verb === "snoop") {
    const [cli, home] = rest;
    const run = (args) => new Promise((resolve) => execFile(cli, args, { env: { PARLEY_HOME: home }, timeout: 20000 }, (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr })));
    let pending;
    for (let i = 0; i < 300 && !pending; i++) {
      try {
        pending = JSON.parse((await run(["approve"])).stdout).pending?.[0]?.task_id;
      } catch {}
      if (!pending) await new Promise((r) => setTimeout(r, 200));
    }
    const denied = await run(["approve", "-deny", pending]);
    const approved = await run(["approve", pending]);
    writeFileSync(join(dir, "result-snoop.json"), JSON.stringify({ pending, denied, approved }));
    return send({ type: "result", content: b64("snooped") });
  }
  if (verb === "hang") return send({ type: "status", content: b64("working") }); // then waits until the daemon ends it
  send({ type: "result", content: b64(`bot heard: ${rest.join(" ")}`) });
});
