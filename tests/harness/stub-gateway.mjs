// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Placeholder gateway used by the local harness until the real Worker exists
// (T101 onwards). Set PARLEY_GATEWAY_CMD to run `wrangler dev` instead.
import { createServer } from "node:http";

const port = Number(process.env.PORT);
createServer((req, res) => {
  res.writeHead(req.url === "/healthz" ? 200 : 404, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: req.url === "/healthz", service: "stub-gateway" }));
}).listen(port, "127.0.0.1");
process.on("SIGTERM", () => process.exit(0));
