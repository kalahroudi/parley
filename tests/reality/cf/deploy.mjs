// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// One real `wrangler deploy` of the throwaway measurement Worker, used by the Go
// soak mid-run. Usage: PARLEY_REALITY_NAME=... PARLEY_REALITY_PROBE_TOKEN=... node deploy.mjs <build-id>
import { deploy } from "./safety.mjs";

const name = process.env.PARLEY_REALITY_NAME;
const token = process.env.PARLEY_REALITY_PROBE_TOKEN;
if (!name || !token || !process.argv[2]) {
  console.error("PARLEY_REALITY_NAME, PARLEY_REALITY_PROBE_TOKEN and a build id are required");
  process.exit(2);
}
const t0 = Date.now();
deploy(name, { DEV_AUTH: "1", PROBE_TOKEN: token, BUILD: process.argv[2] });
console.error(`deployed ${process.argv[2]} in ${Date.now() - t0} ms`);
