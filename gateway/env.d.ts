// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import type { Env as GatewayEnv } from "./src/index";

declare global {
  namespace Cloudflare {
    interface Env extends GatewayEnv {}
  }
}
