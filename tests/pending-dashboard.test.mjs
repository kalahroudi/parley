// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Spec 002 R11 has a dashboard half that cannot be tested until the dashboard's server side exists. The gateway half
// (a gateway with no IdP says so, no fallback credential works, a program holding a session token acts without the
// browser-only CSRF header) is tested in gateway/test/session.test.ts. The task id below is a label: it is not in
// this repository's tasks.md, so this test only skips until it is given the real dashboard task id.

import { pending } from "./harness/pending.mjs";

pending("R11: the dashboard keeps the gateway credential server-side and gives the browser only an HttpOnly, SameSite=Strict cookie (Secure over HTTPS)", "spec002-dashboard-bff",
  "assert the browser never sees the ps_ token in a body, header other than Set-Cookie, or script-readable cookie; assert the cookie attributes; assert a dashboard whose gateway cannot issue admin sessions renders a sign-in-unavailable state and sends no DEV_AUTH-style credential");
