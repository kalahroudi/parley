// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Mock OIDC provider standing in for Google and Entra in local development
// and tests. Authorization-code flow only (PKCE S256 is verified when the
// client sends a code_challenge); every authorize request is approved
// automatically for the user named by `login_hint` (or a default).
// Deliberately permissive: redirect_uri is not checked against an allowlist
// and client authentication is not required.
import { createServer } from "node:http";
import { createHash, createHmac, createSign, generateKeyPairSync, randomBytes } from "node:crypto";

const b64u = (b) => Buffer.from(b).toString("base64url");
const CODE_TTL_MS = 60_000;

export async function startMockOidc({ port = 0, defaultEmail = "alice@example.test" } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = b64u(randomBytes(8));
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, use: "sig", alg: "RS256" };
  const codes = new Map();
  let issuer = "";

  const sign = (claims) => {
    const head = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid }));
    const body = b64u(JSON.stringify(claims));
    const sig = createSign("RSA-SHA256").update(`${head}.${body}`).sign(privateKey);
    return `${head}.${body}.${b64u(sig)}`;
  };
  const json = (res, status, obj) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };

  const handle = async (req, res) => {
    const url = new URL(req.url, issuer);
    if (url.pathname === "/.well-known/openid-configuration") {
      return json(res, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256"],
      });
    }
    if (url.pathname === "/jwks") return json(res, 200, { keys: [jwk] });
    if (url.pathname === "/authorize") {
      let back;
      try {
        back = new URL(url.searchParams.get("redirect_uri"));
      } catch {
        return json(res, 400, { error: "invalid_request", error_description: "bad redirect_uri" });
      }
      const challenge = url.searchParams.get("code_challenge");
      if (challenge && url.searchParams.get("code_challenge_method") !== "S256") {
        return json(res, 400, { error: "invalid_request", error_description: "only S256 is supported" });
      }
      const code = b64u(randomBytes(16));
      codes.set(code, {
        email: url.searchParams.get("login_hint") || defaultEmail,
        nonce: url.searchParams.get("nonce"),
        aud: url.searchParams.get("client_id") || "parley",
        challenge,
        expires: Date.now() + CODE_TTL_MS,
      });
      back.searchParams.set("code", code);
      const state = url.searchParams.get("state");
      if (state) back.searchParams.set("state", state);
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (url.pathname === "/token" && req.method === "POST") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      if (form.get("grant_type") !== "authorization_code") {
        return json(res, 400, { error: "unsupported_grant_type" });
      }
      const code = form.get("code");
      const entry = codes.get(code);
      codes.delete(code); // single use
      if (!entry || entry.expires < Date.now()) return json(res, 400, { error: "invalid_grant" });
      if (entry.challenge) {
        const verifier = form.get("code_verifier") ?? "";
        const want = createHash("sha256").update(verifier).digest("base64url");
        if (want !== entry.challenge) {
          return json(res, 400, { error: "invalid_grant", error_description: "PKCE mismatch" });
        }
      }
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        iss: issuer,
        sub: createHmac("sha256", kid).update(entry.email).digest("hex").slice(0, 24),
        aud: entry.aud,
        iat: now,
        exp: now + 3600,
        email: entry.email,
        email_verified: true,
      };
      if (entry.nonce) claims.nonce = entry.nonce;
      return json(res, 200, {
        access_token: b64u(randomBytes(16)),
        token_type: "Bearer",
        expires_in: 3600,
        id_token: sign(claims),
      });
    }
    json(res, 404, { error: "not_found" });
  };

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) json(res, 500, { error: "server_error" });
      else res.destroy();
    });
  });

  await new Promise((r) => server.listen(port, "127.0.0.1", r));
  issuer = `http://127.0.0.1:${server.address().port}`;
  return {
    issuer,
    close: () => new Promise((r) => (server.closeAllConnections(), server.close(r))),
  };
}
