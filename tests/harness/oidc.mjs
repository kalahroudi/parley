// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Mock OIDC provider standing in for Google and Entra in local development
// and tests. Authorization-code flow only (PKCE S256 is verified when the
// client sends a code_challenge); every authorize request is approved
// automatically for the user named by `login_hint` (or a default).
// Deliberately permissive: redirect_uri is not checked against an allowlist
// and client authentication is not required.
//
// `profile: "entra"` makes it Entra-shaped (Microsoft identity platform v2.0):
// tenant-scoped paths, an issuer of `<base>/<tenant>/v2.0`, the literal
// `{tenantid}` issuer in the multi-tenant (common, organizations, consumers)
// discovery document, Entra id_token claims (ver, tid, oid, pairwise sub,
// preferred_username, no email_verified) and AADSTS-style errors. The shapes
// are recorded in tests/fixtures/entra/ with their Microsoft sources.
import { createServer } from "node:http";
import { createHash, createHmac, createSign, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";

const b64u = (b) => Buffer.from(b).toString("base64url");
// Deterministic GUID-shaped id from a string.
const guid = (s) => {
  const h = createHash("sha256").update(s).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
};
const CODE_TTL_MS = 60_000;
export const MULTI_TENANT = ["common", "organizations", "consumers"];
const ENTRA_ROUTES = {
  "v2.0/.well-known/openid-configuration": "/.well-known/openid-configuration",
  "oauth2/v2.0/authorize": "/authorize",
  "oauth2/v2.0/token": "/token",
  "discovery/v2.0/keys": "/jwks",
};

export async function startMockOidc({ port = 0, defaultEmail = "alice@example.test", profile = "generic", tenantId = randomUUID() } = {}) {
  const entra = profile === "entra";
  const newKey = () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const kid = b64u(randomBytes(8));
    return { kid, privateKey, jwk: { ...publicKey.export({ format: "jwk" }), kid, use: "sig", alg: "RS256", ...(entra && { x5t: kid }) } };
  };
  const keys = [newKey()];
  const subKey = keys[0].kid; // keeps `sub` stable across key rotation
  const codes = new Map();
  let issuer = "";
  let base = "";
  // Test hooks: `claims` are merged over the minted claims; `badSignature`
  // signs with a throwaway key so the token fails verification. Entra profile
  // only: `tenant` is the directory the user belongs to when the endpoint is
  // multi-tenant, `emailClaim` adds an `email` claim, `overage` replaces
  // `groups` with the overage pointer.
  const tweak = { claims: {}, badSignature: false, tenant: undefined, emailClaim: undefined, overage: false };
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;

  const sign = (claims) => {
    const { kid, privateKey } = keys[0];
    const head = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid }));
    const body = b64u(JSON.stringify(claims));
    const sig = createSign("RSA-SHA256").update(`${head}.${body}`).sign(tweak.badSignature ? other : privateKey);
    return `${head}.${body}.${b64u(sig)}`;
  };
  const usedCodes = new Set();
  // Entra v2.0 id_token payload, per Microsoft's ID token claims reference.
  const entraClaims = (entry, now) => {
    const tid = MULTI_TENANT.includes(entry.seg) ? tweak.tenant ?? tenantId : entry.seg;
    const oid = guid(`${tid}:${entry.email}`);
    const claims = {
      aud: entry.aud,
      iss: `${base}/${tid}/v2.0`,
      iat: now,
      nbf: now,
      exp: now + 3600,
      name: entry.email.split("@")[0],
      oid,
      preferred_username: entry.email,
      rh: b64u(randomBytes(24)),
      sub: b64u(createHmac("sha256", entry.aud).update(oid).digest()).slice(0, 43),
      tid,
      uti: b64u(randomBytes(16)),
      ver: "2.0",
    };
    if (tweak.emailClaim !== undefined) claims.email = tweak.emailClaim;
    if (tweak.overage) {
      claims._claim_names = { groups: "src1" };
      claims._claim_sources = { src1: { endpoint: `https://graph.microsoft.com/v1.0/users/${oid}/getMemberObjects` } };
    }
    return claims;
  };
  const json = (res, status, obj) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };

  const handle = async (req, res) => {
    const url = new URL(req.url, base);
    let path = url.pathname;
    let seg = tenantId;
    if (entra) {
      const m = /^\/([^/]+)\/(.+)$/.exec(path);
      path = (m && ENTRA_ROUTES[m[2]]) || "";
      seg = m?.[1];
    }
    if (entra && path === "/.well-known/openid-configuration") {
      const multi = MULTI_TENANT.includes(seg);
      if (!multi && seg !== tenantId) return json(res, 400, { error: "invalid_tenant", error_description: "AADSTS90002: InvalidTenantName - The tenant name wasn't found in the data store. Check to make sure you have the correct tenant ID.", error_codes: [90002] });
      const at = `${base}/${seg}`;
      return json(res, 200, {
        token_endpoint: `${at}/oauth2/v2.0/token`,
        token_endpoint_auth_methods_supported: ["client_secret_post", "private_key_jwt", "client_secret_basic"],
        jwks_uri: `${at}/discovery/v2.0/keys`,
        response_modes_supported: ["query", "fragment", "form_post"],
        subject_types_supported: ["pairwise"],
        id_token_signing_alg_values_supported: ["RS256"],
        response_types_supported: ["code", "id_token", "code id_token", "id_token token"],
        scopes_supported: ["openid", "profile", "email", "offline_access"],
        issuer: multi ? `${base}/{tenantid}/v2.0` : `${at}/v2.0`,
        authorization_endpoint: `${at}/oauth2/v2.0/authorize`,
      });
    }
    if (path === "/.well-known/openid-configuration") {
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
    if (path === "/jwks") return json(res, 200, { keys: keys.map((k) => k.jwk) });
    if (path === "/authorize") {
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
        seg,
        expires: Date.now() + CODE_TTL_MS,
      });
      back.searchParams.set("code", code);
      const state = url.searchParams.get("state");
      if (state) back.searchParams.set("state", state);
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (path === "/token" && req.method === "POST") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      if (form.get("grant_type") !== "authorization_code") {
        return json(res, 400, { error: "unsupported_grant_type" });
      }
      const code = form.get("code");
      const entry = codes.get(code);
      codes.delete(code); // single use
      if (entra && !entry && usedCodes.has(code)) {
        return json(res, 400, { error: "invalid_grant", error_description: "AADSTS54005: OAuth2 Authorization code was already redeemed, please retry with a new valid code or use an existing refresh token.", error_codes: [54005] });
      }
      if (!entry || entry.expires < Date.now()) return json(res, 400, { error: "invalid_grant" });
      usedCodes.add(code);
      if (entry.challenge) {
        const verifier = form.get("code_verifier") ?? "";
        const want = createHash("sha256").update(verifier).digest("base64url");
        if (want !== entry.challenge) {
          return json(res, 400, { error: "invalid_grant", error_description: "PKCE mismatch" });
        }
      }
      const now = Math.floor(Date.now() / 1000);
      const claims = entra ? entraClaims(entry, now) : {
        iss: issuer,
        sub: createHmac("sha256", subKey).update(entry.email).digest("hex").slice(0, 24),
        aud: entry.aud,
        iat: now,
        exp: now + 3600,
        email: entry.email,
        email_verified: true,
      };
      if (entry.nonce) claims.nonce = entry.nonce;
      Object.assign(claims, tweak.claims);
      for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
      return json(res, 200, {
        token_type: "Bearer",
        ...(entra && { scope: "openid profile email" }),
        expires_in: 3600,
        ...(entra && { ext_expires_in: 3600 }),
        access_token: b64u(randomBytes(16)),
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
  base = `http://127.0.0.1:${server.address().port}`;
  issuer = entra ? `${base}/${tenantId}/v2.0` : base;
  return {
    issuer,
    base,
    tenantId,
    tweak,
    // Signs new tokens with a fresh key. The old key stays in the key set
    // (as Entra does while it rolls over) unless `retire` is set.
    rotateKey: ({ retire = false } = {}) => {
      keys.unshift(newKey());
      if (retire) keys.length = 1;
    },
    close: () => new Promise((r) => (server.closeAllConnections(), server.close(r))),
  };
}
