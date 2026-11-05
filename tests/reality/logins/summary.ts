// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109 login check: what the throwaway `parley-test-login` Worker keeps of a real
// sign-in. The gateway's own callback (gateway/src/auth.ts) does all the validation
// (signature, issuer, audience, nonce, expiry, state, PKCE, hosted domain) and
// answers with the identity; the wrapper in tests/reality/cf/worker/entry.ts hands
// that answer here, stores only this summary, and shows the browser a plain page.
// The email, subject id and every token stay out of storage, output and the page.

export interface LoginSummary {
  ok: boolean;
  status: number;
  // Refusal code from the gateway (for example tenant_mismatch), when not ok.
  error?: string;
  provider?: string;
  issuer?: string;
  emailDomain?: string;
  hasSub?: boolean;
  // True when the account is a personal Google account (no Workspace domain).
  personalAccount?: boolean;
  // Whether GOOGLE_HOSTED_DOMAIN was configured, so the `hd` check ran.
  hostedDomainChecked: boolean;
}

const PERSONAL = new Set(["gmail.com", "googlemail.com"]);

export function summarize(status: number, body: unknown, hostedDomain: string | undefined): LoginSummary {
  const hostedDomainChecked = !!hostedDomain;
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  if (status !== 200) {
    const error = typeof b.error === "string" && /^[a-z_]{1,40}$/.test(b.error) ? b.error : "unknown";
    return { ok: false, status, error, hostedDomainChecked };
  }
  const email = typeof b.email === "string" ? b.email : "";
  const emailDomain = email.includes("@") ? email.split("@")[1]!.toLowerCase() : undefined;
  return {
    ok: !!emailDomain && typeof b.provider === "string",
    status,
    provider: typeof b.provider === "string" ? b.provider : undefined,
    issuer: typeof b.issuer === "string" ? b.issuer : undefined,
    emailDomain,
    hasSub: typeof b.sub === "string" && b.sub.length > 0,
    personalAccount: emailDomain ? PERSONAL.has(emailDomain) : undefined,
    hostedDomainChecked,
  };
}

export const SIGNED_IN_PAGE = "Signed in. You can close this tab and return to the terminal.";
export const REFUSED_PAGE = "Sign-in was refused. See the terminal.";
