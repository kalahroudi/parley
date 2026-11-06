// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Display text shown to an admin: NFC, trimmed, no control, format (bidi
// overrides, zero-width), separator, private-use or unpaired-surrogate
// characters, and no whitespace other than a plain space.
export function cleanText(v: string, max: number): string | null {
  const s = v.normalize("NFC").trim();
  if (!s || s.length > max || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}]|[^\S ]/u.test(s)) return null;
  return s;
}

// Identity comparison: ASCII letters fold, nothing else does. `toLowerCase` also maps the Kelvin sign (U+212A) to "k" and
// the dotted capital I (U+0130) to "i" plus a combining dot, so a different account would equal a listed member or admin.
export const fold = (s: string): string => s.replace(/[A-Z]+/g, (c) => c.toLowerCase());
