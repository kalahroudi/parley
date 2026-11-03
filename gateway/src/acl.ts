// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Directory rules: card and group validation, the secrets lint, who may see a
// card, and the find filter. Pure functions, no storage (tier 1).
//
// Visibility here is decided by the gateway and is advisory: the target daemon
// still enforces the owner's allowlist from the root-signed binding. A card the
// viewer may not see is simply absent, so "not permitted" and "does not exist"
// look the same.

import { cleanText } from "./text";

export const MAX_CARDS_PER_DEVICE = 20;
export const MAX_GROUPS = 100;
export const MAX_MEMBERS = 500;
export const MAX_CARD_GROUPS = 10;
export const MAX_TAGS = 10;
export const MAX_EXAMPLES = 5;
export const MAX_RESULTS = 50;

export type Visibility = "tenant" | "groups" | "private";

// What an owner publishes. Plaintext by design: no secrets belong in it.
export interface Card {
  name: string;
  description: string;
  tags: string[]; // lowercase
  examples: string[];
  visibility: Visibility;
  groups: string[]; // group names; only meaningful for "groups"
}

export interface CardQuery {
  text?: string;
  tag?: string;
}

export type ValidationError = "bad_card" | "bad_group" | "bad_members" | "bad_query";

const VISIBILITY: readonly string[] = ["tenant", "groups", "private"];
// Names are case-insensitive: "Eng" and "eng" are one group.
const groupName = (v: unknown) => (typeof v === "string" ? cleanText(v, 64)?.toLowerCase() ?? null : null);

// Common credential shapes. Best effort: the lint stops accidents, not attackers.
const SECRET_PATTERNS: readonly RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}/,
  /\bsk-[A-Za-z0-9_-]{20,}/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  /\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S{8,}/i,
  // Any long unbroken base64 or hex run: pod tokens, signing keys, most API keys.
  /\b[A-Za-z0-9+/_-]{40,}/,
];

// The first field that looks like a secret, or null.
export function lintSecrets(card: Card): keyof Card | null {
  const fields: [keyof Card, string][] = [
    ["name", card.name],
    ["description", card.description],
    ["tags", card.tags.join("\n")],
    ["examples", card.examples.join("\n")],
    ["groups", card.groups.join("\n")],
  ];
  for (const [field, text] of fields) if (SECRET_PATTERNS.some((p) => p.test(text))) return field;
  return null;
}

function strings(v: unknown, max: number, len: number, lower: boolean): string[] | null {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > max) return null;
  const out: string[] = [];
  for (const x of v) {
    const t = typeof x === "string" ? cleanText(x, len) : null;
    if (t === null) return null;
    out.push(lower ? t.toLowerCase() : t);
  }
  return [...new Set(out)];
}

export function validateCard(v: unknown): { card: Card } | { error: "bad_card" | "secret_detected"; field?: string } {
  if (!v) return { error: "bad_card" }; // other non-objects have no name and fail below
  const o = v as Record<string, unknown>;
  const name = typeof o.name === "string" ? cleanText(o.name, 64) : null;
  const description = typeof o.description === "string" ? cleanText(o.description, 500) : null;
  const tags = strings(o.tags, MAX_TAGS, 32, true);
  const examples = strings(o.examples, MAX_EXAMPLES, 200, false);
  const visibility = o.visibility ?? "tenant";
  const rawGroups = strings(o.groups, MAX_CARD_GROUPS, 64, true);
  if (!name || !description || !tags || !examples || !rawGroups || !VISIBILITY.includes(visibility as string)) {
    return { error: "bad_card" };
  }
  // A "groups" card needs at least one group; other modes carry none.
  if ((visibility === "groups") !== (rawGroups.length > 0)) return { error: "bad_card" };
  const card: Card = { name, description, tags, examples, visibility: visibility as Visibility, groups: rawGroups };
  const field = lintSecrets(card);
  return field ? { error: "secret_detected", field } : { card };
}

// Group name and member list, normalized (lowercase, de-duplicated).
export function validateGroup(name: unknown, members: unknown): { name: string; members: string[] } | { error: "bad_group" | "bad_members" } {
  const n = groupName(name);
  if (!n) return { error: "bad_group" };
  const m = strings(members, MAX_MEMBERS, 254, true);
  return m ? { name: n, members: m } : { error: "bad_members" };
}

// The groups a viewer belongs to, given every group as [name, members].
export function memberships(groups: Iterable<[string, readonly string[]]>, viewer: string): Set<string> {
  const out = new Set<string>();
  for (const [name, members] of groups) if (members.includes(viewer)) out.add(name);
  return out;
}

// Whether `viewer` may see (and so call) a card. The owner always can.
export function canSee(card: Pick<Card, "visibility" | "groups">, owner: string, viewer: string, viewerGroups: ReadonlySet<string>): boolean {
  if (viewer === owner) return true;
  if (card.visibility === "tenant") return true;
  if (card.visibility === "groups") return card.groups.some((g) => viewerGroups.has(g));
  return false;
}

// Name/description substring and exact tag filter; an empty query matches all.
export function matches(card: Pick<Card, "name" | "description" | "tags">, q: CardQuery): boolean {
  const text = q.text?.trim().toLowerCase();
  if (text && !`${card.name}\n${card.description}`.toLowerCase().includes(text)) return false;
  const tag = q.tag?.trim().toLowerCase();
  return !tag || card.tags.includes(tag);
}

export function validateQuery(q: unknown): CardQuery | null {
  if (q === undefined) return {};
  if (!q || typeof q !== "object" || Array.isArray(q)) return null;
  const { text, tag } = q as Record<string, unknown>;
  if ((text !== undefined && (typeof text !== "string" || text.length > 200)) || (tag !== undefined && (typeof tag !== "string" || tag.length > 64))) return null;
  return { text: text as string | undefined, tag: tag as string | undefined };
}
