/**
 * Accepted risks, recorded in the repository: `.yof/accepted.json`, committed with the code. An editor writes an entry
 * when you accept one finding with a reason ("yof: Accept this risk…" in VS Code); `yof check` honours it: the finding
 * leaves the open count and the exit code, and is still printed as accepted, with the reason. Never silently hidden.
 *
 *   { "version": 1, "accepted": [ { "rule": "secret.stripe_test", "file": "tests/pay.ts",
 *       "fingerprint": "<32 hex>", "reason": "...", "acceptedBy": "Ada", "acceptedAt": "2026-11-07T10:00:00.000Z" } ] }
 *
 * The fingerprint is the first 32 hex characters of SHA-256 over "yof-accept/1\n<rule>\n<file>\n<content>": content is
 * the finding's line, trimmed (a key), or "<ecosystem>:<name>" (a package). Change that line and the entry no longer
 * matches, so the finding is open again. Remove the entry ("yof: Reopen accepted risk") to reopen it on purpose.
 */
import { createHash } from "node:crypto";

export const ACCEPTED_FILE = ".yof/accepted.json";
export const ACCEPTED_MAX_ENTRIES = 500;
export const ACCEPTED_REASON_MAX = 300;

export interface AcceptedEntry { rule: string; file: string; fingerprint: string; reason: string; acceptedBy: string; acceptedAt: string }
export interface Acceptance { reason: string; acceptedBy: string; acceptedAt: string }

/** The fingerprint of one finding (see the header). */
export function acceptFingerprint(rule: string, file: string, content: string): string {
  return createHash("sha256").update(`yof-accept/1\n${rule}\n${file.replace(/\\/g, "/")}\n${content.trim()}`).digest("hex").slice(0, 32);
}

const RULE = /^[a-z0-9_.-]{1,80}$/i;
const FP = /^[0-9a-f]{32}$/;
const str = (v: unknown, max: number) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, max) : "");

/** The entries of the file; anything off shape is left out, bad JSON is an empty list (and the findings stay open). */
export function parseAccepted(text: string | null | undefined): AcceptedEntry[] {
  if (!text) return [];
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { return []; }
  const list = raw && typeof raw === "object" && Array.isArray((raw as { accepted?: unknown }).accepted) ? (raw as { accepted: unknown[] }).accepted : [];
  const out: AcceptedEntry[] = [];
  for (const e of list.slice(0, ACCEPTED_MAX_ENTRIES)) {
    if (!e || typeof e !== "object") continue;
    const o = e as Record<string, unknown>;
    const entry = {
      rule: str(o.rule, 80), file: str(o.file, 400).replace(/\\/g, "/").replace(/^\.\//, ""), fingerprint: str(o.fingerprint, 64).toLowerCase(),
      reason: str(o.reason, ACCEPTED_REASON_MAX), acceptedBy: str(o.acceptedBy, 120), acceptedAt: str(o.acceptedAt, 40),
    };
    if (!RULE.test(entry.rule) || !entry.file || entry.file.includes("..") || !FP.test(entry.fingerprint) || !entry.reason || !Number.isFinite(Date.parse(entry.acceptedAt))) continue;
    out.push(entry);
  }
  return out;
}

/** The acceptance for one finding, or null. */
export function acceptanceFor(entries: readonly AcceptedEntry[], rule: string, file: string, content: string): Acceptance | null {
  const fp = acceptFingerprint(rule, file, content);
  const e = entries.find((x) => x.fingerprint === fp && x.rule === rule && x.file === file.replace(/\\/g, "/"));
  return e ? { reason: e.reason, acceptedBy: e.acceptedBy, acceptedAt: e.acceptedAt } : null;
}

/** The file with one entry added (an entry for the same finding is replaced). Sorted, two-space JSON, ends in a newline. */
export function withEntry(text: string | null | undefined, entry: AcceptedEntry): string {
  const list = parseAccepted(text).filter((x) => x.fingerprint !== entry.fingerprint);
  list.push(entry);
  list.sort((a, b) => a.file.localeCompare(b.file) || a.rule.localeCompare(b.rule) || a.fingerprint.localeCompare(b.fingerprint));
  return `${JSON.stringify({ version: 1, accepted: list }, null, 2)}\n`;
}

/** The file with one entry removed (reopen). */
export function withoutEntry(text: string | null | undefined, fingerprint: string): string {
  return `${JSON.stringify({ version: 1, accepted: parseAccepted(text).filter((x) => x.fingerprint !== fingerprint) }, null, 2)}\n`;
}
