/**
 * yof attack: the report (JSON for machines, short text for people) and the pull-request comment.
 *
 * The comment carries the regression tests as a hidden payload (gzip, then base64), so `/patch apply` on the pull request can commit them
 * to the pull request's own branch (the yof GitHub App reads only a comment written by a bot, and checks every file).
 * Evidence is masked everywhere; a report never holds a token, a password, a cookie or a full record.
 */
import { gzipSync } from "node:zlib";
import { ATTACK_GROUPS, type AttackGroup } from "./catalog";
import type { Budget } from "./config";
import type { Exchange } from "./http";
import type { Mode, ProofOk } from "./proof";
import type { GeneratedTest } from "./regression";
import type { AttackFinding, GroupStatus, StopReason } from "./runner";

export const COMMENT_MARKER = "<!-- yof-attack -->";
export const PAYLOAD_PREFIX = "<!-- yof-attack-payload:";
/** GitHub comments hold 65,536 characters; the payload stays well under. */
export const MAX_PAYLOAD_CHARS = 48_000;

export interface AttackReport {
  tool: "yof";
  command: "attack";
  version: string;
  app: string;
  target: { origin: string; host: string; kind: ProofOk["kind"]; proof: ProofOk["method"] };
  mode: Mode;
  scope: { full: boolean; label: string; groups: AttackGroup[]; reasons: string[]; routes: string[] };
  consent: { app: string; text: string };
  startedAt: string;
  finishedAt: string;
  stopped: null | StopReason;
  cleanup: { deleted: number; left: string[] };
  requests: number;
  budget: Budget;
  groups: Record<AttackGroup, GroupStatus>;
  findings: AttackFinding[];
  tests: { path: string; framework: string; ruleId: string }[];
  notes: string[];
  unconfirmed: number;
  exchanges: Exchange[];
  failed: boolean;
}

const LABEL = { fix_now: "fix now", fix_week: "fix this week", nice: "nice to have" } as const;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

const stopText = (s: StopReason) =>
  s === "cancelled" ? "Stopped early: you stopped the run." : `Stopped early: the ${s === "requests" ? "request" : "time"} budget ran out.`;

/** What happened to the test records the run created. Nothing to say when it created none. */
export function cleanupLines(c: AttackReport["cleanup"] | undefined): string[] {
  if (!c || (!c.deleted && !c.left.length)) return [];
  const out = ["", `Test records: ${plural(c.deleted, "deleted", "deleted")}${c.left.length ? `, ${c.left.length} left` : ""}.`];
  if (c.left.length) out.push(`  Not deleted (delete them in your app; they hold this run's yof marker text): ${[...new Set(c.left)].join(", ")}`);
  return out;
}

export function formatAttackText(r: AttackReport): string {
  const out: string[] = [];
  out.push(`yof attack on ${r.target.host} (${r.target.kind}, ${r.mode} run, ${r.scope.label})`);
  for (const why of r.scope.reasons.slice(0, 5)) out.push(`  full run because ${why}`);
  out.push(`${plural(r.requests, "request")} in ${Math.max(1, Math.round((Date.parse(r.finishedAt) - Date.parse(r.startedAt)) / 1000))} s`);
  if (r.stopped) out.push(`${stopText(r.stopped)} Groups not reached are marked below.`);
  out.push("", "Groups");
  for (const g of ATTACK_GROUPS) out.push(`  ${g.padEnd(8)} ${r.groups[g].replace("_", " ")}`);
  if (r.findings.length) {
    out.push("", "Findings");
    for (const f of r.findings) {
      out.push(`  ${f.title}  (${LABEL[f.severity]})`);
      out.push(`    ${f.method} ${f.route} as ${f.as === "anon" ? "nobody signed in" : `account ${f.as}`}: ${f.evidence}`);
    }
  }
  if (r.tests.length) { out.push("", "Regression tests"); for (const t of r.tests) out.push(`  ${t.path} (${t.framework})`); }
  out.push(...cleanupLines(r.cleanup));
  if (r.unconfirmed) out.push("", `${plural(r.unconfirmed, "possible finding")} did not show a second time and ${r.unconfirmed === 1 ? "is" : "are"} not reported.`);
  out.push("");
  const now = r.findings.filter((f) => f.severity === "fix_now").length;
  out.push(r.findings.length ? `Found ${plural(r.findings.length, "problem")}${now ? `, ${now} to fix now` : ""}.` : "Nothing found in what was tested. A run shows what it tried, not that nothing can go wrong.");
  return out.join("\n");
}

/** The report as JSON: the exchanges list is capped at the last 200. */
export const formatAttackJson = (r: AttackReport) => JSON.stringify({ ...r, exchanges: r.exchanges.slice(-200) }, null, 2);

export interface CommentPayload { headSha: string; files: { path: string; content: string }[]; headerRuleIds: string[] }

export function attackComment(r: AttackReport, tests: GeneratedTest[], headSha: string | null): string {
  const lines: string[] = [COMMENT_MARKER, `**yof attack** · ${r.target.host} · ${r.mode} run · ${r.scope.label}`, ""];
  if (r.stopped) lines.push(stopText(r.stopped), "");
  if (!r.findings.length) lines.push("Nothing found in what was tested.");
  else {
    lines.push("| Finding | Where | Urgency |", "| --- | --- | --- |");
    for (const f of r.findings) lines.push(`| ${f.title} | \`${f.method} ${f.route.replace(/`/g, "")}\` as ${f.as === "anon" ? "nobody" : `account ${f.as}`} | ${LABEL[f.severity]} |`);
  }
  const headerRuleIds = [...new Set(r.findings.filter((f) => f.ruleId === "attack.missing_headers").flatMap((f) => (f.meta.headers ?? "").split(",").filter(Boolean)))];
  const files = tests.map((t) => ({ path: t.path, content: t.content }));
  const encode = () => gzipSync(Buffer.from(JSON.stringify({ headSha: headSha ?? "", files, headerRuleIds } satisfies CommentPayload))).toString("base64");
  let b64 = headSha ? encode() : "";
  while (headSha && files.length && b64.length > MAX_PAYLOAD_CHARS) { files.pop(); b64 = encode(); }
  const left = tests.length - files.length;
  if (tests.length) {
    lines.push("", `${plural(tests.length, "regression test")} written from the recorded attacks. Each fails while its attack still works.`);
    if (files.length && headSha) lines.push("Comment `/patch apply` to commit them (and the header fix, when there is one) to this pull request's branch. Only people with write access can.");
    if (left) lines.push(`${plural(left, "test")} did not fit in this comment; run yof attack locally with --write-tests to get ${left === 1 ? "it" : "them"}.`);
  }
  lines.push("", "<sub>yof attack tests only your own app, with your test accounts, inside a request and time budget.</sub>");
  if (headSha && (files.length || headerRuleIds.length) && b64.length <= MAX_PAYLOAD_CHARS) lines.push("", `${PAYLOAD_PREFIX}${b64} -->`);
  return `${lines.join("\n")}\n`;
}
