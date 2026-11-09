/**
 * `yof check --format findings-json` and `yof import <findings.json>`: yof's findings in the findings.json format of
 * Cloudflare's security-audit skill, both ways (./findings-json.ts is the mapper; this file adds yof's verdicts and
 * the local check of an imported file).
 *
 * Verdicts here follow yof's verification model (docs: https://yof.io/docs):
 *   confirmed         the exact evidence is in the folder: a key that matches a provider's format, a package the
 *                     registry does not have, an installed version an advisory names
 *   needs_validation  likely, not demonstrated: a name one or two letters from a popular package, a package published
 *                     days ago
 *   hardening notes   keys that are public by design are not findings and are not written
 * Severity is anchored to what was demonstrated: nothing yof check finds is "critical", because yof check never runs
 * the code or reaches a live app; "high" is the most.
 *
 * Importing never trusts the file: every record is checked against the schema (./findings-json.ts) and then against
 * this folder, read only: each file it names must exist inside the folder and each line must exist in that file.
 * Nothing is run and nothing is sent anywhere.
 *
 * findings.json schema: https://github.com/cloudflare/security-audit-skill (MIT License, Copyright (c) 2025-2026
 * Cloudflare, Inc.).
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { CheckReport, DependencyFinding, KeyFinding } from "./check";
import { fromFindingsJson, toFindingsJson, yofFingerprint, type CfSeverity, type VfFinding } from "./findings-json";
import { keyWords } from "./words";

const SEV: Record<string, CfSeverity> = { fix_now: "high", fix_week: "medium", info: "informational" };

function keyToVf(k: KeyFinding): VfFinding | null {
  if (k.severity === "info" || k.accepted) return null;   // public by design: a hardening note, not a finding
  const w = keyWords(k.rule);
  const sev = SEV[k.severity] ?? "medium";
  const why = `${k.name}. ${w.why}`;
  return {
    fingerprint: yofFingerprint(k.rule, k.fingerprint), verdict: "confirmed", title: `${k.name} in ${k.file}`, description: why, rootCause: why,
    intendedBehavior: "The key stays on the server (an environment variable), never in the code.",
    trace: [{ kind: "sink", file: k.file, line: k.line, scope: k.rule, description: why }],
    evidence: [{ file: k.file, line: k.line, description: `Masked value: ${k.masked}` }],
    conditions: [],
    execution: { attackerPerspective: "Anyone who can read the repository or what it ships.", payloads: [k.masked], instructions: [`Open ${k.file} at line ${k.line}.`], observedResult: `The key ${k.masked} is in the file.` },
    remediation: { strategy: "Rotate the key in the provider's dashboard, then keep it on the server only (an environment variable, not the code)." },
    severity: { likelihood: { score: sev, reason: "The key is in the file as committed." }, impact: { score: sev, reason: w.why }, overall: sev },
    confidence: { score: "high", reason: "The value matches the provider's key format exactly." },
  };
}

function packageToVf(p: DependencyFinding): VfFinding | null {
  if (p.accepted) return null;
  const rule = `package.${p.issue}`;
  const sev = SEV[p.severity] ?? "medium";
  const title = `${p.name}${p.version ? `@${p.version}` : ""} (${p.ecosystem === "npm" ? "npm" : "PyPI"}) in ${p.file}`;
  const base = {
    fingerprint: yofFingerprint(rule, p.fingerprint), title, description: p.message, rootCause: p.message,
    trace: [{ kind: "sink" as const, file: p.file, line: 1, scope: rule, description: p.message }],
    evidence: [{ file: p.file, line: 1, description: `${p.file} names ${p.name}${p.version ? ` ${p.version}` : ""}.${p.advisory ? ` Advisory: ${p.advisory}.` : ""}` }],
  };
  if (p.issue === "made_up" || p.issue === "vulnerable") {
    return {
      ...base, verdict: "confirmed",
      intendedBehavior: p.issue === "made_up" ? "Every dependency exists on its registry." : `No installed version has a known advisory${p.fixedIn ? ` (fixed in ${p.fixedIn})` : ""}.`,
      conditions: [],
      execution: { attackerPerspective: "Anyone who installs the project's dependencies.", payloads: [`${p.name}${p.version ? `@${p.version}` : ""}`], instructions: [`Open ${p.file} and find ${p.name}.`], observedResult: p.message },
      remediation: { strategy: p.issue === "made_up" ? `Remove ${p.name} or replace it with the package you meant.` : `Update ${p.name}${p.fixedIn ? ` to ${p.fixedIn} or newer` : ""}.` },
      severity: { likelihood: { score: sev, reason: "The registry answer is exact." }, impact: { score: sev, reason: p.message }, overall: sev },
      confidence: { score: "high", reason: p.issue === "made_up" ? "The registry has no package with this name." : "The advisory names this installed version." },
    };
  }
  return {
    ...base, verdict: "needs_validation",
    blockers: [p.issue === "lookalike" ? `Whether ${p.name} is the package you meant, or a lookalike of ${p.similarTo ?? "a popular package"}.` : `Who published ${p.name}, which is only days old.`],
    validationPlan: { local: `Open ${p.file}, check ${p.name} on its registry page, and compare it with ${p.similarTo ?? "the package you meant"}.` },
  };
}

/** A yof check run as findings.json (open findings only; accepted risks and public-by-design keys are left out). */
export function checkToFindingsJson(r: CheckReport): unknown[] {
  const all = [...r.keys.map(keyToVf), ...r.packages.map(packageToVf)].filter((x): x is VfFinding => !!x);
  return toFindingsJson(all);
}

export type LocalState = "found" | "missing_file" | "missing_line" | "outside_folder" | "live_address";
export interface ImportedRecord { fingerprint: string; verdict: VfFinding["verdict"]; title: string; local: LocalState; where: string }
export interface ImportResult { records: ImportedRecord[]; errors: string[]; total: number }

/** Read a findings.json text and check every record against the schema, then against this folder (read only). */
export function importFindings(text: string, root: string): ImportResult {
  const read = fromFindingsJson(text);
  const base = resolve(root);
  const lineCount = new Map<string, number>();
  const where = (file: string, line: number): LocalState => {
    if (/^https?:\/\//i.test(file)) return "live_address";
    if (isAbsolute(file) || file.split(/[\\/]/).includes("..")) return "outside_folder";
    const abs = resolve(base, file);
    if (abs !== base && !abs.startsWith(base + sep)) return "outside_folder";
    const rel = relative(base, abs);
    if (!lineCount.has(rel)) {
      let n = -1;
      try { if (existsSync(abs) && statSync(abs).isFile()) n = readFileSync(abs, "utf8").split("\n").length; } catch { n = -1; }
      lineCount.set(rel, n);
    }
    const n = lineCount.get(rel)!;
    if (n < 0) return "missing_file";
    return line <= n ? "found" : "missing_line";
  };
  const records = read.findings.map((f) => {
    const steps = [...f.trace, ...f.evidence];
    const states = steps.map((s) => where(s.file, s.line));
    // the worst state wins: one missing file means the record does not match this folder
    const order: LocalState[] = ["outside_folder", "missing_file", "missing_line", "live_address", "found"];
    const local = order.find((s) => states.includes(s)) ?? "found";
    const first = steps[0]!;
    return { fingerprint: f.fingerprint, verdict: f.verdict, title: f.title, local, where: `${first.file}:${first.line}` };
  });
  return { records, errors: read.errors, total: read.total };
}

const LOCAL_WORDS: Record<LocalState, string> = {
  found: "file and line found here",
  missing_file: "file not in this folder",
  missing_line: "line not in the file",
  outside_folder: "path leaves this folder: not read",
  live_address: "a live address: not checked here",
};
const VERDICT_WORDS: Record<VfFinding["verdict"], string> = { confirmed: "Confirmed", needs_validation: "Needs validation", rejected: "Rejected" };

export function formatImportText(r: ImportResult, file: string): string {
  const out: string[] = [`yof read ${file}: ${r.total} ${r.total === 1 ? "record" : "records"} (findings.json).`];
  if (r.errors.length) out.push("", `Left out, because they do not match the findings.json schema (${r.errors.length} ${r.errors.length === 1 ? "problem" : "problems"}):`, ...r.errors.slice(0, 20).map((e) => `  ${e}`));
  for (const v of ["confirmed", "needs_validation", "rejected"] as const) {
    const list = r.records.filter((x) => x.verdict === v);
    if (!list.length) continue;
    out.push("", `${VERDICT_WORDS[v]} (${list.length})${v === "rejected" ? ": kept for the record, not counted" : ""}`);
    for (const x of list) out.push(`  ${x.where}  ${x.title}  (${LOCAL_WORDS[x.local]})`);
  }
  const open = r.records.filter((x) => x.verdict !== "rejected").length;
  out.push("", open ? `${open} to look at. yof checked each file and line in this folder; it did not run anything.` : "Nothing to look at.");
  return out.join("\n");
}
