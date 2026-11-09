/**
 * findings.json, the findings format of Cloudflare's security-audit skill, read AND written by yof (board Y18 C,
 * owner 2026-11-09). One mapper both ways, with no imports at all, so the open-source CLI carries a byte-identical
 * copy (oss/yof/src/findings-json.ts; a test pins that the two files are the same).
 *
 *   toFindingsJson(findings)   yof's findings (VfFinding) -> the findings.json array
 *   fromFindingsJson(value)    a findings.json array -> yof's findings, after a strict check against the schema
 *                              (unknown fields, missing fields, wrong enums and impossible severities are refused,
 *                              never guessed at); a record that fails is reported by index and left out
 *
 * The two are exact inverses: a valid findings.json read and written again gives the same JSON, and a yof finding
 * written and read again gives the same finding (pinned by the round-trip tests).
 *
 * A yof finding's fingerprint is written as "yof/<rule id>/<yof fingerprint>", which the schema's fingerprint pattern
 * allows, so the rule id survives the trip without an extra field (the schema forbids extra fields). A finding on the
 * live app has no repository file: its trace and evidence name its web address instead (with line 1),
 * which the schema accepts; a reader can tell the two apart by the address scheme (http or https).
 *
 * Schema: skills/security-audit/report-schema.json in https://github.com/cloudflare/security-audit-skill
 * MIT License, Copyright (c) 2025-2026 Cloudflare, Inc. The field names, the three verdicts and their rules below
 * follow that schema; the code is yof's own.
 */

export type CfVerdict = "confirmed" | "needs_validation" | "rejected";
export type CfSeverity = "informational" | "low" | "medium" | "high" | "critical";
export type CfTraceKind = "entrypoint" | "propagation" | "sink";
export type CfConditionKind =
  | "authentication_level" | "authorization_role" | "user_interaction" | "system_configuration" | "network_routing"
  | "environmental_dependency" | "data_state" | "timing_dependency" | "third_party_dependency";
export const CF_SEVERITIES: readonly CfSeverity[] = ["informational", "low", "medium", "high", "critical"];
const CF_CONDITION_KINDS: readonly CfConditionKind[] = [
  "authentication_level", "authorization_role", "user_interaction", "system_configuration", "network_routing",
  "environmental_dependency", "data_state", "timing_dependency", "third_party_dependency",
];
const CONFIDENCE = ["low", "medium", "high"] as const;
export const FINGERPRINT_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;
/** The same limits as the skill's own validator. */
export const FINDINGS_JSON_MAX_BYTES = 5 * 1024 * 1024;
export const FINDINGS_JSON_MAX_RECORDS = 1000;

// ── yof's side: a finding with every field findings.json can hold, in yof's naming ──────────────────────────────
export interface VfTraceStep { kind: CfTraceKind; file: string; line: number; scope: string; description: string }
export interface VfEvidence { file: string; line: number; description: string }
export interface VfFinding {
  fingerprint: string;
  verdict: CfVerdict;
  title: string;
  description: string;
  /** root_cause (confirmed) or claimed_root_cause (needs_validation, rejected). */
  rootCause: string;
  trace: VfTraceStep[];
  evidence: VfEvidence[];
  /** confirmed only */
  intendedBehavior?: string;
  conditions?: { kind: CfConditionKind; description: string }[];
  execution?: { attackerPerspective: string; payloads: string[]; instructions: string[]; observedResult: string };
  remediation?: { strategy: string; codeChanges?: { fileName: string; fixedCode: string }[] };
  severity?: { likelihood: { score: CfSeverity; reason: string }; impact: { score: CfSeverity; reason: string }; overall: CfSeverity };
  confidence?: { score: (typeof CONFIDENCE)[number]; reason: string };
  /** needs_validation only */
  blockers?: string[];
  validationPlan?: { local?: string; deployment?: string };
  /** rejected only */
  reason?: string;
}

/** "yof/<rule>/<fingerprint>" for a yof finding; the rule id of a fingerprint written that way, else null. */
export const yofFingerprint = (ruleId: string, fp: string): string => `yof/${ruleId}/${fp}`;
export function ruleOfFingerprint(fp: string): string | null {
  const m = /^yof\/([a-z0-9_.]{3,80})\/[A-Za-z0-9._:@+-]+$/.exec(fp);
  return m ? m[1]! : null;
}

// ── yof -> findings.json ─────────────────────────────────────────────────────────────────────────────────────────
type Rec = Record<string, unknown>;
const traceOut = (t: readonly VfTraceStep[]) => t.map((s) => ({ kind: s.kind, file: s.file, line: s.line, scope: s.scope, description: s.description }));
const evidenceOut = (e: readonly VfEvidence[]) => e.map((x) => ({ file: x.file, line: x.line, description: x.description }));
const dropUndefined = (o: Rec): Rec => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));

export function toFindingsJsonRecord(f: VfFinding): Rec {
  const head = { verdict: f.verdict, fingerprint: f.fingerprint, title: f.title, description: f.description };
  if (f.verdict === "confirmed") {
    // a field yof has no value for is left out (never written as null), so the validator names it instead of guessing
    return dropUndefined({
      ...head, root_cause: f.rootCause, intended_behavior: f.intendedBehavior ?? "", trace: traceOut(f.trace), evidence: evidenceOut(f.evidence),
      conditions: (f.conditions ?? []).map((c) => ({ kind: c.kind, description: c.description })),
      execution: f.execution
        ? { attacker_perspective: f.execution.attackerPerspective, payloads: [...f.execution.payloads], instructions: [...f.execution.instructions], observed_result: f.execution.observedResult }
        : undefined,
      remediation: f.remediation
        ? { strategy: f.remediation.strategy, ...(f.remediation.codeChanges ? { code_changes: f.remediation.codeChanges.map((c) => ({ file_name: c.fileName, fixed_code: c.fixedCode })) } : {}) }
        : undefined,
      severity: f.severity
        ? { likelihood: { score: f.severity.likelihood.score, reason: f.severity.likelihood.reason }, impact: { score: f.severity.impact.score, reason: f.severity.impact.reason }, overall_severity: f.severity.overall }
        : undefined,
      confidence: f.confidence ? { score: f.confidence.score, reason: f.confidence.reason } : undefined,
    });
  }
  if (f.verdict === "needs_validation") {
    const plan: Rec = {};
    if (f.validationPlan?.local !== undefined) plan.local = f.validationPlan.local;
    if (f.validationPlan?.deployment !== undefined) plan.deployment = f.validationPlan.deployment;
    return { ...head, claimed_root_cause: f.rootCause, trace: traceOut(f.trace), evidence: evidenceOut(f.evidence), blockers: [...(f.blockers ?? [])], validation_plan: plan };
  }
  return { ...head, claimed_root_cause: f.rootCause, trace: traceOut(f.trace), evidence: evidenceOut(f.evidence), reason: f.reason ?? "" };
}

/** Every finding as a findings.json array, sorted by fingerprint like the skill writes it. */
export function toFindingsJson(findings: readonly VfFinding[]): Rec[] {
  return [...findings].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0)).map(toFindingsJsonRecord);
}

// ── findings.json -> yof (strict) ────────────────────────────────────────────────────────────────────────────────
const isObj = (v: unknown): v is Rec => !!v && typeof v === "object" && !Array.isArray(v);
const visible = (v: unknown): v is string => typeof v === "string" && v.trim().length > 0;

class Check {
  errors: string[] = [];
  constructor(private readonly at: string) {}
  fail(path: string, msg: string) { this.errors.push(`${this.at}${path}: ${msg}`); }
  only(o: Rec, path: string, allowed: readonly string[], required: readonly string[]) {
    for (const k of Object.keys(o)) if (!allowed.includes(k)) this.fail(`${path}.${k}`, "is not allowed for this verdict");
    for (const k of required) if (!(k in o)) this.fail(`${path}.${k}`, "is missing");
  }
  text(o: Rec, k: string, path: string): string {
    const v = o[k];
    if (!visible(v)) { this.fail(`${path}.${k}`, "must be a non-empty text"); return ""; }
    return v;
  }
  rawText(o: Rec, k: string, path: string): string {
    const v = o[k];
    if (typeof v !== "string" || !v.length) { this.fail(`${path}.${k}`, "must be a non-empty text"); return ""; }
    return v;
  }
  line(o: Rec, path: string): number {
    const v = o.line;
    if (!Number.isInteger(v) || (v as number) < 1) { this.fail(`${path}.line`, "must be a whole number of at least 1"); return 1; }
    return v as number;
  }
  oneOf<T extends string>(v: unknown, list: readonly T[], path: string): T {
    if (typeof v !== "string" || !(list as readonly string[]).includes(v)) { this.fail(path, `must be one of ${list.join(", ")}`); return list[0]!; }
    return v as T;
  }
  array(v: unknown, path: string, min: number): unknown[] {
    if (!Array.isArray(v)) { this.fail(path, "must be a list"); return []; }
    if (v.length < min) this.fail(path, `needs at least ${min} item${min === 1 ? "" : "s"}`);
    const seen = new Set(v.map((x) => JSON.stringify(x)));
    if (seen.size !== v.length) this.fail(path, "has the same item twice");
    return v;
  }
}

function readTrace(c: Check, v: unknown, path: string): VfTraceStep[] {
  const out = c.array(v, path, 1).map((x, i) => {
    const p = `${path}[${i}]`;
    if (!isObj(x)) { c.fail(p, "must be an object"); return null; }
    c.only(x, p, ["kind", "file", "line", "scope", "description"], ["kind", "file", "line", "scope", "description"]);
    return { kind: c.oneOf<CfTraceKind>(x.kind, ["entrypoint", "propagation", "sink"], `${p}.kind`), file: c.rawText(x, "file", p), line: c.line(x, p), scope: c.text(x, "scope", p), description: c.text(x, "description", p) };
  }).filter((x): x is VfTraceStep => !!x);
  // the skill's order rule: a multi-step trace starts at the entrypoint, ends at the sink, propagation only between
  if (out.length > 1) {
    if (out[0]!.kind !== "entrypoint") c.fail(path, "a multi-step trace must start with an entrypoint");
    if (out[out.length - 1]!.kind !== "sink") c.fail(path, "a multi-step trace must end with a sink");
    if (out.slice(1, -1).some((s) => s.kind !== "propagation")) c.fail(path, "only propagation steps may sit between the entrypoint and the sink");
  } else if (out.length === 1 && out[0]!.kind === "propagation") c.fail(path, "a one-step trace is an entrypoint or a sink");
  return out;
}
function readEvidence(c: Check, v: unknown, path: string): VfEvidence[] {
  return c.array(v, path, 1).map((x, i) => {
    const p = `${path}[${i}]`;
    if (!isObj(x)) { c.fail(p, "must be an object"); return null; }
    c.only(x, p, ["file", "line", "description"], ["file", "line", "description"]);
    return { file: c.rawText(x, "file", p), line: c.line(x, p), description: c.text(x, "description", p) };
  }).filter((x): x is VfEvidence => !!x);
}
function readScore(c: Check, v: unknown, path: string): { score: CfSeverity; reason: string } {
  if (!isObj(v)) { c.fail(path, "must be an object"); return { score: "informational", reason: "" }; }
  c.only(v, path, ["score", "reason"], ["score", "reason"]);
  return { score: c.oneOf(v.score, CF_SEVERITIES, `${path}.score`), reason: c.text(v, "reason", path) };
}

/** One record; errors are collected in `c`. */
function readRecord(c: Check, r: unknown): VfFinding | null {
  if (!isObj(r)) { c.fail("", "must be an object"); return null; }
  const verdict = c.oneOf<CfVerdict>(r.verdict, ["confirmed", "needs_validation", "rejected"], ".verdict");
  const fp = typeof r.fingerprint === "string" && FINGERPRINT_RE.test(r.fingerprint) ? r.fingerprint : (c.fail(".fingerprint", "must match the fingerprint pattern"), "");
  const head = { fingerprint: fp, verdict, title: c.text(r, "title", ""), description: c.text(r, "description", "") };
  if (verdict === "confirmed") {
    c.only(r, "", ["verdict", "fingerprint", "title", "description", "root_cause", "intended_behavior", "trace", "evidence", "conditions", "execution", "remediation", "severity", "confidence"],
      ["verdict", "fingerprint", "title", "description", "root_cause", "intended_behavior", "trace", "evidence", "conditions", "execution", "remediation", "severity", "confidence"]);
    const conditions = c.array(r.conditions, ".conditions", 0).map((x, i) => {
      const p = `.conditions[${i}]`;
      if (!isObj(x)) { c.fail(p, "must be an object"); return null; }
      c.only(x, p, ["kind", "description"], ["kind", "description"]);
      return { kind: c.oneOf(x.kind, CF_CONDITION_KINDS, `${p}.kind`), description: c.text(x, "description", p) };
    }).filter((x): x is { kind: CfConditionKind; description: string } => !!x);
    const ex = isObj(r.execution) ? r.execution : (c.fail(".execution", "must be an object"), {} as Rec);
    c.only(ex, ".execution", ["attacker_perspective", "payloads", "instructions", "observed_result"], ["attacker_perspective", "payloads", "instructions", "observed_result"]);
    const payloads = c.array(ex.payloads, ".execution.payloads", 1).map((p, i) => (typeof p === "string" ? p : (c.fail(`.execution.payloads[${i}]`, "must be a text"), "")));
    const instructions = (Array.isArray(ex.instructions) ? ex.instructions : (c.fail(".execution.instructions", "must be a list"), [])).map((p: unknown, i: number) => (visible(p) ? p : (c.fail(`.execution.instructions[${i}]`, "must be a non-empty text"), "")));
    if (Array.isArray(ex.instructions) && !ex.instructions.length) c.fail(".execution.instructions", "needs at least 1 item");
    const rem = isObj(r.remediation) ? r.remediation : (c.fail(".remediation", "must be an object"), {} as Rec);
    c.only(rem, ".remediation", ["strategy", "code_changes"], ["strategy"]);
    const codeChanges = rem.code_changes === undefined ? undefined : (Array.isArray(rem.code_changes) ? rem.code_changes : (c.fail(".remediation.code_changes", "must be a list"), [])).map((x: unknown, i: number) => {
      const p = `.remediation.code_changes[${i}]`;
      if (!isObj(x)) { c.fail(p, "must be an object"); return { fileName: "", fixedCode: "" }; }
      c.only(x, p, ["file_name", "fixed_code"], ["file_name", "fixed_code"]);
      return { fileName: c.rawText(x, "file_name", p), fixedCode: typeof x.fixed_code === "string" ? x.fixed_code : (c.fail(`${p}.fixed_code`, "must be a text"), "") };
    });
    const sv = isObj(r.severity) ? r.severity : (c.fail(".severity", "must be an object"), {} as Rec);
    c.only(sv, ".severity", ["likelihood", "impact", "overall_severity"], ["likelihood", "impact", "overall_severity"]);
    const likelihood = readScore(c, sv.likelihood, ".severity.likelihood");
    const impact = readScore(c, sv.impact, ".severity.impact");
    const overall = c.oneOf(sv.overall_severity, CF_SEVERITIES, ".severity.overall_severity");
    // "Overall severity cannot exceed demonstrated impact."
    if (CF_SEVERITIES.indexOf(overall) > CF_SEVERITIES.indexOf(impact.score)) c.fail(".severity.overall_severity", "is higher than the demonstrated impact");
    const cf = isObj(r.confidence) ? r.confidence : (c.fail(".confidence", "must be an object"), {} as Rec);
    c.only(cf, ".confidence", ["score", "reason"], ["score", "reason"]);
    return {
      ...head, rootCause: c.text(r, "root_cause", ""), intendedBehavior: c.text(r, "intended_behavior", ""),
      trace: readTrace(c, r.trace, ".trace"), evidence: readEvidence(c, r.evidence, ".evidence"), conditions,
      execution: { attackerPerspective: c.text(ex, "attacker_perspective", ".execution"), payloads, instructions, observedResult: c.text(ex, "observed_result", ".execution") },
      remediation: { strategy: c.text(rem, "strategy", ".remediation"), ...(codeChanges ? { codeChanges } : {}) },
      severity: { likelihood, impact, overall },
      confidence: { score: c.oneOf(cf.score, CONFIDENCE, ".confidence.score"), reason: c.text(cf, "reason", ".confidence") },
    };
  }
  if (verdict === "needs_validation") {
    c.only(r, "", ["verdict", "fingerprint", "title", "description", "claimed_root_cause", "trace", "evidence", "blockers", "validation_plan"],
      ["verdict", "fingerprint", "title", "description", "claimed_root_cause", "trace", "evidence", "blockers", "validation_plan"]);
    const blockers = c.array(r.blockers, ".blockers", 1).map((b, i) => (visible(b) ? b : (c.fail(`.blockers[${i}]`, "must be a non-empty text"), "")));
    const vp = isObj(r.validation_plan) ? r.validation_plan : (c.fail(".validation_plan", "must be an object"), {} as Rec);
    c.only(vp, ".validation_plan", ["local", "deployment"], []);
    const plan: { local?: string; deployment?: string } = {};
    if ("local" in vp) plan.local = c.text(vp, "local", ".validation_plan");
    if ("deployment" in vp) plan.deployment = c.text(vp, "deployment", ".validation_plan");
    return { ...head, rootCause: c.text(r, "claimed_root_cause", ""), trace: readTrace(c, r.trace, ".trace"), evidence: readEvidence(c, r.evidence, ".evidence"), blockers, validationPlan: plan };
  }
  c.only(r, "", ["verdict", "fingerprint", "title", "description", "claimed_root_cause", "trace", "evidence", "reason"],
    ["verdict", "fingerprint", "title", "description", "claimed_root_cause", "trace", "evidence", "reason"]);
  return { ...head, rootCause: c.text(r, "claimed_root_cause", ""), trace: readTrace(c, r.trace, ".trace"), evidence: readEvidence(c, r.evidence, ".evidence"), reason: c.text(r, "reason", "") };
}

export interface FindingsJsonRead { findings: VfFinding[]; errors: string[]; total: number }

/**
 * Read a findings.json value (the parsed JSON, or its text). Strict: a record with any error is left out and every
 * error is listed with its index; nothing is repaired. Over FINDINGS_JSON_MAX_BYTES or FINDINGS_JSON_MAX_RECORDS the
 * whole file is refused. Two records with the same fingerprint: the second is refused.
 */
export function fromFindingsJson(input: unknown): FindingsJsonRead {
  let v = input;
  if (typeof input === "string") {
    if (input.length > FINDINGS_JSON_MAX_BYTES) return { findings: [], errors: [`The file is larger than ${FINDINGS_JSON_MAX_BYTES} bytes.`], total: 0 };
    try { v = JSON.parse(input); } catch { return { findings: [], errors: ["The file is not valid JSON."], total: 0 }; }
  }
  if (!Array.isArray(v)) return { findings: [], errors: ["findings.json must be a list of findings."], total: 0 };
  if (v.length > FINDINGS_JSON_MAX_RECORDS) return { findings: [], errors: [`findings.json holds more than ${FINDINGS_JSON_MAX_RECORDS} findings.`], total: v.length };
  const findings: VfFinding[] = [];
  const errors: string[] = [];
  const seen = new Set<string>();
  v.forEach((r, i) => {
    const c = new Check(`[${i}]`);
    const f = readRecord(c, r);
    if (f && seen.has(f.fingerprint)) c.fail(".fingerprint", "is used by an earlier record");
    if (c.errors.length || !f) { errors.push(...c.errors); return; }
    seen.add(f.fingerprint);
    findings.push(f);
  });
  return { findings, errors, total: v.length };
}
