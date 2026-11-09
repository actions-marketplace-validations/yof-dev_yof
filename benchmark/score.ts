/**
 * Scoring: yof's results (the JSON of `yof check --json` and `yof attack --json`) against one app's official list.
 * Deterministic: the same inputs give the same output, byte for byte. Nothing here touches the network.
 *
 * Only what a reader needs is kept: rule, file and line, package name and version, method and route. Never a masked
 * key, a code snippet or an attack's evidence text, so the committed results can hold nothing private or key-shaped.
 */
import type { ListItem } from "./lists.ts";
import type { Detector, MappingEntry, Relation, Target } from "./targets.ts";

export type ItemStatus = "found" | "missed" | "not_tested" | "not_available";
export type Verdict = "false_positive" | "real_not_listed" | "to_review";

export interface ScoredItem {
  key: string;
  name: string;
  category: string;
  status: ItemStatus;
  relation?: Relation;
  /** The yof results that counted (found), in a fixed order. */
  by?: string[];
  /** Why it counts (tested items), why it was missed, or why it is not tested or not available. */
  note: string;
}

export interface ExtraFinding { id: string; source: Finding["source"]; rule: string; where: string; verdict: Verdict; note?: string }

export interface TargetCounts {
  items: number;
  found: number;
  foundSame: number;
  foundRoot: number;
  missed: number;
  notTested: number;
  notAvailable: number;
  extra: number;
  falsePositives: number;
  realNotListed: number;
  toReview: number;
}

export interface TargetResult {
  id: Target["id"];
  name: string;
  repo: string;
  tag: string | null;
  commit: string;
  run: string;
  image: Target["image"];
  list: { file: string; label: string; items: number };
  /** false when the app did not start or yof could not run: no counts are claimed then. */
  ran: boolean;
  error: string | null;
  check: { filesScanned: number; dependenciesChecked: number; registryUnanswered: number; truncated: boolean } | null;
  attack: { requests: number; seconds: number; groups: Record<string, string>; stopped: string | null; notes: string[] } | null;
  /** Juice Shop only: challenges its own score board marked solved while yof attack ran. */
  solvedDuringRun: string[];
  counts: TargetCounts | null;
  items: ScoredItem[];
  extra: ExtraFinding[];
}

export interface Finding { id: string; source: "key" | "package" | "attack"; rule: string; where: string; file?: string; name?: string; route?: string; issue?: string }

export class ScoreError extends Error {}

/* The subset of yof's JSON the scoring reads. Anything else in the files is ignored. */
interface CheckJson {
  filesScanned?: number; dependenciesChecked?: number; truncated?: boolean;
  keys?: { file: string; line: number; rule: string }[];
  packages?: { file: string; name: string; version?: string; issue: string }[];
  unknown?: unknown[];
}
interface AttackJson {
  requests?: number; startedAt?: string; finishedAt?: string; stopped?: string | null; notes?: string[];
  groups?: Record<string, string>;
  findings?: { ruleId: string; method: string; route: string }[];
}

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** yof's check and attack results as one flat, sorted list of findings. */
export function findingsOf(check: CheckJson | null, attack: AttackJson | null): Finding[] {
  const out = new Map<string, Finding>();
  const add = (f: Omit<Finding, "id">) => { const id = `${f.source}|${f.rule}|${f.where}`; if (!out.has(id)) out.set(id, { id, ...f }); };
  for (const k of check?.keys ?? []) add({ source: "key", rule: k.rule, where: `${k.file}:${k.line}`, file: k.file });
  for (const p of check?.packages ?? []) {
    add({ source: "package", rule: `package.${p.issue}`, where: `${p.file} ${p.name}${p.version ? `@${p.version}` : ""}`, file: p.file, name: p.name, issue: p.issue });
  }
  for (const f of attack?.findings ?? []) add({ source: "attack", rule: f.ruleId, where: `${f.method} ${f.route}`, route: f.route });
  return [...out.values()].sort((a, b) => byText(a.id, b.id));
}

export function matches(d: Detector, f: Finding): boolean {
  if (d.source !== f.source) return false;
  if (d.source === "key") return (!d.rule || d.rule === f.rule) && (!d.file || d.file.test(f.file ?? ""));
  if (d.source === "package") {
    return (d.issues as readonly string[]).includes(f.issue ?? "") && (!d.names || d.names.includes(f.name ?? "")) && (!d.file || d.file.test(f.file ?? ""));
  }
  return d.rule === f.rule && (!d.route || d.route.test(f.route ?? ""));
}

export type Reviews = Record<string, Record<string, { verdict: Exclude<Verdict, "to_review">; note?: string }>>;

export interface ScoreInput {
  target: Target;
  list: ListItem[];
  check: CheckJson | null;
  attack: AttackJson | null;
  solvedBefore?: string[];
  solvedAfter?: string[];
  reviews?: Reviews;
  /** Set when the app did not start or yof could not run. */
  error?: string | null;
}

export function scoreTarget(input: ScoreInput): TargetResult {
  const { target, list } = input;
  const keys = new Set(list.map((i) => i.key));
  const unknown = target.mapping.filter((m) => !keys.has(m.key)).map((m) => m.key);
  if (unknown.length) throw new ScoreError(`The mapping names keys that are not in the pinned ${target.list.file}: ${unknown.join(", ")}`);
  const mapped = new Map<string, MappingEntry>(target.mapping.map((m) => [m.key, m]));

  const base = {
    id: target.id, name: target.name, repo: target.repo, tag: target.tag, commit: target.commit, run: target.run, image: target.image,
    list: { file: target.list.file, label: target.list.label, items: list.length },
  };
  const error = input.error ?? null;
  const ran = !error && (input.check !== null || input.attack !== null);

  const findings = ran ? findingsOf(input.check, input.attack) : [];
  const used = new Set<string>();
  const items: ScoredItem[] = list.map((it) => {
    const m = mapped.get(it.key);
    const head = { key: it.key, name: it.name, category: it.category };
    if (m?.kind === "not_available") return { ...head, status: "not_available", note: m.why };
    if (target.disabledEnv && it.disabledEnv.includes(target.disabledEnv)) {
      return { ...head, status: "not_available", note: `${target.name} turns this off when it runs in ${target.disabledEnv}.` };
    }
    if (!m) return { ...head, status: "not_tested", note: target.defaultNotTested };
    if (m.kind !== "tested") return { ...head, status: m.kind, note: m.why };
    const tested = m;
    const missing = tested.detectors.every((d) => (d.source === "attack" ? input.attack === null : input.check === null));
    if (ran && missing) return { ...head, status: "not_available", note: `Not run: yof ${tested.detectors[0]!.source === "attack" ? "attack" : "check"} produced no results in this run.` };
    const hits = findings.filter((f) => tested.detectors.some((d) => matches(d, f)));
    for (const h of hits) used.add(h.id);
    if (!ran) return { ...head, status: "not_available", note: `Not run: ${error ?? "no yof results"}` };
    return hits.length
      ? { ...head, status: "found", relation: m.relation, by: hits.map((h) => `${h.rule} ${h.where}`), note: m.why }
      : { ...head, status: "missed", relation: m.relation, note: m.ifMissed };
  });

  const reviews = input.reviews?.[target.id] ?? {};
  const extra: ExtraFinding[] = findings.filter((f) => !used.has(f.id)).map((f) => {
    const r = reviews[f.id];
    return { id: f.id, source: f.source, rule: f.rule, where: f.where, verdict: r?.verdict ?? "to_review", ...(r?.note ? { note: r.note } : {}) };
  });

  const n = (s: ItemStatus) => items.filter((i) => i.status === s).length;
  const counts: TargetCounts | null = ran ? {
    items: items.length,
    found: n("found"),
    foundSame: items.filter((i) => i.status === "found" && i.relation === "same").length,
    foundRoot: items.filter((i) => i.status === "found" && i.relation === "root").length,
    missed: n("missed"),
    notTested: n("not_tested"),
    notAvailable: n("not_available"),
    extra: extra.length,
    falsePositives: extra.filter((e) => e.verdict === "false_positive").length,
    realNotListed: extra.filter((e) => e.verdict === "real_not_listed").length,
    toReview: extra.filter((e) => e.verdict === "to_review").length,
  } : null;

  const before = new Set(input.solvedBefore ?? []);
  const solvedDuringRun = (input.solvedAfter ?? []).filter((k) => !before.has(k) && keys.has(k)).sort(byText);
  const seconds = input.attack?.startedAt && input.attack.finishedAt
    ? Math.max(0, Math.round((Date.parse(input.attack.finishedAt) - Date.parse(input.attack.startedAt)) / 1000)) : 0;

  return {
    ...base, ran, error,
    check: ran && input.check ? {
      filesScanned: input.check.filesScanned ?? 0, dependenciesChecked: input.check.dependenciesChecked ?? 0,
      registryUnanswered: input.check.unknown?.length ?? 0, truncated: input.check.truncated === true,
    } : null,
    attack: ran && input.attack ? {
      requests: input.attack.requests ?? 0, seconds, groups: { ...(input.attack.groups ?? {}) }, stopped: input.attack.stopped ?? null,
      notes: [...(input.attack.notes ?? [])].slice(0, 20),
    } : null,
    solvedDuringRun, counts, items, extra,
  };
}

export interface RunInfo {
  /** GitHub Actions run id and its page. */
  id: string;
  url: string;
  /** The commit of this repository the run used (yof's code and the mapping). */
  commit: string;
  yofVersion: string;
  startedAt: string;
  finishedAt: string;
  runner: string;
}

export interface BenchmarkResults {
  schema: 1;
  status: "pending" | "done";
  run: RunInfo | null;
  targets: TargetResult[];
}

export const PENDING: BenchmarkResults = { schema: 1, status: "pending", run: null, targets: [] };

export function combine(run: RunInfo, targets: TargetResult[]): BenchmarkResults {
  return { schema: 1, status: "done", run, targets: [...targets].sort((a, b) => byText(a.id, b.id)) };
}
