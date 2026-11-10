/**
 * One check: read the files, find keys, check the dependencies, decide the exit code.
 *
 * Profiles (same names as yof Guard's .yof.yml):
 *   relaxed   shows "fix now" only; fails on "fix now"
 *   balanced  shows "fix now" and "fix this week"; fails on "fix now" (the default)
 *   strict    shows everything, including public keys that are fine; fails on "fix now" and "fix this week"
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseGitignore, parseYofYml, type Profile } from "./config";
import { gitTopLevel, runGit, stagedAddedText, stagedFiles, walkFiles, type GitRunner, type SourceFile } from "./files";
import { checkPackages, isManifest, packageMessage, parseManifest, type Dependency, type Ecosystem, type PackageFetcher, type PackageFinding, type PackageIssue } from "./packages";
import { KEY_RULES, isRepoFixture, scanText, type Severity } from "./secrets";
import { ACCEPTED_FILE, acceptFingerprint, acceptanceFor, parseAccepted, type Acceptance } from "./accepted";

/** Most dependencies checked against the registries in one run. */
export const MAX_DEPENDENCIES = 500;

export interface KeyFinding {
  file: string; line: number; column: number; rule: string; name: string; severity: Severity; masked: string;
  /** For .yof/accepted.json (./accepted.ts): changes when the line changes. */
  fingerprint: string;
  /** Set when .yof/accepted.json accepts this finding: it is still listed, but not counted as open. */
  accepted?: Acceptance;
  /** Other rules that caught the very same value in this file (one finding, not several). */
  alsoMatched?: string[];
}
/** `files`: every manifest that names this dependency (the first is `file`), when there is more than one. */
export interface DependencyFinding {
  file: string; name: string; ecosystem: Ecosystem; issue: PackageIssue; severity: "fix_now" | "fix_week"; message: string;
  similarTo?: string; firstPublished?: string; version?: string; advisory?: string; fixedIn?: string | null;
  fingerprint: string; accepted?: Acceptance; files?: string[];
}
export interface CheckReport {
  root: string;
  mode: "full" | "staged";
  profile: Profile;
  offline: boolean;
  filesScanned: number;
  filesSkipped: number;
  truncated: boolean;
  keys: KeyFinding[];
  packages: DependencyFinding[];
  /** Dependencies checked against the registries (0 when offline). */
  dependenciesChecked: number;
  /** Dependencies the registries did not answer for: nothing is claimed about them. */
  unknown: { name: string; ecosystem: Ecosystem }[];
  /** Open findings by severity (accepted ones are not counted). */
  counts: { fix_now: number; fix_week: number; info: number };
  /** Findings .yof/accepted.json accepts (listed with their reason, never hidden). */
  acceptedCount: number;
  /** True when something at or above the profile's threshold was found (exit code 1). */
  failed: boolean;
}

export interface CheckOptions {
  path?: string;
  cwd?: string;
  staged?: boolean;
  offline?: boolean;
  /** Overrides .yof.yml's profile. */
  profile?: Profile;
  fetcher?: PackageFetcher;
  git?: GitRunner;
  now?: Date;
}

export const visibleIn = (profile: Profile, severity: Severity) =>
  profile === "strict" ? true : profile === "balanced" ? severity !== "info" : severity === "fix_now";
export const failsIn = (profile: Profile, severity: Severity) =>
  severity === "fix_now" || (profile === "strict" && severity === "fix_week");

const RANK: Record<Severity, number> = { fix_now: 3, fix_week: 2, info: 1 };
/** Rules that recognise a value by its name or shape alone: a provider rule on the same value is the primary. */
const GENERIC = new Set(["secret.named_env", "secret.aws_key_id"]);
/** Which of two findings on the same value is the primary (negative = a first): urgency, then the specific rule, then the id. */
export const primaryOrder = (a: Pick<KeyFinding, "rule" | "severity">, b: Pick<KeyFinding, "rule" | "severity">) =>
  RANK[b.severity] - RANK[a.severity] || Number(GENERIC.has(a.rule)) - Number(GENERIC.has(b.rule)) || a.rule.localeCompare(b.rule);

/**
 * One finding per value per file (2026-11-07): when several rules catch the same value (a Stripe key in a VITE_..._SECRET
 * setting is both "Stripe live secret key" and "secret-sounding setting"), the primary stays and the others are listed
 * in `alsoMatched`, so counts and the exit code see one problem. Pure, deterministic.
 */
export function collapseKeys(found: readonly (KeyFinding & { hash: string })[]): KeyFinding[] {
  const by = new Map<string, (KeyFinding & { hash: string })[]>();
  for (const k of found) { const key = `${k.file}|${k.hash}`; by.set(key, [...(by.get(key) ?? []), k]); }
  return [...by.values()].map((g) => {
    const [p, ...rest] = [...g].sort(primaryOrder);
    const { hash: _h, ...primary } = p!;
    const also = [...new Set(rest.map((r) => r.rule))].filter((r) => r !== primary.rule).sort();
    // The primary keeps its own fingerprint. An entry in .yof/accepted.json made for one of the folded rules (same
    // value, same line) still applies to the one finding, so grouping never reopens an accepted risk.
    const accepted = primary.accepted ?? rest.find((r) => r.accepted)?.accepted;
    return { ...primary, ...(accepted ? { accepted } : {}), ...(also.length ? { alsoMatched: also } : {}) };
  });
}

const readIf = (p: string) => { try { return existsSync(p) ? readFileSync(p, "utf8") : null; } catch { return null; } };

export class CheckError extends Error {}

export async function runCheck(opts: CheckOptions = {}): Promise<CheckReport> {
  const git = opts.git ?? runGit;
  const base = opts.cwd ?? process.cwd();
  const target = resolve(base, opts.path ?? ".");
  if (!existsSync(target) || !statSync(target).isDirectory()) throw new CheckError(`Not a folder: ${opts.path ?? "."}`);

  let root = target;
  if (opts.staged) {
    try { root = gitTopLevel(target, git); } catch { throw new CheckError("--staged needs a git repository (git rev-parse failed here)."); }
  }
  const cfg = parseYofYml(readIf(join(root, ".yof.yml")));
  const profile = opts.profile ?? cfg.profile;

  const set = opts.staged ? stagedFiles(root, cfg.ignore, git) : walkFiles(root, cfg.ignore, parseGitignore(readIf(join(root, ".gitignore"))));

  // Accepted risks recorded in the repository (always the working tree's file, so a staged check sees them too).
  const acceptedList = parseAccepted(readIf(join(root, ACCEPTED_FILE)));

  // Keys.
  const found: (KeyFinding & { hash: string })[] = [];
  for (const f of set.files) {
    const lines = f.content.split(/\r?\n/);
    for (const m of scanText(f.content)) {
      const rule = KEY_RULES[m.ruleId] ?? { name: m.ruleId, severity: "fix_week" as Severity };
      const text = lines[m.line - 1] ?? "";
      if (isRepoFixture(m, f.path, text)) continue;   // the app's repository rule (0.3.1)
      const accepted = acceptanceFor(acceptedList, m.ruleId, f.path, text);
      found.push({ file: f.path, line: m.line, column: m.column, rule: m.ruleId, name: rule.name, severity: rule.severity, masked: m.masked, fingerprint: acceptFingerprint(m.ruleId, f.path, text), ...(accepted ? { accepted } : {}), hash: m.hash });
    }
  }
  const keys = collapseKeys(found);

  // Dependencies (staged mode: only the ones on lines this commit adds).
  const deps: (Dependency & { file: string; files: string[] })[] = [];
  const manifests: SourceFile[] = set.files.filter((f) => isManifest(f.path));
  for (const m of manifests) {
    let parsed = parseManifest(m.path, m.content);
    if (opts.staged) {
      let added = "";
      try { added = stagedAddedText(root, m.path, git); } catch { added = m.content; }
      parsed = parsed.filter((d) => added.toLowerCase().includes(d.name) || added.toLowerCase().replace(/[-_.]+/g, "-").includes(d.name));
    }
    // One dependency, however many workspace manifests name it: asked once, reported once, every manifest listed.
    for (const d of parsed) {
      const have = deps.find((x) => x.name === d.name && x.ecosystem === d.ecosystem);
      if (!have) deps.push({ ...d, file: m.path, files: [m.path] });
      else if (!have.files.includes(m.path)) have.files.push(m.path);
    }
  }
  const toCheck = deps.slice(0, MAX_DEPENDENCIES);

  const packages: DependencyFinding[] = [];
  let unknown: { name: string; ecosystem: Ecosystem }[] = [];
  let dependenciesChecked = 0;
  if (!opts.offline && toCheck.length) {
    const result = await checkPackages(toCheck, { fetcher: opts.fetcher, now: opts.now });
    dependenciesChecked = result.checked;
    unknown = result.unknown;
    for (const f of result.findings as PackageFinding[]) {
      const dep = toCheck.find((d) => d.name === f.name && d.ecosystem === f.ecosystem);
      const file = dep?.file ?? "";
      const rule = `package.${f.issue}`, content = `${f.ecosystem}:${f.name}`;
      const accepted = acceptanceFor(acceptedList, rule, file, content);
      packages.push({ file, ...f, message: packageMessage(f), fingerprint: acceptFingerprint(rule, file, content), ...(accepted ? { accepted } : {}), ...((dep?.files.length ?? 0) > 1 ? { files: dep!.files } : {}) });
    }
  }

  const counts = { fix_now: 0, fix_week: 0, info: 0 };
  const open = [...keys, ...packages].filter((x) => !x.accepted);
  for (const x of open) counts[x.severity]++;
  const failed = open.some((x) => failsIn(profile, x.severity));
  const acceptedCount = keys.length + packages.length - open.length;

  return {
    root, mode: opts.staged ? "staged" : "full", profile, offline: !!opts.offline,
    filesScanned: set.files.length, filesSkipped: set.skipped, truncated: set.truncated,
    keys, packages, dependenciesChecked, unknown, counts, acceptedCount, failed,
  };
}
