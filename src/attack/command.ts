/**
 * `yof attack`: load the config, prove the target, scope the run (pull requests), run, write the regression tests,
 * and optionally send the masked results to the person's yof app.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { runGit, type GitRunner } from "../files";
import { blastRadius, groupsFor, routeMatches, scopeLabel } from "./blast";
import { ATTACK_GROUPS, type AttackGroup } from "./catalog";
import { ConfigError, parseAttackConfig } from "./config";
import type { FetchFn } from "./http";
import { findPreviewUrl, proveTarget, type Mode } from "./proof";
import { detectFramework, synthesizeTest, type GeneratedTest } from "./regression";
import { attackComment, type AttackReport } from "./report";
import { runAttack } from "./runner";

export class AttackError extends Error {}

export interface AttackOptions {
  target?: string;
  cwd: string;
  config?: string;
  mode?: Mode;
  /** The pull request's base branch: scope the run to what the change can reach. */
  base?: string;
  writeTests?: boolean;
  /** Write the pull-request comment (markdown) to this file. */
  commentFile?: string;
  upload?: boolean;
  version: string;
  env?: Record<string, string | undefined>;
  fetch?: FetchFn;
  git?: GitRunner;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** The changed files, instead of asking git (tests). */
  changedFiles?: string[];
  /** Aborted when the person stops the run (the CLI wires SIGINT and SIGTERM to it). */
  signal?: AbortSignal;
}

export interface AttackOutcome { report: AttackReport; tests: GeneratedTest[]; comment: string | null; uploaded: boolean | null }

const readIf = (p: string) => { try { return existsSync(p) ? readFileSync(p, "utf8") : null; } catch { return null; } };

export async function runAttackCommand(o: AttackOptions): Promise<AttackOutcome> {
  const env = o.env ?? process.env;
  const now = o.now ?? Date.now;
  const mode = o.mode ?? "full";
  const cfgPath = resolve(o.cwd, o.config ?? ".yof/attack.json");
  const text = readIf(cfgPath);
  if (text == null) throw new AttackError(`No attack config at ${o.config ?? ".yof/attack.json"}. See https://yof.io/docs for the format.`);
  let cfg;
  try { cfg = parseAttackConfig(text); } catch (e) { if (e instanceof ConfigError) throw new AttackError(e.message); throw e; }

  let target = o.target ?? env.YOF_ATTACK_TARGET ?? null;
  if (!target) target = await findPreviewUrl(env, o.fetch);
  if (!target) throw new AttackError("Give the address to test: yof attack <url>, or YOF_ATTACK_TARGET, or run on a pull request with a GitHub deployment.");

  const proof = await proveTarget(target, cfg, mode, { fetch: o.fetch, env, now: new Date(now()) });
  if (!proof.ok) throw new AttackError(`Refused: ${proof.message}`);

  // Scope (feature B): only on a pull-request run, and never narrower than "full" when the mapping is unsure.
  let scope = { full: true, groups: [...ATTACK_GROUPS] as AttackGroup[], reasons: [] as string[], routes: [] as string[] };
  if (o.base) {
    const git = o.git ?? runGit;
    let changed = o.changedFiles;
    let all: string[] = [];
    try {
      changed ??= git(["diff", "--name-only", `origin/${o.base}...HEAD`], o.cwd).toString("utf8").split("\n").map((s) => s.trim()).filter(Boolean);
      all = git(["ls-files"], o.cwd).toString("utf8").split("\n").map((s) => s.trim()).filter(Boolean);
    } catch {
      changed = undefined;
    }
    if (!changed) scope.reasons = ["git could not list the changed files"];
    else {
      const blast = blastRadius(changed, (p) => (p.split("/").includes("..") ? null : readIf(join(o.cwd, p))), all.length ? all : changed);
      if (blast.full) scope.reasons = blast.reasons;
      else scope = { full: false, groups: groupsFor(cfg, blast.routes), reasons: [], routes: blast.routes };
    }
  }

  const started = new Date(now()).toISOString();
  const res = await runAttack({
    cfg, proof, mode, env, fetch: o.fetch, now: o.now, sleep: o.sleep, signal: o.signal,
    groups: scope.groups, ...(scope.full ? {} : { routeFilter: (p: string) => routeMatches(p, scope.routes) }),
  });
  const finished = new Date(now()).toISOString();

  const fw = detectFramework({ read: (p) => readIf(join(o.cwd, p)), exists: (p) => existsSync(join(o.cwd, p)) });
  const tests = res.findings.map((f) => synthesizeTest(f.replay, { method: f.method, route: f.route }, fw));
  const report: AttackReport = {
    tool: "yof", command: "attack", version: o.version, app: cfg.app,
    target: { origin: proof.origin, host: proof.host, kind: proof.kind, proof: proof.method }, mode,
    scope: { full: scope.full, label: scopeLabel(scope.full, scope.groups.length), groups: scope.groups, reasons: scope.reasons, routes: scope.routes },
    consent: { app: cfg.app, text: cfg.consent }, startedAt: started, finishedAt: finished,
    stopped: res.stopped, cleanup: res.cleanup, requests: res.requests, budget: cfg.budget, groups: res.groups, findings: res.findings,
    tests: tests.map((t) => ({ path: t.path, framework: t.framework, ruleId: t.ruleId })),
    notes: res.notes, unconfirmed: res.unconfirmed, exchanges: res.exchanges,
    failed: res.findings.some((f) => f.severity !== "nice"),
  };

  if (o.writeTests) {
    const root = resolve(o.cwd);
    for (const t of tests) {
      const out = resolve(root, t.path);
      if (!out.startsWith(root + sep)) continue;
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, t.content);
    }
  }
  const sha = env.YOF_HEAD_SHA ?? env.GITHUB_SHA ?? null;
  const comment = o.commentFile ? attackComment(report, tests, sha && /^[0-9a-f]{7,64}$/.test(sha) ? sha : null) : null;
  if (o.commentFile && comment) writeFileSync(resolve(o.cwd, o.commentFile), comment);

  let uploaded: boolean | null = null;
  // A run the person stopped is partial: it is shown, never sent to the yof app as a result.
  if (o.upload && report.stopped !== "cancelled") uploaded = await uploadReport(report, env, o.fetch);
  return { report, tests, comment, uploaded };
}

/**
 * Send the masked results to the person's yof app, through the deploy hook address from the app (YOF_HOOK_URL, a CI
 * secret). Only findings with masked evidence and the run's scope go: no exchanges, no tests, no replay steps.
 */
export async function uploadReport(r: AttackReport, env: Record<string, string | undefined>, f: FetchFn = (u, i) => fetch(u, i)): Promise<boolean> {
  const hook = (env.YOF_HOOK_URL ?? "").trim().replace(/\/$/, "");
  if (!/^https:\/\/[^/\s]+\/[^\s]*$/.test(hook)) return false;
  const body = JSON.stringify({
    version: r.version, app: r.app, consent: r.consent, target: r.target, mode: r.mode, scope: r.scope, startedAt: r.startedAt, finishedAt: r.finishedAt,
    stopped: r.stopped, requests: r.requests, groups: r.groups,
    findings: r.findings.map((x) => ({ ruleId: x.ruleId, method: x.method, route: x.route, as: x.as, status: x.status, evidence: x.evidence, meta: x.meta })),
  });
  try {
    const res = await f(`${hook}/attack`, { method: "POST", headers: { "Content-Type": "application/json", "User-Agent": "yof-attack" }, body, redirect: "manual", signal: AbortSignal.timeout(15_000) });
    return res.ok;
  } catch { return false; }
}
