/**
 * yof's MCP tools for AI builders (yof mcp, 2026-11-09). Pure handlers with no MCP library in them, so they are tested
 * directly; ./server.ts wires them to the official MCP SDK over stdio.
 *
 * Local tools read the project on this machine and never upload code:
 *   yof_check        scan the project folder (or a folder inside it): leaked keys and made-up or risky packages
 *   yof_check_diff   scan only what changed: a unified diff passed in, or the working tree against HEAD
 *   yof_explain      what a rule means, why it matters and the safe fix, in plain words
 *   yof_fix_prompt   exact fix instructions for one finding, with the value redacted
 *   yof_verify       re-scan one file for one rule and say fixed or not
 * Account tools need YOF_API_KEY (made by the yof dashboard) and send only ids and rule ids to yof.io:
 *   yof_findings     open findings from the person's yof.io account
 *   yof_patch_status Patch's open pull requests and their CI state
 *   yof_lessons      notes from merged Patch fixes for this project
 *
 * Every answer: the untrusted-data header, JSON data, secrets as prefix + REDACTED (./untrusted.ts). Limits: a folder
 * scan uses the CLI's own caps (files, bytes, 500 dependencies) plus a time limit; a diff is at most 1 MB / 300 files.
 * The package check sends only package names and versions to npm, PyPI and OSV; offline: true turns it off.
 */
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { runCheck, visibleIn, type CheckReport } from "../check";
import { parseYofYml, type Profile } from "../config";
import { runGit, type GitRunner } from "../files";
import { checkPackages, isManifest, packageMessage, parseManifest, type PackageFetcher, type PackageIssue } from "../packages";
import { KEY_RULES, isRepoFixture, scanText, type Severity } from "../secrets";
import { KEY_WORDS, keyFixPrompt } from "../words";
import { addedText, DiffError, parseUnifiedDiff, workingTreeChanges, type ChangedFile } from "./diff";
import { remoteTool, RemoteError, type RemoteConfig } from "./remote";
import { ArgsError, checkArgs, type ToolSchema } from "./schema";
import { redactMasked, untrusted, untrustedError } from "./untrusted";

/** A folder scan stops after this long and says so (the MCP client would time out first otherwise). */
export const CHECK_TIMEOUT_MS = 90_000;
/** At most this many findings are listed in one answer; the counts always cover all of them. */
export const MAX_LISTED = 100;

export interface ToolContext {
  /** The project folder the server was started in. Every path stays inside it. */
  root: string;
  remote: RemoteConfig;
  git?: GitRunner;
  fetcher?: PackageFetcher;
  now?: Date;
  timeoutMs?: number;
}

export interface ToolDef { name: string; title: string; description: string; inputSchema: ToolSchema; remote: boolean; readOnlyHint: true }

const ID = "^[0-9a-fA-F-]{36}$";
const RULE = "^[a-z][a-z0-9_.-]{1,80}$";
const path = (d: string) => ({ type: "string" as const, description: d, maxLength: 500 });
const offline = { type: "boolean" as const, description: "Skip the package-registry lookups (no network at all). Default false." };

export const TOOLS: readonly ToolDef[] = [
  {
    name: "yof_check", title: "Check the project", remote: false, readOnlyHint: true,
    description: "Scan the project folder on this computer for leaked keys and made-up or risky packages. Runs locally; code is never uploaded. Use before you say a change is done.",
    inputSchema: { type: "object", additionalProperties: false, properties: { path: path("A folder inside the project, relative to its root (default: the whole project)."), offline } },
  },
  {
    name: "yof_check_diff", title: "Check what changed", remote: false, readOnlyHint: true,
    description: "Scan only the lines that changed: pass a unified diff, or leave it out to scan the working tree's changes against the last commit (plus new files). Fast; run it after editing files.",
    inputSchema: { type: "object", additionalProperties: false, properties: { diff: { type: "string", description: "A unified diff (at most 1 MB). Leave out to use git.", maxLength: 1_000_000 }, offline } },
  },
  {
    name: "yof_explain", title: "Explain a finding", remote: false, readOnlyHint: true,
    description: "What a yof rule means, why it matters and the safe way to fix it, in plain words. Pass the rule id from a finding (for example secret.stripe_live or package.made_up).",
    inputSchema: { type: "object", additionalProperties: false, required: ["rule_id"], properties: { rule_id: { type: "string", description: "The rule id of a finding.", maxLength: 80, pattern: RULE } } },
  },
  {
    name: "yof_fix_prompt", title: "Fix instructions", remote: false, readOnlyHint: true,
    description: "Exact instructions to fix one finding, ready to follow. The secret value is never included, only a short prefix.",
    inputSchema: {
      type: "object", additionalProperties: false, required: ["rule_id"],
      properties: {
        rule_id: { type: "string", description: "The rule id of the finding.", maxLength: 80, pattern: RULE },
        file: path("The file the finding is in, relative to the project root."),
        line: { type: "integer", description: "The line of the finding.", minimum: 1, maximum: 10_000_000 },
        package: { type: "string", description: "For a package finding: the package name.", maxLength: 214 },
        finding_id: { type: "string", description: "A finding id from yof_findings (yof.io account findings).", maxLength: 36, pattern: ID },
      },
    },
  },
  {
    name: "yof_verify", title: "Verify a fix", remote: false, readOnlyHint: true,
    description: "Re-scan one file and say whether a finding is fixed. Pass the file and the rule id (or leave the rule out to check the file for every key rule).",
    inputSchema: {
      type: "object", additionalProperties: false, required: ["file"],
      properties: {
        file: path("The file to re-scan, relative to the project root."),
        rule_id: { type: "string", description: "The rule id to look for.", maxLength: 80, pattern: RULE },
        package: { type: "string", description: "For a package rule: the package name.", maxLength: 214 },
        offline,
      },
    },
  },
  {
    name: "yof_findings", title: "Findings from your yof account", remote: true, readOnlyHint: true,
    description: "Open findings from your yof.io account (your live site and connected GitHub repositories). Needs the yof key in this tool's config.",
    inputSchema: {
      type: "object", additionalProperties: false,
      properties: {
        app_id: { type: "string", description: "One app's id (default: all your apps).", maxLength: 36, pattern: ID },
        severity: { type: "string", description: "Only this urgency.", maxLength: 10, enum: ["fix_now", "fix_week", "nice", "info"] },
        limit: { type: "integer", description: "At most this many (default 50).", minimum: 1, maximum: 200 },
      },
    },
  },
  {
    name: "yof_patch_status", title: "Patch pull requests", remote: true, readOnlyHint: true,
    description: "Patch's open fix pull requests and the state of their CI checks. Read only: nothing is merged or changed.",
    inputSchema: { type: "object", additionalProperties: false, properties: { app_id: { type: "string", description: "One app's id (default: all).", maxLength: 36, pattern: ID } } },
  },
  {
    name: "yof_lessons", title: "Lessons from merged fixes", remote: true, readOnlyHint: true,
    description: "Short notes from Patch fixes that were merged in your projects: what was fixed, where, and whether the next check confirmed it. Use them to avoid the same mistake again.",
    inputSchema: { type: "object", additionalProperties: false, properties: { app_id: { type: "string", description: "One app's id (default: all).", maxLength: 36, pattern: ID } } },
  },
];

const PACKAGE_WORDS: Record<PackageIssue, { name: string; severity: Severity; why: string; fix: string }> = {
  made_up: { name: "Package that does not exist", severity: "fix_now", why: "The package name is not on the registry. AI assistants sometimes invent names, and attackers register those names with malware.", fix: "Check the spelling. Replace it with the real, well-known package, or remove it, then update the lockfile. Never install a name you cannot find on the registry." },
  brand_new: { name: "Brand-new package", severity: "fix_week", why: "It was first published in the last 14 days, which is when malicious packages are most often caught.", fix: "Check who publishes it and that it is the package the code really needs. If not, use the established package instead and update the lockfile." },
  lookalike: { name: "Lookalike package name", severity: "fix_week", why: "The name is one or two letters away from a popular package, the classic typosquatting trick.", fix: "If the code meant the popular package, change the name and update the lockfile. Keep it only if you are sure it is the right one." },
  vulnerable: { name: "Package with a known security problem", severity: "fix_week", why: "The pinned version has a published advisory.", fix: "Update to the first fixed version or newer, update the lockfile and run the tests. If there is no fixed version yet, replace the package." },
};

const packageIssue = (rule: string): PackageIssue | null => {
  const m = /^package\.(made_up|brand_new|lookalike|vulnerable)$/.exec(rule);
  return m ? (m[1] as PackageIssue) : null;
};

/** A path inside the project, or an error. Symlinks that point outside the project are refused too. */
export function insideRoot(root: string, p: string | undefined): string {
  const realRoot = realpathSync(root);
  const target = resolve(realRoot, p ?? ".");
  const rel = relative(realRoot, target);
  if (rel.startsWith("..") || isAbsolute(rel)) throw new ArgsError("Paths must be inside the project folder.");
  if (existsSync(target)) {
    const real = realpathSync(target);
    if (real !== realRoot && !real.startsWith(realRoot + sep)) throw new ArgsError("Paths must be inside the project folder.");
  }
  return target;
}

const withTimeout = <T>(p: Promise<T>, ms: number): Promise<T> =>
  new Promise<T>((ok, fail) => {
    const t = setTimeout(() => fail(new ArgsError(`The scan took longer than ${Math.round(ms / 1000)} seconds and was stopped. Scan a smaller folder (path) or use yof_check_diff.`)), ms);
    p.then((v) => { clearTimeout(t); ok(v); }, (e) => { clearTimeout(t); fail(e); });
  });

function reportData(r: CheckReport, root: string) {
  const shown = (s: Severity) => visibleIn(r.profile, s);
  const keys = r.keys.filter((k) => shown(k.severity));
  const pkgs = r.packages.filter((p) => shown(p.severity));
  const all = [
    ...keys.map((k) => ({ kind: "key" as const, rule: k.rule, name: k.name, severity: k.severity, file: k.file, line: k.line, column: k.column, value: redactMasked(k.masked), why: KEY_WORDS[k.rule]?.why, ...(k.accepted ? { accepted: true, accepted_reason: k.accepted.reason } : {}) })),
    ...pkgs.map((p) => ({ kind: "package" as const, rule: `package.${p.issue}`, name: p.name, severity: p.severity, file: p.file, message: p.message, ...(p.similarTo ? { similar_to: p.similarTo } : {}), ...(p.fixedIn ? { fixed_in: p.fixedIn } : {}), ...(p.accepted ? { accepted: true } : {}) })),
  ];
  return {
    project: relative(root, r.root) || ".",
    profile: r.profile,
    files_scanned: r.filesScanned,
    stopped_early: r.truncated,
    dependencies_checked: r.dependenciesChecked,
    package_lookups: r.offline ? "off" : "npm, PyPI and OSV (names and versions only)",
    counts: r.counts,
    must_fix_before_done: r.failed,
    findings: all.slice(0, MAX_LISTED),
    ...(all.length > MAX_LISTED ? { more: all.length - MAX_LISTED } : {}),
    next: all.length ? "Fix each finding (yof_fix_prompt gives exact steps), then run yof_verify on the file." : "Nothing to fix.",
  };
}

async function checkDiff(ctx: ToolContext, args: Record<string, unknown>) {
  const root = realpathSync(ctx.root);
  const cfg = parseYofYml(readIf(join(root, ".yof.yml")));
  const files: ChangedFile[] = typeof args.diff === "string" ? parseUnifiedDiff(args.diff) : workingTreeChanges(root, cfg.ignore, ctx.git ?? runGit);
  const keys: Record<string, unknown>[] = [];
  for (const f of files) {
    const added = addedText(f), addedLines = added.split(/\r?\n/);
    for (const m of scanText(added)) {
      if (isRepoFixture(m, f.path, addedLines[m.line - 1] ?? "")) continue;
      const rule = KEY_RULES[m.ruleId] ?? { name: m.ruleId, severity: "fix_week" as Severity };
      if (!visibleIn(cfg.profile as Profile, rule.severity)) continue;
      keys.push({ kind: "key", rule: m.ruleId, name: rule.name, severity: rule.severity, file: f.path, line: m.line, value: redactMasked(m.masked), why: KEY_WORDS[m.ruleId]?.why });
    }
  }
  // Packages: only dependencies named on an added line of a changed manifest.
  const pkgs: Record<string, unknown>[] = [];
  const manifests = files.filter((f) => isManifest(f.path) && f.added.length);
  if (!args.offline && manifests.length) {
    const deps = manifests.flatMap((f) => {
      const current = readIf(join(root, f.path)) ?? f.added.map((a) => a.text).join("\n");
      const added = f.added.map((a) => a.text).join("\n").toLowerCase();
      return parseManifest(f.path, current).filter((d) => added.includes(d.name)).map((d) => ({ ...d, file: f.path }));
    }).slice(0, 200);
    if (deps.length) {
      const res = await checkPackages(deps, { fetcher: ctx.fetcher, now: ctx.now });
      for (const p of res.findings) {
        if (!visibleIn(cfg.profile, p.severity)) continue;
        pkgs.push({ kind: "package", rule: `package.${p.issue}`, name: p.name, severity: p.severity, file: deps.find((d) => d.name === p.name)?.file, message: packageMessage(p), ...(p.similarTo ? { similar_to: p.similarTo } : {}) });
      }
    }
  }
  const all = [...keys, ...pkgs];
  const counts = { fix_now: 0, fix_week: 0, info: 0 };
  for (const x of all) counts[x.severity as Severity]++;
  return {
    source: typeof args.diff === "string" ? "the diff you passed" : "the working tree compared with the last commit, plus new files",
    files_changed: files.length,
    lines_added: files.reduce((n, f) => n + f.added.length, 0),
    package_lookups: args.offline ? "off" : "npm, PyPI and OSV (names and versions only)",
    counts,
    must_fix_before_done: counts.fix_now > 0,
    findings: all.slice(0, MAX_LISTED),
    ...(all.length > MAX_LISTED ? { more: all.length - MAX_LISTED } : {}),
    next: all.length ? "Fix each finding (yof_fix_prompt gives exact steps), then run yof_check_diff again." : "Nothing to fix in what changed.",
  };
}

function readIf(p: string): string | null {
  try { return existsSync(p) && statSync(p).isFile() && statSync(p).size <= 1_000_000 ? readFileSync(p, "utf8") : null; } catch { return null; }
}

function explain(rule: string) {
  const key = KEY_WORDS[rule];
  if (key) return { rule, name: KEY_RULES[rule]?.name ?? rule, severity: KEY_RULES[rule]?.severity ?? "fix_week", why: key.why, safe_fix: key.fix };
  const issue = packageIssue(rule);
  if (issue) { const w = PACKAGE_WORDS[issue]; return { rule, name: w.name, severity: w.severity, why: w.why, safe_fix: w.fix }; }
  return null;
}

async function fixPrompt(ctx: ToolContext, a: Record<string, string | number | boolean>) {
  const rule = String(a.rule_id);
  if (a.finding_id) return remoteTool(ctx.remote, "yof_fix_prompt", { finding_id: a.finding_id });
  if (KEY_WORDS[rule]) {
    if (!a.file) throw new ArgsError("Pass the file the finding is in.");
    const target = insideRoot(ctx.root, String(a.file));
    const text = readIf(target);
    const hit = text ? scanText(text).find((m) => m.ruleId === rule && (!a.line || m.line === a.line)) : undefined;
    const prompt = keyFixPrompt({ rule, name: KEY_RULES[rule]?.name ?? rule, file: String(a.file), line: hit?.line ?? Number(a.line ?? 1), masked: hit?.masked ?? "(see the file)" });
    return { rule, file: a.file, line: hit?.line ?? a.line ?? null, still_in_file: !!hit, instructions: redactMasked(prompt) };
  }
  const issue = packageIssue(rule);
  if (issue) {
    if (!a.package) throw new ArgsError("Pass the package name.");
    const w = PACKAGE_WORDS[issue];
    const where = a.file ? ` in ${String(a.file)}` : "";
    return { rule, package: a.package, instructions: [`yof (a local check that runs on my machine) found this dependency${where}: "${String(a.package)}". ${w.why}`, `What to do: ${w.fix}`, "When you are done, explain in plain English what you changed, in a few short sentences."].join("\n\n") };
  }
  if (ctx.remote.key) return remoteTool(ctx.remote, "yof_fix_prompt", { rule_id: rule });
  throw new ArgsError(`yof does not know the rule ${rule} on this computer. Connect your yof account for the rules of live-site and repository checks.`);
}

async function verify(ctx: ToolContext, a: Record<string, string | number | boolean>) {
  const file = String(a.file);
  const target = insideRoot(ctx.root, file);
  const text = readIf(target);
  const rule = a.rule_id ? String(a.rule_id) : null;
  const issue = rule ? packageIssue(rule) : null;
  if (issue) {
    if (!a.package) throw new ArgsError("Pass the package name.");
    const name = String(a.package);
    const listed = text ? parseManifest(file, text).find((d) => d.name === name.toLowerCase() || d.name === name) : undefined;
    if (!listed) return { file, rule, package: name, fixed: true, why: text ? "The package is no longer listed in this file." : "The file is gone." };
    if (a.offline) return { file, rule, package: name, fixed: false, why: "The package is still listed. Run again without offline to check the registries." };
    const res = await checkPackages([listed], { fetcher: ctx.fetcher, now: ctx.now });
    const still = res.findings.find((p) => p.issue === issue);
    if (res.unknown.length) return { file, rule, package: name, fixed: null, why: "The registry did not answer, so yof cannot say. Try again in a minute." };
    return { file, rule, package: name, fixed: !still, why: still ? packageMessage(still) : "The registries no longer report this problem." };
  }
  if (!text) return { file, rule, fixed: true, why: "The file is gone or too large to read (over 1 MB).", still: [] };
  const still = scanText(text).filter((m) => (rule ? m.ruleId === rule : m.ruleId.startsWith("secret."))).map((m) => ({ rule: m.ruleId, line: m.line, value: redactMasked(m.masked) }));
  return {
    file, rule, fixed: still.length === 0, still,
    why: still.length ? "The value is still in the file." : "No matching value is left in this file.",
    ...(still.length === 0 && rule?.startsWith("secret.") ? { reminder: "If this key was ever committed or public, replace it in the provider's dashboard: removing it from the code does not make the old one safe." } : {}),
  };
}

export interface ToolAnswer { text: string; data: unknown; isError: boolean }

/** Run one tool. Never throws: every problem is an answer with isError, in the same untrusted shape. */
export async function callTool(ctx: ToolContext, name: string, rawArgs: unknown): Promise<ToolAnswer> {
  const def = TOOLS.find((t) => t.name === name);
  if (!def) return fail(name, `Unknown tool: ${String(name).slice(0, 40)}`);
  try {
    const a = checkArgs(def.inputSchema, rawArgs);
    let data: unknown;
    switch (name) {
      case "yof_check": {
        const target = insideRoot(ctx.root, a.path as string | undefined);
        const report = await withTimeout(runCheck({ path: target, cwd: ctx.root, offline: !!a.offline, fetcher: ctx.fetcher, git: ctx.git, now: ctx.now }), ctx.timeoutMs ?? CHECK_TIMEOUT_MS);
        data = reportData(report, realpathSync(ctx.root));
        break;
      }
      case "yof_check_diff": data = await withTimeout(checkDiff(ctx, a), ctx.timeoutMs ?? CHECK_TIMEOUT_MS); break;
      case "yof_explain": {
        const rule = String(a.rule_id);
        data = explain(rule) ?? (ctx.remote.key ? await remoteTool(ctx.remote, "yof_explain", { rule_id: rule }) : null);
        if (!data) return fail(name, `yof does not know the rule ${rule} on this computer. Connect your yof account for the rules of live-site and repository checks.`);
        break;
      }
      case "yof_fix_prompt": data = await fixPrompt(ctx, a); break;
      case "yof_verify": data = await verify(ctx, a); break;
      default: data = await remoteTool(ctx.remote, name, a);
    }
    return { text: untrusted(name, data), data, isError: false };
  } catch (e) {
    if (e instanceof ArgsError || e instanceof DiffError || e instanceof RemoteError) return fail(name, e.message);
    return fail(name, "yof could not finish this. Nothing was changed.");
  }
}

const fail = (tool: string, message: string): ToolAnswer => ({ text: untrustedError(tool, message), data: { error: message }, isError: true });

/** Tools available for this context (account tools are listed always: their answer explains how to connect). */
export const toolList = () => TOOLS.map(({ remote, readOnlyHint, ...t }) => ({ ...t, annotations: { readOnlyHint, destructiveHint: false, openWorldHint: remote } }));

/** The root folder the server works in: the path passed to `yof mcp`, YOF_PROJECT_DIR, or the current folder. */
export function projectRoot(cwd: string, arg: string | undefined, env: Record<string, string | undefined>): string {
  const p = resolve(cwd, arg ?? env.YOF_PROJECT_DIR ?? ".");
  if (!existsSync(p) || !statSync(p).isDirectory()) throw new ArgsError(`Not a folder: ${arg ?? env.YOF_PROJECT_DIR ?? "."}`);
  return p;
}
