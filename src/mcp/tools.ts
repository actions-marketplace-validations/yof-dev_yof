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
import { redactDeep, redactMasked, untrusted, untrustedError } from "./untrusted";

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

/**
 * The four MCP tool annotations, always explicit booleans (MCP spec 2025-06-18, ToolAnnotations). Every tool here only
 * reads: nothing on disk, in git or on the yof account is changed, so a repeat call has no further effect. openWorld is
 * true for every tool because each one can reach the network by default: the scans look package names up on npm,
 * PyPI and OSV (unless offline: true), yof_explain and yof_fix_prompt can ask the yof.io API, and the account tools
 * always do.
 */
export interface ToolAnnotations { readOnlyHint: boolean; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean }
const READ_NET: ToolAnnotations = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

/**
 * An MCP output schema (spec 2025-06-18): the shape of the structuredContent a successful call returns. Only set on
 * tools whose handler returns one stable JSON object. Error answers carry no structuredContent (see server.ts).
 */
export interface OutputSchema { type: "object"; properties: Record<string, unknown>; required?: readonly string[] }

export interface ToolDef { name: string; title: string; description: string; inputSchema: ToolSchema; outputSchema?: OutputSchema; remote: boolean; annotations: ToolAnnotations }

const ID = "^[0-9a-fA-F-]{36}$";
const RULE = "^[a-z][a-z0-9_.-]{1,80}$";
const path = (d: string) => ({ type: "string" as const, description: d, maxLength: 500 });
const offline = { type: "boolean" as const, description: "true skips the npm, PyPI and OSV lookups, so nothing leaves this computer; package problems are then not reported. Default false." };
const appId = (d: string) => ({ type: "string" as const, description: d, maxLength: 36, pattern: ID });

const str = (description: string) => ({ type: "string", description });
const num = (description: string) => ({ type: "integer", description });
const COUNTS = { type: "object", description: "How many findings of each urgency (all of them, not only the listed ones).", properties: { fix_now: { type: "integer" }, fix_week: { type: "integer" }, info: { type: "integer" } } };
const FINDING_LIST = {
  type: "array", description: "At most 100 findings. kind is key or package; value is a prefix plus REDACTED.",
  items: { type: "object", properties: { kind: str("key or package."), rule: str("Rule id, for yof_explain, yof_fix_prompt and yof_verify."), name: str("Readable rule or package name."), severity: str("fix_now, fix_week or info."), file: str("Path relative to the project root."), line: num("Line in the file (key findings)."), value: str("Secret prefix plus REDACTED (key findings)."), why: str("Why it matters."), message: str("What is wrong (package findings).") } },
};
const SCAN_OUT = (extra: Record<string, unknown>, required: string[]): OutputSchema => ({
  type: "object",
  properties: {
    ...extra,
    package_lookups: str("\"off\", or which registries were asked (names and versions only)."),
    counts: COUNTS,
    must_fix_before_done: { type: "boolean", description: "true when at least one fix_now finding is open." },
    findings: FINDING_LIST,
    more: num("How many findings were left out of the list, when there are more than 100."),
    next: str("What to do next."),
  },
  required: [...required, "package_lookups", "counts", "must_fix_before_done", "findings", "next"],
});

export const TOOLS: readonly ToolDef[] = [
  {
    name: "yof_check", title: "Check the project", remote: false, annotations: READ_NET,
    description:
      "Scan the project folder on this computer (or one folder inside it) for leaked API keys and for made-up, brand-new, lookalike or vulnerable packages. " +
      "Use it for a full pass, for example before you say the work is done; after small edits use yof_check_diff, which reads only the changed lines. " +
      "Files are read locally and never uploaded; only package names and versions go to npm, PyPI and OSV, unless offline is true. " +
      "It follows .yof.yml and .gitignore, reads at most 20,000 files (stopped_early says so), looks up at most 500 dependencies and gives up after 90 seconds. " +
      "Returns counts, must_fix_before_done and up to 100 findings with secrets redacted; an empty list means nothing was found within those limits.",
    inputSchema: { type: "object", additionalProperties: false, properties: { path: path("A folder inside the project, relative to the project root, for example \"src\". Default: the whole project. Paths outside the project are refused."), offline } },
    outputSchema: SCAN_OUT({
      project: str("The folder scanned, relative to the project root."),
      profile: str("The .yof.yml profile that decided which urgencies are shown."),
      files_scanned: num("How many files were read."),
      stopped_early: { type: "boolean", description: "true when the file limit was reached before every file was read." },
      dependencies_checked: num("How many dependencies were looked up."),
    }, ["project", "profile", "files_scanned", "stopped_early", "dependencies_checked"]),
  },
  {
    name: "yof_check_diff", title: "Check what changed", remote: false, annotations: READ_NET,
    description:
      "Scan only the lines that changed: a unified diff you pass in, or, with no diff, the working tree against the last commit plus new untracked files (needs git). " +
      "Use it after each edit and before you say the work is done; use yof_check for a full pass that also covers unchanged files. " +
      "Only added lines are checked for keys, and only dependencies added to a changed manifest are looked up on npm, PyPI and OSV; code never leaves this computer. " +
      "Limits: 1 MB of diff, 300 files and 90 seconds. " +
      "Returns counts, must_fix_before_done and up to 100 findings with secrets redacted; an empty list means nothing was found in the changed lines.",
    inputSchema: { type: "object", additionalProperties: false, properties: { diff: { type: "string", description: "A unified diff (git diff format), at most 1 MB and 300 files. Leave it out to let yof ask git for the working tree's changes.", maxLength: 1_000_000 }, offline } },
    outputSchema: SCAN_OUT({
      source: str("Where the changes came from: the diff passed in, or the working tree."),
      files_changed: num("How many changed files were read."),
      lines_added: num("How many added lines were scanned."),
    }, ["source", "files_changed", "lines_added"]),
  },
  {
    name: "yof_explain", title: "Explain a finding", remote: false, annotations: READ_NET,
    description:
      "Explain one yof rule in plain words: what it means, why it matters, how urgent it is and the safe fix. " +
      "Use it to understand a finding from yof_check, yof_check_diff or yof_findings; use yof_fix_prompt instead for step-by-step instructions for one specific finding. " +
      "Key rules (secret.*) and package rules (package.*) are answered on this computer without reading project files; any other rule id is asked of yof.io only when YOF_API_KEY is set, and is an error otherwise. " +
      "Returns rule, name (or title from yof.io), severity, why and safe_fix.",
    inputSchema: { type: "object", additionalProperties: false, required: ["rule_id"], properties: { rule_id: { type: "string", description: "The rule id exactly as a finding shows it, for example secret.stripe_live or package.made_up.", maxLength: 80, pattern: RULE } } },
    outputSchema: {
      type: "object",
      properties: { rule: str("The rule id."), name: str("Readable rule name (rules answered on this computer)."), title: str("Readable rule name (rules answered by yof.io)."), severity: str("fix_now, fix_week, nice or info."), why: str("Why it matters."), safe_fix: str("The safe way to fix it."), standards: { type: ["string", "null"], description: "CWE and OWASP references (rules answered by yof.io)." } },
      required: ["rule", "severity", "why", "safe_fix"],
    },
  },
  {
    name: "yof_fix_prompt", title: "Fix instructions", remote: false, annotations: READ_NET,
    description:
      "Write step-by-step instructions to fix one finding, with any secret shown only as a short prefix plus REDACTED. " +
      "Use it after yof_check, yof_check_diff or yof_findings reports a finding; use yof_explain for background on a rule, and yof_verify once the fix is made. " +
      "For a key rule pass file (and line), which yof reads locally to find the value; for a package rule pass package. " +
      "A finding_id, or a rule this computer does not know, is sent to yof.io and needs YOF_API_KEY. " +
      "Returns rule and instructions, plus file, line and still_in_file for a key finding.",
    inputSchema: {
      type: "object", additionalProperties: false, required: ["rule_id"],
      properties: {
        rule_id: { type: "string", description: "The rule id of the finding, for example secret.openai or package.lookalike.", maxLength: 80, pattern: RULE },
        file: path("The file the finding is in, relative to the project root. Required for key rules (secret.*)."),
        line: { type: "integer", description: "The line of the finding, to pick one match when the file has several. Optional.", minimum: 1, maximum: 10_000_000 },
        package: { type: "string", description: "The package name. Required for package rules (package.*).", maxLength: 214 },
        finding_id: { type: "string", description: "A finding id from yof_findings. When set, the instructions come from yof.io and the other fields are ignored.", maxLength: 36, pattern: ID },
      },
    },
    outputSchema: {
      type: "object",
      properties: { rule: str("The rule id."), instructions: str("The fix instructions, ready to follow."), file: str("The file (key findings)."), line: { type: ["integer", "null"], description: "The line found in the file, or the line passed in." }, still_in_file: { type: "boolean", description: "Whether the value is still in the file (key findings)." }, package: str("The package (package findings)."), finding_id: str("The yof.io finding id, when one was passed.") },
      required: ["rule", "instructions"],
    },
  },
  {
    name: "yof_verify", title: "Verify a fix", remote: false, annotations: READ_NET,
    description:
      "Re-scan one file on this computer and report whether a finding is gone. " +
      "Use it right after fixing something yof_check, yof_check_diff or yof_fix_prompt pointed to; it reads only that file, so run yof_check_diff afterwards to cover the rest of the change. " +
      "With no rule_id it looks for every key rule (secret.*); a package rule needs package and asks npm, PyPI and OSV unless offline is true. " +
      "A missing file, or one over 1 MB, counts as fixed. " +
      "Returns file, rule, fixed (true, false, or null when a registry did not answer), why, and for key rules the matches still there, redacted.",
    inputSchema: {
      type: "object", additionalProperties: false, required: ["file"],
      properties: {
        file: path("The file to re-scan, relative to the project root."),
        rule_id: { type: "string", description: "The rule id to look for, for example secret.stripe_live. Default: every key rule.", maxLength: 80, pattern: RULE },
        package: { type: "string", description: "The package name. Required when rule_id is a package rule (package.*).", maxLength: 214 },
        offline,
      },
    },
    outputSchema: {
      type: "object",
      properties: {
        file: str("The file re-scanned."), rule: { type: ["string", "null"], description: "The rule checked, or null for every key rule." },
        fixed: { type: ["boolean", "null"], description: "true when gone, false when still there, null when a registry did not answer." },
        why: str("The reason, in plain words."), package: str("The package (package rules)."),
        still: { type: "array", description: "Key matches still in the file (key rules).", items: { type: "object", properties: { rule: str("Rule id."), line: num("Line."), value: str("Prefix plus REDACTED.") } } },
        reminder: str("For a removed key: replace it at the provider too."),
      },
      required: ["file", "rule", "fixed", "why"],
    },
  },
  {
    name: "yof_findings", title: "Findings from your yof account", remote: true, annotations: READ_NET,
    description:
      "List open findings stored in your yof.io account: problems yof found on your proven apps' live sites and connected GitHub repositories. " +
      "Use it to see what yof.io already knows; it does not scan this computer (use yof_check or yof_check_diff for that), and yof_fix_prompt takes a finding id from here. " +
      "Needs YOF_API_KEY; sends only these arguments to yof.io and returns results from yof's latest checks, most recently seen first. " +
      "Returns findings (id, app, rule, title, severity, where, redacted value, first and last seen) and next; an empty list means no open findings, and apps not proven yours are left out.",
    inputSchema: {
      type: "object", additionalProperties: false,
      properties: {
        app_id: appId("One app's id, to list only that app. Default: every proven app in the account."),
        severity: { type: "string", description: "Only this urgency: fix_now (fix today), fix_week, nice or info. Default: all.", maxLength: 10, enum: ["fix_now", "fix_week", "nice", "info"] },
        limit: { type: "integer", description: "At most this many findings, 1 to 200. Default 50.", minimum: 1, maximum: 200 },
      },
    },
    outputSchema: {
      type: "object",
      properties: {
        findings: { type: "array", items: { type: "object", properties: { id: str("Finding id, for yof_fix_prompt."), app: { type: ["string", "null"], description: "The app's address." }, app_id: str("The app's id."), rule: str("Rule id."), title: str("Readable rule name."), severity: str("Urgency."), kind: str("Kind of check that found it."), where: { type: ["string", "null"], description: "File, path or URL, and line." }, value: { type: ["string", "null"], description: "Prefix plus REDACTED." }, first_seen: str("ISO time."), last_seen: str("ISO time.") } } },
        note: str("Present when some apps are not proven yours."), next: str("What to do next."),
      },
      required: ["findings", "next"],
    },
  },
  {
    name: "yof_patch_status", title: "Patch pull requests", remote: true, annotations: READ_NET,
    description:
      "List Patch's open fix pull requests from your yof.io account, with the state of each one's CI checks. " +
      "Use it to see whether a fix Patch proposed is waiting, passing or failing; use yof_lessons for fixes already merged, and yof_findings for problems with no pull request yet. " +
      "Needs YOF_API_KEY; sends only app_id to yof.io, which answers from what it last stored (up to 50, newest first) without asking GitHub again. " +
      "Returns open (repository, number, url, draft, rule, title, checks, failed_checks, opened) and a note; an empty list means Patch has no open pull request.",
    inputSchema: { type: "object", additionalProperties: false, properties: { app_id: appId("One app's id, to list only that app's pull requests. Default: every app in the account.") } },
    outputSchema: {
      type: "object",
      properties: {
        open: { type: "array", items: { type: "object", properties: { repository: str("owner/name on GitHub."), number: num("Pull request number."), url: str("Pull request URL."), draft: { type: "boolean" }, rule: str("The rule the fix is for."), title: str("Readable rule name."), checks: str("CI state as yof last stored it."), failed_checks: { type: "array", items: { type: "string" }, description: "Names of failed checks, at most 20." }, opened: str("ISO time.") } } },
        note: str("Reminder that this tool changes nothing."),
      },
      required: ["open"],
    },
  },
  {
    name: "yof_lessons", title: "Lessons from merged fixes", remote: true, annotations: READ_NET,
    description:
      "List short lessons from Patch fixes merged in your projects: what was fixed, in which pull request, whether yof's next check confirmed it, and how to avoid it next time. " +
      "Use it before writing similar code so the same problem does not come back; use yof_patch_status for pull requests still open. " +
      "Needs YOF_API_KEY; sends only app_id to yof.io, which answers from stored data (up to 50 merged pull requests, most recently opened first). " +
      "Returns lessons (repository, pull_request, merged, rule, note, avoid_next_time); an empty list means no Patch fix has been merged yet.",
    inputSchema: { type: "object", additionalProperties: false, properties: { app_id: appId("One app's id, to list only that app's lessons. Default: every app in the account.") } },
    outputSchema: {
      type: "object",
      properties: { lessons: { type: "array", items: { type: "object", properties: { repository: str("owner/name on GitHub."), pull_request: num("Pull request number."), merged: { type: ["string", "null"], description: "ISO time." }, rule: str("Rule id."), note: str("What was fixed and whether the next check confirmed it."), avoid_next_time: { type: ["string", "null"], description: "One sentence on avoiding it." } } } } },
      required: ["lessons"],
    },
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

/** structured: the redacted data for MCP structuredContent, set only on a successful call of a tool with an outputSchema. */
export interface ToolAnswer { text: string; data: unknown; isError: boolean; structured?: Record<string, unknown> }

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
    if (!def.outputSchema) return { text: untrusted(name, data), data, isError: false };
    // a tool with an outputSchema must answer one JSON object (only a misbehaving yof.io could send something else)
    if (!data || typeof data !== "object" || Array.isArray(data)) return fail(name, "yof.io answered without any data. Try again later.");
    return { text: untrusted(name, data), data, isError: false, structured: redactDeep(data) as Record<string, unknown> };
  } catch (e) {
    if (e instanceof ArgsError || e instanceof DiffError || e instanceof RemoteError) return fail(name, e.message);
    return fail(name, "yof could not finish this. Nothing was changed.");
  }
}

const fail = (tool: string, message: string): ToolAnswer => ({ text: untrustedError(tool, message), data: { error: message }, isError: true });

/** Tools available for this context (account tools are listed always: their answer explains how to connect). */
export const toolList = () => TOOLS.map(({ remote: _remote, annotations, ...t }) => ({ ...t, annotations: { ...annotations } }));

/** The root folder the server works in: the path passed to `yof mcp`, YOF_PROJECT_DIR, or the current folder. */
export function projectRoot(cwd: string, arg: string | undefined, env: Record<string, string | undefined>): string {
  const p = resolve(cwd, arg ?? env.YOF_PROJECT_DIR ?? ".");
  if (!existsSync(p) || !statSync(p).isDirectory()) throw new ArgsError(`Not a folder: ${arg ?? env.YOF_PROJECT_DIR ?? "."}`);
  return p;
}
