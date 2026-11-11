/** The `yof` command. main() returns the exit code: 0 nothing to fix, 1 something to fix, 2 a usage or setup error. */
import { AttackError, attackScopeDoc, runAttackCommand } from "./attack/command";
import type { FetchFn } from "./attack/http";
import { cleanupLines, formatAttackJson, formatAttackText } from "./attack/report";
import { processSignalHost, STOP_EXIT_CODE, stopOnSignals, type SignalHost } from "./attack/signals";
import { CheckError, runCheck } from "./check";
import { PROFILES, type Profile } from "./config";
import type { GitRunner } from "./files";
import { formatJson, formatText } from "./format";
import { checkToFindingsJson, formatImportText, importFindings } from "./findings-format";
import { installHook, uninstallHook } from "./hook";
import type { PackageFetcher } from "./packages";

declare const __YOF_VERSION__: string | undefined;
export const VERSION: string = typeof __YOF_VERSION__ === "string" ? __YOF_VERSION__ : "0.0.0-dev";

export const HELP = `yof: catch leaked keys and made-up packages before they ship.

Usage
  yof check [path]          Check a folder (default: the current one)
  yof check --staged        Check only the files staged for the next commit
  yof hook install          Run "yof check --staged" before every commit
  yof hook uninstall        Remove that pre-commit hook
  yof attack [url]          Attack your own app with your test accounts (config: .yof/attack.json)
  yof diff                  Check only what changed since the last commit (plus new files)
  yof import <file> [path]  Read a findings.json (Cloudflare's security-audit format) and check each
                            record's file and line against a folder (default: the current one)
  yof mcp [path]            Run yof as a local MCP server for AI builders (Claude Code, Cursor, VS Code, Codex...)

Options
  --offline                 Skip the package-registry lookups (keys only, no network at all)
  --json                    Print machine-readable JSON
  --format <name>           text | json | findings-json (findings.json, the format of Cloudflare's
                            security-audit skill, with yof's verdicts: confirmed or needs validation)
  --profile <name>          relaxed | balanced | strict (overrides .yof.yml)

yof attack options
  --config <file>           The attack config (default .yof/attack.json)
  --mode <full|light>       light = read-only (no test records, no messages to your assistant)
  --base <branch>           Pull request run: attack only what the change can reach
  --write-tests             Write a regression test for every confirmed finding
  --comment <file>          Write the pull-request comment to this file
  --upload                  Send the masked results to your yof app (YOF_HOOK_URL)
  --scope-doc               Print the scope and rules-of-engagement document for this config
                            (Markdown, to read and sign before a run). Sends nothing.
  -v, --version             Print the version
  -h, --help                Print this help

Exit codes: 0 nothing to fix, 1 something to fix, 2 usage or setup error.
yof attack stopped with Ctrl+C or SIGTERM deletes its test records first, then exits 130 or 143.
yof check runs on your machine. Your code is never sent anywhere; its only network calls are
package-registry lookups (npm, PyPI, OSV), which --offline turns off. yof attack sends requests
only to the app you proved is yours.

yof mcp talks MCP over stdio. Its scans run on your machine and never upload code. With YOF_API_KEY
(made by "Connect your AI builder" in the yof dashboard) it can also read your yof.io findings and Patch
pull requests; then it sends only ids and rule ids to yof.io.

More: https://yof.io`;

export interface Io {
  cwd: string;
  out: (s: string) => void;
  err: (s: string) => void;
  fetcher?: PackageFetcher;
  git?: GitRunner;
  now?: Date;
  /** yof attack: the HTTP client, the environment and a clock (tests). */
  http?: FetchFn;
  env?: Record<string, string | undefined>;
  sleep?: (ms: number) => Promise<void>;
  /** Where SIGINT / SIGTERM come from (tests pass a fake); default: this process. */
  signals?: SignalHost;
  /** yof mcp: the transport (tests pass an in-memory one); default stdio. */
  mcpTransport?: import("@modelcontextprotocol/sdk/shared/transport.js").Transport;
}

const defaultIo = (): Io => ({ cwd: process.cwd(), out: (s) => process.stdout.write(`${s}\n`), err: (s) => process.stderr.write(`${s}\n`) });

export async function main(argv: string[], io: Io = defaultIo()): Promise<number> {
  const flags = new Set<string>();
  const positional: string[] = [];
  let profile: Profile | undefined;
  const values: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const valued = ["--config", "--mode", "--base", "--comment", "--format"].find((f) => a === f || a.startsWith(`${f}=`));
    if (valued) {
      const v = a.includes("=") ? a.slice(a.indexOf("=") + 1) : argv[++i];
      if (!v || v.startsWith("--")) { io.err(`${valued} needs a value.`); return 2; }
      values[valued] = v;
    } else if (a === "--profile" || a.startsWith("--profile=")) {
      const v = a.includes("=") ? a.slice(a.indexOf("=") + 1) : argv[++i];
      if (!v || !(PROFILES as readonly string[]).includes(v)) { io.err(`--profile must be one of: ${PROFILES.join(", ")}`); return 2; }
      profile = v as Profile;
    } else if (a.startsWith("-")) flags.add(a);
    else positional.push(a);
  }
  const known = new Set(["--offline", "--json", "--staged", "--version", "-v", "--help", "-h", "--write-tests", "--upload", "--scope-doc"]);
  for (const f of flags) if (!known.has(f)) { io.err(`Unknown option: ${f}\n\n${HELP}`); return 2; }

  if (flags.has("--version") || flags.has("-v")) { io.out(VERSION); return 0; }
  const [cmd, ...rest] = positional;
  if (flags.has("--help") || flags.has("-h") || !cmd || cmd === "help") { io.out(HELP); return 0; }

  if (cmd === "hook") {
    const sub = rest[0];
    if (sub !== "install" && sub !== "uninstall") { io.err("Usage: yof hook install | yof hook uninstall"); return 2; }
    const r = sub === "install" ? installHook(io.cwd, io.git) : uninstallHook(io.cwd, io.git);
    (r.ok ? io.out : io.err)(r.message);
    return r.ok ? 0 : 2;
  }

  const format = values["--format"] ?? (flags.has("--json") ? "json" : "text");
  if (!["text", "json", "findings-json"].includes(format)) { io.err("--format must be text, json or findings-json."); return 2; }

  if (cmd === "check") {
    if (rest.length > 1) { io.err("yof check takes one path at most."); return 2; }
    try {
      const report = await runCheck({
        path: rest[0] ?? ".", cwd: io.cwd, staged: flags.has("--staged"), offline: flags.has("--offline"),
        profile, fetcher: io.fetcher, git: io.git, now: io.now,
      });
      io.out(format === "findings-json" ? JSON.stringify(checkToFindingsJson(report), null, 2) : format === "json" ? formatJson(report, { version: VERSION }) : formatText(report));
      return report.failed ? 1 : 0;
    } catch (e) {
      if (e instanceof CheckError) { io.err(e.message); return 2; }
      throw e;
    }
  }

  if (cmd === "attack") {
    if (rest.length > 1) { io.err("yof attack takes one address at most."); return 2; }
    const mode = values["--mode"] ?? "full";
    if (mode !== "full" && mode !== "light") { io.err("--mode must be full or light."); return 2; }
    if (flags.has("--scope-doc")) {
      // The document only: the config is read, nothing is sent and no account variable is read.
      try {
        io.out(attackScopeDoc({ cwd: io.cwd, config: values["--config"], mode, target: rest[0], version: VERSION, now: io.now ? () => io.now!.getTime() : undefined }));
        return 0;
      } catch (e) {
        if (e instanceof AttackError) { io.err(e.message); return 2; }
        throw e;
      }
    }
    const stop = stopOnSignals(io.signals ?? processSignalHost());
    try {
      const out = await runAttackCommand({
        target: rest[0], cwd: io.cwd, config: values["--config"], mode, base: values["--base"], writeTests: flags.has("--write-tests"),
        commentFile: values["--comment"], upload: flags.has("--upload"), version: VERSION, env: io.env, fetch: io.http, git: io.git,
        now: io.now ? () => io.now!.getTime() : undefined, sleep: io.sleep, signal: stop.signal,
      });
      io.out(flags.has("--json") ? formatAttackJson(out.report) : formatAttackText(out.report));
      if (out.uploaded === false) io.err("The results could not be sent to your yof app (check YOF_HOOK_URL).");
      const sig = stop.received();
      if (sig) {
        const c = out.report.cleanup;
        io.err(c.left.length ? cleanupLines(c).join("\n").trim() : `yof attack: stopped. ${c.deleted ? `Deleted ${c.deleted === 1 ? "the test record" : `all ${c.deleted} test records`} it created.` : "It had created no test records."}`);
        return STOP_EXIT_CODE[sig];
      }
      return out.report.failed ? 1 : 0;
    } catch (e) {
      if (e instanceof AttackError) { io.err(e.message); return 2; }
      throw e;
    } finally {
      stop.dispose();
    }
  }

  // `yof import <findings.json> [path]`: read a findings.json strictly and check each record against the folder, read
  // only. Exit 2 when the file is not valid findings.json, 1 when a record needs a look, 0 when none does.
  if (cmd === "import") {
    if (!rest.length || rest.length > 2) { io.err("Usage: yof import <findings.json> [path]"); return 2; }
    const { readFileSync, statSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    const file = resolve(io.cwd, rest[0]!);
    let text: string;
    try {
      if (statSync(file).size > 5 * 1024 * 1024) { io.err(`${rest[0]} is larger than 5 MB.`); return 2; }
      text = readFileSync(file, "utf8");
    } catch { io.err(`Could not read ${rest[0]}.`); return 2; }
    const r = importFindings(text, resolve(io.cwd, rest[1] ?? "."));
    io.out(format === "json" ? JSON.stringify(r, null, 2) : formatImportText(r, rest[0]!));
    if (r.errors.length) return 2;
    return r.records.some((x) => x.verdict !== "rejected") ? 1 : 0;
  }

  // `yof diff`: the same scan as the MCP tool yof_check_diff (the working tree's changes against HEAD, plus new files),
  // for hooks such as the Claude Code plugin's. Exit 1 when something marked "fix now" was added.
  if (cmd === "diff") {
    if (rest.length) { io.err("yof diff takes no path: it checks the changes of the folder it runs in."); return 2; }
    const [{ callTool }, { remoteConfig }] = await Promise.all([import("./mcp/tools"), import("./mcp/remote")]);
    const a = await callTool({ root: io.cwd, remote: remoteConfig({}, VERSION), fetcher: io.fetcher, git: io.git, now: io.now }, "yof_check_diff", { offline: flags.has("--offline") });
    const d = a.data as { error?: string; findings?: { severity: string; rule: string; name: string; file: string; line?: number; value?: string; message?: string }[]; must_fix_before_done?: boolean };
    if (d.error) { io.err(d.error); return 2; }
    if (flags.has("--json")) { io.out(JSON.stringify(d, null, 2)); return d.must_fix_before_done ? 1 : 0; }
    const f = d.findings ?? [];
    io.out(f.length ? [`yof found ${f.length} ${f.length === 1 ? "problem" : "problems"} in what changed:`, ...f.map((x) => `  ${x.severity === "fix_now" ? "Fix now" : x.severity === "fix_week" ? "Fix this week" : "Info"}  ${x.file}${x.line ? `:${x.line}` : ""}  ${x.name}${x.value ? ` (${x.value})` : ""}`)].join("\n") : "yof: nothing to fix in what changed.");
    return d.must_fix_before_done ? 1 : 0;
  }

  if (cmd === "mcp") {
    if (rest.length > 1) { io.err("yof mcp takes one folder at most."); return 2; }
    const [{ runMcpServer }, { projectRoot }, { remoteConfig }] = await Promise.all([import("./mcp/server"), import("./mcp/tools"), import("./mcp/remote")]);
    const env = io.env ?? process.env;
    let root: string;
    try { root = projectRoot(io.cwd, rest[0], env); } catch (e) { io.err(e instanceof Error ? e.message : String(e)); return 2; }
    await runMcpServer({ root, remote: remoteConfig(env, VERSION), fetcher: io.fetcher, git: io.git, now: io.now }, VERSION, io.mcpTransport, io.err);
    return 0;
  }

  io.err(`Unknown command: ${cmd}\n\n${HELP}`);
  return 2;
}
