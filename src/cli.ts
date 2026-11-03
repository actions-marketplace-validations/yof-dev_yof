/** The `yof` command. main() returns the exit code: 0 nothing to fix, 1 something to fix, 2 a usage or setup error. */
import { AttackError, runAttackCommand } from "./attack/command";
import type { FetchFn } from "./attack/http";
import { cleanupLines, formatAttackJson, formatAttackText } from "./attack/report";
import { processSignalHost, STOP_EXIT_CODE, stopOnSignals, type SignalHost } from "./attack/signals";
import { CheckError, runCheck } from "./check";
import { PROFILES, type Profile } from "./config";
import type { GitRunner } from "./files";
import { formatJson, formatText } from "./format";
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

Options
  --offline                 Skip the package-registry lookups (keys only, no network at all)
  --json                    Print machine-readable JSON
  --profile <name>          relaxed | balanced | strict (overrides .yof.yml)

yof attack options
  --config <file>           The attack config (default .yof/attack.json)
  --mode <full|light>       light = read-only (no test records, no messages to your assistant)
  --base <branch>           Pull request run: attack only what the change can reach
  --write-tests             Write a regression test for every confirmed finding
  --comment <file>          Write the pull-request comment to this file
  --upload                  Send the masked results to your yof app (YOF_HOOK_URL)
  -v, --version             Print the version
  -h, --help                Print this help

Exit codes: 0 nothing to fix, 1 something to fix, 2 usage or setup error.
yof attack stopped with Ctrl+C or SIGTERM deletes its test records first, then exits 130 or 143.
yof check runs on your machine. Your code is never sent anywhere; its only network calls are
package-registry lookups (npm, PyPI, OSV), which --offline turns off. yof attack sends requests
only to the app you proved is yours.

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
}

const defaultIo = (): Io => ({ cwd: process.cwd(), out: (s) => process.stdout.write(`${s}\n`), err: (s) => process.stderr.write(`${s}\n`) });

export async function main(argv: string[], io: Io = defaultIo()): Promise<number> {
  const flags = new Set<string>();
  const positional: string[] = [];
  let profile: Profile | undefined;
  const values: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const valued = ["--config", "--mode", "--base", "--comment"].find((f) => a === f || a.startsWith(`${f}=`));
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
  const known = new Set(["--offline", "--json", "--staged", "--version", "-v", "--help", "-h", "--write-tests", "--upload"]);
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

  if (cmd === "check") {
    if (rest.length > 1) { io.err("yof check takes one path at most."); return 2; }
    try {
      const report = await runCheck({
        path: rest[0] ?? ".", cwd: io.cwd, staged: flags.has("--staged"), offline: flags.has("--offline"),
        profile, fetcher: io.fetcher, git: io.git, now: io.now,
      });
      io.out(flags.has("--json") ? formatJson(report, { version: VERSION }) : formatText(report));
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

  io.err(`Unknown command: ${cmd}\n\n${HELP}`);
  return 2;
}
