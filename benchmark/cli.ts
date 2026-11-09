/**
 * yof benchmark command line, used by .github/workflows/yof-benchmark.yml (Node 22 or newer runs the .ts files as
 * they are). Steps that talk to an app only reach localhost (setup.ts refuses anything else).
 *
 *   node benchmark/cli.ts setup <juice-shop|nodegoat> --work <dir> [--env-file <file>]
 *   node benchmark/cli.ts solved <juice-shop> --out <file>
 *   node benchmark/cli.ts score <target> --list <file> [--check <file>] [--attack <file>] [--solved-before <file>]
 *                               [--solved-after <file>] [--error <text>] --out <file>
 *   node benchmark/cli.ts combine --run-id <id> --run-url <url> --commit <sha> --yof-version <v> --started <iso>
 *                                 --finished <iso> --runner <label> --out-dir <dir> <target.json>...
 *   node benchmark/cli.ts summary <results.json>
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseList } from "./lists.ts";
import { combine, scoreTarget, type BenchmarkResults, type Reviews, type TargetResult } from "./score.ts";
import { envLines, setupJuiceShop, setupNodeGoat, solvedChallenges } from "./setup.ts";
import { summaryMarkdown } from "./summary.ts";
import { targetById } from "./targets.ts";

const HERE = dirname(fileURLToPath(import.meta.url));

function args(argv: string[]): { pos: string[]; opt: Record<string, string> } {
  const pos: string[] = [];
  const opt: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith("--")) throw new Error(`${a} needs a value.`);
      opt[a.slice(2)] = v;
      i++;
    } else pos.push(a);
  }
  return { pos, opt };
}

const need = (opt: Record<string, string>, k: string) => { const v = opt[k]; if (!v) throw new Error(`--${k} is required.`); return v; };
const json = <T>(p: string | undefined): T | null => (p && existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) as T : null);
const write = (p: string, text: string) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); };

/** yof's --json output, or null when the file is empty or not JSON (yof printed an error instead). */
function yofJson<T>(p: string | undefined): T | null {
  if (!p || !existsSync(p)) return null;
  const text = readFileSync(p, "utf8").trim();
  if (!text.startsWith("{")) return null;
  try { return JSON.parse(text) as T; } catch { return null; }
}

export async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  const { pos, opt } = args(rest);

  if (cmd === "setup") {
    const t = targetById(pos[0] ?? "");
    if (!t) throw new Error("setup needs a target: juice-shop or nodegoat.");
    const out = t.id === "juice-shop" ? await setupJuiceShop(t) : await setupNodeGoat(t);
    for (const s of out.secrets) console.log(`::add-mask::${s}`);
    const work = need(opt, "work");
    write(join(work, ".yof", "attack.json"), `${JSON.stringify(out.config, null, 2)}\n`);
    if (opt["env-file"]) appendFileSync(opt["env-file"], envLines(out.env));
    for (const n of out.notes) console.log(n);
    return 0;
  }

  if (cmd === "solved") {
    const t = targetById(pos[0] ?? "");
    if (!t || t.id !== "juice-shop") throw new Error("solved reads Juice Shop's score board only.");
    write(need(opt, "out"), `${JSON.stringify(await solvedChallenges(t))}\n`);
    return 0;
  }

  if (cmd === "score") {
    const t = targetById(pos[0] ?? "");
    if (!t) throw new Error("score needs a target: juice-shop or nodegoat.");
    const list = parseList(t.list.format, readFileSync(need(opt, "list"), "utf8"));
    const check = yofJson<Parameters<typeof scoreTarget>[0]["check"]>(opt.check);
    const attack = yofJson<Parameters<typeof scoreTarget>[0]["attack"]>(opt.attack);
    const error = opt.error ?? (check === null && attack === null ? "yof produced no results" : null);
    const result = scoreTarget({
      target: t, list, check, attack, error,
      solvedBefore: json<string[]>(opt["solved-before"]) ?? [], solvedAfter: json<string[]>(opt["solved-after"]) ?? [],
      reviews: json<Reviews>(join(HERE, "reviews.json")) ?? {},
    });
    write(need(opt, "out"), `${JSON.stringify(result, null, 2)}\n`);
    console.log(`${t.name}: ${result.counts ? `${result.counts.found} found, ${result.counts.missed} missed, ${result.counts.extra} extra` : `did not run (${result.error})`}`);
    return 0;
  }

  if (cmd === "combine") {
    if (!pos.length) throw new Error("combine needs at least one target result file.");
    const results = combine({
      id: need(opt, "run-id"), url: need(opt, "run-url"), commit: need(opt, "commit"), yofVersion: need(opt, "yof-version"),
      startedAt: need(opt, "started"), finishedAt: need(opt, "finished"), runner: need(opt, "runner"),
    }, pos.map((p) => JSON.parse(readFileSync(p, "utf8")) as TargetResult));
    const dir = need(opt, "out-dir");
    write(join(dir, "results.json"), `${JSON.stringify(results, null, 2)}\n`);
    write(join(dir, "summary.md"), summaryMarkdown(results));
    return 0;
  }

  if (cmd === "summary") {
    const r = json<BenchmarkResults>(pos[0]);
    if (!r) throw new Error("summary needs a results file.");
    process.stdout.write(summaryMarkdown(r));
    return 0;
  }

  console.error("Commands: setup, solved, score, combine, summary (see the top of benchmark/cli.ts).");
  return 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e: unknown) => {
    console.error(e instanceof Error ? e.message : String(e));
    process.exitCode = 2;
  });
}
