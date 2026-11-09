/**
 * The markdown summary of a benchmark run (uploaded with the results JSON, and the text to read before publishing).
 * Facts only: counts, the items found and missed with the reason written before the run, and every extra finding
 * with its review verdict. Deterministic: the same results give the same text.
 */
import type { BenchmarkResults, ScoredItem, TargetResult } from "./score.ts";

const short = (sha: string) => sha.slice(0, 7);
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const RELATION = { same: "same weakness", root: "same root cause" } as const;
const VERDICT = { false_positive: "false positive", real_not_listed: "real, not on the official list", to_review: "to review" } as const;
const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");

export function versionLine(t: Pick<TargetResult, "tag" | "commit">): string {
  return t.tag ? `${t.tag} (commit ${short(t.commit)})` : `commit ${short(t.commit)}`;
}

function grouped(items: ScoredItem[]): { note: string; names: string[] }[] {
  const by = new Map<string, string[]>();
  for (const i of items) by.set(i.note, [...(by.get(i.note) ?? []), i.name]);
  return [...by.entries()].map(([note, names]) => ({ note, names }));
}

function targetSection(t: TargetResult): string[] {
  const out = [`## ${t.name} ${versionLine(t)}`, ""];
  out.push(`Source and official list: ${t.repo}/tree/${t.commit}, list file \`${t.list.file}\` (${plural(t.list.items, t.list.label.replace(/s$/, ""), t.list.label)}).`);
  out.push(`How it ran: ${t.run}`);
  if (t.image) out.push(`Image: \`${t.image.ref}@${t.image.digest}\``);
  out.push("");
  if (!t.ran || !t.counts) {
    out.push(`**Did not run:** ${t.error ?? "no yof results"}. No numbers are claimed for this app.`, "");
    return out;
  }
  const c = t.counts;
  out.push("| Result | Count |", "| --- | --- |");
  out.push(`| Found (same weakness) | ${c.foundSame} |`);
  out.push(`| Found (same root cause) | ${c.foundRoot} |`);
  out.push(`| Missed | ${c.missed} |`);
  out.push(`| Not tested by yof | ${c.notTested} |`);
  out.push(`| Not available in this run | ${c.notAvailable} |`);
  out.push(`| Extra findings, not on the official list | ${c.extra} (${c.falsePositives} false positives, ${c.realNotListed} real, ${c.toReview} to review) |`);
  out.push("");
  if (t.check) out.push(`yof check: ${plural(t.check.filesScanned, "file")} read, ${plural(t.check.dependenciesChecked, "dependency", "dependencies")} looked up${t.check.registryUnanswered ? `, ${t.check.registryUnanswered} not answered by the registry` : ""}${t.check.truncated ? ", stopped at the file limit" : ""}.`);
  if (t.attack) {
    const groups = Object.entries(t.attack.groups).map(([g, s]) => `${g} ${s.replace("_", " ")}`).join(", ");
    out.push(`yof attack: ${plural(t.attack.requests, "request")} in ${t.attack.seconds} s${t.attack.stopped ? `, stopped early (${t.attack.stopped} budget)` : ""}. Groups: ${groups || "none"}.`);
  }
  if (t.solvedDuringRun.length) out.push(`${t.name}'s own score board marked these solved during yof's run: ${t.solvedDuringRun.join(", ")}.`);
  out.push("");

  const found = t.items.filter((i) => i.status === "found");
  out.push("### Found", "");
  if (!found.length) out.push("Nothing on the official list.");
  for (const i of found) out.push(`- **${i.name}** (${RELATION[i.relation ?? "same"]}): ${i.note} yof: ${(i.by ?? []).map((b) => `\`${b}\``).join(", ")}`);
  out.push("");
  const missed = t.items.filter((i) => i.status === "missed");
  out.push("### Missed", "");
  if (!missed.length) out.push("None.");
  for (const i of missed) out.push(`- **${i.name}**: ${i.note}`);
  out.push("");
  out.push("### Extra findings (not on the official list)", "");
  if (!t.extra.length) out.push("None.");
  else {
    out.push("| yof result | Where | Verdict |", "| --- | --- | --- |");
    for (const e of t.extra) out.push(`| \`${esc(e.rule)}\` | \`${esc(e.where)}\` | ${VERDICT[e.verdict]}${e.note ? `: ${esc(e.note)}` : ""} |`);
  }
  out.push("");
  for (const [status, title] of [["not_available", "Not available in this run"], ["not_tested", "Not tested by yof"]] as const) {
    const list = t.items.filter((i) => i.status === status);
    if (!list.length) continue;
    out.push(`### ${title} (${list.length})`, "");
    for (const g of grouped(list)) out.push(`- ${g.note} ${g.names.join(", ")}.`);
    out.push("");
  }
  return out;
}

export function summaryMarkdown(r: BenchmarkResults): string {
  if (r.status === "pending" || !r.run) return "# yof benchmark\n\nNo run yet. The first run is started by hand from the Actions tab (docs/YOF_BENCHMARK.md).\n";
  const out = ["# yof benchmark", ""];
  out.push(`Run ${r.run.id} (${r.run.url}), ${r.run.startedAt.slice(0, 10)}. yof ${r.run.yofVersion} at commit ${short(r.run.commit)}, on GitHub's ${r.run.runner} runner.`);
  out.push("");
  out.push("Each item of an app's official list is: found (one of the yof results named for it fired), missed (yof tests this kind of problem and did not find it here; the reason was written before the run), not tested (yof does not test this kind of problem) or not available (it cannot happen in this run). Extra findings are yof results that match no item; each is reviewed by hand before publishing.");
  out.push("");
  for (const t of r.targets) out.push(...targetSection(t));
  return `${out.join("\n").replace(/\n{3,}/g, "\n\n").trim()}\n`;
}
