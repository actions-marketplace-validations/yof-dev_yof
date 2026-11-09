/** Output: short, plain text for people, or JSON for machines. Never a full secret, only the masked value. */
import { visibleIn, type CheckReport } from "./check";
import { KEY_RULES, type Severity } from "./secrets";
import { fileFixPrompt, keyFixPrompt, keyWords, packageFixPrompt } from "./words";

export const CLOSING_LINE = "Want this on every pull request? https://yof.io";

const LABEL: Record<Severity, string> = { fix_now: "fix now", fix_week: "fix this week", info: "fine, public by design" };
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export interface FormatOptions { version: string }

export function formatText(r: CheckReport): string {
  const out: string[] = [];
  const where = r.mode === "staged" ? "staged files" : "files";
  out.push(`yof checked ${plural(r.filesScanned, where.slice(0, -1), where)} (profile: ${r.profile})`);
  if (r.truncated) out.push(`Stopped after ${r.filesScanned} files. Point yof at a smaller folder or add ignore entries to .yof.yml.`);

  const keys = r.keys.filter((k) => !k.accepted && visibleIn(r.profile, k.severity));
  const pkgs = r.packages.filter((p) => !p.accepted && visibleIn(r.profile, p.severity));
  const acceptedKeys = r.keys.filter((k) => k.accepted);
  const acceptedPkgs = r.packages.filter((p) => p.accepted);
  const hidden = r.keys.length + r.packages.length - keys.length - pkgs.length - acceptedKeys.length - acceptedPkgs.length;

  if (keys.length) {
    out.push("", "Keys");
    for (const k of keys) out.push(`  ${k.file}:${k.line}  ${k.name}  ${k.masked}  (${LABEL[k.severity]})${k.alsoMatched?.length ? `  also matched: ${k.alsoMatched.map((r) => KEY_RULES[r]?.name ?? r).join(", ")}` : ""}`);
    if (keys.some((k) => k.severity !== "info")) {
      out.push("  A key that was ever committed or shipped counts as leaked: rotate it in the provider's dashboard,", "  then keep it on the server only (an environment variable, not the code).");
    }
  }
  if (pkgs.length) {
    out.push("", "Packages");
    for (const p of pkgs) {
      out.push(`  ${p.file}  ${p.name}${p.version ? `@${p.version}` : ""} (${p.ecosystem === "npm" ? "npm" : "PyPI"})  (${LABEL[p.severity]})`);
      out.push(`    ${p.message}`);
      if (p.files && p.files.length > 1) out.push(`    Named in ${p.files.length} manifests: ${p.files.join(", ")}`);
    }
  }

  if (acceptedKeys.length || acceptedPkgs.length) {
    // Accepted in .yof/accepted.json: listed with the reason, never hidden, not counted as open.
    out.push("", "Accepted risks (.yof/accepted.json)");
    for (const k of acceptedKeys) out.push(`  ${k.file}:${k.line}  ${k.name}  ${k.masked}  (accepted by ${k.accepted!.acceptedBy || "someone"} on ${k.accepted!.acceptedAt.slice(0, 10)}: ${k.accepted!.reason})`);
    for (const p of acceptedPkgs) out.push(`  ${p.file}  ${p.name} (${p.ecosystem === "npm" ? "npm" : "PyPI"})  (accepted by ${p.accepted!.acceptedBy || "someone"} on ${p.accepted!.acceptedAt.slice(0, 10)}: ${p.accepted!.reason})`);
  }

  out.push("");
  if (r.offline) out.push("Package check skipped (--offline): only keys were checked.");
  else if (r.unknown.length) out.push(`The registry did not answer for ${plural(r.unknown.length, "package")} (${r.unknown.slice(0, 5).map((u) => u.name).join(", ")}${r.unknown.length > 5 ? ", …" : ""}). Nothing is claimed about them.`);

  const now = [...keys, ...pkgs].filter((x) => x.severity === "fix_now").length;
  const week = [...keys, ...pkgs].filter((x) => x.severity === "fix_week").length;
  if (now + week === 0) {
    const deps = r.offline ? "" : r.dependenciesChecked ? `, ${plural(r.dependenciesChecked, "dependency", "dependencies")} look fine` : "";
    out.push(`Nothing to fix: no leaked keys${deps}.`);
  } else {
    const parts = [now ? `${now} to fix now` : "", week ? `${week} to fix this week` : ""].filter(Boolean);
    out.push(`Found ${plural(now + week, "problem")}: ${parts.join(", ")}.`);
  }
  if (hidden > 0) out.push(`${plural(hidden, "lower-priority finding")} hidden by profile ${r.profile} (use --profile strict to see everything).`);
  out.push(CLOSING_LINE);
  return out.join("\n");
}

/**
 * One combined prompt per file that holds two or more problems the profile shows (info, public by design, never
 * needs a fix): what the editor plugins offer as "Copy one fix prompt for this file".
 */
export function filePrompts(r: CheckReport): { file: string; count: number; prompt: string }[] {
  const by = new Map<string, { keys: CheckReport["keys"]; pkgs: CheckReport["packages"] }>();
  const slot = (f: string) => { const s = by.get(f) ?? { keys: [], pkgs: [] }; by.set(f, s); return s; };
  // an accepted risk (.yof/accepted.json) needs no fix: never in a combined prompt
  for (const k of r.keys) if (!k.accepted && k.severity !== "info" && visibleIn(r.profile, k.severity)) slot(k.file).keys.push(k);
  for (const p of r.packages) if (!p.accepted && visibleIn(r.profile, p.severity)) slot(p.file).pkgs.push(p);
  return [...by.entries()].filter(([, s]) => s.keys.length + s.pkgs.length > 1).sort(([a], [b]) => a.localeCompare(b))
    .map(([file, s]) => ({ file, count: s.keys.length + s.pkgs.length, prompt: fileFixPrompt(file, [...s.keys].sort((a, b) => a.line - b.line || a.column - b.column), s.pkgs) }));
}

export function formatJson(r: CheckReport, o: FormatOptions): string {
  return JSON.stringify({
    tool: "yof", version: o.version, mode: r.mode, profile: r.profile, offline: r.offline,
    filesScanned: r.filesScanned, filesSkipped: r.filesSkipped, truncated: r.truncated,
    keys: r.keys.map((k) => ({ ...k, why: keyWords(k.rule).why, fixPrompt: keyFixPrompt(k) })),
    packages: r.packages.map((p) => ({ ...p, why: p.message, fixPrompt: packageFixPrompt(p) })),
    filePrompts: filePrompts(r),
    dependenciesChecked: r.dependenciesChecked, unknown: r.unknown,
    counts: r.counts, acceptedCount: r.acceptedCount, failed: r.failed,
  }, null, 2);
}
