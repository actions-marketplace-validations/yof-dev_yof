/** Output: short, plain text for people, or JSON for machines. Never a full secret, only the masked value. */
import { visibleIn, type CheckReport } from "./check";
import type { Severity } from "./secrets";
import { keyFixPrompt, keyWords, packageFixPrompt } from "./words";

export const CLOSING_LINE = "Want this on every pull request? https://yof.io";

const LABEL: Record<Severity, string> = { fix_now: "fix now", fix_week: "fix this week", info: "fine, public by design" };
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export interface FormatOptions { version: string }

export function formatText(r: CheckReport): string {
  const out: string[] = [];
  const where = r.mode === "staged" ? "staged files" : "files";
  out.push(`yof checked ${plural(r.filesScanned, where.slice(0, -1), where)} (profile: ${r.profile})`);
  if (r.truncated) out.push(`Stopped after ${r.filesScanned} files. Point yof at a smaller folder or add ignore entries to .yof.yml.`);

  const keys = r.keys.filter((k) => visibleIn(r.profile, k.severity));
  const pkgs = r.packages.filter((p) => visibleIn(r.profile, p.severity));
  const hidden = r.keys.length + r.packages.length - keys.length - pkgs.length;

  if (keys.length) {
    out.push("", "Keys");
    for (const k of keys) out.push(`  ${k.file}:${k.line}  ${k.name}  ${k.masked}  (${LABEL[k.severity]})`);
    if (keys.some((k) => k.severity !== "info")) {
      out.push("  A key that was ever committed or shipped counts as leaked: rotate it in the provider's dashboard,", "  then keep it on the server only (an environment variable, not the code).");
    }
  }
  if (pkgs.length) {
    out.push("", "Packages");
    for (const p of pkgs) {
      out.push(`  ${p.file}  ${p.name}${p.version ? `@${p.version}` : ""} (${p.ecosystem === "npm" ? "npm" : "PyPI"})  (${LABEL[p.severity]})`);
      out.push(`    ${p.message}`);
    }
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

export function formatJson(r: CheckReport, o: FormatOptions): string {
  return JSON.stringify({
    tool: "yof", version: o.version, mode: r.mode, profile: r.profile, offline: r.offline,
    filesScanned: r.filesScanned, filesSkipped: r.filesSkipped, truncated: r.truncated,
    keys: r.keys.map((k) => ({ ...k, why: keyWords(k.rule).why, fixPrompt: keyFixPrompt(k) })),
    packages: r.packages.map((p) => ({ ...p, why: p.message, fixPrompt: packageFixPrompt(p) })),
    dependenciesChecked: r.dependenciesChecked, unknown: r.unknown,
    counts: r.counts, failed: r.failed,
  }, null, 2);
}
