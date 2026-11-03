import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { scanText } from "../src/secrets";
import { LEAK_RULES, scanForLeaks } from "./leak-rules";

const ROOT = join(__dirname, "..");
function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    if (n === "node_modules" || n === ".git" || n === "dist" || n === "coverage" || n === ".DS_Store") continue;
    const p = join(dir, n);
    if (statSync(p).isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
}

describe("nothing private in this repository", () => {
  it("has no credential, private host, customer address or engine internal", () => {
    const findings = scanForLeaks(ROOT);
    expect(findings, findings.map((f) => `${f.file}: ${f.rule} (${f.match})`).join("\n")).toEqual([]);
  });

  it("yof's own rules find no key in its source, docs or workflows (README examples are masked)", () => {
    const hits: string[] = [];
    for (const f of walk(ROOT)) {
      if (!/\.(?:ts|md|yml|json)$/.test(f) || f.includes(`${join("test", "")}`)) continue;
      for (const m of scanText(readFileSync(f, "utf8"))) hits.push(`${relative(ROOT, f)}:${m.line} ${m.ruleId}`);
    }
    expect(hits).toEqual([]);
  });

  // api.github.com: yof attack reads this repository's own deployments with the workflow's GITHUB_TOKEN (proof.ts).
  it("the only URLs in the source are the four package registries, GitHub's API and yof.io", () => {
    // Plus one address that is never requested: the shape of a Slack webhook, named in the Slack rule's fix words.
    const allowed = /^https:\/\/(?:registry\.npmjs\.org|api\.npmjs\.org|pypi\.org|api\.osv\.dev|api\.github\.com|yof\.io)(?:\/|$)|^https:\/\/hooks\.slack\.com\/services\/\.\.\.$/;
    for (const f of walk(join(ROOT, "src"))) {
      for (const m of readFileSync(f, "utf8").matchAll(/https?:\/\/[^\s"'`)\\]+/g)) expect(m[0], relative(ROOT, f)).toMatch(allowed);
    }
  });

  it("no runtime dependencies", () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { dependencies?: unknown; name: string; license: string };
    expect(pkg.dependencies).toBeUndefined();
    expect(pkg.name).toBe("@yof/cli");
    expect(pkg.license).toBe("Apache-2.0");
  });

  // The samples are assembled at run time so this file never contains the strings it tests for.
  it("the leak rules catch what they are meant to catch", () => {
    const hit = (id: string, s: string) => { const r = LEAK_RULES.find((x) => x.id === id)!; return [...s.matchAll(r.re)].some((m) => !r.allow?.(m[0])); };
    expect(hit("ip-address", ["10", "1", "2", "3"].join("."))).toBe(true);
    expect(hit("ip-address", "192.0.2.10")).toBe(false);
    expect(hit("private-subdomain", `engine.${"mondaily"}.com`)).toBe(true);
    expect(hit("email-address", ["someone", "gmail.com"].join("@"))).toBe(true);
    expect(hit("email-address", "security@mondaily.com")).toBe(false);
    expect(hit("payment-key", ["sk", "_live_", "AbCdEfGhIjKl"].join(""))).toBe(true);
  });
});
