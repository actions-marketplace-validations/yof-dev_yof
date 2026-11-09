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
    // Plus addresses that are never requested: the shape of a Slack webhook, named in the Slack rule's fix words, and the
    // reserved .invalid addresses inside the assistant probes' message text (they never resolve; the probe image host is
    // the constant PROBE_IMAGE_HOST, yof-canary.invalid).
    const allowed = /^https:\/\/(?:registry\.npmjs\.org|api\.npmjs\.org|pypi\.org|api\.osv\.dev|api\.github\.com|yof\.io|mcp\.yof\.io)(?:\/|$)|^https:\/\/hooks\.slack\.com\/services\/\.\.\.$|^https:\/\/example\.invalid$|^https:\/\/\$\{PROBE_IMAGE_HOST\}\//;
    for (const f of walk(join(ROOT, "src"))) {
      for (const m of readFileSync(f, "utf8").matchAll(/https?:\/\/[^\s"'`)\\]+/g)) expect(m[0], relative(ROOT, f)).toMatch(allowed);
    }
  });

  // 2026-11-09 (owner, board Y17): `yof mcp` runs on the official MCP SDK. It is bundled into dist at build time (tsup
  // bundles devDependencies), pinned to an exact version with the zod it needs, so installing @yof/cli still installs
  // nothing else; and only `yof mcp` loads it (the CLI imports ./mcp/server on demand).
  it("no runtime dependencies (the MCP SDK is bundled, pinned exactly)", () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { dependencies?: unknown; devDependencies: Record<string, string>; name: string; license: string };
    expect(pkg.dependencies).toBeUndefined();
    expect(pkg.devDependencies["@modelcontextprotocol/sdk"]).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pkg.devDependencies.zod).toMatch(/^\d+\.\d+\.\d+$/);
    const eager = walk(join(ROOT, "src")).filter((f) => !f.includes(join("src", "mcp", "server.ts")) && readFileSync(f, "utf8").includes('from "@modelcontextprotocol'));
    expect(eager).toEqual([]);
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
    expect(hit("email-address", "security@yof.io")).toBe(false);
    expect(hit("email-address", "privacy@yof.io")).toBe(false);
    expect(hit("email-address", ["sales", "yof.io"].join("@"))).toBe(true);
    expect(hit("payment-key", ["sk", "_live_", "AbCdEfGhIjKl"].join(""))).toBe(true);
  });
});
