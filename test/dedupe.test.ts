/**
 * One problem, one finding (2026-11-07): a value caught by several rules is one key finding with `alsoMatched`, a
 * dependency named in several workspace manifests is asked once and reported once, and a file with two or more
 * problems gets one combined prompt in `--json` (`filePrompts`).
 */
import { describe, expect, it } from "vitest";
import { collapseKeys, primaryOrder, runCheck, type KeyFinding } from "../src/check";
import { ACCEPTED_FILE, acceptFingerprint, withEntry } from "../src/accepted";
import { filePrompts, formatJson, formatText } from "../src/format";
import { fakeStripeLive, mockFetcher, rand, tempDir } from "./helpers";

const P = (...p: string[]) => p.join("");

describe("several rules on one value", () => {
  it("a Stripe key in a VITE_..._SECRET setting is ONE finding (the Stripe rule), the setting rule as alsoMatched", async () => {
    const key = fakeStripeLive();
    const dir = tempDir({ "src/env.ts": `export const env = { ${P("VITE_", "STRI", "PE_SEC", "RET")}: "${key}" };\n` });
    const r = await runCheck({ cwd: dir, offline: true });
    expect(r.keys).toHaveLength(1);   // before: 2 (secret.stripe_live and secret.named_env)
    expect(r.keys[0]).toMatchObject({ rule: "secret.stripe_live", severity: "fix_now", alsoMatched: ["secret.named_env"] });
    expect(r.counts.fix_now + r.counts.fix_week).toBe(1);
    const text = formatText(r);
    expect(text).toMatch(/also matched: /);
    expect(text).toMatch(/Found 1 problem: 1 to fix now\./);
    expect(text.includes(key)).toBe(false);
    expect(formatJson(r, { version: "test" }).includes(key)).toBe(false);
  });
  it("the primary is the most urgent, then the specific rule, then the rule id; the same answer in any order", () => {
    const base = { file: "a.ts", line: 1, column: 1, name: "x", masked: "m", hash: "h", fingerprint: "f" };
    const a = { ...base, rule: "secret.named_env", severity: "fix_week" as const };
    const b = { ...base, rule: "secret.stripe_test", severity: "fix_week" as const };
    expect(collapseKeys([a, b])).toEqual(collapseKeys([b, a]));
    expect(collapseKeys([a, b])[0]).toMatchObject({ rule: "secret.stripe_test", alsoMatched: ["secret.named_env"] });
    expect([{ rule: "z", severity: "fix_now" }, { rule: "a", severity: "fix_week" }].sort(primaryOrder as never)[0]).toMatchObject({ rule: "z" });
    // other values and other files stay apart
    expect(collapseKeys([a, { ...b, hash: "other" }, { ...b, file: "b.ts" }])).toHaveLength(3);
  });
});

describe("a monorepo's manifests", () => {
  it("a dependency named in three workspaces is asked once and reported once, every manifest listed", async () => {
    const calls: string[] = [];
    const pkg = (deps: Record<string, string>) => JSON.stringify({ dependencies: deps });
    const dir = tempDir({
      "package.json": pkg({ "reqeusts-helper": "^1.0.0" }),
      "apps/web/package.json": pkg({ "reqeusts-helper": "^1.0.0" }),
      "packages/ui/package.json": pkg({ "reqeusts-helper": "^1.0.0" }),
    });
    const r = await runCheck({ cwd: dir, fetcher: mockFetcher({ "https://registry.npmjs.org/reqeusts-helper": { status: 404 } }, calls) });
    expect(calls.filter((c) => c.includes("reqeusts-helper"))).toHaveLength(1);
    expect(r.packages).toHaveLength(1);
    expect([...r.packages[0]!.files!].sort()).toEqual(["apps/web/package.json", "package.json", "packages/ui/package.json"]);
    expect(r.packages[0]!.file).toBe(r.packages[0]!.files![0]);
    expect(formatText(r)).toMatch(/Named in 3 manifests: /);
  });
});

describe("one fix prompt per file", () => {
  it("two problems in one file: one prompt, numbered, each with its rule and line; single prompts stay", async () => {
    const live = fakeStripeLive();
    const dir = tempDir({ "src/pay.ts": `export const a = "${live}";\n\nexport const gh = "${P("gh", "p_", rand(36, undefined, 41))}";\n`, "src/one.ts": `export const k = "${P("sk", "_test_", rand(26, undefined, 43))}";\n` });
    const r = await runCheck({ cwd: dir, offline: true });
    const fp = filePrompts(r);
    expect(fp.map((x) => [x.file, x.count])).toEqual([["src/pay.ts", 2]]);   // src/one.ts has one problem: no combined prompt
    const p = fp[0]!.prompt;
    expect(p).toContain("Fix these 2 problems in src/pay.ts together, so the file is edited once:");
    expect(p).toMatch(/\[1\] \(rule secret\.stripe_live, line 1\)/);
    expect(p).toMatch(/\[2\] \(rule secret\.github, line 3\)/);
    expect(p.includes(live)).toBe(false);
    const json = JSON.parse(formatJson(r, { version: "test" })) as { keys: { fixPrompt: string }[]; filePrompts: unknown[] };
    expect(json.filePrompts).toHaveLength(1);
    expect(json.keys.every((k) => k.fixPrompt.startsWith("yof (a local check that runs on my machine) found this in my code"))).toBe(true);
  });
  it("info findings (public by design) never make a file prompt", () => {
    const k = (rule: string, severity: KeyFinding["severity"], line: number): KeyFinding => ({ file: "a.ts", line, column: 1, rule, name: rule, severity, masked: "m", fingerprint: `f${line}` });
    const r = { profile: "strict", keys: [k("public.stripe_publishable", "info", 1), k("secret.stripe_test", "fix_week", 2)], packages: [] } as never;
    expect(filePrompts(r)).toEqual([]);
  });
});

describe("accepted risks still match after grouping", () => {
  it("an entry in .yof/accepted.json for the folded rule (same value, same line) keeps the one finding accepted", async () => {
    const key = fakeStripeLive();
    const line = `export const env = { ${P("VITE_", "STRI", "PE_SEC", "RET")}: "${key}" };`;
    const entry = { rule: "secret.named_env", file: "src/env.ts", fingerprint: acceptFingerprint("secret.named_env", "src/env.ts", line), reason: "Test fixture only.", acceptedBy: "Sam", acceptedAt: "2026-11-07" };
    const dir = tempDir({ "src/env.ts": `${line}\n`, [ACCEPTED_FILE]: withEntry(null, entry) });
    const r = await runCheck({ cwd: dir, offline: true });
    expect(r.keys).toHaveLength(1);
    expect(r.keys[0]).toMatchObject({ rule: "secret.stripe_live", alsoMatched: ["secret.named_env"], accepted: { reason: "Test fixture only." } });
    expect(r.keys[0]!.fingerprint).toBe(acceptFingerprint("secret.stripe_live", "src/env.ts", line));   // its own fingerprint
    expect(r.counts.fix_now).toBe(0);
    expect(r.acceptedCount).toBe(1);
    expect(r.failed).toBe(false);
    expect(filePrompts(r)).toEqual([]);
  });
  it("an entry for the primary rule matches as before", async () => {
    const key = fakeStripeLive();
    const line = `export const env = { ${P("VITE_", "STRI", "PE_SEC", "RET")}: "${key}" };`;
    const entry = { rule: "secret.stripe_live", file: "src/env.ts", fingerprint: acceptFingerprint("secret.stripe_live", "src/env.ts", line), reason: "Rotated.", acceptedBy: "Sam", acceptedAt: "2026-11-07" };
    const r = await runCheck({ cwd: tempDir({ "src/env.ts": `${line}\n`, [ACCEPTED_FILE]: withEntry(null, entry) }), offline: true });
    expect(r.keys[0]!.accepted?.reason).toBe("Rotated.");
  });
});
