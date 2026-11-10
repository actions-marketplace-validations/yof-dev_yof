/**
 * 0.3.1: found by running yof on our own repository (2026-11-09). The walk read every Claude Code worktree under
 * .claude/worktrees/ (each a full copy of the repo) and stopped at 20,000 files before the real code, and the CLI
 * listed fixture values the yof app drops. Both fixed here.
 */
import { describe, expect, it } from "vitest";
import { runCheck } from "../src/check";
import { isLinkedWorktree, shouldSkipPath, walkFiles } from "../src/files";
import { isRepoFixture } from "../src/secrets";
import { fakeStripeLive, tempDir } from "./helpers";

/** AWS's own documented example key id, joined at run time so the oss/ leak rules never see a key-shaped literal here. */
const AWS_EXAMPLE_ID = ["AKIA", "IOSFODNN7EXAMPLE"].join("");

describe("walk: nested worktrees and hidden tool folders are read once", () => {
  it("skips .claude/worktrees and any linked git worktree, keeps the rest of .claude and submodules", () => {
    const key = `const k = "${fakeStripeLive()}";`;
    const dir = tempDir({
      "src/app.ts": key,
      ".claude/worktrees/agent-1/.git": "gitdir: /repo/.git/worktrees/agent-1\n",
      ".claude/worktrees/agent-1/src/app.ts": key,
      ".claude/settings.json": "{}",
      "copies/feature/.git": "gitdir: /Users/me/repo/.git/worktrees/feature\n",
      "copies/feature/src/app.ts": key,
      "vendor/lib/.git": "gitdir: ../../.git/modules/vendor/lib\n",
      "vendor/lib/index.ts": "export {};",
      ".cache/x/app.ts": key, ".history/src/app_20261109.ts": key, ".wrangler/state/a.js": key,
    });
    const paths = walkFiles(dir).files.map((f) => f.path).sort();
    expect(paths).toEqual([".claude/settings.json", "src/app.ts", "vendor/lib/index.ts"]);
  });

  it("isLinkedWorktree only for a .git FILE that points into worktrees/", () => {
    const dir = tempDir({ "a/.git": "gitdir: /r/.git/worktrees/a\n", "b/.git": "gitdir: ../.git/modules/b\n", "c/.git/HEAD": "ref: refs/heads/main\n" });
    expect(isLinkedWorktree(`${dir}/a`)).toBe(true);
    expect(isLinkedWorktree(`${dir}/b`)).toBe(false);
    expect(isLinkedWorktree(`${dir}/c`)).toBe(false);
    expect(isLinkedWorktree(`${dir}/missing`)).toBe(false);
  });

  it("staged and diff paths under .claude/worktrees are skipped too", () => {
    expect(shouldSkipPath(".claude/worktrees/agent-1/src/a.ts", [])).toBe(true);
    expect(shouldSkipPath(".claude/settings.local.json", [])).toBe(false);
  });
});

describe("keys: the app's repository rule for fixtures", () => {
  it("a secret-named browser setting in tests and docs is not reported; a provider key there still is; one shipped to the browser always is", async () => {
    // public/config.js is the yof demo's planted problem (oss/yof-demo, y4-yof-demo test): a setting named like a secret
    // in a file every visitor gets is the finding whatever its value looks like, so a "demo-..." value is still reported.
    const live = fakeStripeLive();
    const dir = tempDir({
      "src/__tests__/env.test.ts": `const env = { VITE_STRIPE_SECRET: "realLooking9f8e7d6c5b4a" };\n`,
      "docs/setup.md": `VITE_SECRET_TOKEN="a9F3kQ7zL2mX8vB4nR6t"\n`,
      "public/config.js": `window.cfg = { VITE_SERVICE_SECRET: "demo-9f8e7d6c5b4a3210" };\n`,
      "src/env.ts": `export const s = { VITE_STRIPE_SECRET: "a9F3kQ7zL2mX8vB4nR6t" };\n`,
      "test/keys.ts": `export const k = "${live}";\n`,
      "src/aws.ts": `// AWS's documented key: ${AWS_EXAMPLE_ID}\nexport const id = "${AWS_EXAMPLE_ID}";\n`,
    });
    const r = await runCheck({ cwd: dir, offline: true });
    const got = r.keys.map((k) => `${k.rule} ${k.file}`).sort();
    expect(got).toEqual(["secret.named_env public/config.js", "secret.named_env src/env.ts", "secret.stripe_live test/keys.ts"]);
  });

  it("isRepoFixture: name-only guesses in fixture paths, placeholder starts, EXAMPLE lines", () => {
    expect(isRepoFixture({ ruleId: "secret.named_env", masked: "a9F3••••••••" }, "e2e/a.ts", "")).toBe(true);
    expect(isRepoFixture({ ruleId: "secret.named_env", masked: "a9F3••••••••" }, "CLAUDE.md", "")).toBe(false);
    expect(isRepoFixture({ ruleId: "secret.named_env", masked: "a9F3••••••••" }, "src/a.ts", "")).toBe(false);
    expect(isRepoFixture({ ruleId: "secret.named_env", masked: "\\${p••••••••" }, "src/a.ts", "")).toBe(true);
    expect(isRepoFixture({ ruleId: "secret.named_env", masked: "demo••••••••" }, "public/config.js", "")).toBe(false);
    expect(isRepoFixture({ ruleId: "secret.stripe_live", masked: "sk_live_51Ab••••••••" }, "tests/a.ts", "")).toBe(false);
    expect(isRepoFixture({ ruleId: "secret.aws_key_id", masked: `${AWS_EXAMPLE_ID.slice(0, 8)}••••••••` }, "src/a.ts", `id = ${AWS_EXAMPLE_ID}`)).toBe(true);
  });
});
