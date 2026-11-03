import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { main, VERSION } from "../src/cli";
import { stagedFiles, stagedPaths, walkFiles } from "../src/files";
import { CLOSING_LINE } from "../src/format";
import { HOOK_MARKER } from "../src/hook";
import { captureIo, fakeStripeLive, mockFetcher, rand, tempDir, testGit } from "./helpers";

const registry = {
  "https://registry.npmjs.org/reqeusts-helper": { status: 404 },
  "https://registry.npmjs.org/react": { status: 200, json: { time: { created: "2013-05-29T00:00:00Z" }, versions: Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`18.0.${i}`, {}])) } },
};

describe("yof check: exit codes and output", () => {
  it("0 and a short 'nothing to fix' on a clean folder", async () => {
    const dir = tempDir({ "src/a.ts": "export const a = 1;\n", "package.json": JSON.stringify({ dependencies: { react: "^18" } }) });
    const { cap, io } = captureIo(dir, { fetcher: mockFetcher(registry) });
    expect(await main(["check"], io)).toBe(0);
    const text = cap.out.join("\n");
    expect(text).toMatch(/Nothing to fix: no leaked keys, 1 dependency look fine\./);
    expect(text.trim().endsWith(CLOSING_LINE)).toBe(true);
  });

  it("1 on a leaked key and a made-up package; the key is masked, never printed whole", async () => {
    const key = fakeStripeLive();
    const dir = tempDir({ "src/config.ts": `export const stripe = "${key}";\n`, "package.json": JSON.stringify({ dependencies: { react: "^18", "reqeusts-helper": "^1.0.0" } }) });
    const { cap, io } = captureIo(dir, { fetcher: mockFetcher(registry) });
    expect(await main(["check", "."], io)).toBe(1);
    const text = cap.out.join("\n");
    expect(text).toContain("src/config.ts:1");
    expect(text).toContain("Stripe live secret key");
    expect(text).toContain(`${key.slice(0, 12)}••••••••`);
    expect(text.includes(key)).toBe(false);
    expect(text).toMatch(/reqeusts-helper \(npm\)/);
    expect(text).toMatch(/doesn't exist on npm/);
    expect(text).toMatch(/Found 2 problems: 2 to fix now\./);
  });

  it("--offline never calls the registry and still finds keys", async () => {
    const calls: string[] = [];
    const dir = tempDir({ "a.env": `KEY=${fakeStripeLive()}\n`, "package.json": JSON.stringify({ dependencies: { "reqeusts-helper": "1" } }) });
    const { cap, io } = captureIo(dir, { fetcher: mockFetcher(registry, calls) });
    expect(await main(["check", "--offline"], io)).toBe(1);
    expect(calls).toEqual([]);
    expect(cap.out.join("\n")).toMatch(/Package check skipped \(--offline\)/);
  });

  it("--json is valid JSON with masked values and the same exit code", async () => {
    const key = fakeStripeLive();
    const dir = tempDir({ "x.js": `const k = "${key}"`, "package.json": JSON.stringify({ dependencies: { "reqeusts-helper": "1" } }) });
    const { cap, io } = captureIo(dir, { fetcher: mockFetcher(registry) });
    expect(await main(["check", "--json"], io)).toBe(1);
    const raw = cap.out.join("\n");
    expect(raw.includes(key)).toBe(false);
    const j = JSON.parse(raw);
    expect(j).toMatchObject({ tool: "yof", mode: "full", profile: "balanced", failed: true, counts: { fix_now: 2 } });
    expect(j.keys[0]).toMatchObject({ file: "x.js", line: 1, rule: "secret.stripe_live", severity: "fix_now" });
    expect(j.packages[0]).toMatchObject({ file: "package.json", name: "reqeusts-helper", issue: "made_up" });
    // The plain words and the prompt to paste into an AI assistant (the editor plugins show these): masked value only.
    expect(j.keys[0].why).toMatch(/take payments/);
    expect(j.keys[0].fixPrompt).toContain("Where: x.js, line 1.");
    expect(j.keys[0].fixPrompt).toContain(j.keys[0].masked);
    expect(j.keys[0].fixPrompt.includes(key)).toBe(false);
    expect(j.packages[0].why).toBe(j.packages[0].message);
    expect(j.packages[0].fixPrompt).toMatch(/Do not invent a package name/);
  });

  it("profiles decide what fails: a Stripe test key passes balanced, fails strict, is hidden by relaxed", async () => {
    const dir = tempDir({ "a.ts": `const k = "${["sk", "_test_", rand(28)].join("")}";` });
    const run = async (args: string[]) => { const { cap, io } = captureIo(dir); return { code: await main(args, io), text: cap.out.join("\n") }; };
    const balanced = await run(["check", "--offline"]);
    expect(balanced.code).toBe(0);
    expect(balanced.text).toMatch(/1 to fix this week/);
    expect((await run(["check", "--offline", "--profile", "strict"])).code).toBe(1);
    const relaxed = await run(["check", "--offline", "--profile=relaxed"]);
    expect(relaxed.code).toBe(0);
    expect(relaxed.text).toMatch(/1 lower-priority finding hidden by profile relaxed/);
    writeFileSync(join(dir, ".yof.yml"), "profile: strict\n");
    expect((await run(["check", "--offline"])).code).toBe(1);
  });

  it("public-by-design keys never fail", async () => {
    const dir = tempDir({ "a.ts": `const k = "${["pk", "_live_", rand(28)].join("")}";` });
    const { io } = captureIo(dir);
    expect(await main(["check", "--offline", "--profile", "strict"], io)).toBe(0);
  });

  it("skips node_modules, .git, dist, build, .next, binary files, big files, .gitignore and .yof.yml entries", async () => {
    const key = `const k = "${fakeStripeLive()}";`;
    const dir = tempDir({
      "node_modules/x/index.js": key, "dist/a.js": key, "build/a.js": key, ".next/a.js": key, ".git/config": key,
      "fixtures/a.ts": key, "logs/a.log": key, "big.txt": `${key}\n${"a".repeat(1_100_000)}`, "img.dat": `\u0000${key}`,
      ".gitignore": "*.log\n", ".yof.yml": "ignore:\n  - fixtures/\n", "src/ok.ts": "export {};",
    });
    const set = walkFiles(dir, ["fixtures/"], ["*.log"]);
    expect(set.files.map((f) => f.path).sort()).toEqual([".gitignore", ".yof.yml", "src/ok.ts"]);
    const { io } = captureIo(dir);
    expect(await main(["check", "--offline"], io)).toBe(0);
  });

  it("2 on usage errors; --version and --help", async () => {
    const dir = tempDir();
    const { cap, io } = captureIo(dir);
    expect(await main(["check", "--nope"], io)).toBe(2);
    expect(await main(["frobnicate"], io)).toBe(2);
    expect(await main(["check", "missing-folder"], io)).toBe(2);
    expect(await main(["check", "--profile", "loose"], io)).toBe(2);
    expect(await main(["--version"], io)).toBe(0);
    expect(cap.out).toContain(VERSION);
    expect(await main(["--help"], io)).toBe(0);
    expect(await main([], io)).toBe(0);
    expect(cap.out.join("\n")).toMatch(/yof check --staged/);
  });
});

describe("yof check --staged (temporary git repository)", () => {
  const repo = (files: Record<string, string>) => { const dir = tempDir(files); testGit(["init", "-q"], dir); return dir; };

  it("lists only added/modified staged files and reads their STAGED content", async () => {
    const key = fakeStripeLive();
    const dir = repo({ "staged.ts": `const k = "${key}";\n`, "unstaged.ts": `const k = "${key}";\n`, "clean.ts": "export {};\n" });
    testGit(["add", "staged.ts", "clean.ts"], dir);
    // The working copy no longer has the key, but the commit would: the staged content is what counts.
    writeFileSync(join(dir, "staged.ts"), "export {};\n");
    expect(stagedPaths(dir, testGit).sort()).toEqual(["clean.ts", "staged.ts"]);
    expect(stagedFiles(dir, [], testGit).files.find((f) => f.path === "staged.ts")!.content).toContain(key.slice(0, 12));

    const { cap, io } = captureIo(dir);
    expect(await main(["check", "--staged", "--offline"], io)).toBe(1);
    const text = cap.out.join("\n");
    expect(text).toContain("staged.ts:1");
    expect(text).not.toContain("unstaged.ts");
    expect(text).toMatch(/yof checked 2 staged files/);
  });

  it("checks only the dependencies the commit adds", async () => {
    const dir = repo({ "package.json": JSON.stringify({ dependencies: { react: "^18" } }, null, 2) });
    testGit(["add", "package.json"], dir);
    testGit(["-c", "user.name=t", "-c", "user.email=noreply@github.com", "commit", "-q", "-m", "init"], dir);
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { "reqeusts-helper": "^1", react: "^18" } }, null, 2));
    testGit(["add", "package.json"], dir);
    const calls: string[] = [];
    const { cap, io } = captureIo(dir, { fetcher: mockFetcher(registry, calls) });
    expect(await main(["check", "--staged"], io)).toBe(1);
    expect(calls).toEqual(["GET https://registry.npmjs.org/reqeusts-helper"]);
    expect(cap.out.join("\n")).toMatch(/reqeusts-helper/);
  });

  it("0 with nothing staged; 2 outside a repository", async () => {
    const dir = repo({ "a.ts": `const k = "${fakeStripeLive()}";` });
    expect(await main(["check", "--staged"], captureIo(dir).io)).toBe(0);
    const plain = tempDir();
    const failing = captureIo(plain, { git: () => { throw new Error("not a repo"); } });
    expect(await main(["check", "--staged"], failing.io)).toBe(2);
    expect(failing.cap.err.join("\n")).toMatch(/needs a git repository/);
  });
});

describe("yof hook", () => {
  it("installs, is idempotent, and uninstalls its own hook", async () => {
    const dir = tempDir(); testGit(["init", "-q"], dir);
    const hook = join(dir, ".git/hooks/pre-commit");
    const { cap, io } = captureIo(dir);
    expect(await main(["hook", "install"], io)).toBe(0);
    const body = readFileSync(hook, "utf8");
    expect(body).toContain(HOOK_MARKER);
    expect(body).toContain("npx --yes @yof/cli check --staged");
    expect(await main(["hook", "install"], io)).toBe(0);
    expect(cap.out.join("\n")).toMatch(/already installed/);
    expect(await main(["hook", "uninstall"], io)).toBe(0);
    expect(existsSync(hook)).toBe(false);
  });

  it("never clobbers or removes someone else's hook", async () => {
    const dir = tempDir(); testGit(["init", "-q"], dir);
    const hook = join(dir, ".git/hooks/pre-commit");
    mkdirSync(join(dir, ".git/hooks"), { recursive: true });
    writeFileSync(hook, "#!/bin/sh\necho mine\n"); chmodSync(hook, 0o755);
    const { cap, io } = captureIo(dir);
    expect(await main(["hook", "install"], io)).toBe(2);
    expect(await main(["hook", "uninstall"], io)).toBe(2);
    expect(readFileSync(hook, "utf8")).toBe("#!/bin/sh\necho mine\n");
    expect(cap.err.join("\n")).toMatch(/not yof's/);
  });

  it("2 outside a repository and on a bad subcommand", async () => {
    const { io } = captureIo(tempDir(), { git: () => { throw new Error("no"); } });
    expect(await main(["hook", "install"], io)).toBe(2);
    expect(await main(["hook", "remove"], io)).toBe(2);
  });
});

describe("paths", () => {
  it("accepts an absolute path", async () => {
    const dir = tempDir({ "a.ts": `const k = "${fakeStripeLive()}";` });
    const { io } = captureIo(tempDir());
    expect(await main(["check", dir, "--offline"], io)).toBe(1);
  });
});
