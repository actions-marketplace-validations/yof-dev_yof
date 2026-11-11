import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { gunzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { blastRadius, groupsFor, nextRoute, routeMatches, scopeLabel } from "../src/attack/blast";
import { ATTACK_RULES, consentText } from "../src/attack/catalog";
import { ConfigError, inWindow, parseAttackConfig } from "../src/attack/config";
import { runAttackCommand } from "../src/attack/command";
import { AttackClient, BudgetError, RefusedError } from "../src/attack/http";
import { proveTarget, registrableDomain, sameSite } from "../src/attack/proof";
import { detectFramework, GENERATED_MARK, synthesizeTest } from "../src/attack/regression";
import { attackComment, PAYLOAD_PREFIX } from "../src/attack/report";
import { answerShape, maskEvidence, runAttack } from "../src/attack/runner";
import { main } from "../src/cli";
import { fakeConfig, fakeEnv, startFakeApp, type FakeApp } from "./fake-app";

const run = promisify(execFile);
const noSleep = async () => {};

async function attack(app: FakeApp, cfgText = fakeConfig(), mode: "full" | "light" = "full") {
  const cfg = parseAttackConfig(cfgText);
  const proof = await proveTarget(app.url, cfg, mode, { env: {} });
  if (!proof.ok) throw new Error(proof.message);
  return runAttack({ cfg, proof, mode, env: fakeEnv(), sleep: noSleep });
}

let bad: FakeApp, good: FakeApp;
beforeAll(async () => { bad = await startFakeApp(true); good = await startFakeApp(false); });
afterAll(async () => { await bad.close(); await good.close(); });

describe("the runner finds each planted problem, and nothing on the fixed app", () => {
  it("vulnerable app: IDOR read + write, missing admin check, auth bypass, injectable assistant and its tool", async () => {
    const r = await attack(bad);
    const ids = new Set(r.findings.map((f) => f.ruleId));
    for (const id of ["attack.auth_bypass", "attack.tenant_read", "attack.tenant_write", "attack.rbac_escalation", "attack.prompt_injection",
      "attack.indirect_injection", "attack.prompt_extraction", "attack.tool_cross_tenant", "attack.open_redirect", "attack.missing_headers"]) {
      expect(ids.has(id), id).toBe(true);
    }
    expect(r.findings.find((f) => f.ruleId === "attack.auth_bypass")!.route).toBe("/api/me");
    expect(r.findings.find((f) => f.ruleId === "attack.rbac_escalation")!.route).toBe("/api/admin/users");
    expect(r.findings.filter((f) => f.ruleId === "attack.tenant_read").map((f) => f.route).sort()).toEqual(["/api/notes", "/api/notes/{id}"]);
    // Evidence is masked: no full email of the fake users is ever kept.
    expect(JSON.stringify(r.findings)).not.toMatch(/alice@example\.com|a-person@example\.com/);
    // And it never holds a piece of the answer: no name, no plan, no hidden instruction text, only the answer's shape.
    const kept = JSON.stringify(r.findings.map((f) => [f.evidence, f.meta]));
    expect(kept).not.toMatch(/Alice|Bob|Admin-View|team-plan-gold|user-a\b|example\.com/);
    const ev = (id: string, route?: string) => r.findings.find((f) => f.ruleId === id && (!route || f.route === route))!.evidence;
    expect(ev("attack.auth_bypass")).toMatch(/^the same data a signed-in account gets came back: a JSON object with 3 fields \(id, email, plan\), \d+ characters$/);
    expect(ev("attack.rbac_escalation")).toMatch(/^a member got the admin answer: a JSON object with 1 field \(users\), \d+ characters$/);
    expect(ev("attack.tenant_read", "/api/notes/{id}")).toMatch(/^the answer held the test record of account A: a JSON object with \d+ fields? \([a-z, ]+\), \d+ characters$/);
    expect(ev("attack.tenant_read", "/api/notes")).toMatch(/^the list held the test record of account A: a JSON /);
    expect(ev("attack.prompt_extraction")).toMatch(/^an answer of \d+ characters that reads like its hidden instructions \(the text is not kept\)$/);
    expect(kept).not.toContain("yofmarker");
    expect(r.stopped).toBeNull();
    // Every test record the run created is deleted again.
    expect(bad.notes.size).toBe(0);
  });

  it("fixed app: nothing found, everything cleaned up", async () => {
    const r = await attack(good);
    expect(r.findings).toEqual([]);
    expect(good.notes.size).toBe(0);
    expect(r.groups).toMatchObject({ auth: "done", tenant: "done", rbac: "done", ai: "done", surface: "done" });
  });

  it("writes only what it owns: PATCH and DELETE touch only records the run created; POST only to configured routes", async () => {
    const before = bad.requests.length;
    await attack(bad);
    const sent = bad.requests.slice(before);
    for (const q of sent.filter((x) => x.method === "PATCH" || x.method === "DELETE")) expect(q.path).toMatch(/^\/api\/notes\/n\d+$/);
    for (const q of sent.filter((x) => x.method === "POST")) expect(["/api/notes", "/api/chat"]).toContain(q.path);
    expect(sent.every((x) => ["GET", "POST", "PATCH", "DELETE"].includes(x.method))).toBe(true);
  });

  it("a light run is read-only: no POST, PATCH or DELETE at all", async () => {
    const before = bad.requests.length;
    const r = await attack(bad, fakeConfig(), "light");
    expect(bad.requests.slice(before).every((q) => q.method === "GET" || q.method === "HEAD")).toBe(true);
    expect(r.groups.tenant).toBe("skipped");
    expect(r.findings.some((f) => f.ruleId === "attack.rbac_escalation")).toBe(true);
  });
});

describe("safety rules in the client", () => {
  const client = () => new AttackClient({ origin: "http://127.0.0.1:1", budget: { requests: 5, seconds: 60, perSecond: 100 }, postPaths: ["/api/notes"], fetch: async () => new Response("{}", { status: 200 }), sleep: noSleep });
  it("refuses other hosts, unlisted POSTs and writes to records it did not create", () => {
    const c = client();
    expect(() => c.check("GET", "//evil.example/x", "read")).toThrow(RefusedError);
    expect(() => c.check("GET", "https://evil.example/x", "read")).toThrow(RefusedError);
    expect(() => c.check("POST", "/api/other", "create")).toThrow(RefusedError);
    expect(() => c.check("DELETE", "/api/notes/n1", "cleanup")).toThrow(RefusedError);
    expect(() => c.check("PATCH", "/api/notes/n1", "owned")).toThrow(RefusedError);
    c.own("n1");
    expect(() => c.check("PATCH", "/api/notes/n1", "owned")).not.toThrow();
    expect(() => c.check("PATCH", "/api/notes/n12", "owned")).toThrow(RefusedError);
  });
  it("the request budget is hard, with room held back to clean up", async () => {
    const c = client();
    await c.send("a", "POST", "/api/notes", { purpose: "create", body: "{}" });
    c.own("n1");
    for (let i = 0; i < 3; i++) await c.send("a", "GET", "/x");
    await expect(c.send("a", "GET", "/x")).rejects.toBeInstanceOf(BudgetError);
    await c.send("a", "DELETE", "/api/notes/n1", { purpose: "cleanup" });
    expect(c.used).toBe(5);
    await expect(c.send("a", "GET", "/x")).rejects.toBeInstanceOf(BudgetError);
  });
});

describe("budgets in a real run", () => {
  it("a 12-request budget stops the run, says so, and still deletes its test records", async () => {
    const before = bad.requests.length;
    const r = await attack(bad, fakeConfig({ budget: { requests: 12, seconds: 110, perSecond: 20 } }));
    expect(r.stopped).toBe("requests");
    expect(bad.requests.length - before).toBeLessThanOrEqual(12);
    expect(r.exchanges.length).toBeLessThanOrEqual(12);
    expect(bad.notes.size).toBe(0);
    expect(Object.values(r.groups)).toContain("not_run");
  });
  it("the time budget is hard (fake clock)", async () => {
    let t = 0;
    const cfg = parseAttackConfig(fakeConfig({ budget: { requests: 300, seconds: 20, perSecond: 20 } }));
    const proof = await proveTarget(bad.url, cfg, "full", { env: {} });
    if (!proof.ok) throw new Error("proof");
    const r = await runAttack({ cfg, proof, mode: "full", env: fakeEnv(), sleep: noSleep, now: () => (t += 1000) });
    expect(r.stopped).toBe("time");
    expect(r.requests).toBeLessThan(20);
  });
});

describe("evidence holds the shape of an answer, never its content", () => {
  it("answerShape names the kind, the size and plain field names only", () => {
    const person = JSON.stringify({ id: 7, fullName: "Maria Example", phone: "+44 20 7946 0958", "maria@example.com": true, "Maria Example": 1, "12345": 2 });
    const shape = answerShape(person);
    expect(shape).toBe(`a JSON object with 6 fields (id, fullName, phone, ...), ${person.length} characters`);
    expect(shape).not.toMatch(/Maria|7946|example\.com/);
    const list = JSON.stringify([{ name: "Maria Example", address: "1 High Street" }, { name: "Sam" }]);
    expect(answerShape(list)).toBe(`a JSON list of 2 items, the first with 2 fields (name, address), ${list.length} characters`);
    expect(answerShape("[]")).toBe("a JSON list of 0 items, 2 characters");
    expect(answerShape('"Maria Example"')).toBe("a JSON string, 15 characters");
    expect(answerShape("<html><body>Maria Example, +44 20 7946 0958</body></html>")).toBe("text, 57 characters");
  });
  it("maskEvidence also hides phone numbers and other long numbers", () => {
    expect(maskEvidence("call +44 20 7946 0958 or (555) 010-9999, card 4111 1111 1111 1111")).toBe("call •••58 or (•••99, card •••11");
    expect(maskEvidence("12 wrong passwords in a row, none slowed down")).toBe("12 wrong passwords in a row, none slowed down");
    expect(maskEvidence("a JSON object with 3 fields (id, email, plan), 71 characters")).toBe("a JSON object with 3 fields (id, email, plan), 71 characters");
  });
});

describe("only proven hosts", () => {
  const cfg = parseAttackConfig(fakeConfig({ app: "shop.example.com", consent: consentText("shop.example.com") }));
  it("an https host with no proof is refused before any attack request", async () => {
    const urls: string[] = [];
    const f = async (u: string) => { urls.push(u); return new Response("nothing", { status: 404 }); };
    const p = await proveTarget("https://shop.example.com", cfg, "full", { fetch: f, env: { YOF_VERIFY_TOKEN: "yof_abcdefghijklmnopqrstuvwxyz" }, resolveTxt: async () => [] });
    expect(p).toMatchObject({ ok: false, code: "not_proven" });
    expect(urls.every((u) => /yof-verify\.txt$|\/$/.test(u))).toBe(true);
  });
  it("another host than the config's app is refused without a request", async () => {
    const urls: string[] = [];
    const p = await proveTarget("https://other.example.net", cfg, "full", { fetch: async (u) => { urls.push(u); return new Response("", { status: 404 }); }, env: {} });
    expect(p).toMatchObject({ ok: false, code: "not_this_app" });
    expect(urls).toEqual([]);
  });
  it("plain http is refused except on localhost", async () => {
    expect(await proveTarget("http://shop.example.com", cfg, "full", { env: {} })).toMatchObject({ ok: false, code: "not_https" });
  });
  it("a proven production host: off unless enabled; full only inside the window, light any time", async () => {
    const token = "yof_abcdefghijklmnopqrstuvwxyz";
    const f = async (u: string) => new Response(u.endsWith("/.well-known/yof-verify.txt") ? token : "", { status: u.endsWith(".txt") ? 200 : 404 });
    const deps = { fetch: f, env: { YOF_VERIFY_TOKEN: token }, now: new Date("2026-11-02T12:00:00Z") };
    expect(await proveTarget("https://shop.example.com", cfg, "light", deps)).toMatchObject({ ok: false, code: "production_off" });
    const on = parseAttackConfig(fakeConfig({ app: "shop.example.com", consent: consentText("shop.example.com"), production: { enabled: true, window: "02:00-04:00" } }));
    expect(await proveTarget("https://shop.example.com", on, "full", deps)).toMatchObject({ ok: false, code: "outside_window" });
    expect(await proveTarget("https://shop.example.com", on, "light", deps)).toMatchObject({ ok: true, kind: "production", method: "file" });
    expect(await proveTarget("https://shop.example.com", on, "full", { ...deps, now: new Date("2026-11-02T03:00:00Z") })).toMatchObject({ ok: true });
    expect(inWindow("23:00-01:00", new Date("2026-11-02T00:30:00Z"))).toBe(true);
  });
  it("a GitHub preview deployment of this repository for this commit is proof (and reads as preview)", async () => {
    const f = async (u: string) => {
      if (u.includes("/deployments?sha=")) return Response.json([{ id: 7, environment: "Preview", production_environment: false }]);
      if (u.includes("/deployments/7/statuses")) return Response.json([{ state: "success", environment_url: "https://shop-git-fix.vercel.app", creator: { login: "vercel[bot]", type: "Bot" } }]);
      return new Response("", { status: 404 });
    };
    const env = { GITHUB_TOKEN: "t", GITHUB_REPOSITORY: "acme/shop", YOF_HEAD_SHA: "abcdef1234567" };
    expect(await proveTarget("https://shop-git-fix.vercel.app", cfg, "full", { fetch: f, env })).toMatchObject({ ok: true, kind: "preview", method: "github-deployment" });
  });

  // Security audit A5 (11 Nov 2026): a deployment status of YOUR OWN repository naming ANY host was proof, skipping the
  // token, the production switch and the window.
  const VERCEL = { login: "vercel[bot]", type: "Bot" };
  const deployAt = (url: string, environment = "Preview", production = false, creator: { login: string; type: string } | null = VERCEL) => async (u: string) => {
    if (u.includes("/deployments?sha=")) return Response.json([{ id: 7, environment, production_environment: production }]);
    if (u.includes("/deployments/7/statuses")) return Response.json([{ state: "success", environment_url: url, ...(creator ? { creator } : {}) }]);
    return new Response("", { status: 404 });
  };
  const ghEnv = { GITHUB_TOKEN: "t", GITHUB_REPOSITORY: "acme/shop", YOF_HEAD_SHA: "abcdef1234567" };
  it("a deployment naming someone else's host is refused, whatever its environment", async () => {
    expect(await proveTarget("https://victim.example", cfg, "full", { fetch: deployAt("https://victim.example"), env: ghEnv })).toMatchObject({ ok: false, code: "not_this_app" });
    expect(await proveTarget("https://victim-git-x.vercel.app", cfg, "full", { fetch: deployAt("https://victim-git-x.vercel.app"), env: ghEnv })).toMatchObject({ ok: false, code: "not_this_app" });
  });
  // Security audit 3.2 (11 Nov 2026): the repository's name is the attacker's to pick, and so is a deployment status.
  it("a platform preview named after the repository still needs a status written by the platform's own app", async () => {
    const host = "https://shop-git-x-victim.vercel.app";
    for (const creator of [null, { login: "mallory", type: "User" }, { login: "github-actions[bot]", type: "Bot" }, { login: "vercel[bot]", type: "User" }, { login: "netlify[bot]", type: "Bot" }]) {
      const p = await proveTarget(host, cfg, "full", { fetch: deployAt(host, "Preview", false, creator), env: ghEnv });
      expect(p, JSON.stringify(creator)).toMatchObject({ ok: false, code: "not_this_app" });
      expect((p as { message: string }).message).toContain("Vercel's own GitHub app");
    }
    expect(await proveTarget(host, cfg, "full", { fetch: deployAt(host), env: ghEnv })).toMatchObject({ ok: true, kind: "preview" });
    const nf = "https://deploy-preview-4--shop.netlify.app";
    expect(await proveTarget(nf, cfg, "full", { fetch: deployAt(nf, "Preview", false, { login: "netlify[bot]", type: "Bot" }), env: ghEnv })).toMatchObject({ ok: true, kind: "preview" });
    const cf = "https://fix.shop.pages.dev";
    expect(await proveTarget(cf, cfg, "full", { fetch: deployAt(cf, "Preview", false, { login: "cloudflare-workers-and-pages[bot]", type: "Bot" }), env: ghEnv })).toMatchObject({ ok: true, kind: "preview" });
    expect(await proveTarget(cf, cfg, "full", { fetch: deployAt(cf, "Preview", false, VERCEL), env: ghEnv })).toMatchObject({ ok: false, code: "not_this_app" });
  });
  it("on shared hosting two customers are never one site", async () => {
    expect(registrableDomain("victim.github.io")).toBe("victim.github.io");
    expect(registrableDomain("attacker.github.io")).toBe("attacker.github.io");
    expect(registrableDomain("fix.shop.pages.dev")).toBe("shop.pages.dev");
    expect(registrableDomain("api.shop.herokuapp.com")).toBe("shop.herokuapp.com");
    expect(registrableDomain("bucket-a.s3.eu-west-1.amazonaws.com")).toBe("bucket-a.s3.eu-west-1.amazonaws.com");
    expect(registrableDomain("victim.scm.azurewebsites.net")).toBe("victim.scm.azurewebsites.net");
    expect(registrableDomain("pr-12.shop.example.com")).toBe("example.com");
    expect(registrableDomain("pr-12.shop.example.co.uk")).toBe("example.co.uk");
    expect(sameSite("pr-12.example.com", "shop.example.com")).toBe(true);
    for (const suffix of ["github.io", "vercel.app", "netlify.app", "pages.dev", "web.app", "firebaseapp.com", "herokuapp.com", "onrender.com", "fly.dev", "cloudfront.net", "workers.dev"]) {
      expect(sameSite(`attacker.${suffix}`, `victim.${suffix}`), suffix).toBe(false);
      expect(sameSite(`victim.${suffix}`, suffix), suffix).toBe(false);
    }
    for (const suffix of ["azurewebsites.net", "amazonaws.com", "s3.amazonaws.com", "run.app"]) expect(sameSite(`attacker.${suffix}`, `victim.${suffix}`), suffix).toBe(false);

    // The run itself: the attacker's app is attacker.github.io, proven with their own token; GitHub reports a
    // deployment of their repository at victim.github.io. Refused, and the victim's host gets no request.
    const mine = parseAttackConfig(fakeConfig({ app: "attacker.github.io", consent: consentText("attacker.github.io") }));
    const token = "yof_abcdefghijklmnopqrstuvwxyz";
    const urls: string[] = [];
    const f = async (u: string) => {
      urls.push(u);
      if (u === "https://attacker.github.io/.well-known/yof-verify.txt") return new Response(token, { status: 200 });
      return deployAt("https://victim.github.io", "Preview", false, { login: "github-actions[bot]", type: "Bot" })(u);
    };
    expect(await proveTarget("https://victim.github.io", mine, "full", { fetch: f, env: { ...ghEnv, YOF_VERIFY_TOKEN: token }, resolveTxt: async () => [] })).toMatchObject({ ok: false, code: "not_this_app" });
    expect(urls.some((u) => u.includes("victim.github.io"))).toBe(false);
  });
  it("only environment_url counts, not target_url", async () => {
    const f = async (u: string) => {
      if (u.includes("/deployments?sha=")) return Response.json([{ id: 7, environment: "Preview" }]);
      if (u.includes("/deployments/7/statuses")) return Response.json([{ state: "success", target_url: "https://shop-git-x.vercel.app" }]);
      return new Response("", { status: 404 });
    };
    expect(await proveTarget("https://shop-git-x.vercel.app", cfg, "full", { fetch: f, env: ghEnv })).toMatchObject({ ok: false });
  });
  it("a host on the app's own domain needs the app proven with the token first", async () => {
    const f = deployAt("https://pr-12.example.com");
    expect(await proveTarget("https://pr-12.example.com", cfg, "full", { fetch: f, env: ghEnv, resolveTxt: async () => [] })).toMatchObject({ ok: false, code: "not_proven" });
    const token = "yof_abcdefghijklmnopqrstuvwxyz";
    const proven = async (u: string) => (u === "https://shop.example.com/.well-known/yof-verify.txt" ? new Response(token, { status: 200 }) : f(u));
    expect(await proveTarget("https://pr-12.example.com", cfg, "full", { fetch: proven, env: { ...ghEnv, YOF_VERIFY_TOKEN: token }, resolveTxt: async () => [] })).toMatchObject({ ok: true, kind: "preview", method: "github-deployment" });
  });
  it("an environment named prod or live, or the app's own host, is production: the switch and window apply", async () => {
    expect(await proveTarget("https://shop.vercel.app", cfg, "full", { fetch: deployAt("https://shop.vercel.app", "prod"), env: ghEnv })).toMatchObject({ ok: false, code: "production_off" });
    expect(await proveTarget("https://shop.vercel.app", cfg, "full", { fetch: deployAt("https://shop.vercel.app", "live"), env: ghEnv })).toMatchObject({ ok: false, code: "production_off" });
    const token = "yof_abcdefghijklmnopqrstuvwxyz";
    const f = deployAt("https://shop.example.com", "Preview");
    const proven = async (u: string) => (u === "https://shop.example.com/.well-known/yof-verify.txt" ? new Response(token, { status: 200 }) : f(u));
    expect(await proveTarget("https://shop.example.com", cfg, "full", { fetch: proven, env: { ...ghEnv, YOF_VERIFY_TOKEN: token }, resolveTxt: async () => [] })).toMatchObject({ ok: false, code: "production_off" });
  });
  it("the token never goes to a plain-http GitHub API", async () => {
    const urls: string[] = [];
    const f = async (u: string) => { urls.push(u); return deployAt("https://shop-git-fix.vercel.app")(u); };
    expect(await proveTarget("https://shop-git-fix.vercel.app", cfg, "full", { fetch: f, env: { ...ghEnv, GITHUB_API_URL: "http://fake.example" } })).toMatchObject({ ok: false });
    expect(urls.some((u) => u.startsWith("http://fake.example"))).toBe(false);
  });
  it("the config needs the written consent, word for word", () => {
    expect(() => parseAttackConfig(fakeConfig({ consent: "yes" }))).toThrow(ConfigError);
    expect(() => parseAttackConfig(fakeConfig({ accounts: { a: { env: "YOF_ATTACK_A", password: "x" } } }))).toThrow(ConfigError);
  });
});

describe("regression tests from recorded attacks (feature A)", () => {
  it("the generated node:test file fails on the vulnerable app and passes on the fixed one", async () => {
    const r = await attack(bad);
    const dir = mkdtempSync(join(tmpdir(), "yof-attack-reg-"));
    const fw = detectFramework({ read: () => null, exists: () => false });
    expect(fw.framework).toBe("generic");
    for (const ruleId of ["attack.tenant_read", "attack.rbac_escalation", "attack.prompt_injection", "attack.tool_cross_tenant", "attack.indirect_injection", "attack.auth_bypass", "attack.open_redirect", "attack.tenant_write"]) {
      const f = r.findings.find((x) => x.ruleId === ruleId)!;
      const t = synthesizeTest(f.replay, f, fw);
      expect(t.content.startsWith(`// ${GENERATED_MARK}`)).toBe(true);
      expect(t.content).not.toMatch(/tok-[ab]-|tok-admin/);
      const file = join(dir, t.path.replace(/\//g, "_"));
      writeFileSync(file, t.content);
      const env = { ...process.env, ...fakeEnv() };
      const onBad = await run(process.execPath, ["--test", file], { env: { ...env, YOF_ATTACK_TARGET: bad.url } }).then(() => "pass", () => "fail");
      const onGood = await run(process.execPath, ["--test", file], { env: { ...env, YOF_ATTACK_TARGET: good.url } }).then(() => "pass", (e) => `fail ${e.stdout}`);
      expect(onBad, ruleId).toBe("fail");
      expect(onGood, ruleId).toBe("pass");
    }
    expect(bad.notes.size + good.notes.size).toBe(0);
  }, 60_000);

  it("detects vitest, jest, playwright and pytest, and writes a test in each", async () => {
    const r = await attack(bad);
    const f = r.findings.find((x) => x.ruleId === "attack.tenant_read")!;
    const repo = (files: Record<string, string>) => ({ read: (p: string) => files[p] ?? null, exists: (p: string) => p in files });
    const cases: [Record<string, string>, string, RegExp][] = [
      [{ "package.json": JSON.stringify({ devDependencies: { vitest: "2" } }) }, "vitest", /from "vitest";[\s\S]*describe\.skipIf/],
      [{ "jest.config.js": "" }, "jest", /describe\.skip/],
      [{ "package.json": JSON.stringify({ devDependencies: { "@playwright/test": "1" } }), "playwright.config.ts": 'export default { testDir: "./e2e" }' }, "playwright", /from "@playwright\/test"/],
      [{ "pyproject.toml": "[tool.pytest.ini_options]\n" }, "pytest", /def test_yof_attack_/],
    ];
    for (const [files, name, re] of cases) {
      const fw = detectFramework(repo(files));
      expect(fw.framework).toBe(name);
      const t = synthesizeTest(f.replay, f, fw);
      expect(t.content).toMatch(re);
      if (name === "playwright") expect(t.path.startsWith("e2e/yof-attack/")).toBe(true);
    }
  });

  it("the pytest file runs with plain python too: fails on the vulnerable app, passes on the fixed one", async () => {
    const py = await run("python3", ["--version"]).then(() => true, () => false);
    if (!py) return;
    const r = await attack(bad);
    const f = r.findings.find((x) => x.ruleId === "attack.tenant_read")!;
    const t = synthesizeTest(f.replay, f, { framework: "pytest", dir: "tests" });
    const dir = mkdtempSync(join(tmpdir(), "yof-attack-py-"));
    const file = join(dir, "t.py");
    writeFileSync(file, t.content);
    const env = { ...process.env, ...fakeEnv() };
    expect(await run("python3", ["-I", file], { env: { ...env, YOF_ATTACK_TARGET: bad.url } }).then(() => "pass", () => "fail")).toBe("fail");
    expect(await run("python3", ["-I", file], { env: { ...env, YOF_ATTACK_TARGET: good.url } }).then(() => "pass", (e) => `fail ${e.stderr}`)).toBe("pass");
  }, 30_000);

  it("the pull-request comment carries the tests as a payload with the head commit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "yof-attack-cmd-"));
    mkdirSync(join(dir, ".yof"));
    writeFileSync(join(dir, ".yof/attack.json"), fakeConfig());
    const out = await runAttackCommand({ target: bad.url, cwd: dir, version: "0.2.0", env: { ...fakeEnv(), YOF_HEAD_SHA: "abcdef1234567" }, sleep: noSleep, commentFile: "c.md" });
    const c = readFileSync(join(dir, "c.md"), "utf8");
    expect(c.startsWith("<!-- yof-attack -->")).toBe(true);
    const b64 = c.slice(c.indexOf(PAYLOAD_PREFIX) + PAYLOAD_PREFIX.length, c.lastIndexOf(" -->"));
    const payload = JSON.parse(gunzipSync(Buffer.from(b64, "base64")).toString("utf8"));
    expect(payload.headSha).toBe("abcdef1234567");
    expect(payload.files.length).toBe(out.tests.length);
    expect(payload.headerRuleIds).toEqual(expect.arrayContaining(["headers.nosniff", "headers.frame"]));
    expect(attackComment(out.report, [], null)).not.toContain(PAYLOAD_PREFIX);
  });
});

describe("blast radius (feature B)", () => {
  const files: Record<string, string> = {
    "app/api/notes/[id]/route.ts": "export async function GET() {}",
    "app/(shop)/api/orders/route.ts": "export async function GET() {}",
    "pages/api/users/[id].ts": "export default function h() {}",
    "pages/api/index.ts": "export default function h() {}",
    "src/routes/billing.ts": 'import { money } from "../lib/money";\nbilling.get("/invoices/:id", h);\nbilling.post("/invoices", h);',
    "src/app.ts": 'import { billing } from "./routes/billing";\napp.route("/api/billing", billing);',
    "src/lib/money.ts": "export const money = 1;",
    "src/lib/format.ts": "export const f = 1;",
    "src/routes/a.ts": 'import { f } from "../lib/format";\nr.get("/a", h);',
    "src/routes/b.ts": 'import { f } from "../lib/format";\nr.get("/b", h);',
    "src/routes/c.ts": 'import { f } from "../lib/format";\nr.get("/c", h);',
    "src/lib/orphan.ts": "export const o = 1;",
  };
  const all = Object.keys(files);
  const read = (p: string) => files[p] ?? null;
  it("maps Next.js app and pages routes", () => {
    expect(nextRoute("app/api/notes/[id]/route.ts")).toBe("/api/notes/{id}");
    expect(nextRoute("app/(shop)/api/orders/route.ts")).toBe("/api/orders");
    expect(nextRoute("src/pages/api/users/[id].ts")).toBe("/api/users/{id}");
    expect(nextRoute("pages/api/index.ts")).toBe("/api");
    expect(nextRoute("app/docs/[...slug]/page.tsx")).toBe("/docs/{slug}");
    expect(nextRoute("src/lib/x.ts")).toBeNull();
  });
  it("maps Hono/Express files with their mount prefix, and a helper to the routes that import it", () => {
    expect(blastRadius(["src/routes/billing.ts"], read, all)).toMatchObject({ full: false, routes: ["/api/billing/invoices", "/api/billing/invoices/{id}"] });
    expect(blastRadius(["src/lib/money.ts", "README.md"], read, all)).toMatchObject({ full: false, routes: ["/api/billing/invoices", "/api/billing/invoices/{id}"], ignored: ["README.md"] });
  });
  it("a full run when shared code changes, a helper is used by many routes, or the mapping is unsure", () => {
    expect(blastRadius(["middleware.ts"], read, all).full).toBe(true);
    expect(blastRadius(["src/lib/auth/session.ts"], read, all).reasons[0]).toMatch(/auth or permissions/);
    expect(blastRadius(["src/db/client.ts"], read, all).reasons[0]).toMatch(/database access/);
    expect(blastRadius(["src/lib/format.ts"], read, all).reasons[0]).toMatch(/used by 3 route files/);
    expect(blastRadius(["src/lib/orphan.ts"], read, all).reasons[0]).toMatch(/mapping is unsure/);
    expect(blastRadius(["docs/guide.md", "src/x.test.ts"], read, all)).toMatchObject({ full: false, routes: [] });
  });
  it("picks the attack groups whose config targets the change reaches, and labels the run", () => {
    const cfg = parseAttackConfig(fakeConfig());
    expect(routeMatches("/api/notes/{id}", ["/api/notes/{id}"])).toBe(true);
    expect(routeMatches("/api/notes/:id", ["/api/notes/{noteId}"])).toBe(true);
    expect(routeMatches("/api/me", ["/api/notes/{id}"])).toBe(false);
    expect(groupsFor(cfg, ["/api/notes/{id}"])).toEqual(["tenant"]);
    expect(groupsFor(cfg, ["/api/admin/users"])).toEqual(["auth", "rbac"]);
    expect(scopeLabel(false, 2)).toBe("partial run: 2 attack groups");
    expect(scopeLabel(true, 5)).toBe("full run");
  });
  it("a scoped command run attacks only the reached group", async () => {
    const dir = mkdtempSync(join(tmpdir(), "yof-attack-scope-"));
    mkdirSync(join(dir, ".yof"));
    mkdirSync(join(dir, "app/api/notes/[id]"), { recursive: true });
    writeFileSync(join(dir, "app/api/notes/[id]/route.ts"), "export async function GET() {}");
    writeFileSync(join(dir, ".yof/attack.json"), fakeConfig());
    const out = await runAttackCommand({ target: bad.url, cwd: dir, version: "0.2.0", env: fakeEnv(), sleep: noSleep, base: "main",
      changedFiles: ["app/api/notes/[id]/route.ts"], git: () => Buffer.from("app/api/notes/[id]/route.ts\n") });
    expect(out.report.scope).toMatchObject({ full: false, label: "partial run: 1 attack group", groups: ["tenant"] });
    expect(new Set(out.report.findings.map((f) => f.group))).toEqual(new Set(["tenant"]));
  });
});

describe("the yof attack command", () => {
  it("exit 1 with findings, 0 on the fixed app, 2 when refused; JSON never holds a token", async () => {
    const dir = mkdtempSync(join(tmpdir(), "yof-attack-cli-"));
    mkdirSync(join(dir, ".yof"));
    writeFileSync(join(dir, ".yof/attack.json"), fakeConfig());
    const io = (out: string[], err: string[]) => ({ cwd: dir, out: (s: string) => out.push(s), err: (s: string) => err.push(s), env: fakeEnv(), sleep: noSleep });
    const o1: string[] = [], e1: string[] = [];
    expect(await main(["attack", bad.url, "--json"], io(o1, e1))).toBe(1);
    const j = JSON.parse(o1.join("\n"));
    expect(j).toMatchObject({ tool: "yof", command: "attack", target: { kind: "local" }, scope: { label: "full run" } });
    expect(o1.join("\n")).not.toMatch(/tok-a-|tok-b-|tok-admin/);
    const o2: string[] = [];
    expect(await main(["attack", good.url], io(o2, []))).toBe(0);
    expect(o2.join("\n")).toMatch(/Nothing found in what was tested/);
    const e3: string[] = [];
    expect(await main(["attack", "http://shop.example.com"], io([], e3))).toBe(2);
    expect(e3.join("\n")).toMatch(/Refused/);
    expect(await main(["attack", bad.url, "--mode", "loud"], io([], []))).toBe(2);
  }, 30_000);
  it("the catalog: twenty-one rules, unique ids under attack.*", () => {
    expect(ATTACK_RULES).toHaveLength(21);
    expect(new Set(ATTACK_RULES.map((r) => r.id)).size).toBe(21);
    for (const r of ATTACK_RULES) { expect(r.id).toMatch(/^attack\.[a-z_]+$/); expect(`${r.title}${r.why}`).not.toMatch(/—/); }
  });
});
