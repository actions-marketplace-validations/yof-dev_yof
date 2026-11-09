/**
 * The benchmark's scoring and summary, from hand-made samples in the shapes yof and the two apps produce (fixtures/).
 * Nothing here starts an app or touches the network.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { consentText } from "../../src/attack/catalog";
import { parseAttackConfig } from "../../src/attack/config";
import { ListError, parseJuiceShopChallenges, parseNodeGoatTutorial, yamlScalar } from "../lists.ts";
import { combine, findingsOf, PENDING, ScoreError, scoreTarget, type BenchmarkResults, type RunInfo } from "../score.ts";
import { assertLoopback, consentFor, envLines, juiceShopConfig, nodeGoatConfig, setupJuiceShop } from "../setup.ts";
import { summaryMarkdown } from "../summary.ts";
import { JUICE_SHOP, NODEGOAT, TARGETS } from "../targets.ts";

const FIX = join(__dirname, "fixtures");
const text = (f: string) => readFileSync(join(FIX, f), "utf8");
const data = (f: string) => JSON.parse(text(f));
const jsList = () => parseJuiceShopChallenges(text("juice-shop-challenges.sample.yml"));
const ngList = () => parseNodeGoatTutorial(text("nodegoat-layout.sample.html"));
const RUN: RunInfo = { id: "123", url: "https://github.com/example/example/actions/runs/123", commit: "0123456789abcdef0123456789abcdef01234567", yofVersion: "0.2.0", startedAt: "2026-11-09T10:00:00Z", finishedAt: "2026-11-09T10:06:00Z", runner: "ubuntu-latest" };

const juice = (extra: Partial<Parameters<typeof scoreTarget>[0]> = {}) => scoreTarget({
  target: JUICE_SHOP, list: jsList(), check: data("juice-shop-check.sample.json"), attack: data("juice-shop-attack.sample.json"),
  solvedBefore: [], solvedAfter: ["errorHandlingChallenge", "notOnTheList"], ...extra,
});
const goat = () => scoreTarget({ target: NODEGOAT, list: ngList(), check: data("nodegoat-check.sample.json"), attack: data("nodegoat-attack.sample.json") });

describe("official lists", () => {
  it("Juice Shop: keys, quoted names, trailing comments, disabledEnv only from its own field", () => {
    const l = jsList();
    expect(l).toHaveLength(24);
    expect(l.find((i) => i.key === "resetPasswordBjoernOwaspChallenge")!.name).toBe("Bjoern's Favorite Pet");
    expect(l.find((i) => i.key === "csrfChallenge")!.name).toBe("CSRF");
    expect(l.find((i) => i.key === "restfulXssChallenge")!.disabledEnv).toEqual(["Docker", "Heroku"]);
    expect(l.find((i) => i.key === "adminSectionChallenge")!.disabledEnv).toEqual([]);   // its tags and hints are lists too
    expect(l.find((i) => i.key === "jwtForgedChallenge")!.disabledEnv).toEqual(["Windows"]);
  });
  it("NodeGoat: the twelve tutorial topics", () => {
    const l = ngList();
    expect(l.map((i) => i.key)).toEqual(["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "redos", "ssrf"]);
    expect(l[3]).toEqual({ key: "a4", name: "A4 Insecure DOR", category: "OWASP Top 10 2013", disabledEnv: [] });
    expect(l[10]!.category).toBe("Extra topic");
  });
  it("anything unexpected is an error, never a guess", () => {
    expect(() => parseJuiceShopChallenges("---\n")).toThrow(ListError);
    expect(() => parseJuiceShopChallenges("-\n  name: A\n  category: B\n  key: k\n-\n  name: C\n  category: D\n  key: k\n")).toThrow(/Duplicate key/);
    expect(() => parseJuiceShopChallenges("-\n  name: A\n  category: B\n")).toThrow(/without key/);
    expect(() => parseNodeGoatTutorial("<p>nothing</p>")).toThrow(ListError);
    expect(yamlScalar("'It''s'")).toBe("It's");
    expect(yamlScalar("plain # comment")).toBe("plain");
  });
});

describe("scoring", () => {
  it("Juice Shop sample: found, missed, not tested, not available and the extra findings", () => {
    const r = juice();
    expect(r.ran).toBe(true);
    expect(r.counts).toEqual({ items: 24, found: 5, foundSame: 1, foundRoot: 4, missed: 7, notTested: 6, notAvailable: 6, extra: 4, falsePositives: 0, realNotListed: 0, toReview: 4 });
    const s = (k: string) => r.items.find((i) => i.key === k)!;
    expect(s("knownVulnerableComponentChallenge")).toMatchObject({ status: "found", relation: "same", by: ["package.vulnerable package.json express-jwt@0.1.3", "package.vulnerable package.json sanitize-html@1.4.2"] });
    expect(s("jwtUnsignedChallenge").by).toEqual(["package.vulnerable package.json express-jwt@0.1.3", "package.vulnerable package.json jsonwebtoken@0.4.0"]);
    expect(s("adminSectionChallenge")).toMatchObject({ status: "found", relation: "root", by: ["attack.rbac_escalation GET /api/Users"] });
    expect(s("weakPasswordChallenge").status).toBe("found");
    expect(s("basketAccessChallenge")).toMatchObject({ status: "missed", note: expect.stringMatching(/basket holds products/) });
    expect(s("restfulXssChallenge")).toMatchObject({ status: "not_available", note: "OWASP Juice Shop turns this off when it runs in Docker." });
    expect(s("jwtForgedChallenge").status).toBe("found");   // turned off on Windows only
    expect(s("systemPromptExtractionChallenge").status).toBe("not_available");
    expect(s("csrfChallenge")).toMatchObject({ status: "not_tested", note: JUICE_SHOP.defaultNotTested });
    expect(r.extra.map((e) => e.id)).toEqual([
      "attack|attack.rbac_escalation|GET /api/Feedbacks",
      "attack|attack.tenant_write|PUT /api/Addresss/{id}",
      "key|secret.private_key|lib/insecurity.ts:21",
      "package|package.vulnerable|package.json unzipper@0.9.15",
    ]);
    expect(r.solvedDuringRun).toEqual(["errorHandlingChallenge"]);   // keys not on the list are dropped
    expect(r.attack).toEqual({ requests: 188, seconds: 72, groups: { auth: "done", tenant: "done", rbac: "done", ai: "skipped", surface: "done" }, stopped: null, notes: ["no_ingest:none"] });
    expect(r.check).toEqual({ filesScanned: 812, dependenciesChecked: 160, registryUnanswered: 0, truncated: false });
  });
  it("keeps nothing key-shaped or private: no masked value, snippet or evidence text", () => {
    const out = JSON.stringify(juice());
    expect(out).not.toMatch(/\[masked\]|\[sample\]|GHSA-sample|evidence|snippet/);
  });
  it("NodeGoat sample", () => {
    const r = goat();
    expect(r.counts).toMatchObject({ items: 12, found: 2, missed: 4, notTested: 6, notAvailable: 0, extra: 0 });
    expect(r.items.filter((i) => i.status === "found").map((i) => i.key)).toEqual(["a5", "a9"]);
    expect(r.check!.registryUnanswered).toBe(1);
  });
  it("review verdicts are applied to the extra findings", () => {
    const r = juice({ reviews: { "juice-shop": { "attack|attack.rbac_escalation|GET /api/Feedbacks": { verdict: "false_positive", note: "Public by design: the feedback carousel." }, "key|secret.private_key|lib/insecurity.ts:21": { verdict: "real_not_listed" } } } });
    expect(r.counts).toMatchObject({ extra: 4, falsePositives: 1, realNotListed: 1, toReview: 2 });
    expect(r.extra[0]).toEqual({ id: "attack|attack.rbac_escalation|GET /api/Feedbacks", source: "attack", rule: "attack.rbac_escalation", where: "GET /api/Feedbacks", verdict: "false_positive", note: "Public by design: the feedback carousel." });
  });
  it("a mapping key missing from the pinned list fails the scoring", () => {
    expect(() => scoreTarget({ target: JUICE_SHOP, list: jsList().filter((i) => i.key !== "redirectChallenge"), check: null, attack: null })).toThrow(ScoreError);
  });
  it("an app that did not start claims no numbers", () => {
    const r = juice({ check: null, attack: null, error: "Juice Shop did not answer within 120 s." });
    expect(r.ran).toBe(false);
    expect(r.counts).toBeNull();
    expect(r.items.every((i) => i.status !== "found" && i.status !== "missed")).toBe(true);
    expect(summaryMarkdown(combine(RUN, [r]))).toContain("**Did not run:** Juice Shop did not answer within 120 s.. No numbers are claimed for this app.");
  });
  it("a missing yof attack output makes its items not available, never missed", () => {
    const r = juice({ attack: null });
    expect(r.items.find((i) => i.key === "basketAccessChallenge")).toMatchObject({ status: "not_available", note: "Not run: yof attack produced no results in this run." });
    expect(r.items.find((i) => i.key === "knownVulnerableComponentChallenge")!.status).toBe("found");
    expect(r.attack).toBeNull();
  });
  it("findings are de-duplicated and sorted", () => {
    const f = findingsOf({ keys: [{ file: "b", line: 1, rule: "r" }, { file: "a", line: 2, rule: "r" }, { file: "a", line: 2, rule: "r" }] }, null);
    expect(f.map((x) => x.where)).toEqual(["a:2", "b:1"]);
  });
});

describe("summary", () => {
  it("is deterministic and matches the recorded expectation", () => {
    const results = combine(RUN, [goat(), juice()]);
    expect(results.targets.map((t) => t.id)).toEqual(["juice-shop", "nodegoat"]);
    const md = summaryMarkdown(results);
    expect(summaryMarkdown(combine(RUN, [juice(), goat()]))).toBe(md);
    expect(md).toBe(text("expected-summary.md"));
  });
  it("a pending results file says no run yet", () => {
    expect(summaryMarkdown(PENDING)).toMatch(/No run yet/);
  });
});

describe("the committed results file (results/latest.json)", () => {
  const latest = JSON.parse(readFileSync(join(__dirname, "..", "results", "latest.json"), "utf8")) as BenchmarkResults;
  it("is pending with no numbers, or a finished run whose counts add up", () => {
    expect(latest.schema).toBe(1);
    if (latest.status === "pending") { expect(latest).toEqual(PENDING); return; }
    expect(latest.run).toBeTruthy();
    for (const t of latest.targets) {
      if (!t.counts) continue;
      expect(t.counts.found + t.counts.missed + t.counts.notTested + t.counts.notAvailable).toBe(t.counts.items);
      expect(t.counts.falsePositives + t.counts.realNotListed + t.counts.toReview).toBe(t.counts.extra);
    }
  });
  it("reviews.json holds only the two verdicts", () => {
    const reviews = JSON.parse(readFileSync(join(__dirname, "..", "reviews.json"), "utf8")) as Record<string, Record<string, { verdict: string }>>;
    for (const t of Object.values(reviews)) for (const v of Object.values(t)) expect(["false_positive", "real_not_listed"]).toContain(v.verdict);
  });
});

describe("pins and set-up", () => {
  it("each target is pinned to a full commit; Juice Shop's image to a digest", () => {
    for (const t of TARGETS) {
      expect(t.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(new Set(t.mapping.map((m) => m.key)).size).toBe(t.mapping.length);
      for (const m of t.mapping) if (m.kind === "tested") { expect(m.detectors.length).toBeGreaterThan(0); expect(m.why && m.ifMissed).toBeTruthy(); }
    }
    expect(JUICE_SHOP.tag).toBe("v20.3.0");
    expect(JUICE_SHOP.image!.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
  it("the attack configs pass yof's own strict config check, name localhost, keep default budgets and never production", () => {
    for (const cfg of [juiceShopConfig({ basketId: "6" }), nodeGoatConfig({ userIdA: "1" }), nodeGoatConfig({ userIdA: null })]) {
      const parsed = parseAttackConfig(JSON.stringify(cfg));
      expect(parsed.app).toMatch(/^localhost:\d+$/);
      expect(parsed.consent).toBe(consentText(parsed.app));
      expect(parsed.production.enabled).toBe(false);
      expect(parsed.budget).toEqual({ requests: 300, seconds: 110, perSecond: 8 });
      expect(JSON.stringify(cfg)).not.toMatch(/password"\s*:\s*"[^{]/);   // env names only, never a value
    }
    expect(consentFor("localhost:3000")).toBe(consentText("localhost:3000"));
  });
  it("refuses any host that is not localhost, and unsafe environment values", async () => {
    for (const bad of ["https://localhost:3000", "http://example.com", "http://192.0.2.1:3000", "nonsense"]) expect(() => assertLoopback(bad)).toThrow();
    expect(assertLoopback("http://127.0.0.1:3000").port).toBe("3000");
    expect(() => envLines({ A: "x\ny" })).toThrow();
    expect(envLines({ YOF_A: "1", YOF_B: "2" })).toBe("YOF_A=1\nYOF_B=2\n");
    const calls: string[] = [];
    const f = (async (u: string | URL) => { calls.push(String(u)); return new Response(JSON.stringify({ version: "19.0.0" })); }) as typeof fetch;
    await expect(setupJuiceShop(JUICE_SHOP, f)).rejects.toThrow(/not 20\.3\.0/);
    expect(calls.every((c) => c.startsWith("http://localhost:3000/"))).toBe(true);
  });
  it("the expected summary fixture exists", () => { expect(existsSync(join(FIX, "expected-summary.md"))).toBe(true); });
});
