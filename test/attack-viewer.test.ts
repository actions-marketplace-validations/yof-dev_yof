/**
 * Y24, first slice: the read-only member. With a "viewer" account the rbac group checks that a member who may only
 * read cannot create, change or delete the config's objects and cannot open admin routes. What works is reported as
 * attack.viewer_escalation, confirmed twice, with a regression test generated like the others.
 */
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ATTACK_RULE_BY_ID, ATTACK_RULES } from "../src/attack/catalog";
import { parseAttackConfig } from "../src/attack/config";
import { proveTarget, type Mode } from "../src/attack/proof";
import { synthesizeTest } from "../src/attack/regression";
import { runAttack } from "../src/attack/runner";
import { attackPlan } from "../src/attack/scope-doc";
import { VIEWER_ACCOUNTS, fakeConfig, fakeEnv, startFakeApp, type FakeApp } from "./fake-app";

const run = promisify(execFile);
const noSleep = async () => {};
const RULE = "attack.viewer_escalation";

async function attack(app: FakeApp, mode: Mode = "full", extra: Record<string, unknown> = {}) {
  const cfg = parseAttackConfig(fakeConfig({ accounts: VIEWER_ACCOUNTS, ai: [], ...extra }));
  const proof = await proveTarget(app.url, cfg, mode, { env: {} });
  if (!proof.ok) throw new Error(proof.message);
  const before = app.requests.length;
  const res = await runAttack({ cfg, proof, mode, env: fakeEnv(), sleep: noSleep, groups: ["rbac"] });
  return { res, cfg, requests: app.requests.slice(before) };
}

let bad: FakeApp, good: FakeApp;
beforeAll(async () => { bad = await startFakeApp(true); good = await startFakeApp(false); });
afterAll(async () => { await bad.close(); await good.close(); });

describe("the read-only member (attack.viewer_escalation)", () => {
  it("is a rule of the rbac group, next to the member rule", () => {
    const i = ATTACK_RULES.findIndex((r) => r.id === RULE);
    expect(ATTACK_RULES[i - 1]!.id).toBe("attack.rbac_escalation");
    expect(ATTACK_RULE_BY_ID[RULE]).toMatchObject({ group: "rbac", severity: "fix_now" });
  });

  it("vulnerable app: the viewer creates, changes and deletes; each is found twice and reported as the viewer", async () => {
    const { res, requests } = await attack(bad);
    const mine = res.findings.filter((f) => f.ruleId === RULE);
    expect(mine.map((f) => `${f.method} ${f.route}`).sort()).toEqual(["DELETE /api/notes/{id}", "PATCH /api/notes/{id}", "POST /api/notes"]);
    for (const f of mine) {
      expect(f).toMatchObject({ group: "rbac", severity: "fix_now", as: "viewer" });
      expect(f.evidence).toMatch(/^a read-only member (created a test record|changed a test record of account A|deleted a test record of account A) with /);
      expect(f.replay.accounts.viewer).toEqual({ headers: [{ header: "Authorization", env: "YOF_ATTACK_VIEWER" }] });
    }
    // the admin route is open to every member there: reported once, under the member rule
    expect(res.findings.filter((f) => f.route === "/api/admin/users").map((f) => f.ruleId)).toEqual(["attack.rbac_escalation"]);
    // confirmed twice: two creates by the viewer, two deletes by the viewer
    expect(res.unconfirmed).toBe(0);
    expect(requests.filter((r) => r.method === "DELETE").length).toBeGreaterThanOrEqual(2);
    // every test record is gone again, and no token is in the result
    expect(bad.notes.size).toBe(0);
    expect(res.cleanup.left).toEqual([]);
    expect(JSON.stringify(res)).not.toMatch(/tok-(a|b|admin|viewer)-123456/);
    expect(res.groups.rbac).toBe("done");
  });

  it("an admin route open to the viewer only is reported under the viewer rule", async () => {
    // A fetch wrapper turns the fixed app into one whose admin route forgets the viewer.
    const cfg = parseAttackConfig(fakeConfig({ accounts: VIEWER_ACCOUNTS, ai: [], objects: [] }));
    const proof = await proveTarget(good.url, cfg, "light", { env: {} });
    if (!proof.ok) throw new Error(proof.message);
    const leaky: typeof fetch = async (u, init) => {
      const h = (init?.headers ?? {}) as Record<string, string>;
      if (String(u).endsWith("/api/admin/users") && h.Authorization === fakeEnv().YOF_ATTACK_VIEWER) return fetch(u, { ...init, headers: { ...h, Authorization: fakeEnv().YOF_ATTACK_ADMIN! } });
      return fetch(u, init);
    };
    const res = await runAttack({ cfg, proof, mode: "light", env: fakeEnv(), sleep: noSleep, groups: ["rbac"], fetch: leaky as never });
    expect(res.findings.map((f) => [f.ruleId, f.method, f.route, f.as])).toEqual([[RULE, "GET", "/api/admin/users", "viewer"]]);
    expect(res.findings[0]!.evidence).toMatch(/^a read-only member got the admin answer: a JSON object with 1 field \(users\), \d+ characters$/);
    expect(JSON.stringify(res.findings)).not.toMatch(/Alice|example\.com/);
    expect(res.findings[0]!.replay.steps).toEqual([{ as: "viewer", method: "GET", path: "/api/admin/users", expect: { kind: "denied" } }]);
  });

  it("fixed app: nothing found, nothing left behind", async () => {
    const { res } = await attack(good);
    expect(res.findings).toEqual([]);
    expect(res.groups.rbac).toBe("done");
    expect(good.notes.size).toBe(0);
    expect(res.cleanup.left).toEqual([]);
  });

  it("a light run is read-only: the viewer opens admin routes and writes nothing", async () => {
    const { res, requests } = await attack(bad, "light");
    expect(requests.every((r) => r.method === "GET")).toBe(true);
    expect(requests.some((r) => r.path === "/api/admin/users")).toBe(true);
    expect(res.findings.some((f) => f.ruleId === RULE)).toBe(false);
  });

  it("without a viewer account the group is as before; with the viewer alone its tests still run", async () => {
    const cfgNo = parseAttackConfig(fakeConfig({ ai: [] }));
    const proof = await proveTarget(bad.url, cfgNo, "full", { env: {} });
    if (!proof.ok) throw new Error(proof.message);
    const before = bad.requests.length;
    const r = await runAttack({ cfg: cfgNo, proof, mode: "full", env: fakeEnv(), sleep: noSleep, groups: ["rbac"] });
    expect(r.findings.map((f) => f.ruleId)).toEqual(["attack.rbac_escalation"]);
    expect(bad.requests.slice(before).every((x) => x.method === "GET")).toBe(true);

    const only = await attack(bad, "full", { accounts: { viewer: VIEWER_ACCOUNTS.viewer } });
    expect(only.res.groups.rbac).toBe("done");
    expect(only.res.findings.map((f) => `${f.ruleId} ${f.method} ${f.route}`).sort()).toEqual([`${RULE} GET /api/admin/users`, `${RULE} POST /api/notes`]);
    expect(only.res.notes).toContain("viewer_needs_account_a:the change and delete tests need a record of account A");
    expect(bad.notes.size).toBe(0);
    // the viewer's token is not set: said in the notes, nothing sent as the viewer
    const cfg = parseAttackConfig(fakeConfig({ accounts: VIEWER_ACCOUNTS, ai: [] }));
    const env = { ...fakeEnv(), YOF_ATTACK_VIEWER: "" };
    const unset = await runAttack({ cfg, proof, mode: "full", env, sleep: noSleep, groups: ["rbac"] });
    expect(unset.notes).toContain("no_account:viewer");
    expect(unset.findings.some((f) => f.ruleId === RULE)).toBe(false);
  });

  it("the scope document's plan matches: rbac runs for the viewer alone, and is skipped with nothing to test", async () => {
    for (const [extra, mode] of [[{ accounts: { viewer: VIEWER_ACCOUNTS.viewer } }, "full"], [{ accounts: { viewer: VIEWER_ACCOUNTS.viewer }, admin: [] }, "full"], [{ accounts: { viewer: VIEWER_ACCOUNTS.viewer }, admin: [] }, "light"], [{ accounts: VIEWER_ACCOUNTS }, "light"]] as const) {
      const { res, cfg } = await attack(good, mode, extra);
      const plan = attackPlan(cfg, mode).find((p) => p.group === "rbac")!;
      expect(res.groups.rbac, JSON.stringify([extra, mode])).toBe(plan.runs ? "done" : "skipped");
    }
    const full = attackPlan(parseAttackConfig(fakeConfig({ accounts: VIEWER_ACCOUNTS })), "full").find((p) => p.group === "rbac")!;
    expect(full.does.join(" ")).toContain("The read-only member tries to create a test record on 1 object, and to change and delete a test record of account A.");
    expect(full.does.join(" ")).toContain("Opens 1 admin route as the read-only member (viewer).");
  });

  it("the generated regression tests fail on the vulnerable app and pass on the fixed one", async () => {
    const { res } = await attack(bad);
    const dir = mkdtempSync(join(tmpdir(), "yof-attack-viewer-"));
    const env = { ...process.env, ...fakeEnv() };
    for (const f of res.findings.filter((x) => x.ruleId === RULE)) {
      const t = synthesizeTest(f.replay, { method: f.method, route: f.route }, { framework: "generic", dir: "yof-attack" });
      expect(t.content).not.toMatch(/tok-(a|b|admin|viewer)-123456/);
      const file = join(dir, t.path);
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, t.content);
      const where = `${f.method} ${f.route}`;
      expect(await run(process.execPath, ["--test", file], { env: { ...env, YOF_ATTACK_TARGET: bad.url } }).then(() => "pass", () => "fail"), where).toBe("fail");
      expect(await run(process.execPath, ["--test", file], { env: { ...env, YOF_ATTACK_TARGET: good.url } }).then(() => "pass", (e) => `fail ${e.stdout}`), where).toBe("pass");
    }
    expect(bad.notes.size).toBe(0);
    expect(good.notes.size).toBe(0);
  }, 120_000);
});
