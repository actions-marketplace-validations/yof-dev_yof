/**
 * Y24, first slice: `yof attack --scope-doc`, the scope and rules-of-engagement document.
 *   - made from the parsed config and its consent sentence only: pure, no network, the same input gives the same text;
 *   - names the variables of each account, never a value (the environment is not even read);
 *   - the groups it says will run or be skipped are the groups the runner really runs or skips (compared on the fake app);
 *   - honest wording: never "certified" or "secure"; it says what it is and that it does not replace a manual test;
 *   - the CLI flag prints it and sends nothing.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { consentText } from "../src/attack/catalog";
import { parseAttackConfig, type AttackConfig } from "../src/attack/config";
import { proveTarget, type Mode } from "../src/attack/proof";
import { runAttack } from "../src/attack/runner";
import { attackPlan, scopeDocument } from "../src/attack/scope-doc";
import { main } from "../src/cli";
import { fakeConfig, fakeEnv, startFakeApp, type FakeApp } from "./fake-app";

const shop = (extra: Record<string, unknown> = {}): AttackConfig => parseAttackConfig(JSON.stringify({
  app: "shop.example.com", consent: consentText("shop.example.com"),
  accounts: {
    a: { login: { path: "/api/login", body: '{"email":"{{email}}","password":"{{password}}","code":"{{totp}}"}', totpEnv: "YOF_ATTACK_A_TOTP" }, emailEnv: "YOF_ATTACK_A_EMAIL", passwordEnv: "YOF_ATTACK_A_PASSWORD", headers: [{ header: "X-Workspace-Id", env: "YOF_ATTACK_A_WS" }] },
    b: { headers: [{ header: "Cookie", env: "YOF_ATTACK_B" }, { header: "X-Workspace-Id", env: "YOF_ATTACK_B_WS" }] },
    viewer: { env: "YOF_ATTACK_VIEWER" },
  },
  routes: ["/api/me", "/api/notes"], admin: ["/api/admin/users"],
  objects: [{ create: { path: "/api/notes", body: '{"title":"{{marker}}"}' }, idPath: "id", read: "/api/notes/{id}", list: "/api/notes", update: { method: "PATCH", path: "/api/notes/{id}", body: '{"title":"{{marker}}"}' }, delete: "/api/notes/{id}" }],
  ai: [{ path: "/api/chat", body: '{"message":"{{message}}"}', replyPath: "reply", limits: true }],
  surface: { redirectPaths: ["/login", "/out"], rateLimit: true },
  production: { enabled: true, window: "02:00-04:00" },
  budget: { requests: 250, seconds: 90, perSecond: 5 },
  ...extra,
}));
const doc = (cfg: AttackConfig, mode: Mode = "full", target: string | null = null) => scopeDocument({ cfg, mode, target, date: "2026-11-11", version: "0.4.0" });

describe("the scope and rules-of-engagement document", () => {
  it("says what is in scope, from the config: consent, hosts, accounts by role, mode, window, budget, groups, signature", () => {
    const text = doc(shop(), "full", "https://shop.example.com/some/path?x=1");
    expect(text.startsWith("# Scope and rules of engagement: yof attack on shop.example.com\n")).toBe(true);
    expect(text).toContain("Prepared on 2026-11-11 with yof attack 0.4.0 from `.yof/attack.json`.");
    expect(text).toContain(`> ${consentText("shop.example.com")}`);
    expect(text).toContain("This run is aimed at: `https://shop.example.com`.");
    expect(text).not.toContain("/some/path");
    expect(text).toContain("- **The app:** `shop.example.com` (and `www.shop.example.com`)");
    expect(text).toContain("Every other host is out of scope.");
    // accounts by role: how each signs in and the NAMES of its variables
    expect(text).toContain("| a | a member | signs in at `POST /api/login` with an email and a password and a one-time code; also sends X-Workspace-Id | `YOF_ATTACK_A_EMAIL`, `YOF_ATTACK_A_PASSWORD`, `YOF_ATTACK_A_TOTP`, `YOF_ATTACK_A_WS` |");
    expect(text).toContain("| b | a member of a second tenant (its own workspace) | sends Cookie, X-Workspace-Id | `YOF_ATTACK_B`, `YOF_ATTACK_B_WS` |");
    expect(text).toContain("| admin | an administrator | not set | none |");
    expect(text).toContain("| viewer | a member who may only read | sends Authorization | `YOF_ATTACK_VIEWER` |");
    expect(text).toContain("- **Mode: full.**");
    expect(text).toContain("- **Production: on.** A light run may go at any time. A full run goes only inside the agreed window, 02:00-04:00 UTC, every day.");
    expect(text).toContain("- At most 250 requests and 90 seconds for the whole run, at most 5 requests a second.");
    for (const g of ["auth", "tenant", "rbac", "ai", "surface"]) expect(text, g).toMatch(new RegExp(`### [A-Za-z -]+ \\(\`${g}\`\\): will run`));
    expect(text).toContain("Sign-in rate limit (turned on in the config): 12 wrong passwords in a row for one test account.");
    expect(text).toContain("Usage limits (turned on in the config): 10 tiny messages two at a time, and one request for a very long text.");
    expect(text).toContain("Routes named in the config: signed-in `/api/me`, signed-in `/api/notes`, admin `/api/admin/users`, object `/api/notes/{id}`, assistant `/api/chat`.");
    expect(text).toContain("## 7. What is never done");
    expect(text).toMatch(/## 9\. Agreed\n\nThe owner of shop\.example\.com, or the client who asked for this test, agrees to the scope and rules above:\n\n- Name: _+\n- Role: _+\n- Date: _+\n- Signature: _+\n/);
  });

  it("is pure: the same input gives the same text, and no variable's value can reach it", () => {
    const secret = "sk-test-value-that-must-not-appear";
    const before = { ...process.env };
    for (const n of ["YOF_ATTACK_A_EMAIL", "YOF_ATTACK_A_PASSWORD", "YOF_ATTACK_A_TOTP", "YOF_ATTACK_A_WS", "YOF_ATTACK_B", "YOF_ATTACK_B_WS", "YOF_ATTACK_VIEWER"]) process.env[n] = secret;
    try {
      const a = doc(shop()), b = doc(shop());
      expect(a).toBe(b);
      expect(a).not.toContain(secret);
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in before)) delete process.env[k];
    }
  });

  it("says which groups are skipped and why: no accounts, one account, a light run, production off", () => {
    const none = doc(shop({ accounts: undefined, production: { enabled: false } }));
    expect(none).toContain("### Sign-in (`auth`): skipped\n\nSkipped because no test account to sign in with (add account A).");
    expect(none).toContain("### Roles (`rbac`): skipped\n\nSkipped because no member account to open admin routes with (add account A).");
    expect(none).toContain("### Tenant barrier (`tenant`): skipped\n\nSkipped because the tenant-barrier test needs two accounts in separate tenants (add accounts A and B).");
    expect(none).toContain("### Assistant (`ai`): skipped\n\nSkipped because no account to talk to the assistant as (add account A).");
    expect(none).toContain("### Public surface (`surface`): will run");
    expect(none).toContain("The sign-in rate limit is not tested (no account signs in with a password).");
    expect(none).toContain("- **Production: off.** The app's live host is not tested. A run aimed at it is refused.");
    for (const r of ["a", "b", "admin", "viewer"]) expect(none).toMatch(new RegExp(`\\| ${r} \\| [^|]+ \\| not set \\| none \\|`));

    const onlyA = doc(shop({ accounts: { a: { env: "YOF_ATTACK_A" } } }));
    expect(onlyA).toContain("(only account A is set; add account B)");
    expect(onlyA).toContain("### Sign-in (`auth`): will run");

    const light = doc(shop(), "light");
    expect(light).toContain("- **Mode: light.** Read-only checks");
    expect(light).toContain("### Tenant barrier (`tenant`): skipped\n\nSkipped because a light run is read-only: it creates no test record and sends no message to the assistant.");
    expect(light).toContain("The sign-in rate limit is not tested (a light run is read-only).");

    const noWindow = doc(shop({ production: { enabled: true } }));
    expect(noWindow).toContain("- **Production: on, with no window.** A light run may go at any time. A full run on production is refused until a window is set.");
    const bare = doc(parseAttackConfig(JSON.stringify({ app: "shop.example.com", consent: consentText("shop.example.com") })));
    expect(bare).toContain("The config names no routes, so only the public surface is tested.");
    expect(bare).toContain("Skipped because the config names no admin routes without {id}.");
  });

  it("keeps the honest wording: what it is, what it does not replace, and no claim about the app", () => {
    for (const text of [doc(shop()), doc(shop({ accounts: undefined }), "light")]) {
      expect(text).toContain("automated attack testing, evidence for your security reviews");
      expect(text).toContain("It does not replace a manual test where a standard requires one.");
      expect(text).not.toMatch(/\bcertifi|\bsecure\b|\bcompliant\b|\bguarantee|\bpenetration test\b|\bsafe\b/i);
      expect(text).not.toMatch(/\u2014|\u2013/);
      expect(text).not.toMatch(/\bCRM\b/);
    }
  });
});

describe("the plan in the document is the plan the runner follows", () => {
  let app: FakeApp;
  beforeAll(async () => { app = await startFakeApp(false); });
  afterAll(async () => { await app.close(); });
  const noSleep = async () => {};
  const cases: [string, Record<string, unknown>, Mode][] = [
    ["every account, full", {}, "full"],
    ["every account, light", {}, "light"],
    ["no accounts", { accounts: undefined }, "full"],
    ["account A only", { accounts: { a: { env: "YOF_ATTACK_A" } } }, "full"],
    ["admin only", { accounts: { admin: { env: "YOF_ATTACK_ADMIN" } } }, "full"],
    ["no objects, no assistant, no admin routes", { objects: [], ai: [], admin: [] }, "full"],
    ["only routes with {id}", { routes: ["/api/notes/{id}"], admin: [] }, "full"],
  ];
  it.each(cases)("%s", async (_name, extra, mode) => {
    const cfg = parseAttackConfig(fakeConfig(extra));
    const proof = await proveTarget(app.url, cfg, mode, { env: {} });
    if (!proof.ok) throw new Error(proof.message);
    const res = await runAttack({ cfg, proof, mode, env: fakeEnv(), sleep: noSleep });
    for (const p of attackPlan(cfg, mode)) {
      expect(res.groups[p.group], `${p.group}: ${p.why}`).toBe(p.runs ? "done" : "skipped");
      expect(p.runs ? p.does.length > 0 && p.why === "" : p.why.length > 0, p.group).toBe(true);
    }
    expect(app.notes.size).toBe(0);
  }, 60_000);
});

describe("yof attack --scope-doc", () => {
  it("prints the document for the config and sends nothing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "yof-scope-doc-"));
    mkdirSync(join(dir, ".yof"));
    writeFileSync(join(dir, ".yof/attack.json"), JSON.stringify({ app: "shop.example.com", consent: consentText("shop.example.com"), accounts: { a: { env: "YOF_ATTACK_A" } }, routes: ["/api/me"] }));
    const out: string[] = [], err: string[] = [], urls: string[] = [];
    const http = async (u: string) => { urls.push(u); return new Response("", { status: 500 }); };
    const io = { cwd: dir, out: (s: string) => out.push(s), err: (s: string) => err.push(s), env: { YOF_ATTACK_A: "Bearer real-token-value" }, http: http as never, now: new Date("2026-11-11T09:00:00Z") };
    expect(await main(["attack", "https://shop.example.com", "--mode", "light", "--scope-doc"], io)).toBe(0);
    expect(urls).toEqual([]);
    expect(err).toEqual([]);
    expect(out).toHaveLength(1);
    expect(out[0]).toContain("# Scope and rules of engagement: yof attack on shop.example.com");
    expect(out[0]).toContain("Prepared on 2026-11-11 with yof attack");
    expect(out[0]).toContain("- **Mode: light.**");
    expect(out[0]).toContain("`YOF_ATTACK_A`");
    expect(out[0]).not.toContain("real-token-value");
    // no address needed, and a custom config path is named
    writeFileSync(join(dir, "other.json"), JSON.stringify({ app: "shop.example.com", consent: consentText("shop.example.com") }));
    out.length = 0;
    expect(await main(["attack", "--scope-doc", "--config", "other.json"], io)).toBe(0);
    expect(out[0]).toContain("from `other.json`");
    expect(urls).toEqual([]);
  });
  it("a missing or refused config is a setup error (exit 2), with the reason", async () => {
    const dir = mkdtempSync(join(tmpdir(), "yof-scope-doc-"));
    const out: string[] = [], err: string[] = [];
    const io = { cwd: dir, out: (s: string) => out.push(s), err: (s: string) => err.push(s) };
    expect(await main(["attack", "--scope-doc"], io)).toBe(2);
    expect(err[0]).toContain("No attack config at .yof/attack.json");
    mkdirSync(join(dir, ".yof"));
    writeFileSync(join(dir, ".yof/attack.json"), JSON.stringify({ app: "shop.example.com", consent: consentText("shop.example.com"), accounts: { a: { env: "GITHUB_TOKEN" } } }));
    err.length = 0;
    expect(await main(["attack", "--scope-doc"], io)).toBe(2);
    expect(err[0]).toContain("accounts.a.env must name an environment variable that starts with YOF_ATTACK_");
    expect(out).toEqual([]);
  });
});
