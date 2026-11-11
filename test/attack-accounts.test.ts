/**
 * Y23: an attack account may carry SEVERAL headers (a session cookie and a workspace header), and there is a "viewer"
 * role. The config names environment variables, never values; header values never reach a report or the exchanges.
 */
import { describe, expect, it } from "vitest";
import { consentText } from "../src/attack/catalog";
import { ConfigError, isLoginAccount, parseAttackConfig, type AttackConfig } from "../src/attack/config";
import { runAttack } from "../src/attack/runner";
import type { FetchFn } from "../src/attack/http";
import type { ProofOk } from "../src/attack/proof";

const base = (accounts: Record<string, unknown>) => ({
  app: "shop.example.com",
  consent: consentText("shop.example.com"),
  accounts,
  routes: ["/api/me"],
  budget: { requests: 50, seconds: 110, perSecond: 100 },
});
const cfg = (accounts: Record<string, unknown>) => parseAttackConfig(JSON.stringify(base(accounts)));

describe("Y23 account headers", () => {
  it("keeps a single header, normalised to a one-item list", () => {
    const c = cfg({ a: { env: "YOF_ATTACK_A" }, b: { header: "Cookie", env: "YOF_ATTACK_B" } });
    expect(isLoginAccount(c.accounts.a!)).toBe(false);
    expect((c.accounts.a as { headers: unknown }).headers).toEqual([{ header: "Authorization", env: "YOF_ATTACK_A" }]);
    expect((c.accounts.b as { headers: unknown }).headers).toEqual([{ header: "Cookie", env: "YOF_ATTACK_B" }]);
  });

  it("reads several headers for one role (session cookie plus a workspace header)", () => {
    const c = cfg({
      a: { headers: [{ header: "Cookie", env: "YOF_ATTACK_A_SESSION" }, { header: "X-Workspace-Id", env: "YOF_ATTACK_A_WS" }] },
      b: { env: "YOF_ATTACK_B" },
    });
    expect((c.accounts.a as { headers: unknown }).headers).toEqual([
      { header: "Cookie", env: "YOF_ATTACK_A_SESSION" },
      { header: "X-Workspace-Id", env: "YOF_ATTACK_A_WS" },
    ]);
  });

  it("lets a login account add static headers next to its session", () => {
    const c = cfg({
      a: { login: { path: "/login", body: '{"email":"{{email}}","password":"{{password}}"}' }, emailEnv: "YOF_ATTACK_A_EMAIL", passwordEnv: "YOF_ATTACK_A_PW", headers: [{ header: "X-Workspace-Id", env: "YOF_ATTACK_A_WS" }] },
      b: { env: "YOF_ATTACK_B" },
    });
    const a = c.accounts.a!;
    expect(isLoginAccount(a)).toBe(true);
    expect((a as { headers: unknown }).headers).toEqual([{ header: "X-Workspace-Id", env: "YOF_ATTACK_A_WS" }]);
  });

  it("accepts the optional viewer role", () => {
    const c = cfg({ a: { env: "YOF_ATTACK_A" }, b: { env: "YOF_ATTACK_B" }, viewer: { env: "YOF_ATTACK_VIEWER" } });
    expect(c.accounts.viewer && (c.accounts.viewer as { headers: { env: string }[] }).headers[0]!.env).toBe("YOF_ATTACK_VIEWER");
  });

  it("refuses both a single header and a headers list", () => {
    expect(() => cfg({ a: { header: "Cookie", env: "YOF_ATTACK_A", headers: [{ header: "X", env: "YOF_ATTACK_X" }] }, b: { env: "YOF_ATTACK_B" } })).toThrow(ConfigError);
  });
  it("refuses two headers with the same name", () => {
    expect(() => cfg({ a: { headers: [{ header: "Cookie", env: "YOF_ATTACK_A" }, { header: "cookie", env: "YOF_ATTACK_B" }] }, b: { env: "YOF_ATTACK_B" } })).toThrow(ConfigError);
  });
  it("refuses a forbidden header and an empty headers list", () => {
    expect(() => cfg({ a: { header: "Host", env: "YOF_ATTACK_A" }, b: { env: "YOF_ATTACK_B" } })).toThrow(ConfigError);
    expect(() => cfg({ a: { headers: [] }, b: { env: "YOF_ATTACK_B" } })).toThrow(ConfigError);
  });
  it("refuses a header account with no header at all", () => {
    expect(() => cfg({ a: {}, b: { env: "YOF_ATTACK_B" } })).toThrow(ConfigError);
  });
});

describe("audit 3.9: an account may only name YOF_ATTACK_* environment variables", () => {
  const login = (extra: Record<string, unknown> = {}, l: Record<string, unknown> = {}) => ({
    login: { path: "/login", body: '{"email":"{{email}}","password":"{{password}}","code":"{{totp}}"}', totpEnv: "YOF_ATTACK_A_TOTP", ...l },
    emailEnv: "YOF_ATTACK_A_EMAIL", passwordEnv: "YOF_ATTACK_A_PASSWORD", ...extra,
  });
  it("accepts YOF_ATTACK_* names in every field", () => {
    expect(() => cfg({ a: login({ headers: [{ header: "X-Workspace-Id", env: "YOF_ATTACK_A_WS" }] }), b: { env: "YOF_ATTACK_B" } })).not.toThrow();
  });
  it.each([
    ["accounts.a.env", { a: { env: "GITHUB_TOKEN" } }],
    ["accounts.b.headers[1].env", { b: { headers: [{ header: "Cookie", env: "YOF_ATTACK_B" }, { header: "X-Extra", env: "NPM_TOKEN" }] } }],
    ["accounts.a.emailEnv", { a: login({ emailEnv: "AWS_ACCESS_KEY_ID" }) }],
    ["accounts.a.passwordEnv", { a: login({ passwordEnv: "AWS_SECRET_ACCESS_KEY" }) }],
    ["accounts.a.login.totpEnv", { a: login({}, { totpEnv: "SLACK_BOT_TOKEN" }) }],
    ["accounts.a.headers[0].env", { a: login({ headers: [{ header: "X-Workspace-Id", env: "YOF_HOOK_URL" }] }) }],
    ["accounts.viewer.env", { viewer: { env: "YOF_VERIFY_TOKEN" } }],
    ["accounts.admin.env", { admin: { env: "yof_attack_admin" } }],
    ["accounts.admin.env", { admin: { env: "YOF_ATTACK_" } }],
    ["accounts.admin.env", { admin: { env: "XYOF_ATTACK_ADMIN" } }],
  ])("refuses another variable and names the field: %s", (field, accounts) => {
    let message = "";
    try { cfg(accounts); } catch (e) { expect(e).toBeInstanceOf(ConfigError); message = (e as Error).message; }
    expect(message).toContain(`${field} must name an environment variable that starts with YOF_ATTACK_`);
  });
  it("the runner reads no other variable, even from a config built in code", async () => {
    const sent: Record<string, string>[] = [];
    const fetchFn: FetchFn = async (_u, init) => { sent.push({ ...(init.headers as Record<string, string>) }); return new Response("{}", { status: 200 }); };
    const config = { ...cfg({}), accounts: { a: { headers: [{ header: "Authorization", env: "GITHUB_TOKEN" }] } } } as AttackConfig;
    const proof: ProofOk = { ok: true, kind: "preview", method: "github-deployment", origin: "https://shop.example.com", host: "shop.example.com" };
    const res = await runAttack({ cfg: config, proof, mode: "light", env: { GITHUB_TOKEN: "ghs_ciSecretValue0123456789" }, fetch: fetchFn, groups: ["auth"] });
    expect(JSON.stringify(sent)).not.toContain("ghs_ciSecretValue0123456789");
    expect(JSON.stringify(res)).not.toContain("ghs_ciSecretValue0123456789");
  });
});

describe("Y23 runner sends every header, never the value in evidence", () => {
  const SECRET_COOKIE = "session=supersecretvalue123";
  const SECRET_WS = "ws_abcdef123456";

  async function run(config: AttackConfig, env: Record<string, string>) {
    const sent: Record<string, string>[] = [];
    const fetchFn: FetchFn = async (_url, init) => {
      sent.push({ ...(init.headers as Record<string, string>) });
      return new Response(JSON.stringify({ id: "user-a", email: "a@example.com" }), { status: 200, headers: { "Content-Type": "application/json" } });
    };
    const proof: ProofOk = { ok: true, kind: "preview", method: "github-deployment", origin: "https://shop.example.com", host: "shop.example.com" };
    const res = await runAttack({ cfg: config, proof, mode: "light", env, fetch: fetchFn, groups: ["auth"] });
    return { res, sent };
  }

  it("sends both the cookie and the workspace header as account A", async () => {
    const config = cfg({
      a: { headers: [{ header: "Cookie", env: "YOF_ATTACK_A_SESSION" }, { header: "X-Workspace-Id", env: "YOF_ATTACK_A_WS" }] },
      b: { env: "YOF_ATTACK_B" },
    });
    const { res, sent } = await run(config, { YOF_ATTACK_A_SESSION: SECRET_COOKIE, YOF_ATTACK_A_WS: SECRET_WS, YOF_ATTACK_B: "Bearer tok-b" });
    const asA = sent.find((h) => h.Cookie === SECRET_COOKIE);
    expect(asA).toBeTruthy();
    expect(asA!["X-Workspace-Id"]).toBe(SECRET_WS);
    // No finding carries a raw secret value in its masked evidence.
    const text = JSON.stringify(res.findings);
    expect(text).not.toContain("supersecretvalue");
    expect(text).not.toContain(SECRET_WS);
  });
});
