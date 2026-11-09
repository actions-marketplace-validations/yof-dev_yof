/**
 * Benchmark set-up INSIDE THE GITHUB RUNNER: wait for the practice app on localhost, create the two test accounts
 * (A and B) through the app's own sign-up, and write the yof attack config. Every address is checked to be loopback
 * before anything is sent; this code refuses any other host.
 *
 * Passwords are made fresh per run (crypto random) and handed to later steps through $GITHUB_ENV, masked in the log.
 * Nothing here is stored or committed. The config names environment variables only, like any yof attack config.
 */
import { randomBytes } from "node:crypto";
import type { Target } from "./targets.ts";

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

export class SetupError extends Error {}

export function assertLoopback(origin: string): URL {
  let u: URL;
  try { u = new URL(origin); } catch { throw new SetupError(`Not an address: ${origin}`); }
  if (!LOOPBACK.has(u.hostname) || u.protocol !== "http:") throw new SetupError(`The benchmark only talks to http on localhost, not ${u.host}.`);
  return u;
}

/** The consent line yof requires, word for word (src/attack/catalog.ts consentText; a test keeps the two equal). */
export const consentFor = (app: string) => `I own ${app} and allow yof attack to test it and its preview builds with my own test accounts.`;

const BUDGET = { requests: 300, seconds: 110, perSecond: 8 };

/** Juice Shop: the routes its own pages call while signed in, and the two the administration page loads. */
export function juiceShopConfig(o: { basketId: string }) {
  const app = "localhost:3000";
  const login = (who: "A" | "B") => ({
    login: { path: "/rest/user/login", body: "{\"email\":\"{{email}}\",\"password\":\"{{password}}\"}", tokenPath: "authentication.token" },
    emailEnv: `YOF_BENCH_JS_${who}_EMAIL`, passwordEnv: `YOF_BENCH_JS_${who}_PASSWORD`,
  });
  return {
    app, consent: consentFor(app),
    accounts: { a: login("A"), b: login("B") },
    routes: ["/rest/user/whoami", "/api/Cards", "/api/Addresss", "/rest/order-history", "/rest/wallet/balance", "/rest/deluxe-membership", `/rest/basket/${o.basketId}`],
    admin: ["/api/Users", "/api/Feedbacks"],
    objects: [
      {
        create: { path: "/api/Addresss", body: "{\"fullName\":\"{{marker}}\",\"mobileNum\":5550100,\"zipCode\":\"10001\",\"streetAddress\":\"1 Test Street\",\"city\":\"Testville\",\"country\":\"Testland\"}" },
        idPath: "data.id", read: "/api/Addresss/{id}", list: "/api/Addresss",
        update: { method: "PUT", path: "/api/Addresss/{id}", body: "{\"fullName\":\"{{marker}}\"}" },
        delete: "/api/Addresss/{id}",
      },
      {
        create: { path: "/api/Cards", body: "{\"fullName\":\"{{marker}}\",\"cardNum\":4000000000000002,\"expMonth\":1,\"expYear\":2090}" },
        idPath: "data.id", read: "/api/Cards/{id}", list: "/api/Cards", delete: "/api/Cards/{id}",
      },
    ],
    ai: [],
    surface: { redirectPaths: ["/redirect"], rateLimit: true },
    production: { enabled: false },
    budget: BUDGET,
  };
}

/** NodeGoat: signs in with a redirect, so the benchmark signs in itself and hands yof the session cookies. */
export function nodeGoatConfig(o: { userIdA: string | null }) {
  const app = "localhost:4000";
  return {
    app, consent: consentFor(app),
    accounts: {
      a: { header: "Cookie", env: "YOF_BENCH_NG_A_COOKIE" },
      b: { header: "Cookie", env: "YOF_BENCH_NG_B_COOKIE" },
      admin: { header: "Cookie", env: "YOF_BENCH_NG_ADMIN_COOKIE" },
    },
    routes: ["/dashboard", "/profile", "/contributions", "/memos", "/research", ...(o.userIdA ? [`/allocations/${o.userIdA}`] : [])],
    admin: ["/benefits"],
    objects: [],
    ai: [],
    surface: { redirectPaths: ["/learn"], rateLimit: false },
    production: { enabled: false },
    budget: BUDGET,
  };
}

type Fetch = typeof fetch;
const password = () => `Yb1${randomBytes(9).toString("base64url").replace(/[^A-Za-z0-9]/g, "x")}`;
const cookieOf = (r: Response) => r.headers.getSetCookie().map((c) => c.split(";")[0]!).filter(Boolean).join("; ");

export async function waitFor(origin: string, path: string, f: Fetch = fetch, tries = 60, sleepMs = 2000): Promise<void> {
  const u = assertLoopback(origin);
  for (let i = 0; i < tries; i++) {
    try { const r = await f(new URL(path, u), { redirect: "manual" }); await r.arrayBuffer(); if (r.status > 0 && r.status < 500) return; } catch { /* not up yet */ }
    await new Promise((res) => setTimeout(res, sleepMs));
  }
  throw new SetupError(`${origin} did not answer within ${Math.round((tries * sleepMs) / 1000)} s.`);
}

export interface SetupOutput { config: Record<string, unknown>; env: Record<string, string>; secrets: string[]; notes: string[] }

export async function setupJuiceShop(t: Target, f: Fetch = fetch, expectVersion = t.tag?.replace(/^v/, "") ?? ""): Promise<SetupOutput> {
  const origin = assertLoopback(t.origin);
  const url = (p: string) => new URL(p, origin).toString();
  await waitFor(t.origin, "/rest/admin/application-version", f);
  const v = await (await f(url("/rest/admin/application-version"))).json() as { version?: string };
  if (expectVersion && v.version !== expectVersion) throw new SetupError(`The running Juice Shop is ${v.version ?? "unknown"}, not ${expectVersion}.`);
  const env: Record<string, string> = {};
  const secrets: string[] = [];
  let basketId = "";
  for (const who of ["A", "B"] as const) {
    const email = `yof-bench-${who.toLowerCase()}@example.com`;
    const pw = password();
    const reg = await f(url("/api/Users"), { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: pw, passwordRepeat: pw, securityQuestion: { id: 1 }, securityAnswer: "yof benchmark" }) });
    if (reg.status !== 201) throw new SetupError(`Juice Shop sign-up for account ${who} answered ${reg.status}.`);
    const login = await f(url("/rest/user/login"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password: pw }) });
    const body = await login.json() as { authentication?: { token?: string; bid?: number } };
    if (!login.ok || !body.authentication?.token) throw new SetupError(`Juice Shop sign-in for account ${who} answered ${login.status}.`);
    if (who === "A") basketId = String(body.authentication.bid ?? "");
    env[`YOF_BENCH_JS_${who}_EMAIL`] = email;
    env[`YOF_BENCH_JS_${who}_PASSWORD`] = pw;
    secrets.push(pw);
  }
  if (!/^\d+$/.test(basketId)) throw new SetupError("Juice Shop did not return account A's basket id.");
  return { config: juiceShopConfig({ basketId }), env, secrets, notes: [`Juice Shop ${v.version} is up; accounts A and B created.`] };
}

export async function setupNodeGoat(t: Target, f: Fetch = fetch): Promise<SetupOutput> {
  const origin = assertLoopback(t.origin);
  const url = (p: string) => new URL(p, origin).toString();
  const form = { "Content-Type": "application/x-www-form-urlencoded" };
  await waitFor(t.origin, "/login", f, 90);
  const env: Record<string, string> = {};
  const secrets: string[] = [];
  const notes: string[] = [];
  let userIdA: string | null = null;
  for (const who of ["A", "B"] as const) {
    const pw = password();
    const r = await f(url("/signup"), { method: "POST", headers: form, redirect: "manual",
      body: new URLSearchParams({ userName: `yofbench${who.toLowerCase()}`, firstName: "Yof", lastName: `Bench${who}`, password: pw, verify: pw, email: "" }).toString() });
    const cookie = cookieOf(r);
    await r.arrayBuffer();
    if (!cookie) throw new SetupError(`NodeGoat sign-up for account ${who} answered ${r.status} without a session.`);
    const dash = await f(url("/dashboard"), { headers: { Cookie: cookie }, redirect: "manual" });
    const html = await dash.text();
    if (dash.status !== 200) throw new SetupError(`NodeGoat's dashboard answered ${dash.status} for account ${who}.`);
    if (who === "A") userIdA = /\/allocations\/(\d+)/.exec(html)?.[1] ?? null;
    env[`YOF_BENCH_NG_${who}_COOKIE`] = cookie;
    secrets.push(cookie);
  }
  if (!userIdA) notes.push("NodeGoat's dashboard showed no allocations link for account A; that route is left out.");
  // NodeGoat's own documented demo admin (artifacts/db-reset.js), created by the app's seed inside the runner.
  const adm = await f(url("/login"), { method: "POST", headers: form, redirect: "manual", body: new URLSearchParams({ userName: "admin", password: "Admin_123" }).toString() });
  const admCookie = cookieOf(adm);
  await adm.arrayBuffer();
  if (admCookie && adm.status >= 300 && adm.status < 400) { env.YOF_BENCH_NG_ADMIN_COOKIE = admCookie; secrets.push(admCookie); }
  else notes.push(`NodeGoat's demo admin sign-in answered ${adm.status}; the admin comparison runs without it.`);
  return { config: nodeGoatConfig({ userIdA }), env, secrets, notes: [`NodeGoat is up; accounts A and B created.`, ...notes] };
}

/** Lines for $GITHUB_ENV (one NAME=value per line; values never hold a newline). */
export function envLines(env: Record<string, string>): string {
  return Object.entries(env).map(([k, v]) => {
    if (/[\r\n]/.test(v) || !/^[A-Z][A-Z0-9_]*$/.test(k)) throw new SetupError(`Unsafe environment value for ${k}.`);
    return `${k}=${v}\n`;
  }).join("");
}

/** Juice Shop's score board: the keys of the challenges marked solved. */
export async function solvedChallenges(t: Target, f: Fetch = fetch): Promise<string[]> {
  const r = await f(new URL("/api/Challenges", assertLoopback(t.origin)).toString());
  const body = await r.json() as { data?: { key?: string; solved?: boolean }[] };
  return (body.data ?? []).filter((c) => c.solved && c.key).map((c) => c.key!).sort();
}
