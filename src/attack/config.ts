/**
 * yof attack: the config file (.yof/attack.json), checked strictly. Anything unknown or out of range is an error, never
 * a guess. The file holds no secret: accounts name ENVIRONMENT VARIABLES (CI secrets), never a token or password.
 *
 * {
 *   "app": "shop.example.com",
 *   "consent": "I own shop.example.com and allow yof attack to test it and its preview builds with my own test accounts.",
 *   "accounts": {
 *     "a": { "header": "Authorization", "env": "YOF_ATTACK_A" },
 *     "b": { "login": { "path": "/api/login", "body": "{\"email\":\"{{email}}\",\"password\":\"{{password}}\"}", "tokenPath": "token" },
 *            "emailEnv": "YOF_ATTACK_B_EMAIL", "passwordEnv": "YOF_ATTACK_B_PASSWORD" },
 *     "admin": { "env": "YOF_ATTACK_ADMIN" }
 *   },
 *   "routes": ["/api/me", "/api/notes"],
 *   "admin": ["/api/admin/users"],
 *   "objects": [{ "create": { "path": "/api/notes", "body": "{\"title\":\"{{marker}}\"}" }, "idPath": "id",
 *                 "read": "/api/notes/{id}", "update": { "method": "PATCH", "path": "/api/notes/{id}", "body": "{\"title\":\"{{marker}}\"}" },
 *                 "delete": "/api/notes/{id}" }],
 *   "ai": [{ "path": "/api/chat", "body": "{\"message\":\"{{message}}\"}", "replyPath": "reply", "limits": false }],
 *   "surface": { "redirectPaths": ["/login"], "rateLimit": true },
 *   "production": { "enabled": false, "window": "02:00-04:00" },
 *   "budget": { "requests": 300, "seconds": 110, "perSecond": 8 }
 * }
 *
 * ai[i].limits (opt-in, default false): also measure the assistant's usage limits, like surface.rateLimit does for
 * the sign-in. A burst of 10 tiny messages ("Reply with the single word OK."), two at a time, and one request for a
 * very long story. It costs the owner a little model use, so it never runs unless this is true.
 */
import { consentText } from "./catalog";

export type Role = "a" | "b" | "admin";
export type HeaderAccount = { header: string; env: string };
export type LoginAccount = {
  login: { path: string; body: string; tokenPath?: string; header?: string; prefix?: string };
  emailEnv: string; passwordEnv: string;
};
export type AccountSpec = HeaderAccount | LoginAccount;

export interface ObjectSpec {
  create: { path: string; body: string };
  idPath: string;
  read: string;
  update?: { method: "PATCH" | "PUT"; path: string; body: string };
  delete: string;
  /** A list route that should never show another account's records. */
  list?: string;
}
export interface AiSpec {
  path: string;
  /** JSON body with {{message}} (and optionally {{id}} for a record the message is about). */
  body: string;
  replyPath: string;
  account?: Role;
  /** Indirect injection: the assistant reads a record the runner creates with a hidden instruction in it. */
  ingest?: { create: { path: string; body: string }; idPath: string; delete: string };
  /** Opt-in: a small burst and one very long answer, to see whether the assistant limits use (attack.ai_no_limit). */
  limits?: boolean;
}
export interface Budget { requests: number; seconds: number; perSecond: number }
export interface AttackConfig {
  app: string;
  consent: string;
  accounts: { a: AccountSpec; b: AccountSpec; admin?: AccountSpec };
  routes: string[];
  admin: string[];
  objects: ObjectSpec[];
  ai: AiSpec[];
  surface: { redirectPaths: string[]; rateLimit: boolean };
  production: { enabled: boolean; window: string | null };
  budget: Budget;
}

export const DEFAULT_BUDGET: Budget = { requests: 300, seconds: 110, perSecond: 8 };
/** Hard ceilings no config can lift. */
export const MAX_BUDGET: Budget = { requests: 2000, seconds: 900, perSecond: 20 };

export class ConfigError extends Error {}

const PATH = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/{}-]{0,300}$/;
const ENV = /^[A-Z][A-Z0-9_]{1,63}$/;
const HEADER = /^[A-Za-z][A-Za-z0-9-]{0,39}$/;
const FORBIDDEN_HEADERS = new Set(["host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer"]);
const JSON_PATH = /^[A-Za-z0-9_$-]{1,40}(?:\.[A-Za-z0-9_$-]{1,40}){0,7}$/;
const HOST = /^[a-z0-9.-]{1,253}(?::\d{1,5})?$/;
const WINDOW = /^([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d)$/;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
function str(v: unknown, what: string, re?: RegExp): string {
  if (typeof v !== "string" || !v.trim()) throw new ConfigError(`${what} must be a text value.`);
  const s = v.trim();
  if (re && !re.test(s)) throw new ConfigError(`${what} has an unexpected shape: ${JSON.stringify(s.slice(0, 60))}`);
  return s;
}
const path = (v: unknown, what: string) => {
  const p = str(v, what, PATH);
  if (p.split("/").includes("..")) throw new ConfigError(`${what} may not contain "..".`);
  return p;
};
function bodyTemplate(v: unknown, what: string, needs: string[]): string {
  const t = str(v, what);
  if (t.length > 4000) throw new ConfigError(`${what} is too long.`);
  for (const n of needs) if (!t.includes(`{{${n}}}`)) throw new ConfigError(`${what} needs {{${n}}}.`);
  try { JSON.parse(fill(t, { message: "a \"b\"\nc", marker: "m", email: "e", password: "p", id: "1", document: "d" })); }
  catch { throw new ConfigError(`${what} must be JSON once the {{...}} values are filled in.`); }
  return t;
}
/** {{name}} replaced by the value as JSON string content (quotes and newlines stay valid JSON). */
export function fill(template: string, values: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (m, k: string) => (k in values ? JSON.stringify(values[k]).slice(1, -1) : m));
}
const list = (v: unknown, what: string, max = 50): unknown[] => {
  if (v === undefined) return [];
  if (!Array.isArray(v)) throw new ConfigError(`${what} must be a list.`);
  if (v.length > max) throw new ConfigError(`${what} may hold at most ${max} entries.`);
  return v;
};

function account(v: unknown, what: string): AccountSpec {
  if (!isObj(v)) throw new ConfigError(`${what} must be an object.`);
  if (isObj(v.login)) {
    const l = v.login;
    const header = l.header === undefined ? "Authorization" : str(l.header, `${what}.login.header`, HEADER);
    return {
      login: {
        path: path(l.path, `${what}.login.path`), body: bodyTemplate(l.body, `${what}.login.body`, ["email", "password"]),
        ...(l.tokenPath === undefined ? {} : { tokenPath: str(l.tokenPath, `${what}.login.tokenPath`, JSON_PATH) }),
        header, prefix: l.prefix === undefined ? "Bearer " : String(l.prefix).slice(0, 20),
      },
      emailEnv: str(v.emailEnv, `${what}.emailEnv`, ENV), passwordEnv: str(v.passwordEnv, `${what}.passwordEnv`, ENV),
    };
  }
  const header = v.header === undefined ? "Authorization" : str(v.header, `${what}.header`, HEADER);
  if (FORBIDDEN_HEADERS.has(header.toLowerCase())) throw new ConfigError(`${what}.header may not be ${header}.`);
  return { header, env: str(v.env, `${what}.env`, ENV) };
}

function num(v: unknown, def: number, max: number, what: string): number {
  if (v === undefined) return def;
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) throw new ConfigError(`${what} must be a positive number.`);
  return Math.min(v, max);
}

export function parseAttackConfig(text: string): AttackConfig {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { throw new ConfigError("The attack config is not valid JSON."); }
  if (!isObj(raw)) throw new ConfigError("The attack config must be a JSON object.");
  const known = new Set(["app", "consent", "accounts", "routes", "admin", "objects", "ai", "surface", "production", "budget", "$schema"]);
  for (const k of Object.keys(raw)) if (!known.has(k)) throw new ConfigError(`Unknown setting "${k}".`);

  const app = str(raw.app, "app", HOST).toLowerCase();
  const consent = str(raw.consent, "consent");
  if (consent !== consentText(app)) throw new ConfigError(`consent must read exactly: ${consentText(app)}`);

  if (!isObj(raw.accounts)) throw new ConfigError("accounts needs a (account A) and b (account B).");
  const accounts = {
    a: account(raw.accounts.a, "accounts.a"),
    b: account(raw.accounts.b, "accounts.b"),
    ...(raw.accounts.admin === undefined ? {} : { admin: account(raw.accounts.admin, "accounts.admin") }),
  };

  const objects = list(raw.objects, "objects", 10).map((o, i): ObjectSpec => {
    const w = `objects[${i}]`;
    if (!isObj(o) || !isObj(o.create)) throw new ConfigError(`${w} needs create, idPath, read and delete.`);
    const read = path(o.read, `${w}.read`);
    const del = path(o.delete, `${w}.delete`);
    if (!read.includes("{id}") || !del.includes("{id}")) throw new ConfigError(`${w}.read and ${w}.delete need {id}.`);
    let update: ObjectSpec["update"];
    if (o.update !== undefined) {
      if (!isObj(o.update)) throw new ConfigError(`${w}.update must be an object.`);
      const method = str(o.update.method ?? "PATCH", `${w}.update.method`).toUpperCase();
      if (method !== "PATCH" && method !== "PUT") throw new ConfigError(`${w}.update.method must be PATCH or PUT.`);
      const up = path(o.update.path, `${w}.update.path`);
      if (!up.includes("{id}")) throw new ConfigError(`${w}.update.path needs {id}.`);
      update = { method, path: up, body: bodyTemplate(o.update.body, `${w}.update.body`, ["marker"]) };
    }
    return {
      create: { path: path(o.create.path, `${w}.create.path`), body: bodyTemplate(o.create.body, `${w}.create.body`, ["marker"]) },
      idPath: str(o.idPath, `${w}.idPath`, JSON_PATH), read, delete: del, ...(update ? { update } : {}),
      ...(o.list === undefined ? {} : { list: path(o.list, `${w}.list`) }),
    };
  });

  const ai = list(raw.ai, "ai", 5).map((a, i): AiSpec => {
    const w = `ai[${i}]`;
    if (!isObj(a)) throw new ConfigError(`${w} must be an object.`);
    const role = a.account === undefined ? undefined : str(a.account, `${w}.account`);
    if (role !== undefined && role !== "a" && role !== "b" && role !== "admin") throw new ConfigError(`${w}.account must be a, b or admin.`);
    let ingest: AiSpec["ingest"];
    if (a.ingest !== undefined) {
      if (!isObj(a.ingest) || !isObj(a.ingest.create)) throw new ConfigError(`${w}.ingest needs create, idPath and delete.`);
      const del = path(a.ingest.delete, `${w}.ingest.delete`);
      if (!del.includes("{id}")) throw new ConfigError(`${w}.ingest.delete needs {id}.`);
      ingest = { create: { path: path(a.ingest.create.path, `${w}.ingest.create.path`), body: bodyTemplate(a.ingest.create.body, `${w}.ingest.create.body`, ["document"]) }, idPath: str(a.ingest.idPath, `${w}.ingest.idPath`, JSON_PATH), delete: del };
    }
    if (a.limits !== undefined && typeof a.limits !== "boolean") throw new ConfigError(`${w}.limits must be true or false.`);
    return { path: path(a.path, `${w}.path`), body: bodyTemplate(a.body, `${w}.body`, ["message"]), replyPath: str(a.replyPath, `${w}.replyPath`, JSON_PATH), ...(role ? { account: role as Role } : {}), ...(ingest ? { ingest } : {}), ...(a.limits === true ? { limits: true } : {}) };
  });

  const s = isObj(raw.surface) ? raw.surface : {};
  const p = isObj(raw.production) ? raw.production : {};
  const window = p.window === undefined || p.window === null ? null : str(p.window, "production.window", WINDOW);
  const b = isObj(raw.budget) ? raw.budget : {};

  return {
    app, consent, accounts,
    routes: list(raw.routes, "routes").map((r, i) => path(r, `routes[${i}]`)),
    admin: list(raw.admin, "admin").map((r, i) => path(r, `admin[${i}]`)),
    objects, ai,
    surface: { redirectPaths: list(s.redirectPaths, "surface.redirectPaths", 10).map((r, i) => path(r, `surface.redirectPaths[${i}]`)), rateLimit: s.rateLimit === true },
    production: { enabled: p.enabled === true, window },
    budget: {
      requests: Math.floor(num(b.requests, DEFAULT_BUDGET.requests, MAX_BUDGET.requests, "budget.requests")),
      seconds: num(b.seconds, DEFAULT_BUDGET.seconds, MAX_BUDGET.seconds, "budget.seconds"),
      perSecond: num(b.perSecond, DEFAULT_BUDGET.perSecond, MAX_BUDGET.perSecond, "budget.perSecond"),
    },
  };
}

/** Is `now` (UTC) inside "HH:MM-HH:MM"? A window that wraps midnight ("23:00-01:00") works too. */
export function inWindow(window: string, now: Date): boolean {
  const m = WINDOW.exec(window);
  if (!m) return false;
  const start = Number(m[1]) * 60 + Number(m[2]);
  const end = Number(m[3]) * 60 + Number(m[4]);
  const t = now.getUTCHours() * 60 + now.getUTCMinutes();
  return start <= end ? t >= start && t < end : t >= start || t < end;
}
