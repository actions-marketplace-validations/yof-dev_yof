/**
 * yof attack: the runner. It tests the person's OWN app, already proven by ./proof.ts, with the test accounts they
 * name in the config, and records each finding together with the exact steps that proved it.
 *
 *   auth     each signed-in route, without a sign-in (and with a broken token): the same data back = attack.auth_bypass
 *   rbac     each admin route as a normal member: the admin answer back = attack.rbac_escalation
 *   tenant   account A creates a test record; account B reads it by id (attack.tenant_read), lists it, and changes it
 *            (attack.tenant_write, seen when A reads the change). The record is deleted at the end, always.
 *   ai       the app's own assistant: hidden-instruction extraction, a typed injection, an injection hidden in a record
 *            the assistant reads, a record of another account fetched through its tools, admin data fetched through
 *            its tools by a member; and (Y11, OWASP LLM Top 10 2025) live markup or picture links in its answers, the
 *            same injection hidden in pasted text, a mild fixed jailbreak that asks only for a harmless word, internal
 *            details (only their kinds are kept), a claimed email to a .invalid address, account B's record steering
 *            account A's general answer (RAG poisoning), account B's record renamed through A's assistant, and, only
 *            with ai[i].limits, a 10-message burst and one very long answer
 *   surface  open redirects, missing security headers, sign-in with no rate limit, a sign-in cookie without its flags
 *
 * CONFIRMED only: every finding is reproduced a second time before it is reported. What did not reproduce is counted
 * in the notes, never reported as a finding.
 *
 * A light run (production at night) is read-only: auth, rbac and the read-only surface checks; nothing is created
 * and no message is sent to the assistant.
 */
import { randomBytes } from "node:crypto";
import { maskAll } from "../secrets";
import { ATTACK_GROUPS, ATTACK_RULE_BY_ID, type AttackGroup, type AttackSeverity } from "./catalog";
import { fill, type AccountSpec, type AiSpec, type AttackConfig, type Budget, type ObjectSpec, type Role } from "./config";
import { AttackClient, BudgetError, RefusedError, StoppedError, type As, type Exchange, type FetchFn, type HttpAnswer, type Method } from "./http";
import {
  BURST_MESSAGE, BURST_PARALLEL, BURST_SIZE, CARRIERS, LONG_OUTPUT_PROBE, UNBOUNDED_CHARS, aiProbes, aiProbesY11, burstLimited, carrierDocument,
  claimsOutwardAction, crossTenantQuestion, indirectQuestion, internalDetails, looksLikeInstructions, privilegeQuestion, ragQuestion, readPath,
  saysUnlockWord, unboundedOutput, unlockWord, unsafeMarkup, writeQuestion,
} from "./probes";
import type { Mode, ProofOk } from "./proof";
import type { ReplaySpec, ReplayStep } from "./replay";

export const REDIRECT_PROBE_HOST = "yof.io";
const REDIRECT_PROBE = "https://yof.io/yof-attack-redirect-check";
const REDIRECT_PARAMS = ["next", "redirect", "redirect_uri", "returnTo", "return_to", "url", "continue", "dest"];
const RATE_TRIES = 12;

export interface AttackFinding {
  ruleId: string;
  group: AttackGroup;
  severity: AttackSeverity;
  title: string;
  method: Method;
  /** The route as written in the config (with {id}), never a real id. */
  route: string;
  as: As;
  status: number;
  /** At most 200 characters, keys and email addresses masked. */
  evidence: string;
  meta: Record<string, string>;
  replay: ReplaySpec;
}

export type GroupStatus = "done" | "partial" | "skipped" | "not_run";
/** Why a run ended early: a budget ran out, or the person stopped it (a signal). */
export type StopReason = "requests" | "time" | "cancelled";
/** After a stop signal, clean-up gets at most this long before the run gives up and lists what is left. */
export const STOP_CLEANUP_MS = 10_000;
export interface AttackRunResult {
  findings: AttackFinding[];
  groups: Record<AttackGroup, GroupStatus>;
  notes: string[];
  stopped: null | StopReason;
  /** The test records this run created: how many it deleted, and the routes (with {id}) of any it could not. */
  cleanup: { deleted: number; left: string[] };
  exchanges: Exchange[];
  requests: number;
  unconfirmed: number;
}

export interface RunOptions {
  cfg: AttackConfig;
  proof: ProofOk;
  mode: Mode;
  /** Groups to run (a scoped pull-request run); default all. */
  groups?: readonly AttackGroup[];
  /** A scoped run attacks only routes this accepts. */
  routeFilter?: (path: string) => boolean;
  env?: Record<string, string | undefined>;
  fetch?: FetchFn;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => string;
  budget?: Budget;
  /** Aborted when the person stops the run: no new probe, then the clean-up (at most STOP_CLEANUP_MS). */
  signal?: AbortSignal;
}

const EMAIL_G = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;
const maskEmail = (e: string) => { const [u, d] = e.split("@"); return `${(u ?? "").slice(0, 1)}•••@${d ?? ""}`; };
/** Evidence as it may be shown or stored: keys and emails masked, whitespace folded, 200 characters at most. */
export const maskEvidence = (s: string) => maskAll(s.replace(EMAIL_G, maskEmail)).replace(/\s+/g, " ").trim().slice(0, 200);

const ok = (s: number) => s >= 200 && s < 300;
const DENIED = /\b(forbidden|unauthori[sz]ed|not allowed|access denied|permission denied|no permission|sign ?in|log ?in|login required)\b/i;
function leaves(text: string): string[] {
  let v: unknown;
  try { v = JSON.parse(text); } catch { return []; }
  const out: string[] = [];
  const walk = (x: unknown) => {
    if (out.length > 500) return;
    if (typeof x === "string" && x.length >= 6 && x.length <= 120) out.push(x);
    else if (typeof x === "number" && String(x).length >= 4) out.push(String(x));
    else if (x && typeof x === "object") for (const k of Object.keys(x)) walk((x as Record<string, unknown>)[k]);
  };
  walk(v);
  return out;
}
/** Does `other` carry the same data as `base` (the owner's answer)? Same body, or a shared distinctive value. */
export function sameData(base: string, other: string): boolean {
  if (!other.trim()) return false;
  if (base.trim() === other.trim()) return true;
  if (DENIED.test(other.slice(0, 2000)) && other.length < 2000) return false;
  const a = new Set(leaves(base));
  return leaves(other).some((x) => a.has(x));
}
/** The first distinctive value in `a` that does not appear in `b` ("" when none). */
export const distinct = (a: string, b: string) => leaves(a).filter((x) => !/^\d+$/.test(x)).find((x) => !b.includes(x)) ?? "";

const withId = (p: string, id: string) => p.split("{id}").join(encodeURIComponent(id));

class Auth {
  private cache = new Map<Role, Record<string, string> | null>();
  readonly cookieFlags = new Map<Role, string[]>();
  constructor(private cfg: AttackConfig, private env: Record<string, string | undefined>, private http: AttackClient) {}
  has(role: Role): boolean { return !!this.cfg.accounts[role as "a"]; }
  /** The headers already known for a role (clean-up never signs in again: a role that made a record has them). */
  cached(role: As): Record<string, string> | null { return role === "anon" ? {} : this.cache.get(role) ?? null; }
  async headers(role: As): Promise<Record<string, string> | null> {
    if (role === "anon") return {};
    if (this.cache.has(role)) return this.cache.get(role)!;
    const acc = this.cfg.accounts[role] as AccountSpec | undefined;
    let h: Record<string, string> | null = null;
    if (acc && "env" in acc) {
      const v = this.env[acc.env];
      h = v ? { [acc.header]: v } : null;
    } else if (acc) {
      const email = this.env[acc.emailEnv], pw = this.env[acc.passwordEnv];
      if (email && pw) {
        const r = await this.http.send(role, "POST", acc.login.path, { body: fill(acc.login.body, { email, password: pw }), purpose: "login" });
        if (ok(r.status)) {
          if (acc.login.tokenPath) { const t = readPath(r.body, acc.login.tokenPath); h = t ? { [acc.login.header ?? "Authorization"]: `${acc.login.prefix ?? ""}${t}` } : null; }
          else {
            const sc = setCookies(r.headers);
            this.cookieFlags.set(role, sc);
            const c = sc.map((x) => x.split(";")[0]).filter(Boolean).join("; ");
            h = c ? { Cookie: c } : null;
          }
        }
      }
    }
    this.cache.set(role, h);
    return h;
  }
}
const setCookies = (h: Headers): string[] => (typeof (h as Headers & { getSetCookie?: () => string[] }).getSetCookie === "function" ? h.getSetCookie() : [h.get("set-cookie") ?? ""]).filter(Boolean);

export async function runAttack(o: RunOptions): Promise<AttackRunResult> {
  const { cfg, mode } = o;
  const env = o.env ?? process.env;
  const random = o.random ?? (() => randomBytes(6).toString("hex"));
  const postPaths = [
    ...cfg.objects.map((x) => x.create.path), ...cfg.ai.map((a) => a.path), ...cfg.ai.flatMap((a) => (a.ingest ? [a.ingest.create.path] : [])),
    ...(["a", "b", "admin"] as const).flatMap((r) => { const acc = cfg.accounts[r as "a"]; return acc && "login" in acc ? [acc.login.path] : []; }),
  ];
  const http = new AttackClient({ origin: o.proof.origin, budget: o.budget ?? cfg.budget, fetch: o.fetch, now: o.now, sleep: o.sleep, postPaths, signal: o.signal });
  const auth = new Auth(cfg, env, http);
  const findings: AttackFinding[] = [];
  const notes: string[] = [];
  let unconfirmed = 0;
  const groups = Object.fromEntries(ATTACK_GROUPS.map((g) => [g, "not_run"])) as Record<AttackGroup, GroupStatus>;
  const wanted = new Set(o.groups ?? ATTACK_GROUPS);
  const routeOk = o.routeFilter ?? (() => true);
  const accounts = (...roles: Role[]) => Object.fromEntries(roles.map((r) => [r, cfg.accounts[r as "a"]]).filter(([, v]) => v)) as ReplaySpec["accounts"];
  const cleanupList: { as: Role; path: string }[] = [];
  const cleanup: AttackRunResult["cleanup"] = { deleted: 0, left: [] };

  const send = async (as: As, method: Method, path: string, init: { body?: string; purpose?: "read" | "login" | "create" | "ai" | "owned" | "cleanup"; headers?: Record<string, string> } = {}): Promise<HttpAnswer | null> => {
    const h = await auth.headers(as);
    if (h === null) return null;
    return http.send(as, method, path, { ...init, headers: { ...h, ...(init.headers ?? {}) } });
  };
  const report = (ruleId: string, x: { method: Method; route: string; as: As; status: number; evidence: string; meta?: Record<string, string>; replay: Omit<ReplaySpec, "ruleId" | "title"> }) => {
    const rule = ATTACK_RULE_BY_ID[ruleId]!;
    if (findings.some((f) => f.ruleId === ruleId && f.route === x.route && f.method === x.method)) return;
    findings.push({ ruleId, group: rule.group, severity: rule.severity, title: rule.title, method: x.method, route: x.route, as: x.as, status: x.status, evidence: maskEvidence(x.evidence), meta: x.meta ?? {}, replay: { ruleId, title: rule.title, ...x.replay } });
  };
  /** Run `probe` again; only a finding that shows twice is reported. */
  const confirm = async (probe: () => Promise<boolean>): Promise<boolean> => { const yes = await probe(); if (!yes) unconfirmed++; return yes; };

  /** Create a test-owned record as `role`; returns its id or null. */
  const create = async (role: Role, spec: { create: { path: string; body: string }; idPath: string; delete: string }, values: Record<string, string>): Promise<string | null> => {
    if (!http.roomToCreate) throw new BudgetError("requests");
    const r = await send(role, "POST", spec.create.path, { body: fill(spec.create.body, values), purpose: "create" });
    if (!r || !ok(r.status)) { notes.push(`create_failed:${spec.create.path}:${r?.status ?? "no_account"}`); return null; }
    const id = readPath(r.body, spec.idPath);
    if (!id || id.length > 200) { notes.push(`no_id:${spec.create.path}`); return null; }
    http.own(id);
    cleanupList.push({ as: role, path: withId(spec.delete, id) });
    return id;
  };

  // ── auth ──────────────────────────────────────────────────────────────────────────────────────
  const authGroup = async () => {
    const targets = [...cfg.routes.map((p) => ({ p, owner: "a" as Role })), ...cfg.admin.map((p) => ({ p, owner: (auth.has("admin") ? "admin" : "a") as Role }))]
      .filter((t) => !t.p.includes("{id}") && routeOk(t.p));
    if (!targets.length) return "skipped" as const;
    const header = (() => { const acc = cfg.accounts.a; return "env" in acc ? acc.header : acc.login.header ?? "Authorization"; })();
    const variants: { label: string; headers?: Record<string, string> }[] = [{ label: "no sign-in" }, ...(header.toLowerCase() === "authorization" ? [{ label: "a broken token", headers: { Authorization: "Bearer undefined" } }] : [])];
    for (const t of targets) {
      const base = await send(t.owner, "GET", t.p);
      if (!base) { notes.push(`no_account:${t.owner}`); continue; }
      if (!ok(base.status)) { notes.push(`baseline_${base.status}:${t.p}`); continue; }
      for (const v of variants) {
        const x = await send("anon", "GET", t.p, { headers: v.headers });
        if (!x || !ok(x.status) || !sameData(base.body, x.body)) continue;
        if (!(await confirm(async () => { const y = await send("anon", "GET", t.p, { headers: v.headers }); return !!y && ok(y.status) && sameData(base.body, y.body); }))) continue;
        report("attack.auth_bypass", { method: "GET", route: t.p, as: "anon", status: x.status, evidence: x.body, meta: { request: `GET ${t.p} with ${v.label}`, status: String(x.status) },
          replay: { vars: [], accounts: {}, steps: [{ as: "anon", method: "GET", path: t.p, ...(v.headers ? { headers: v.headers } : {}), expect: { kind: "denied" } }] } });
        break;
      }
    }
    return "done" as const;
  };

  // ── rbac ──────────────────────────────────────────────────────────────────────────────────────
  const rbacGroup = async () => {
    const routes = cfg.admin.filter((p) => !p.includes("{id}") && routeOk(p));
    if (!routes.length) return "skipped" as const;
    for (const p of routes) {
      if (findings.some((f) => f.ruleId === "attack.auth_bypass" && f.route === p)) continue;
      const admin = auth.has("admin") ? await send("admin", "GET", p) : null;
      const m = await send("a", "GET", p);
      if (!m) { notes.push("no_account:a"); break; }
      if (!ok(m.status) || (DENIED.test(m.body.slice(0, 2000)) && m.body.length < 2000)) continue;
      const looksAdmin = admin && ok(admin.status) ? sameData(admin.body, m.body) : leaves(m.body).length > 0;
      if (!looksAdmin) continue;
      if (!(await confirm(async () => { const y = await send("a", "GET", p); return !!y && ok(y.status) && (admin && ok(admin.status) ? sameData(admin.body, y.body) : leaves(y.body).length > 0); }))) continue;
      report("attack.rbac_escalation", { method: "GET", route: p, as: "a", status: m.status, evidence: m.body, meta: { request: `GET ${p} as a member`, status: String(m.status) },
        replay: { vars: [], accounts: accounts("a"), steps: [{ as: "a", method: "GET", path: p, expect: { kind: "denied" } }] } });
    }
    return "done" as const;
  };

  // ── tenant ────────────────────────────────────────────────────────────────────────────────────
  const tenantGroup = async () => {
    const objs = cfg.objects.filter((x) => routeOk(x.read) || routeOk(x.create.path));
    if (!objs.length) return "skipped" as const;
    for (const spec of objs) await tenantObject(spec);
    return "done" as const;
  };
  const tenantObject = async (spec: ObjectSpec) => {
    const marker = `yofmarker${random()}`;
    const id = await create("a", spec, { marker });
    if (!id) return;
    const read = withId(spec.read, id);
    const own = await send("a", "GET", read);
    if (!own || !ok(own.status) || !own.body.includes(marker)) { notes.push(`owner_cannot_read:${spec.read}`); return; }
    const setup: ReplayStep[] = [{ as: "a", method: "POST", path: spec.create.path, body: spec.create.body, save: { name: "id", from: spec.idPath }, setup: true }];
    const cleanup: ReplayStep = { as: "a", method: "DELETE", path: spec.delete.split("{id}").join("{{id}}"), cleanup: true };

    const other = await send("b", "GET", read);
    if (other === null) { notes.push("no_account:b"); return; }
    if (ok(other.status) && other.body.includes(marker) && await confirm(async () => { const y = await send("b", "GET", read); return !!y && ok(y.status) && y.body.includes(marker); })) {
      report("attack.tenant_read", { method: "GET", route: spec.read, as: "b", status: other.status, evidence: other.body.split(marker).join("[test record of account A]"), meta: { request: `GET ${spec.read} as account B, for a record of account A`, status: String(other.status) },
        replay: { vars: ["marker"], accounts: accounts("a", "b"), steps: [...setup, { as: "b", method: "GET", path: spec.read.split("{id}").join("{{id}}"), expect: { kind: "not_contains", value: "{{marker}}" } }, cleanup] } });
    }
    if (spec.list) {
      const l = await send("b", "GET", spec.list);
      if (l && ok(l.status) && l.body.includes(marker) && await confirm(async () => { const y = await send("b", "GET", spec.list!); return !!y && ok(y.status) && y.body.includes(marker); })) {
        report("attack.tenant_read", { method: "GET", route: spec.list, as: "b", status: l.status, evidence: l.body.split(marker).join("[test record of account A]"), meta: { request: `GET ${spec.list} as account B listed a record of account A`, status: String(l.status) },
          replay: { vars: ["marker"], accounts: accounts("a", "b"), steps: [...setup, { as: "b", method: "GET", path: spec.list, expect: { kind: "not_contains", value: "{{marker}}" } }, cleanup] } });
      }
    }
    if (spec.update) {
      const up = spec.update;
      const changedBy = async () => {
        const m2 = `yofchange${random()}`;
        await send("b", up.method, withId(up.path, id), { body: fill(up.body, { marker: m2 }), purpose: "owned" });
        const after = await send("a", "GET", read);
        return { hit: !!after && ok(after.status) && after.body.includes(m2), status: after?.status ?? 0 };
      };
      const first = await changedBy();
      if (first.hit && await confirm(async () => (await changedBy()).hit)) {
        report("attack.tenant_write", { method: up.method, route: up.path, as: "b", status: first.status, evidence: `account B changed a test record of account A with ${up.method} ${up.path}`, meta: { request: `${up.method} ${up.path} as account B, then GET ${spec.read} as account A`, status: String(first.status) },
          replay: { vars: ["marker", "change"], accounts: accounts("a", "b"), steps: [...setup,
            { as: "b", method: up.method, path: up.path.split("{id}").join("{{id}}"), body: up.body.split("{{marker}}").join("{{change}}") },
            { as: "a", method: "GET", path: spec.read.split("{id}").join("{{id}}"), expect: { kind: "not_contains", value: "{{change}}" } }, cleanup] } });
      }
    }
  };

  // ── ai ────────────────────────────────────────────────────────────────────────────────────────
  const aiGroup = async () => {
    const specs = cfg.ai.filter((a) => routeOk(a.path));
    if (!specs.length) return "skipped" as const;
    for (const a of specs) await aiTarget(a);
    return "done" as const;
  };
  const aiTarget = async (a: AiSpec) => {
    const role = a.account ?? "a";
    const ask = async (message: string, id = "") => {
      const r = await send(role, "POST", a.path, { body: fill(a.body, { message, id }), purpose: "ai" });
      return r && ok(r.status) ? readPath(r.body, a.replyPath) : null;
    };
    const aiStep = (message: string, expect: ReplayStep["expect"]): ReplayStep => ({ as: role, method: "POST", path: a.path, body: fill(a.body, { message }), replyPath: a.replyPath, expect });
    const canary = `YOF-CANARY-${random().toUpperCase()}`;
    const probes = aiProbes(canary);

    for (const p of probes.filter((x) => x.id.startsWith("leak_"))) {
      const reply = await ask(p.message);
      if (reply === null) { notes.push(`ai_unreachable:${a.path}`); return; }
      if (looksLikeInstructions(reply) && await confirm(async () => looksLikeInstructions((await ask(p.message)) ?? ""))) {
        report("attack.prompt_extraction", { method: "POST", route: a.path, as: role, status: 200, evidence: reply.slice(0, 160), meta: { probe: p.id },
          replay: { vars: [], accounts: accounts(role), steps: [aiStep(p.message, { kind: "not_instructions" })] } });
        break;
      }
    }
    const inject = probes.find((x) => x.id === "inject")!;
    const r = await ask(inject.message);
    if (r?.includes(canary) && await confirm(async () => ((await ask(inject.message)) ?? "").includes(canary))) {
      report("attack.prompt_injection", { method: "POST", route: a.path, as: role, status: 200, evidence: "answered with the hidden test word", meta: { probe: "inject" },
        replay: { vars: ["canary"], accounts: accounts(role), steps: [aiStep(inject.message.split(canary).join("{{canary}}"), { kind: "not_contains", value: "{{canary}}" })] } });
    }
    // ── Y11: unsafe output, injection in pasted content, jailbreak, internal details, excessive agency ──
    const y11 = aiProbesY11(canary);
    const y11Replay = aiProbesY11("{{canary}}");
    const y11Step = (id: string, expect: ReplayStep["expect"]) => aiStep(y11Replay.find((x) => x.id === id)!.message, expect);
    const unlock = unlockWord(canary);
    const once = async (ids: string[], hit: (reply: string) => boolean, found: (id: string, reply: string) => void) => {
      for (const id of ids) {
        const msg = y11.find((x) => x.id === id)!.message;
        const reply = await ask(msg);
        if (reply !== null && hit(reply) && await confirm(async () => hit((await ask(msg)) ?? ""))) { found(id, reply); return; }
      }
    };
    await once(["out_html", "out_image"], (r) => !!unsafeMarkup(r, canary), (id, reply) => {
      const kind = unsafeMarkup(reply, canary)!.kind;
      report("attack.unsafe_output", { method: "POST", route: a.path, as: role, status: 200, evidence: `the answer carried ${kind === "image_link" ? "a picture link with the test word" : "live HTML a page would run"}`, meta: { probe: id, kind },
        replay: { vars: ["canary"], accounts: accounts(role), steps: [y11Step(id, { kind: "no_unsafe_markup", value: "{{canary}}" })] } });
    });
    await once(["inject_comment", "inject_markdown"], (r) => r.includes(canary), (id) => {
      report("attack.indirect_injection", { method: "POST", route: a.path, as: role, status: 200, evidence: "a hidden instruction in pasted text changed the answer", meta: { probe: id, carrier: id === "inject_comment" ? "html_comment" : "markdown_title" },
        replay: { vars: ["canary"], accounts: accounts(role), steps: [y11Step(id, { kind: "not_contains", value: "{{canary}}" })] } });
    });
    await once(["jb_dev_mode", "jb_opposite"], (r) => saysUnlockWord(r, unlock), (id) => {
      report("attack.jailbreak", { method: "POST", route: a.path, as: role, status: 200, evidence: "said the test word it was to say only with its rules off", meta: { probe: id },
        replay: { vars: ["canary"], accounts: accounts(role), steps: [y11Step(id, { kind: "not_unlocked", value: unlockWord("{{canary}}") })] } });
    });
    await once(["int_debug", "int_tools"], (r) => internalDetails(r).length > 0, (id, reply) => {
      // The KINDS only: never an address, a path or a tool definition from the answer.
      const kinds = internalDetails(reply).join(", ");
      report("attack.data_disclosure", { method: "POST", route: a.path, as: role, status: 200, evidence: `the answer showed: ${kinds}`, meta: { probe: id, kinds },
        replay: { vars: [], accounts: accounts(role), steps: [y11Step(id, { kind: "no_internal" })] } });
    });
    await once(["agency_email"], claimsOutwardAction, (id) => {
      report("attack.excessive_agency", { method: "POST", route: a.path, as: role, status: 200, evidence: "said an email was sent, with no question first", meta: { probe: id },
        replay: { vars: [], accounts: accounts(role), steps: [y11Step(id, { kind: "no_claimed_action" })] } });
    });

    const other: Role = role === "b" ? "a" : "b";
    if (a.ingest) {
      const ing = a.ingest;
      // Same account: a record with a hidden instruction, in each carrier until one works (attack.indirect_injection).
      for (const carrier of CARRIERS) {
        if (findings.some((f) => f.ruleId === "attack.indirect_injection" && f.route === a.path)) break;
        const c2 = `YOF-CANARY-${random().toUpperCase()}`;
        const id = await create(role, ing, { document: carrierDocument(carrier, c2) });
        if (!id) break;
        const reply = await ask(indirectQuestion(id), id);
        if (reply?.includes(c2) && await confirm(async () => ((await ask(indirectQuestion(id), id)) ?? "").includes(c2))) {
          report("attack.indirect_injection", { method: "POST", route: a.path, as: role, status: 200, evidence: "a record with a hidden instruction changed the answer", meta: { record: ing.create.path, carrier },
            replay: { vars: ["canary"], accounts: accounts(role), steps: [
              { as: role, method: "POST", path: ing.create.path, body: fill(ing.create.body, { document: carrierDocument(carrier, "{{canary}}") }), save: { name: "id", from: ing.idPath }, setup: true },
              { as: role, method: "POST", path: a.path, body: fill(a.body, { message: indirectQuestion("{{id}}"), id: "{{id}}" }), replyPath: a.replyPath, expect: { kind: "not_contains", value: "{{canary}}" } },
              { as: role, method: "DELETE", path: ing.delete.split("{id}").join("{{id}}"), cleanup: true }] } });
        }
      }
      // Across accounts (attack.rag_poisoning): the OTHER account plants a record about a fresh topic; this account asks a
      // general question about the topic without the id. The test word back = other users' records steer the answers.
      if (auth.has(other)) {
        for (const carrier of CARRIERS) {
          const c3 = `YOF-CANARY-${random().toUpperCase()}`;
          const topic = `yoftopic${random()}`;
          const id = await create(other, ing, { document: carrierDocument(carrier, c3, topic) });
          if (!id) break;
          const reply = await ask(ragQuestion(topic));
          if (reply?.includes(c3) && await confirm(async () => ((await ask(ragQuestion(topic))) ?? "").includes(c3))) {
            report("attack.rag_poisoning", { method: "POST", route: a.path, as: role, status: 200, evidence: `a record of account ${other.toUpperCase()} with a hidden instruction steered a general answer`, meta: { record: ing.create.path, carrier, across: `account ${other.toUpperCase()} wrote, account ${role.toUpperCase()} asked` },
              replay: { vars: ["canary", "topic"], accounts: accounts(role, other), steps: [
                { as: other, method: "POST", path: ing.create.path, body: fill(ing.create.body, { document: carrierDocument(carrier, "{{canary}}", "{{topic}}") }), save: { name: "id", from: ing.idPath }, setup: true },
                aiStep(ragQuestion("{{topic}}"), { kind: "not_contains", value: "{{canary}}" }),
                { as: other, method: "DELETE", path: ing.delete.split("{id}").join("{{id}}"), cleanup: true }] } });
            break;
          }
        }
      }
    } else notes.push(`no_ingest:${a.path}`);

    const spec = cfg.objects[0];
    if (spec) {
      const marker = `yofmarker${random()}`;
      const id = await create(other, spec, { marker });
      if (id) {
        const reply = await ask(crossTenantQuestion(id), id);
        if (reply?.includes(marker) && await confirm(async () => ((await ask(crossTenantQuestion(id), id)) ?? "").includes(marker))) {
          report("attack.tool_cross_tenant", { method: "POST", route: a.path, as: role, status: 200, evidence: `the assistant returned a test record of account ${other.toUpperCase()}`, meta: { record: spec.read },
            replay: { vars: ["marker"], accounts: accounts(role, other), steps: [
              { as: other, method: "POST", path: spec.create.path, body: spec.create.body, save: { name: "id", from: spec.idPath }, setup: true },
              { as: role, method: "POST", path: a.path, body: fill(a.body, { message: crossTenantQuestion("{{id}}"), id: "{{id}}" }), replyPath: a.replyPath, expect: { kind: "not_contains", value: "{{marker}}" } },
              { as: other, method: "DELETE", path: spec.delete.split("{id}").join("{{id}}"), cleanup: true }] } });
        }
        // Writes through the tools (attack.tool_cross_tenant_write): ask to rename the other account's TEST record, then
        // the other account reads it. Only the run's own record is ever named; it is deleted at the end like the rest.
        const changedVia = async () => {
          const m2 = `yofchange${random()}`;
          await ask(writeQuestion(id, m2), id);
          const after = await send(other, "GET", withId(spec.read, id));
          return !!after && ok(after.status) && after.body.includes(m2);
        };
        if (await changedVia() && await confirm(changedVia)) {
          report("attack.tool_cross_tenant_write", { method: "POST", route: a.path, as: role, status: 200, evidence: `the assistant changed a test record of account ${other.toUpperCase()}`, meta: { record: spec.read },
            replay: { vars: ["marker", "change"], accounts: accounts(role, other), steps: [
              { as: other, method: "POST", path: spec.create.path, body: spec.create.body, save: { name: "id", from: spec.idPath }, setup: true },
              { as: role, method: "POST", path: a.path, body: fill(a.body, { message: writeQuestion("{{id}}", "{{change}}"), id: "{{id}}" }), replyPath: a.replyPath },
              { as: other, method: "GET", path: spec.read.split("{id}").join("{{id}}"), expect: { kind: "not_contains", value: "{{change}}" } },
              { as: other, method: "DELETE", path: spec.delete.split("{id}").join("{{id}}"), cleanup: true }] } });
        }
      }
    }
    if (auth.has("admin") && role !== "admin") {
      for (const p of cfg.admin.filter((x) => !x.includes("{id}")).slice(0, 2)) {
        const adm = await send("admin", "GET", p);
        const mem = await send(role, "GET", p);
        if (!adm || !mem || !ok(adm.status) || ok(mem.status)) continue;
        const secret = distinct(adm.body, mem.body);
        if (!secret) continue;
        const reply = await ask(privilegeQuestion(p));
        if (reply?.includes(secret) && await confirm(async () => ((await ask(privilegeQuestion(p))) ?? "").includes(secret))) {
          report("attack.tool_privilege", { method: "POST", route: a.path, as: role, status: 200, evidence: `the assistant returned data from ${p}, which this member is refused`, meta: { adminRoute: p },
            replay: { vars: [], accounts: accounts(role, "admin"), steps: [
              { as: "admin", method: "GET", path: p, keep: "adminBody", setup: true },
              { as: role, method: "GET", path: p, keep: "memberBody" },
              { derive: { name: "secret", from: ["adminBody", "memberBody"] } },
              aiStep(privilegeQuestion(p), { kind: "not_contains", value: "{{secret}}" })] } });
          break;
        }
      }
    }

    // ── Y11, opt-in only (ai[i].limits): does anything limit use of the assistant (attack.ai_no_limit)? ──
    // A burst of BURST_SIZE tiny messages, BURST_PARALLEL at a time, then one request for a very long story. Like the
    // sign-in rate test, the burst is itself the repetition (it is not sent twice); it counts against the budget.
    if (a.limits) {
      if (http.left < BURST_SIZE + 2) { notes.push(`ai_limits_budget:${a.path}`); return; }
      const statuses: number[] = [];
      for (let i = 0; i < BURST_SIZE; i += BURST_PARALLEL) {
        const wave = await Promise.all(Array.from({ length: Math.min(BURST_PARALLEL, BURST_SIZE - i) }, () =>
          send(role, "POST", a.path, { body: fill(a.body, { message: BURST_MESSAGE, id: "" }), purpose: "ai" })));
        for (const r of wave) statuses.push(r?.status ?? 0);
        if (burstLimited(statuses)) break;
      }
      if (statuses.length === BURST_SIZE && !burstLimited(statuses) && statuses.every(ok)) {
        report("attack.ai_no_limit", { method: "POST", route: a.path, as: role, status: statuses.at(-1)!, evidence: `${BURST_SIZE} quick messages in a row, none slowed down`, meta: { burst: `${BURST_SIZE} of ${BURST_SIZE} answered` },
          replay: { vars: [], accounts: accounts(role), steps: [{ ...aiStep(BURST_MESSAGE, { kind: "some_status", status: [429, 503] }), repeat: BURST_SIZE }] } });
      } else {
        const reply = await ask(LONG_OUTPUT_PROBE.message);
        if (reply !== null && unboundedOutput(reply)) {
          report("attack.ai_no_limit", { method: "POST", route: a.path, as: role, status: 200, evidence: `a request for a very long text got ${reply.length} characters back`, meta: { probe: LONG_OUTPUT_PROBE.id, chars: String(reply.length) },
            replay: { vars: [], accounts: accounts(role), steps: [aiStep(LONG_OUTPUT_PROBE.message, { kind: "short_answer", max: UNBOUNDED_CHARS })] } });
        }
      }
    }
  };

  // ── surface ───────────────────────────────────────────────────────────────────────────────────
  const surfaceGroup = async () => {
    const home = await send("anon", "GET", "/");
    if (home) {
      const missing: { rule: string; name: string }[] = [];
      const h = home.headers;
      if (o.proof.origin.startsWith("https:") && !h.get("strict-transport-security")) missing.push({ rule: "headers.hsts", name: "strict-transport-security" });
      if (!/nosniff/i.test(h.get("x-content-type-options") ?? "")) missing.push({ rule: "headers.nosniff", name: "x-content-type-options" });
      if (!h.get("x-frame-options") && !/frame-ancestors/i.test(h.get("content-security-policy") ?? "")) missing.push({ rule: "headers.frame", name: "x-frame-options" });
      if (!h.get("referrer-policy")) missing.push({ rule: "headers.referrer", name: "referrer-policy" });
      if (missing.length) {
        const again = await send("anon", "GET", "/");
        if (again && missing.every((m) => !again.headers.get(m.name) || (m.name === "x-content-type-options" && !/nosniff/i.test(again.headers.get(m.name) ?? "")))) {
          report("attack.missing_headers", { method: "GET", route: "/", as: "anon", status: home.status, evidence: `missing: ${missing.map((m) => m.name).join(", ")}`, meta: { headers: missing.map((m) => m.rule).join(",") },
            replay: { vars: [], accounts: {}, steps: missing.map((m) => ({ as: "anon" as const, method: "GET" as const, path: "/", expect: { kind: "header_present" as const, name: m.name } })) } });
        } else unconfirmed++;
      }
    }
    const paths = cfg.surface.redirectPaths.length ? cfg.surface.redirectPaths : ["/login"];
    outer: for (const p of paths) {
      for (const param of REDIRECT_PARAMS) {
        const q = `${p}${p.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(REDIRECT_PROBE)}`;
        const r = await send("anon", "GET", q);
        const to = (loc: string | null | undefined) => { try { return loc ? new URL(loc, o.proof.origin).hostname : ""; } catch { return ""; } };
        if (r && r.status >= 300 && r.status < 400 && to(r.location) === REDIRECT_PROBE_HOST) {
          const y = await send("anon", "GET", q);
          if (!(y && to(y.location) === REDIRECT_PROBE_HOST)) { unconfirmed++; continue; }
          report("attack.open_redirect", { method: "GET", route: `${p}?${param}=`, as: "anon", status: r.status, evidence: `${param}= sent the visitor to ${REDIRECT_PROBE_HOST}`, meta: { param },
            replay: { vars: [], accounts: {}, steps: [{ as: "anon", method: "GET", path: q, expect: { kind: "not_redirect_to", host: REDIRECT_PROBE_HOST } }] } });
          continue outer;
        }
      }
    }
    // Sign-in: the cookie flags (seen when the runner signed in) and, in a full run with rateLimit on, wrong passwords.
    for (const role of ["a", "b"] as const) {
      const acc = cfg.accounts[role];
      if (!("login" in acc) || acc.login.tokenPath) continue;
      await auth.headers(role);
      const weak = (auth.cookieFlags.get(role) ?? []).filter((c) => !/;\s*httponly/i.test(c) || !/;\s*samesite=/i.test(c) || (o.proof.origin.startsWith("https:") && !/;\s*secure/i.test(c)));
      if (weak.length) {
        report("attack.weak_session_cookie", { method: "POST", route: acc.login.path, as: role, status: 200, evidence: `cookie ${weak[0]!.split("=")[0]} is missing a flag`, meta: { cookie: weak[0]!.split("=")[0]!.slice(0, 40) },
          replay: { vars: [], accounts: accounts(role), steps: [{ as: role, method: "POST", path: acc.login.path, login: { role, wrong: false }, expect: { kind: "cookie_flags" } }] } });
      }
      break;
    }
    if (mode === "full" && cfg.surface.rateLimit) {
      const role = (["a", "b"] as const).find((r) => "login" in cfg.accounts[r]);
      const acc = role ? cfg.accounts[role] : null;
      if (role && acc && "login" in acc && env[acc.emailEnv]) {
        const statuses: number[] = [];
        for (let i = 0; i < RATE_TRIES; i++) {
          const r = await http.send(role, "POST", acc.login.path, { body: fill(acc.login.body, { email: env[acc.emailEnv]!, password: `yof-wrong-${random()}` }), purpose: "login" });
          statuses.push(r.status);
          if (r.status === 429 || r.status === 423) break;
        }
        if (statuses.length === RATE_TRIES && !statuses.some((s) => s === 429 || s === 423) && statuses.every((s) => s > 0)) {
          report("attack.no_rate_limit", { method: "POST", route: acc.login.path, as: role, status: statuses.at(-1)!, evidence: `${RATE_TRIES} wrong passwords in a row, none slowed down`, meta: { tries: String(RATE_TRIES) },
            replay: { vars: ["wrong"], accounts: accounts(role), steps: [{ as: role, method: "POST", path: acc.login.path, login: { role, wrong: true }, repeat: RATE_TRIES, expect: { kind: "some_status", status: [429, 423] } }] } });
        }
      } else notes.push("no_rate_limit_account");
    }
    return "done" as const;
  };

  const plan: [AttackGroup, () => Promise<"done" | "skipped">][] = [
    ["auth", authGroup], ["rbac", rbacGroup], ["surface", surfaceGroup],
    ...(mode === "full" ? [["tenant", tenantGroup], ["ai", aiGroup]] as [AttackGroup, () => Promise<"done" | "skipped">][] : []),
  ];
  if (mode === "light") { if (wanted.has("tenant")) groups.tenant = "skipped"; if (wanted.has("ai")) groups.ai = "skipped"; notes.push("light_run_read_only"); }
  let stopped: AttackRunResult["stopped"] = null;
  try {
    for (const [g, fn] of plan) {
      if (!wanted.has(g)) continue;
      groups[g] = "partial";
      try { groups[g] = await fn(); }
      catch (e) {
        if (e instanceof BudgetError) { stopped = e.reason; throw e; }
        if (e instanceof StoppedError) { stopped = "cancelled"; throw e; }
        if (e instanceof RefusedError) { notes.push(`refused:${e.message.slice(0, 120)}`); continue; }
        throw e;
      }
    }
  } catch (e) {
    if (e instanceof StoppedError) stopped = "cancelled";
    else if (!(e instanceof BudgetError)) throw e;
  } finally {
    // Delete every record this run created, newest first. After a stop signal the clean-up has a hard deadline.
    const clock = o.now ?? Date.now;
    const deadline = stopped === "cancelled" || o.signal?.aborted ? clock() + STOP_CLEANUP_MS : Infinity;
    for (const c of cleanupList.reverse()) {
      const route = c.path.replace(/\/[^/]*$/, "/{id}");
      const remaining = deadline - clock();
      if (remaining <= 0) { cleanup.left.push(route); continue; }
      try {
        const h = auth.cached(c.as);
        const r = await http.send(c.as, "DELETE", c.path, { headers: h ?? {}, purpose: "cleanup", timeoutMs: Number.isFinite(remaining) ? remaining : undefined });
        if (ok(r.status) || r.status === 404) cleanup.deleted++;
        else { notes.push(`cleanup_${r.status}:${route}`); cleanup.left.push(route); }
      } catch { notes.push("cleanup_failed"); cleanup.left.push(route); }
    }
  }
  return { findings, groups, notes, stopped, cleanup, exchanges: http.exchanges, requests: http.used, unconfirmed };
}
