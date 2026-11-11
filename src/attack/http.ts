/**
 * yof attack: the ONE way the runner talks to the app. Every safety rule lives here, in code, so no attack can forget it:
 *
 *   - one origin only: the proven target. A path is joined to it; an absolute URL or another host is never requested,
 *     and redirects are never followed;
 *   - reads by default: GET and HEAD. A write is allowed only for what the runner itself owns:
 *       POST    to a create route (a test object), a login route, or the app's own assistant route named in the config;
 *       PATCH / PUT / DELETE only on a path that holds the id of an object THIS run created;
 *   - a hard request budget and a hard time budget: when either runs out the run stops (BudgetError), no request after.
 *     Room for the clean-up of every object the run created is held back from both (CLEANUP_MS of the time, one
 *     request per object), so a run that hits its budget still deletes what it made;
 *   - a steady pace (perSecond), a 10 s timeout and a 64 KB cap per answer;
 *   - every exchange is recorded with the ROLE that sent it (a, b, admin, anon), never the credential;
 *   - a stop signal (the person pressed Ctrl+C, or an editor cancelled the run) ends ordinary work at once
 *     (StoppedError, and a read or assistant request in flight is aborted). A create request in flight is allowed to
 *     finish, so its id is known and the record can be deleted. Clean-up requests still go.
 */
import type { Budget } from "./config";

export type As = "a" | "b" | "admin" | "viewer" | "anon";
export type Method = "GET" | "HEAD" | "POST" | "PATCH" | "PUT" | "DELETE";
export type Purpose = "read" | "login" | "create" | "ai" | "owned" | "cleanup";

export interface Exchange { method: Method; path: string; as: As; status: number; ms: number }
export interface HttpAnswer { status: number; body: string; headers: Headers; location: string | null }

export type FetchFn = (url: string, init: { method: string; headers: Record<string, string>; body?: string; redirect: "manual"; signal: AbortSignal }) => Promise<Response>;

export const REQUEST_TIMEOUT_MS = 10_000;
export const MAX_ANSWER_BYTES = 64 * 1024;
export const USER_AGENT = "yof-attack (+https://yof.io)";
/** Time held back at the end of the time budget for deleting the run's own test objects. */
export const CLEANUP_MS = 15_000;

export class BudgetError extends Error {
  constructor(readonly reason: "requests" | "time") { super(reason === "requests" ? "The request budget is used up." : "The time budget is used up."); }
}
export class RefusedError extends Error {}
/** The person stopped the run (SIGINT / SIGTERM): no new probe goes out, only clean-up. */
export class StoppedError extends Error {
  constructor() { super("The run was stopped."); }
}

export interface ClientOptions {
  origin: string;
  budget: Budget;
  fetch?: FetchFn;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** POST routes the config names (create, login, assistant). Anything else is refused. */
  postPaths: readonly string[];
  /** Aborted when the person stops the run. */
  signal?: AbortSignal;
}

const pathOnly = (p: string) => p.split("?")[0]!;

export class AttackClient {
  readonly exchanges: Exchange[] = [];
  readonly origin: string;
  private readonly started: number;
  private last = 0;
  private readonly owned = new Set<string>();
  /** Requests held back for clean-up: one per object this run created and has not deleted yet. */
  private reserved = 0;
  private readonly f: FetchFn;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(private readonly o: ClientOptions) {
    const u = new URL(o.origin);
    this.origin = u.origin;
    this.f = o.fetch ?? ((url, init) => fetch(url, init));
    this.now = o.now ?? Date.now;
    this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.started = this.now();
  }

  get used(): number { return this.exchanges.length; }
  /** Requests left for ordinary work (clean-up room excluded). */
  get left(): number { return Math.max(0, this.o.budget.requests - this.exchanges.length - this.reserved); }
  /** Milliseconds left for ordinary work (clean-up room excluded). */
  get timeLeft(): number { return this.started + this.o.budget.seconds * 1000 - CLEANUP_MS - this.now(); }
  /** Can one more object be created (its create request plus its later delete)? */
  get roomToCreate(): boolean { return this.left >= 2 && this.timeLeft > 0; }

  /** Mark an id as created by this run: from now on PATCH/PUT/DELETE may touch paths that contain it. */
  own(id: string): void { if (id && !this.owned.has(id)) { this.owned.add(id); this.reserved++; } }
  isOwned(path: string): boolean {
    const parts = pathOnly(path).split("/");
    return [...this.owned].some((id) => parts.includes(encodeURIComponent(id)));
  }

  /** The safety rules for one request; throws RefusedError when it may not be sent. */
  check(method: Method, path: string, purpose: Purpose): URL {
    if (!path.startsWith("/") || path.startsWith("//") || /[\r\n\\]/.test(path)) throw new RefusedError(`Refused: ${path.slice(0, 80)} is not a path on the app.`);
    const url = new URL(path, this.origin);
    if (url.origin !== this.origin) throw new RefusedError(`Refused: ${url.origin} is not the proven app.`);
    if (method === "GET" || method === "HEAD") return url;
    if (method === "POST") {
      if ((purpose === "create" || purpose === "login" || purpose === "ai") && this.o.postPaths.includes(pathOnly(path))) return url;
      throw new RefusedError(`Refused: POST ${pathOnly(path)} is not a route the config allows.`);
    }
    if ((purpose === "owned" || purpose === "cleanup") && this.isOwned(path)) return url;
    throw new RefusedError(`Refused: ${method} ${pathOnly(path)} does not touch an object this run created.`);
  }

  get stopped(): boolean { return this.o.signal?.aborted === true; }

  async send(as: As, method: Method, path: string, init: { headers?: Record<string, string>; body?: string; purpose?: Purpose; timeoutMs?: number } = {}): Promise<HttpAnswer> {
    const purpose = init.purpose ?? "read";
    const url = this.check(method, path, purpose);
    const cleanup = purpose === "cleanup";
    if (!cleanup && this.stopped) throw new StoppedError();
    if (cleanup) {
      if (this.reserved <= 0 || this.exchanges.length >= this.o.budget.requests) throw new BudgetError("requests");
      if (this.timeLeft + CLEANUP_MS <= 0) throw new BudgetError("time");
      this.reserved--;
    } else {
      if (this.left <= 0) throw new BudgetError("requests");
      if (this.timeLeft <= 0) throw new BudgetError("time");
      const gap = 1000 / this.o.budget.perSecond - (this.now() - this.last);
      if (gap > 0) await this.sleep(gap);
      if (this.timeLeft <= 0) throw new BudgetError("time");
      if (this.stopped) throw new StoppedError();
    }
    this.last = this.now();
    const headers: Record<string, string> = { "User-Agent": USER_AGENT, Accept: "application/json, text/plain;q=0.9, */*;q=0.5", ...(init.headers ?? {}) };
    if (init.body !== undefined) headers["Content-Type"] = headers["Content-Type"] ?? "application/json";
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), Math.max(1, Math.min(REQUEST_TIMEOUT_MS, init.timeoutMs ?? REQUEST_TIMEOUT_MS, this.timeLeft + (cleanup ? CLEANUP_MS : 0))));
    // A stop aborts a request in flight, except a create (its record must be known to be deleted) and clean-up.
    const interruptible = purpose !== "create" && !cleanup;
    const onStop = () => ctl.abort();
    if (interruptible) this.o.signal?.addEventListener("abort", onStop, { once: true });
    const start = this.now();
    const rec: Exchange = { method, path: pathOnly(path), as, status: 0, ms: 0 };
    this.exchanges.push(rec);
    try {
      const r = await this.f(url.toString(), { method, headers, body: init.body, redirect: "manual", signal: ctl.signal });
      const body = await readCapped(r);
      rec.status = r.status;
      return { status: r.status, body, headers: r.headers, location: r.headers.get("location") };
    } catch {
      if (interruptible && this.stopped) throw new StoppedError();
      return { status: 0, body: "", headers: new Headers(), location: null };
    } finally {
      clearTimeout(timer);
      if (interruptible) this.o.signal?.removeEventListener("abort", onStop);
      rec.ms = this.now() - start;
    }
  }
}

async function readCapped(r: Response): Promise<string> {
  if (!r.body) return "";
  const reader = r.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done || !value) break;
    const room = MAX_ANSWER_BYTES - size;
    if (value.length >= room) { chunks.push(value.subarray(0, room)); size = MAX_ANSWER_BYTES; await reader.cancel().catch(() => {}); break; }
    chunks.push(value); size += value.length;
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
}
