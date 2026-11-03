/**
 * yof attack: may this host be attacked at all? Nothing is sent to a target before this says yes.
 *
 *   local       localhost, 127.0.0.1 or ::1 (your own machine). http is allowed only here.
 *   preview     a deployment of THIS repository that GitHub reports as successful for the commit under test (the
 *               GitHub Actions token reads it; the yof App installed on the repository is the owner's proof on our side).
 *               A deployment GitHub marks as production counts as production.
 *   production  any other https host, proven the yof way: the token from your yof app (YOF_VERIFY_TOKEN) in
 *               /.well-known/yof-verify.txt, /yof-verify.txt, a <meta name="yof-verify"> tag or a DNS TXT record
 *               "yof-verify=TOKEN".
 *
 * Then the production rule: never against production unless the config turns it on for this app
 * ("production": { "enabled": true }). With it on, a light (read-only) run may go any time; a full run only inside the
 * agreed window ("window": "02:00-04:00", UTC).
 */
import { resolveTxt as dnsResolveTxt } from "node:dns/promises";
import { inWindow, type AttackConfig } from "./config";
import { USER_AGENT, type FetchFn } from "./http";

export type TargetKind = "local" | "preview" | "production";
export type ProofMethod = "local" | "github-deployment" | "file" | "meta" | "dns";
export type Mode = "full" | "light";

export interface ProofOk { ok: true; kind: TargetKind; method: ProofMethod; origin: string; host: string }
export interface ProofRefused { ok: false; code: "bad_url" | "not_https" | "not_proven" | "not_this_app" | "production_off" | "outside_window"; message: string }
export type ProofResult = ProofOk | ProofRefused;

export interface ProofDeps {
  fetch?: FetchFn;
  resolveTxt?: (name: string) => Promise<string[][]>;
  env?: Record<string, string | undefined>;
  now?: Date;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
const GITHUB_API_DEFAULT = "https://api.github.com";

export function parseTarget(raw: string): { ok: true; url: URL } | ProofRefused {
  let u: URL;
  try { u = new URL(raw.trim()); } catch { return { ok: false, code: "bad_url", message: `Not a web address: ${raw.slice(0, 80)}` }; }
  if (u.username || u.password) return { ok: false, code: "bad_url", message: "The address may not carry a user name or password." };
  if (u.protocol === "http:" && !LOOPBACK.has(u.hostname)) return { ok: false, code: "not_https", message: "yof attack tests https addresses (http only on localhost)." };
  if (u.protocol !== "http:" && u.protocol !== "https:") return { ok: false, code: "bad_url", message: "Use an http(s) address." };
  return { ok: true, url: u };
}

async function getText(f: FetchFn, url: string): Promise<{ status: number; body: string }> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 10_000);
  try {
    const r = await f(url, { method: "GET", headers: { "User-Agent": USER_AGENT, Accept: "text/plain, text/html;q=0.9" }, redirect: "manual", signal: ctl.signal });
    return { status: r.status, body: (await r.text()).slice(0, 200_000) };
  } catch { return { status: 0, body: "" }; } finally { clearTimeout(t); }
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The yof proof on a live host: file, meta tag or DNS TXT, with the token from the person's yof app. */
async function tokenProof(origin: string, host: string, token: string, f: FetchFn, txt: (n: string) => Promise<string[][]>): Promise<ProofMethod | null> {
  for (const p of ["/.well-known/yof-verify.txt", "/yof-verify.txt"]) {
    const r = await getText(f, `${origin}${p}`);
    const first = r.body.split(/\r?\n/).map((l) => l.trim()).find(Boolean) ?? "";
    if (r.status >= 200 && r.status < 300 && (first === token || first === `yof-verify=${token}`)) return "file";
  }
  const home = await getText(f, `${origin}/`);
  if (home.status >= 200 && home.status < 300) {
    for (const tag of home.body.match(/<meta\b[^>]*>/gi) ?? []) {
      if (/\bname\s*=\s*["']?yof-verify["'\s/>]/i.test(tag) && new RegExp(`\\bcontent\\s*=\\s*["']?${escapeRe(token)}["'\\s/>]`).test(tag)) return "meta";
    }
  }
  for (const n of [host, ...(host.startsWith("www.") ? [host.slice(4)] : [])]) {
    const records = await txt(n).catch(() => [] as string[][]);
    if (records.some((parts) => parts.join("").trim() === `yof-verify=${token}`)) return "dns";
  }
  return null;
}

/**
 * A preview proven by GitHub: a successful deployment status of this repository, for this commit, whose address is
 * the target. Read with the workflow's own GITHUB_TOKEN; nothing is written.
 */
export async function githubDeploymentProof(host: string, env: Record<string, string | undefined>, f: FetchFn): Promise<{ kind: "preview" | "production"; url: string } | null> {
  const token = env.GITHUB_TOKEN, repo = env.GITHUB_REPOSITORY, sha = env.YOF_HEAD_SHA ?? env.GITHUB_SHA;
  if (!token || !repo || !sha || !/^[\w.-]+\/[\w.-]+$/.test(repo) || !/^[0-9a-f]{7,64}$/.test(sha)) return null;
  const api = (env.GITHUB_API_URL ?? GITHUB_API_DEFAULT).replace(/\/$/, "");
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": USER_AGENT };
  const get = async <T>(p: string): Promise<T | null> => {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 10_000);
    try { const r = await f(`${api}${p}`, { method: "GET", headers, redirect: "manual", signal: ctl.signal }); return r.ok ? ((await r.json()) as T) : null; }
    catch { return null; } finally { clearTimeout(t); }
  };
  const deployments = await get<{ id: number; environment?: string; production_environment?: boolean }[]>(`/repos/${repo}/deployments?sha=${sha}&per_page=30`);
  for (const d of deployments ?? []) {
    const statuses = await get<{ state?: string; environment_url?: string; target_url?: string }[]>(`/repos/${repo}/deployments/${d.id}/statuses?per_page=10`);
    for (const s of statuses ?? []) {
      if (s.state !== "success") continue;
      for (const u of [s.environment_url, s.target_url]) {
        if (!u) continue;
        try {
          if (new URL(u).hostname === host) {
            const production = d.production_environment === true || /^production$/i.test(d.environment ?? "");
            return { kind: production ? "production" : "preview", url: u };
          }
        } catch { /* not an address */ }
      }
    }
  }
  return null;
}

/** The preview address GitHub reports for this commit (for a pull-request run that was given no address). */
export async function findPreviewUrl(env: Record<string, string | undefined>, f: FetchFn = (u, i) => fetch(u, i)): Promise<string | null> {
  const token = env.GITHUB_TOKEN, repo = env.GITHUB_REPOSITORY, sha = env.YOF_HEAD_SHA ?? env.GITHUB_SHA;
  if (!token || !repo || !sha) return null;
  const api = (env.GITHUB_API_URL ?? GITHUB_API_DEFAULT).replace(/\/$/, "");
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": USER_AGENT };
  try {
    const r = await f(`${api}/repos/${repo}/deployments?sha=${sha}&per_page=30`, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(10_000) });
    if (!r.ok) return null;
    for (const d of (await r.json()) as { id: number; environment?: string; production_environment?: boolean }[]) {
      if (d.production_environment || /^production$/i.test(d.environment ?? "")) continue;
      const s = await f(`${api}/repos/${repo}/deployments/${d.id}/statuses?per_page=10`, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(10_000) });
      if (!s.ok) continue;
      const ok = ((await s.json()) as { state?: string; environment_url?: string }[]).find((x) => x.state === "success" && x.environment_url);
      if (ok?.environment_url) return ok.environment_url;
    }
  } catch { return null; }
  return null;
}

/** May `target` be attacked in this mode? The one gate every run passes first. */
export async function proveTarget(target: string, cfg: AttackConfig, mode: Mode, deps: ProofDeps = {}): Promise<ProofResult> {
  const parsed = parseTarget(target);
  if (!parsed.ok) return parsed;
  const u = parsed.url;
  const host = u.hostname.toLowerCase();
  const origin = u.origin;
  const env = deps.env ?? process.env;
  const f: FetchFn = deps.fetch ?? ((url, init) => fetch(url, init));

  if (LOOPBACK.has(host)) return { ok: true, kind: "local", method: "local", origin, host };

  let kind: TargetKind | null = null;
  let method: ProofMethod | null = null;
  const dep = await githubDeploymentProof(host, env, f);
  if (dep) { kind = dep.kind; method = "github-deployment"; }
  else {
    const appHost = cfg.app.replace(/:\d+$/, "");
    if (host !== appHost && host !== `www.${appHost}` && `www.${host}` !== appHost) {
      return { ok: false, code: "not_this_app", message: `${host} is not ${cfg.app}, the app named in the config, and GitHub reports no deployment of this repository there.` };
    }
    const token = (env.YOF_VERIFY_TOKEN ?? "").trim();
    if (!/^yof_[A-Za-z0-9_-]{20,64}$/.test(token)) return { ok: false, code: "not_proven", message: "Set YOF_VERIFY_TOKEN to the proof token from your yof app, or run on a pull request with a GitHub deployment." };
    method = await tokenProof(origin, host, token, f, deps.resolveTxt ?? dnsResolveTxt);
    if (!method) return { ok: false, code: "not_proven", message: `yof found no proof on ${host}: no yof-verify file, meta tag or DNS record with your token.` };
    kind = "production";
  }

  if (kind === "production") {
    if (!cfg.production.enabled) return { ok: false, code: "production_off", message: `${host} is production. Turn it on for this app with "production": { "enabled": true } in the config.` };
    if (mode === "full" && !(cfg.production.window && inWindow(cfg.production.window, deps.now ?? new Date()))) {
      return { ok: false, code: "outside_window", message: `A full run on production only goes inside the agreed window${cfg.production.window ? ` (${cfg.production.window} UTC)` : ' ("production.window" is not set)'}. A light, read-only run may go now: --mode light.` };
    }
  }
  return { ok: true, kind, method, origin, host };
}
