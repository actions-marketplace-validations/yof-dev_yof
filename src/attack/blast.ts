/**
 * yof attack: blast radius. From the files a pull request changes (`git diff --name-only origin/<base>...HEAD`), which
 * routes can the change reach? A pull-request run then attacks only those, and says "partial run: N attack groups".
 *
 * FULL run instead (said out loud, with the reason) when:
 *   - shared code changed: middleware, auth, sessions, permissions/roles, database access, or the dependency list;
 *   - a changed code file is imported by three or more route files ("used by many routes");
 *   - a changed code file maps to no route at all and is not a test, doc or asset ("the mapping is unsure").
 *
 * Route detection, simple and stated:
 *   Next.js app router   app/**\/route.(ts|js) -> the folder path; (group) folders dropped, [id] -> {id}, [...x] -> {x}
 *   Next.js pages        pages/api/** -> /api/...; index -> its folder
 *   Hono / Express       .get/.post/.put/.patch/.delete/.all("/path") calls in a file; app.route("/prefix", x) or
 *                        app.use("/prefix", x) in another file that imports it adds the prefix; :id -> {id}
 *   imports              a changed helper maps to the routes of the (one or two) route files that import it
 */
import type { AttackGroup } from "./catalog";
import type { AttackConfig } from "./config";

export interface BlastResult {
  full: boolean;
  reasons: string[];
  /** Route patterns the change can reach ({param} style). */
  routes: string[];
  /** Changed files that were left out (tests, docs, assets). */
  ignored: string[];
}

const SHARED = [
  { re: /(?:^|\/)middleware\.[cm]?[jt]sx?$/, why: "middleware" },
  { re: /(?:^|\/)(?:auth|authn|authz|session|sessions|permissions?|rbac|acl|roles?|guards?|policies|policy)(?:\/|\.|-|_)/i, why: "auth or permissions" },
  { re: /(?:^|\/)(?:db|database|prisma|drizzle|supabase)(?:\/|\.[cm]?[jt]s$)/i, why: "database access" },
  { re: /(?:^|\/)schema\.prisma$|(?:^|\/)migrations?\//i, why: "database access" },
  { re: /(?:^|\/)(?:package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|requirements\.txt|pyproject\.toml)$/, why: "dependencies" },
];
const IGNORED = /(?:^|\/)(?:__tests__|tests?|e2e|docs?|\.github|fixtures?)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|\.(?:md|mdx|txt|png|jpe?g|gif|svg|webp|ico|css|scss|snap|lock)$/i;
const CODE = /\.(?:[cm]?[jt]sx?|py|rb|go)$/;
const VERB_CALL = /\.(?:get|post|put|patch|delete|all)\(\s*["'`](\/[^"'`]*)["'`]/g;
const MOUNT = /\.(?:route|use)\(\s*["'`](\/[^"'`]*)["'`]\s*,\s*([A-Za-z_$][\w$]*)/g;

const norm = (p: string) => {
  const s = `/${p.split("/").filter(Boolean).join("/")}`.replace(/:(\w+)/g, "{$1}");
  return s === "" ? "/" : s;
};

/** A Next.js route file's URL path, or null when the file isn't one. */
export function nextRoute(file: string): string | null {
  const f = file.replace(/^(?:apps\/[^/]+\/|packages\/[^/]+\/)?/, "").replace(/^src\//, "");
  const seg = (s: string) => s.replace(/^\[\[?\.\.\.(\w+)\]?\]$/, "{$1}").replace(/^\[(\w+)\]$/, "{$1}");
  let m = /^app\/(.*?)\/?route\.[cm]?[jt]sx?$/.exec(f) ?? /^app\/(.*?)\/?page\.[cm]?[jt]sx?$/.exec(f);
  if (m) return norm(m[1]!.split("/").filter((s) => s && !/^\(.*\)$/.test(s) && !s.startsWith("@")).map(seg).join("/"));
  m = /^pages\/(api\/.*)\.[cm]?[jt]sx?$/.exec(f);
  if (m) return norm(m[1]!.split("/").map(seg).filter((s, i, a) => !(s === "index" && i === a.length - 1)).join("/"));
  return null;
}

const base = (p: string) => p.replace(/^.*\//, "").replace(/\.[^.]+$/, "");
/** Does `content` import the file at `path` (by its file name, any relative path)? */
const imports = (content: string, path: string) => {
  const b = base(path);
  if (b === "index") return false;
  return new RegExp(`(?:from\\s+|require\\(|import\\()\\s*["'][^"']*/${b.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:\\.[cm]?[jt]sx?)?["']`).test(content);
};

/** Route patterns declared in one Hono/Express file, with the prefixes other files mount it under. */
function serverRoutes(file: string, read: (p: string) => string | null, all: readonly string[]): string[] {
  const src = read(file);
  if (!src) return [];
  const paths = [...src.matchAll(VERB_CALL)].map((m) => m[1]!);
  if (!paths.length) return [];
  const prefixes = new Set<string>();
  for (const other of all) {
    if (other === file || !CODE.test(other)) continue;
    const o = read(other);
    if (!o || !imports(o, file)) continue;
    for (const m of o.matchAll(MOUNT)) {
      const ident = m[2]!;
      if (new RegExp(`import\\s*\\{?[^;]*\\b${ident}\\b[^;]*from\\s*["'][^"']*/${base(file)}`).test(o) || new RegExp(`\\b${ident}\\b\\s*=\\s*require\\(`).test(o)) prefixes.add(m[1]!);
    }
  }
  const pre = prefixes.size ? [...prefixes] : [""];
  return pre.flatMap((p) => paths.map((x) => norm(`${p}/${x}`)));
}

export function routesOf(file: string, read: (p: string) => string | null, all: readonly string[]): string[] {
  const n = nextRoute(file);
  if (n) return [n];
  return serverRoutes(file, read, all);
}

export function blastRadius(changed: readonly string[], read: (p: string) => string | null, all: readonly string[]): BlastResult {
  const reasons: string[] = [];
  const routes = new Set<string>();
  const ignored: string[] = [];
  const routeFiles = all.filter((f) => CODE.test(f) && !IGNORED.test(f) && routesOf(f, read, all).length > 0);
  for (const file of changed) {
    const shared = SHARED.find((s) => s.re.test(file));
    if (shared) { reasons.push(`${file}: ${shared.why} changed`); continue; }
    if (IGNORED.test(file) || !CODE.test(file)) { ignored.push(file); continue; }
    const own = routesOf(file, read, all);
    if (own.length) { own.forEach((r) => routes.add(r)); continue; }
    const users = routeFiles.filter((r) => { const c = read(r); return !!c && imports(c, file); });
    if (users.length >= 3) { reasons.push(`${file}: used by ${users.length} route files`); continue; }
    if (!users.length) { reasons.push(`${file}: no route found for it, so the mapping is unsure`); continue; }
    for (const u of users) routesOf(u, read, all).forEach((r) => routes.add(r));
  }
  return { full: reasons.length > 0, reasons, routes: [...routes].sort(), ignored };
}

const segs = (p: string) => p.split("?")[0]!.replace(/:(\w+)/g, "{$1}").split("/").filter(Boolean);
/** Does the config route `path` fall under one of the blast routes? A {param} matches any segment either way. */
export function routeMatches(path: string, patterns: readonly string[]): boolean {
  const a = segs(path);
  return patterns.some((p) => {
    const b = segs(p);
    if (a.length !== b.length) return false;
    return a.every((s, i) => s === b[i] || /^\{\w+\}$/.test(s) || /^\{\w+\}$/.test(b[i]!));
  });
}

/** The groups a scoped run needs: those with at least one config target the change can reach. Surface stays with full runs. */
export function groupsFor(cfg: AttackConfig, patterns: readonly string[]): AttackGroup[] {
  const hit = (p: string) => routeMatches(p, patterns);
  const out: AttackGroup[] = [];
  if (cfg.routes.some(hit) || cfg.admin.some(hit)) out.push("auth");
  if (cfg.objects.some((o) => hit(o.read) || hit(o.create.path) || (o.update ? hit(o.update.path) : false) || (o.list ? hit(o.list) : false))) out.push("tenant");
  if (cfg.admin.some(hit)) out.push("rbac");
  if (cfg.ai.some((a) => hit(a.path))) out.push("ai");
  return out;
}

/** "full run" or "partial run: N attack groups". */
export const scopeLabel = (full: boolean, groups: number) => (full ? "full run" : `partial run: ${groups} attack group${groups === 1 ? "" : "s"}`);
