/**
 * yof attack: the scope and rules-of-engagement document (Y24, first slice). A plain Markdown text made from the parsed
 * config and its consent sentence, for the owner or a client to read and sign BEFORE a run: which hosts are in scope,
 * which test accounts are used (the NAMES of their environment variables, never a value), the mode and the production
 * window, the budget, which test groups will run and which are skipped and why, what is never done, and a signature
 * block.
 *
 * Pure: no AI, no network, no clock (the date is given). `attackPlan` mirrors the runner's own skip rules
 * (./runner.ts); a test runs both on the same configs and compares them, so the document cannot promise a group the
 * runner would skip.
 *
 * Wording (owner rules): this is automated attack testing and evidence for the reader's own reviews. The document
 * never says what the app IS, and it says that it does not replace a manual test where a standard requires one.
 */
import { ATTACK_GROUPS, type AttackGroup } from "./catalog";
import { isLoginAccount, MAX_BUDGET, ROLES, type AccountSpec, type AttackConfig, type Role } from "./config";
import { REQUEST_TIMEOUT_MS } from "./http";
import { parseTarget, type Mode } from "./proof";

export interface GroupPlan {
  group: AttackGroup;
  runs: boolean;
  /** Why the group is skipped (empty when it runs). */
  why: string;
  /** What the group does in this run, one line each. */
  does: string[];
}

const plain = (p: string) => !p.includes("{id}");
const loginRole = (cfg: AttackConfig, roles: readonly Role[]): Role | null => roles.find((r) => { const a = cfg.accounts[r]; return !!a && isLoginAccount(a); }) ?? null;

/** Which groups a run of this config in this mode attacks, and why the others are skipped. Pure. */
export function attackPlan(cfg: AttackConfig, mode: Mode): GroupPlan[] {
  const has = (r: Role) => !!cfg.accounts[r];
  const routes = cfg.routes.filter(plain), admin = cfg.admin.filter(plain);
  const skip = (group: AttackGroup, why: string): GroupPlan => ({ group, runs: false, why, does: [] });
  const out: Record<AttackGroup, GroupPlan> = {} as Record<AttackGroup, GroupPlan>;

  const owner: Role | null = has("a") ? "a" : has("admin") ? "admin" : null;
  out.auth = !owner ? skip("auth", "no test account to sign in with (add account A)")
    : !routes.length && !admin.length ? skip("auth", "the config names no signed-in routes without {id}")
      : { group: "auth", runs: true, why: "", does: [`Opens ${count(routes.length + admin.length, "signed-in route")} with no sign-in and with a broken token, and compares the answer with the signed-in one.`] };

  const viewerObjects = mode === "full" && has("viewer") ? cfg.objects.length : 0;
  const memberPart = admin.length > 0 && has("a");
  const viewerPart = has("viewer") && (admin.length > 0 || viewerObjects > 0);
  out.rbac = !memberPart && !viewerPart
    ? skip("rbac", !admin.length ? (has("viewer") ? "the config names no admin routes without {id}, and the read-only member's write tests need a full run and an object" : "the config names no admin routes without {id}") : "no member account to open admin routes with (add account A)")
    : { group: "rbac", runs: true, why: "", does: [
      ...(memberPart ? [`Opens ${count(admin.length, "admin route")} as a normal member${has("admin") ? " and compares the answer with the admin account's" : ""}.`] : []),
      ...(viewerPart && admin.length ? [`Opens ${count(admin.length, "admin route")} as the read-only member (viewer).`] : []),
      ...(viewerObjects ? [`The read-only member tries to create a test record on ${count(viewerObjects, "object")}${has("a") ? ", and to change and delete a test record of account A" : " (the change and delete tests need account A)"}. Test records are deleted at the end.`] : []),
      ...(has("viewer") && mode === "light" && cfg.objects.length ? ["The read-only member's create, change and delete tests are not run (a light run is read-only)."] : []),
      ...(!has("viewer") ? ["The read-only member is not tested (no viewer account)."] : []),
    ] };

  const light = "a light run is read-only: it creates no test record and sends no message to the assistant";
  out.tenant = mode === "light" ? skip("tenant", light)
    : !cfg.objects.length ? skip("tenant", "the config names no objects")
      : !has("a") || !has("b") ? skip("tenant", `the tenant-barrier test needs two accounts in separate tenants${has("a") ? " (only account A is set; add account B)" : has("b") ? " (only account B is set; add account A)" : " (add accounts A and B)"}`)
        : { group: "tenant", runs: true, why: "", does: [
          `Account A creates a test record on ${count(cfg.objects.length, "object")}; account B tries to read it by id${cfg.objects.some((o) => o.list) ? ", to find it in a list" : ""}${cfg.objects.some((o) => o.update) ? " and to change it" : ""}.`,
          "Every test record is deleted at the end, also when the run is stopped or its budget runs out.",
        ] };

  const aiRunnable = cfg.ai.filter((a) => has(a.account ?? "a"));
  out.ai = mode === "light" ? skip("ai", light)
    : !cfg.ai.length ? skip("ai", "the config names no assistant route")
      : !aiRunnable.length ? skip("ai", "no account to talk to the assistant as (add account A)")
        : { group: "ai", runs: true, why: "", does: [
          `Sends fixed, mild test messages to ${count(aiRunnable.length, "assistant route")}: asks for its hidden instructions, types a command, asks for live markup, for one harmless word with its rules off, for internal details, and to send an email to an address that cannot exist.`,
          ...(aiRunnable.some((a) => a.ingest) ? ["Saves a test record with a hidden instruction and asks the assistant about it."] : []),
          ...(cfg.objects.length ? ["Asks the assistant to read and to rename a test record of the other account."] : []),
          ...(aiRunnable.some((a) => a.limits) ? ["Usage limits (turned on in the config): 10 tiny messages two at a time, and one request for a very long text."] : ["Usage limits are not tested (\"limits\" is off)."]),
        ] };

  const cookieRole = (["a", "b"] as const).find((r) => { const a = cfg.accounts[r]; return !!a && isLoginAccount(a) && !a.login.tokenPath; });
  const rate = mode === "full" && cfg.surface.rateLimit && !!loginRole(cfg, ["a", "b"]);
  out.surface = { group: "surface", runs: true, why: "", does: [
    "Reads the home page and checks its browser protection headers.",
    `Checks ${(cfg.surface.redirectPaths.length ? cfg.surface.redirectPaths : ["/login"]).map(tick).join(", ")} for a redirect to an address given in the link.`,
    ...(cookieRole ? [`Checks the flags of the sign-in cookie of account ${cookieRole.toUpperCase()}.`] : []),
    rate ? "Sign-in rate limit (turned on in the config): 12 wrong passwords in a row for one test account." : `The sign-in rate limit is not tested (${mode === "light" ? "a light run is read-only" : !cfg.surface.rateLimit ? "\"surface.rateLimit\" is off" : "no account signs in with a password"}).`,
  ] };
  return ATTACK_GROUPS.map((g) => out[g]);
}

const count = (n: number, one: string) => `${n} ${n === 1 ? one : `${one}s`}`;
const tick = (s: string) => `\`${s.replace(/`/g, "")}\``;
const ROLE_WORDS: Record<Role, string> = {
  a: "a member", b: "a member of a second tenant (its own workspace)", admin: "an administrator", viewer: "a member who may only read",
};
const GROUP_WORDS: Record<AttackGroup, string> = { auth: "Sign-in", tenant: "Tenant barrier", rbac: "Roles", ai: "Assistant", surface: "Public surface" };

function accountLines(role: Role, acc: AccountSpec | undefined): string {
  if (!acc) return `| ${role} | ${ROLE_WORDS[role]} | not set | none |`;
  const headers = acc.headers.map((h) => h.header).join(", ");
  const names = isLoginAccount(acc)
    ? [acc.emailEnv, acc.passwordEnv, ...(acc.login.totpEnv ? [acc.login.totpEnv] : []), ...acc.headers.map((h) => h.env)]
    : acc.headers.map((h) => h.env);
  const how = isLoginAccount(acc)
    ? `signs in at ${tick(`POST ${acc.login.path}`)} with an email and a password${acc.login.totpEnv ? " and a one-time code" : ""}${headers ? `; also sends ${headers}` : ""}`
    : `sends ${headers}`;
  return `| ${role} | ${ROLE_WORDS[role]} | ${how} | ${names.map(tick).join(", ")} |`;
}

export interface ScopeDocInput {
  cfg: AttackConfig;
  mode: Mode;
  /** The address this run is aimed at, when one was given. Only its origin is shown. */
  target?: string | null;
  /** The day the document is made, as YYYY-MM-DD. */
  date: string;
  version: string;
  /** The config file's path as the person gave it. */
  configPath?: string;
}

/** The scope and rules-of-engagement document, as Markdown. Pure: the same input always gives the same text. */
export function scopeDocument(i: ScopeDocInput): string {
  const { cfg, mode } = i;
  const plan = attackPlan(cfg, mode);
  const parsed = i.target ? parseTarget(i.target) : null;
  const origin = parsed && parsed.ok ? parsed.url.origin : null;
  const prod = cfg.production;
  const L: string[] = [];
  const add = (...s: string[]) => { L.push(...s); };

  add(`# Scope and rules of engagement: yof attack on ${cfg.app}`, "");
  add(`Prepared on ${i.date} with yof attack ${i.version} from ${tick(i.configPath ?? ".yof/attack.json")}. Nothing was sent to any host to make this document.`, "");
  add("This describes automated attack testing, evidence for your security reviews. It does not replace a manual test where a standard requires one.", "");

  add("## 1. Consent", "", "The config carries this sentence, word for word. yof attack refuses to run without it.", "", `> ${cfg.consent}`, "");

  add("## 2. Hosts in scope", "");
  if (origin) add(`This run is aimed at: ${tick(origin)}. It starts only after yof attack has proven that address as described below.`, "");
  add(
    `- **The app:** ${tick(cfg.app)} (and ${tick(`www.${cfg.app.replace(/^www\./, "")}`)}). This is production: see section 4. It must be proven with the proof token from the owner's yof app (a file, a meta tag or a DNS record on the host).`,
    `- **Preview builds of the app's repository:** an address that GitHub reports as a successful deployment of the repository for the commit under test, and that is also the repository's own: a Vercel, Netlify or Cloudflare Pages preview named after the repository and reported by that platform's own GitHub app, or a host on the app's own domain once the app is proven.`,
    "- **The tester's own machine:** `localhost`, `127.0.0.1` and `::1`. Plain http is allowed only there.",
    "",
    "Every other host is out of scope. Attack requests go to the one proven address only, redirects are never followed, and a host that cannot be proven is refused before any attack request is sent.",
    "",
  );

  add("## 3. Test accounts", "", "The accounts are test accounts the owner made for this purpose. The config names environment variables only; this document lists those names and never a value. yof stores none of them.", "");
  add("| Role | What it is | How it signs in | Variables (names only) |", "| --- | --- | --- | --- |");
  for (const r of ROLES) add(accountLines(r, cfg.accounts[r]));
  add("");

  add("## 4. Mode and production", "");
  add(mode === "light"
    ? "- **Mode: light.** Read-only checks: no test record is created and no message is sent to the assistant. A test account that signs in with a password still sends its sign-in request."
    : "- **Mode: full.** Reads, sign-in requests, test records the run creates and deletes itself, and test messages to the assistant route named in the config.");
  add(!prod.enabled
    ? "- **Production: off.** The app's live host is not tested. A run aimed at it is refused."
    : prod.window
      ? `- **Production: on.** A light run may go at any time. A full run goes only inside the agreed window, ${prod.window} UTC, every day.`
      : "- **Production: on, with no window.** A light run may go at any time. A full run on production is refused until a window is set.");
  add("");

  add("## 5. Budget", "");
  add(
    `- At most ${count(cfg.budget.requests, "request")} and ${cfg.budget.seconds} seconds for the whole run, at most ${cfg.budget.perSecond} requests a second.`,
    `- Each request waits at most ${REQUEST_TIMEOUT_MS / 1000} seconds. No config can lift the ceilings of ${MAX_BUDGET.requests} requests, ${MAX_BUDGET.seconds} seconds and ${MAX_BUDGET.perSecond} requests a second.`,
    "- When a budget runs out the run stops, deletes its test records and says which groups it did not reach.",
    "- The person running it can stop it at any time (Ctrl+C or a cancel in CI): nothing new is sent and the test records are deleted.",
    "",
  );

  add("## 6. Test groups", "");
  for (const p of plan) {
    add(`### ${GROUP_WORDS[p.group]} (${tick(p.group)}): ${p.runs ? "will run" : "skipped"}`, "");
    if (!p.runs) add(`Skipped because ${p.why}.`, "");
    else { for (const d of p.does) add(`- ${d}`); add(""); }
  }
  const named = [...cfg.routes.map((r) => `signed-in ${tick(r)}`), ...cfg.admin.map((r) => `admin ${tick(r)}`), ...cfg.objects.map((o) => `object ${tick(o.read)}`), ...cfg.ai.map((a) => `assistant ${tick(a.path)}`)];
  add(named.length ? `Routes named in the config: ${named.slice(0, 60).join(", ")}${named.length > 60 ? `, and ${named.length - 60} more` : ""}. A route the config does not name is not tested.` : "The config names no routes, so only the public surface is tested.", "");
  add("A finding is reported only when it shows a second time. On a pull request, a run may be narrowed to the routes the change can reach; it then says so.", "");

  add("## 7. What is never done", "");
  add(
    "- No request to a host outside section 2, and no following of redirects.",
    "- No change to data the run did not create: PATCH, PUT and DELETE touch only the run's own test records; POST goes only to the create, sign-in and assistant routes named in the config.",
    "- No load test and no attempt to make the app unavailable. The only repeated requests are the two small bursts named in section 6, and only when the config turns them on.",
    "- No harmful content in assistant messages: the messages are fixed and mild, and links in them point at addresses that cannot exist.",
    "- No social engineering, no phishing, no physical access, no testing of other companies' services the app uses.",
    "- No password, token, cookie or full record in a report: evidence describes the shape of an answer, with keys, email addresses and long numbers masked.",
    "",
  );

  add("## 8. What the result is, and is not", "");
  add(
    "- The result lists what was tried, what was found twice, and what was skipped and why.",
    "- It is automated attack testing, evidence for your security reviews. It does not replace a manual test where a standard requires one.",
    "- It describes the app on the day of the run and only for the routes and accounts above. It is no statement about anything that was not tested.",
    "",
  );

  add("## 9. Agreed", "");
  add(
    `The owner of ${cfg.app}, or the client who asked for this test, agrees to the scope and rules above:`, "",
    "- Name: ______________________________", "- Role: ______________________________", "- Date: ______________________________", "- Signature: _________________________", "",
    "The person or team that runs yof attack:", "",
    "- Name: ______________________________", "- Date: ______________________________", "- Signature: _________________________", "",
  );
  return L.join("\n");
}
