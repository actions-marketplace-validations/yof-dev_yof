/**
 * yof's public benchmark: the two practice apps it is run against, pinned, and how each item of their OFFICIAL list is
 * scored. Run by .github/workflows/yof-benchmark.yml on GitHub's machines only (owner decision 2026-11-08): nothing
 * deliberately vulnerable is downloaded or started anywhere else. How to run it: docs/YOF_BENCHMARK.md.
 *
 * The official list is read at run time from the SAME commit as the app (Juice Shop: data/static/challenges.yml;
 * NodeGoat: the tutorial menu in app/views/tutorial/layout.html), so a name or a count is never typed in by hand.
 * This file only says, per item key:
 *   tested         yof claims to test this kind of problem. Found when one of the detectors fired, missed otherwise
 *                  (with the reason we expect it to be missed, written BEFORE any run, so a miss is never explained
 *                  away afterwards). relation "same" = the same weakness; "root" = the root cause the item exploits.
 *   not_tested     yof does not test this kind of problem. Listed, never counted as a miss or a find.
 *   not_available  the item cannot happen in this run (turned off by the app in Docker, or it needs a part this run
 *                  does not start). Listed with the reason.
 * Every key not named here is not_tested with the target's default reason. A key named here that is missing from the
 * pinned list fails the scoring (score.ts), so the mapping can never drift silently from the list.
 */

export type Relation = "same" | "root";
export type PackageIssueName = "made_up" | "brand_new" | "lookalike" | "vulnerable";

/** One yof result that counts for an item. Regexes match the file (repository-relative) or the route as configured. */
export type Detector =
  | { source: "key"; rule?: string; file?: RegExp }
  | { source: "package"; issues: PackageIssueName[]; names?: string[]; file?: RegExp }
  | { source: "attack"; rule: string; route?: RegExp };

export type MappingEntry =
  | { key: string; kind: "tested"; relation: Relation; detectors: Detector[]; why: string; ifMissed: string }
  | { key: string; kind: "not_tested" | "not_available"; why: string };

export type ListFormat = "juice-shop-challenges" | "nodegoat-tutorial";

export interface Target {
  id: "juice-shop" | "nodegoat";
  name: string;
  repo: string;
  /** The release tag, when the project tags releases (NodeGoat does not). */
  tag: string | null;
  /** The full commit the source, the list and the running app come from. */
  commit: string;
  /** How the app runs inside the runner. */
  run: string;
  /** Juice Shop: the official image of the same release, pinned by digest. */
  image: { ref: string; digest: string } | null;
  list: { file: string; format: ListFormat; label: string };
  origin: string;
  /** Items the app itself turns off in this environment (Juice Shop's disabledEnv). */
  disabledEnv: string | null;
  defaultNotTested: string;
  mapping: MappingEntry[];
}

const NOT_YOF =
  "Outside what yof checks. yof looks for leaked keys and risky packages in the source, and runs five attack groups against the running app: sign-in bypass, one user reading or changing another user's records, member access to admin routes, assistant probes, and redirects, headers and sign-in limits.";

const NEEDS_MODEL =
  "Needs the shop's AI chatbot, which talks to a local language-model server. The benchmark does not start one, to keep the run short, so yof's assistant probes are not run here.";

/** OWASP Juice Shop v20.3.0 (released 2026-10-11). */
export const JUICE_SHOP: Target = {
  id: "juice-shop",
  name: "OWASP Juice Shop",
  repo: "https://github.com/juice-shop/juice-shop",
  tag: "v20.3.0",
  commit: "f189f521266f42c6bd05884468292000cee852ed",
  run: "The project's official Docker image of the same release, pinned by digest, on 127.0.0.1:3000 inside the runner.",
  image: { ref: "bkimminich/juice-shop:v20.3.0", digest: "sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27" },
  list: { file: "data/static/challenges.yml", format: "juice-shop-challenges", label: "challenges" },
  origin: "http://localhost:3000",
  disabledEnv: "Docker",
  defaultNotTested: NOT_YOF,
  mapping: [
    {
      key: "knownVulnerableComponentChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "package", issues: ["vulnerable"], names: ["express-jwt", "sanitize-html"], file: /^package\.json$/ }],
      why: "The challenge's accepted answers are express-jwt 0.1.3 and sanitize-html 1.4.2, both pinned in package.json. yof's package check looks up exact pinned versions in the OSV advisory database.",
      ifMissed: "OSV did not return an advisory for either pinned version, or the registry did not answer during the run.",
    },
    {
      key: "jwtUnsignedChallenge", kind: "tested", relation: "root",
      detectors: [{ source: "package", issues: ["vulnerable"], names: ["jsonwebtoken", "express-jwt"], file: /^package\.json$/ }],
      why: "The shop accepts a token signed with the 'none' algorithm because it pins jsonwebtoken 0.4.0 and express-jwt 0.1.3, which have published advisories for that token check.",
      ifMissed: "OSV did not return an advisory for either pinned version, or the registry did not answer during the run.",
    },
    {
      key: "jwtForgedChallenge", kind: "tested", relation: "root",
      detectors: [{ source: "package", issues: ["vulnerable"], names: ["jsonwebtoken", "express-jwt"], file: /^package\.json$/ }],
      why: "The forged token works because the pinned jsonwebtoken 0.4.0 accepts a token signed with the public key as an HMAC secret, the advisory published for versions before 4.2.2.",
      ifMissed: "OSV did not return an advisory for either pinned version, or the registry did not answer during the run.",
    },
    {
      key: "typosquattingNpmChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "package", issues: ["lookalike", "made_up"], names: ["epilogue-js"] }],
      why: "A typosquatting package (epilogue-js) the shop once depended on.",
      ifMissed: "The package is named only in ftp/package.json.bak, a backup file. yof reads package.json, requirements files and pyproject.toml, not backups.",
    },
    {
      key: "typosquattingAngularChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "package", issues: ["lookalike", "made_up"], names: ["ngy-cookie"] }],
      why: "A typosquatting package (ngy-cookie) in frontend/package.json.",
      ifMissed: "yof flags a lookalike only when the name is one or two letters from a package on its bundled popular list. ngx-cookie, the package it imitates, is not on that list.",
    },
    {
      key: "supplyChainAttackChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "package", issues: ["vulnerable"], names: ["eslint-scope"] }],
      why: "A compromised eslint-scope release the developers used.",
      ifMissed: "eslint-scope is not pinned in a manifest yof reads; the challenge points at the forgotten backup files under ftp/.",
    },
    {
      key: "basketAccessChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.tenant_read", route: /^\/rest\/basket/ }],
      why: "One user reading another user's basket is the cross-user read yof's tenant group tests.",
      ifMissed: "yof's tenant test creates a record holding a marker text and reads it back as account B. A basket holds products, not text yof can mark, so the test cannot be set up for baskets.",
    },
    {
      key: "basketManipulateChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.tenant_write", route: /^\/(?:api\/BasketItems|rest\/basket)/ }],
      why: "Changing another user's basket is the cross-user write yof's tenant group tests.",
      ifMissed: "The same limit as View Basket: yof's tenant test needs a record with a text field it can mark, and basket items have none.",
    },
    {
      key: "forgedReviewChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.tenant_write", route: /^\/rest\/products\// }],
      why: "Editing another user's review is a cross-user write.",
      ifMissed: "Reviews are changed with the review id in the request body. yof's tenant test needs the id in the address, so it cannot be configured for reviews.",
    },
    {
      key: "adminSectionChallenge", kind: "tested", relation: "root",
      detectors: [{ source: "attack", rule: "attack.rbac_escalation", route: /^\/api\/Users$/ }],
      why: "The administration page is hidden only in the browser. The user list it shows comes from /api/Users, which any signed-in member can read.",
      ifMissed: "yof's member-versus-admin test did not see admin data at /api/Users as a member.",
    },
    {
      key: "redirectChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.open_redirect", route: /^\/redirect/ }],
      why: "An open redirect through /redirect?to=.",
      ifMissed: "The shop allows a redirect when an allowed address appears anywhere in the link. yof's probe sends a plain outside address, which the shop refuses.",
    },
    {
      key: "weakPasswordChallenge", kind: "tested", relation: "root",
      detectors: [{ source: "attack", rule: "attack.no_rate_limit", route: /^\/rest\/user\/login$/ }],
      why: "Nothing slows down password guessing at sign-in, which is how the admin's weak password can be found by trying.",
      ifMissed: "Twelve wrong passwords in a row were slowed down or refused.",
    },
    { key: "chatbotPromptInjectionChallenge", kind: "not_available", why: NEEDS_MODEL },
    { key: "chatbotGreedyInjectionChallenge", kind: "not_available", why: NEEDS_MODEL },
    { key: "systemPromptExtractionChallenge", kind: "not_available", why: NEEDS_MODEL },
    { key: "aiDebuggingChallenge", kind: "not_available", why: NEEDS_MODEL },
    { key: "leakedApiKeyChallenge", kind: "not_available", why: "The key is not in the shop's source code: it sits in a separate scheduled job, so no source check of this repository can find it." },
    { key: "exposedCredentialsChallenge", kind: "not_tested", why: "yof finds keys by their exact shape. An email address and a password written in code have no shape it can tell apart from ordinary text." },
    { key: "vulnerableDockerImageChallenge", kind: "not_tested", why: "yof does not read Dockerfiles or container images." },
    { key: "exposedMetricsChallenge", kind: "not_tested", why: "yof attack tests the routes its config lists. It does not search for unlisted pages such as /metrics." },
  ],
};

/** OWASP NodeGoat, master at 2023-06-21 (the project does not tag releases). */
export const NODEGOAT: Target = {
  id: "nodegoat",
  name: "OWASP NodeGoat",
  repo: "https://github.com/OWASP/NodeGoat",
  tag: null,
  commit: "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
  run: "Built from its own Dockerfile at the pinned commit, with MongoDB 4.4.29 (pinned by digest), on 127.0.0.1:4000 inside the runner.",
  image: null,
  list: { file: "app/views/tutorial/layout.html", format: "nodegoat-tutorial", label: "tutorial topics" },
  origin: "http://localhost:4000",
  disabledEnv: null,
  defaultNotTested: NOT_YOF,
  mapping: [
    {
      key: "a2", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.no_rate_limit" }, { source: "attack", rule: "attack.weak_session_cookie" }],
      why: "Unlimited password guessing and weak session cookie flags are the sign-in checks of yof's surface group.",
      ifMissed: "yof's sign-in checks need a sign-in route that answers 2xx with a token or a cookie. NodeGoat answers its sign-in with a redirect, so the benchmark signs in itself and those two checks cannot run.",
    },
    {
      key: "a4", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.tenant_read", route: /^\/allocations/ }],
      why: "Reading another user's allocations by changing the user id in the address.",
      ifMissed: "yof's tenant test creates its own record through a JSON API and reads it back as account B. NodeGoat's pages are server-rendered forms with no such API, so the test cannot be set up.",
    },
    {
      key: "a5", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.missing_headers" }],
      why: "The fix the app documents for this topic (server.js, \"Fix for A5\") adds the security headers that yof's surface group checks for.",
      ifMissed: "yof saw the security headers it checks for.",
    },
    {
      key: "a7", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.rbac_escalation", route: /^\/benefits$/ }],
      why: "A normal member opening the admin-only benefits page.",
      ifMissed: "yof compares JSON answers to decide whether a member got admin data. /benefits answers an HTML page that differs per user, so yof cannot tell the member's page from the admin's.",
    },
    {
      key: "a9", kind: "tested", relation: "same",
      detectors: [{ source: "package", issues: ["vulnerable"], file: /^package\.json$/ }],
      why: "Dependencies with published advisories, which yof's package check looks up for exact pinned versions.",
      ifMissed: "OSV returned no advisory for an exactly pinned version in package.json (yof checks exact pins only), or the registry did not answer.",
    },
    {
      key: "a10", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.open_redirect", route: /^\/learn/ }],
      why: "An open redirect through /learn?url=.",
      ifMissed: "The redirect sits behind sign-in, and yof's redirect probe runs signed out.",
    },
  ],
};

export const TARGETS: readonly Target[] = [JUICE_SHOP, NODEGOAT];
export const targetById = (id: string): Target | undefined => TARGETS.find((t) => t.id === id);
