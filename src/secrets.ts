/**
 * Key patterns: text in, matches out. Nothing here touches the network or stores anything.
 *
 * Every rule has a fixed, documented shape. Providers without one (keys that look like any other random string) are
 * not guessed at, so a random hash never raises an alarm.
 *
 * fix_now   live secrets: Supabase service-role JWTs (the role claim is DECODED, never guessed from the shape), Stripe
 *           sk_live_ / rk_live_ / whsec_, OpenAI, Anthropic, Resend, SendGrid, Mailgun, Twilio, AWS secret keys,
 *           GitHub, Slack, Hugging Face, Groq, Replicate, private keys.
 * fix_week  Stripe sk_test_, an AWS key ID on its own, and VITE_ / NEXT_PUBLIC_ style settings named like secrets.
 * info      keys that are meant to be public: the Supabase anon JWT, the Firebase web key, Stripe pk_ keys.
 *
 * MASKING: a match is never returned in full. `masked` keeps the recognisable prefix and four characters; `snippet`
 * is at most 40 characters of context on each side with EVERY secret-looking run in it masked. `hash` is a SHA-256
 * prefix of the value, used only to recognise the same secret again, never reversible.
 */
import { createHash } from "node:crypto";

export type Severity = "fix_now" | "fix_week" | "info";

export interface SecretMatch {
  ruleId: string;
  /** Where in the text (1-based line and column). */
  line: number;
  column: number;
  masked: string;
  snippet: string;
  /** sha256(value) prefix: identifies the same secret across runs without keeping it. */
  hash: string;
  /** Extra, non-secret facts (the decoded JWT role, the setting's name). */
  meta?: Record<string, string>;
}

/** Plain-English name and severity of every rule. */
export const KEY_RULES: Record<string, { name: string; severity: Severity }> = {
  "secret.supabase_service_role": { name: "Supabase service-role key (skips every database rule)", severity: "fix_now" },
  "secret.stripe_live": { name: "Stripe live secret key", severity: "fix_now" },
  "secret.stripe_restricted": { name: "Stripe restricted key", severity: "fix_now" },
  "secret.stripe_test": { name: "Stripe test secret key", severity: "fix_week" },
  "secret.stripe_webhook": { name: "Stripe webhook signing secret", severity: "fix_now" },
  "secret.github": { name: "GitHub token", severity: "fix_now" },
  "secret.slack": { name: "Slack token or webhook URL", severity: "fix_now" },
  "secret.huggingface": { name: "Hugging Face token", severity: "fix_now" },
  "secret.groq": { name: "Groq API key", severity: "fix_now" },
  "secret.replicate": { name: "Replicate API token", severity: "fix_now" },
  "secret.mailgun": { name: "Mailgun private API key", severity: "fix_now" },
  "secret.twilio": { name: "Twilio credential", severity: "fix_now" },
  "secret.anthropic": { name: "Anthropic (Claude) API key", severity: "fix_now" },
  "secret.openai": { name: "OpenAI API key", severity: "fix_now" },
  "secret.resend": { name: "Resend API key", severity: "fix_now" },
  "secret.sendgrid": { name: "SendGrid API key", severity: "fix_now" },
  "secret.private_key": { name: "Private key", severity: "fix_now" },
  "secret.aws": { name: "AWS access key with its secret", severity: "fix_now" },
  "secret.aws_key_id": { name: "AWS access key ID", severity: "fix_week" },
  "secret.named_env": { name: "Browser-visible setting named like a secret", severity: "fix_week" },
  "public.supabase_anon": { name: "Supabase anon key (public by design)", severity: "info" },
  "public.firebase_web": { name: "Firebase web key (public by design)", severity: "info" },
  "public.stripe_publishable": { name: "Stripe publishable key (public by design)", severity: "info" },
};

const sha = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 32);

const KNOWN_PREFIX = /^(sk_live_|rk_live_|sk_test_|pk_live_|pk_test_|whsec_|sk-ant-[a-z]+\d*-|sk-proj-|sk-svcacct-|sk-admin-|sk-|re_|SG\.|AKIA|ASIA|AIza|eyJ|github_pat_|gh[pousr]_|xox[bpa]-|xapp-|hf_|gsk_|r8_|key-|SK|https:\/\/hooks\.slack\.com\/services\/|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

/** "sk_live_51AbCd••••••••" style: a known prefix plus four characters, the rest hidden. */
export function maskSecret(value: string, prefixLen?: number): string {
  const known = KNOWN_PREFIX.exec(value);
  const head = prefixLen ?? (known ? known[0].length : 0);
  const keep = Math.min(value.length - 2, head + 4);
  return `${value.slice(0, Math.max(0, keep))}${"•".repeat(8)}`;
}

/**
 * Docs, tests and example files are full of fake keys like sk_live_xxxxxxxx or sk_live_your_key_here. A value whose
 * body (after the known prefix) is one or two repeated characters, or spells a placeholder word, is not reported.
 */
export function isPlaceholder(value: string): boolean {
  const known = KNOWN_PREFIX.exec(value);
  const body = value.slice(known ? known[0].length : 0);
  const chars = body.replace(/[^A-Za-z0-9]/g, "");
  if (chars.length > 0 && new Set(chars.toLowerCase()).size <= 2) return true;
  return /x{5,}|your|example|placeholder|dummy|redacted|changeme|replace|sample|fake|invented|insert|1234567890|abcdefghij/i.test(body);
}

/**
 * A private key header with no key after it is prose (a setup guide saying the PEM text starts with the header) or a
 * stub (the header, a line break and four characters in a test), not a key. A real PEM has a base64 body of hundreds of characters:
 * at least one run of 40 within the next 200 characters (escaped \n line breaks and string joins allowed).
 */
export function hasKeyBody(text: string, end: number): boolean {
  const after = text.slice(end, end + 260).replace(/\\[nr]/g, "\n").replace(/["'`+,]/g, "");
  return /[A-Za-z0-9+/]{40}/.test(after.slice(0, 200));
}

function lineCol(text: string, index: number): { line: number; column: number } {
  let line = 1, last = -1;
  for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) { line++; last = i; }
  return { line, column: index - last };
}

/** Decode a JWT payload (base64url JSON). Null when it is not one. */
export function jwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const v = JSON.parse(json);
    return v && typeof v === "object" ? v as Record<string, unknown> : null;
  } catch { return null; }
}

type Verdict = { ruleId: string; meta?: Record<string, string> } | null;
interface Pattern { ruleId: string | ((value: string, text: string, index: number) => Verdict); re: RegExp; group?: number }

// Starts only where a run of token characters starts: without the lookbehind every "eyJ" inside one long run
// re-scanned to its end (quadratic; 30 KB of "eyJeyJ..." took 3.4 s, measured 2026-10-31).
const JWT = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}/g;

const PATTERNS: Pattern[] = [
  {
    re: JWT,
    ruleId: (v) => {
      const p = jwtPayload(v);
      if (!p) return null;
      const role = typeof p.role === "string" ? p.role : null;
      const iss = typeof p.iss === "string" ? p.iss : "";
      const supa = iss === "supabase" || /supabase/.test(iss) || typeof p.ref === "string";
      if (role === "service_role") return { ruleId: "secret.supabase_service_role", meta: { role } };
      if (role === "anon" && supa) return { ruleId: "public.supabase_anon", meta: { role } };
      return null;   // any other JWT (a session, a test token) is not judged here
    },
  },
  { re: /\bsk_live_[A-Za-z0-9]{20,}/g, ruleId: "secret.stripe_live" },
  { re: /\brk_live_[A-Za-z0-9]{20,}/g, ruleId: "secret.stripe_restricted" },
  { re: /\bsk_test_[A-Za-z0-9]{20,}/g, ruleId: "secret.stripe_test" },
  { re: /\bpk_(?:live|test)_[A-Za-z0-9]{20,}/g, ruleId: "public.stripe_publishable" },
  // Stripe webhook signing secret: whoever has it can fake "payment succeeded" events to your server.
  { re: /\bwhsec_[A-Za-z0-9]{24,}\b/g, ruleId: "secret.stripe_webhook" },
  // GitHub: classic (ghp_), OAuth (gho_), user-to-server (ghu_), server-to-server (ghs_), refresh (ghr_), fine-grained.
  { re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g, ruleId: "secret.github" },
  { re: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/g, ruleId: "secret.github" },
  // Slack: bot / user / legacy app tokens, app-level tokens, and incoming-webhook URLs.
  { re: /\bxox[bpa]-\d{8,}-\d{8,}(?:-\d{8,})?-[A-Za-z0-9]{24,}\b/g, ruleId: "secret.slack" },
  { re: /\bxapp-\d-[A-Z0-9]{8,}-\d{8,}-[a-f0-9]{32,}\b/g, ruleId: "secret.slack" },
  { re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}\b/g, ruleId: "secret.slack" },
  // AI providers with a fixed prefix and length.
  { re: /\bhf_[A-Za-z0-9]{34}\b/g, ruleId: "secret.huggingface" },
  { re: /\bgsk_[A-Za-z0-9]{52}\b/g, ruleId: "secret.groq" },
  { re: /\br8_[A-Za-z0-9]{37}\b/g, ruleId: "secret.replicate" },
  // Mailgun private API key (the public validation key starts with pubkey-, which never matches \bkey-).
  { re: /\bkey-[a-f0-9]{32}\b/g, ruleId: "secret.mailgun" },
  {
    // A Twilio API key SID: SK + 32 hex. Only with Twilio named nearby, so a random hash never alarms.
    re: /\bSK[a-f0-9]{32}\b/g,
    ruleId: (_v, text, i) => /twilio/i.test(text.slice(Math.max(0, i - 600), i + 600)) ? { ruleId: "secret.twilio" } : null,
  },
  // Anthropic before OpenAI: "sk-ant-" also starts with "sk-".
  { re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g, ruleId: "secret.anthropic" },
  { re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}/g, ruleId: "secret.openai" },
  { re: /\bsk-(?!ant-)[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, ruleId: "secret.openai" },
  { re: /\bsk-(?!ant-|proj-|svcacct-|admin-)[A-Za-z0-9]{48}\b/g, ruleId: "secret.openai" },
  { re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}\b/g, ruleId: "secret.resend" },
  { re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, ruleId: "secret.sendgrid" },
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, ruleId: "secret.private_key" },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, ruleId: "public.firebase_web" },
  {
    // A Twilio auth token: 32 hex characters assigned to a name that says so, with an Account SID nearby.
    re: /(?:auth_?token|authtoken|twilio_?token)["'`]?\s*[:=]\s*["'`]([a-f0-9]{32})["'`]/gi, group: 1,
    ruleId: (_v, text, i) => /\bAC[a-f0-9]{32}\b/.test(text.slice(Math.max(0, i - 600), i + 600)) ? { ruleId: "secret.twilio" } : null,
  },
  {
    // AWS: the key ID alone is "this week"; with a 40-character secret beside it, "now".
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    ruleId: (_v, text, i) => {
      const near = text.slice(Math.max(0, i - 400), i + 400);
      return /(?:secret_?access_?key|secretAccessKey|aws_?secret)["'`]?\s*[:=]\s*["'`][A-Za-z0-9/+]{40}["'`]/i.test(near)
        ? { ruleId: "secret.aws" } : { ruleId: "secret.aws_key_id" };
    },
  },
  {
    // A build-time setting the browser receives whose NAME says secret. Value must look like a value, not a placeholder.
    re: /\b((?:VITE|NEXT_PUBLIC|REACT_APP|EXPO_PUBLIC)_[A-Z0-9_]{1,100})["'`]?\s*[:=]\s*["'`]([^"'`\s]{12,200})["'`]/g, group: 2,
    ruleId: (v, text, i) => {
      if (/^(?:your|xxx|changeme|placeholder|example|<|\$\{|process\.env|import\.meta)/i.test(v)) return null;
      const name = /([A-Z0-9_]+)["'`]?\s*[:=]\s*["'`][^"'`]*$/.exec(text.slice(Math.max(0, i - 120), i + 1))?.[1] ?? "";
      // The "secret-sounding name" test lives here, not in the pattern: two overlapping [A-Z0-9_]* around SECRET made
      // the pattern quadratic on "VITE_SECRETSECRET..." (measured 2026-10-31).
      if (!/SECRET|PRIVATE|PASSWORD|SERVICE[_]ROLE/.test(name)) return null;
      return { ruleId: "secret.named_env", meta: name ? { name } : undefined };
    },
  },
];

/** Every secret-looking run, for masking a snippet (broader than the rules on purpose). */
const MASK_ANY = /((?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}|\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|\bwhsec_[A-Za-z0-9]{8,}|\bgithub_pat_[A-Za-z0-9_]{12,}|\bgh[pousr]_[A-Za-z0-9]{12,}|\bxox[bpa]-[A-Za-z0-9-]{12,}|\bxapp-[A-Za-z0-9-]{12,}|\bhf_[A-Za-z0-9]{12,}|\bgsk_[A-Za-z0-9]{12,}|\br8_[A-Za-z0-9]{12,}|\bkey-[a-f0-9]{16,}|\bsk-[A-Za-z0-9_-]{16,}|\bre_[A-Za-z0-9_]{12,}|\bSG\.[A-Za-z0-9_.-]{20,}|\b(?:AKIA|ASIA)[0-9A-Z]{16}|\bAIza[0-9A-Za-z_-]{20,}|\b[a-f0-9]{32,}\b|[A-Za-z0-9/+]{40,})/g;

export function maskAll(text: string): string {
  return text.replace(MASK_ANY, (m) => maskSecret(m));
}

function snippetAt(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 40), end = Math.min(text.length, index + length + 40);
  // A token cut by the window edge could be the tail of another secret too short to recognise: drop it.
  let before = text.slice(start, index), after = text.slice(index + length, end);
  if (start > 0) before = before.replace(/^[A-Za-z0-9_\-./+=]+/, "");
  if (end < text.length) after = after.replace(/[A-Za-z0-9_\-./+=]+$/, "");
  const value = text.slice(index, index + length);
  return `${maskAll(before)}${maskSecret(value)}${maskAll(after)}`.replace(/\s+/g, " ").slice(0, 140);
}

/**
 * Paths whose values are fake on purpose: tests, fixtures, mocks, examples, docs, demos and .env.example-style files.
 * The same list as the yof app's repository check (yof inside), so the CLI and the app agree on a repository.
 */
export const FIXTURE_PATH = /(?:^|\/)(?:__tests__|__mocks__|__fixtures__|__snapshots__|tests?|spec|specs|fixtures?|mocks?|examples?|samples?|docs?|testdata|e2e|cypress|playwright)\/|\.(?:test|spec|stories|story)\.[cm]?[jt]sx?$|\.(?:md|mdx|rst|txt)$|(?:^|\/)\.env\.(?:example|sample|template|dist|defaults?)$/i;
/** Files that steer an AI coding tool hold real values even as .md or in a docs folder: always read like code. */
const AI_CONFIG_FILE = /(?:^|\/)(?:\.cursorrules|\.windsurfrules|\.roorules|\.clinerules|CLAUDE(?:\.local)?\.md|AGENTS\.md|GEMINI\.md|\.?mcp\.json|mcp_config\.json|claude_desktop_config\.json)$|(?:^|\/)\.cursor\/rules\/|(?:^|\/)\.github\/copilot-instructions\.md$|(?:^|\/)\.(?:cursor|vscode|windsurf|roo|kiro|amazonq)\/mcp(?:_config)?\.json$/;
/** The masked start of a value that is a placeholder ("demo...", "test...", "${...}", "1234..."). Same as the app. */
const FAKE_START = /x{4,}|\*{3,}|0{6,}|1234|abcd|example|sample|dummy|fake|placeholder|changeme|change_me|your[_-]|<[^>]*>|\$\{|^(?:test|demo|secret|password|token)/i;

/**
 * The repository rule the yof app applies to keys found in a repository (0.3.1). Before it, `yof check` on our own
 * repository listed 14 values the app dropped, all fixtures:
 *   - "a browser setting whose NAME says secret" is a guess from the name: not in tests, docs, examples and demos;
 *     provider-shaped keys (sk_live_, ghp_, ...) are still reported there. Elsewhere such a setting is reported even
 *     when its value looks like a placeholder (the setting itself is the problem), unless the value is a "\${...}" template;
 *   - a value whose visible start is a placeholder ("demo", "test", "${...}") is not a key;
 *   - a line that says EXAMPLE (AWS's own documented example keys) is not a key.
 */
export function isRepoFixture(m: Pick<SecretMatch, "ruleId" | "masked">, path: string, lineText: string): boolean {
  const start = m.masked.replace(/•+$/, "");
  if (m.ruleId === "secret.named_env") {
    if (FIXTURE_PATH.test(path) && !AI_CONFIG_FILE.test(path)) return true;
    // Outside tests, docs and demos the finding is the setting itself: a secret-named value shipped to the browser is
    // the problem whatever the value looks like, so a placeholder-looking value ("demo-...", the yof demo's own plant)
    // is still reported. Only a template ("\${...}") is not a value at all.
    return /\$\{/.test(start) || /EXAMPLE/.test(lineText);
  }
  if (FAKE_START.test(start)) return true;
  return /EXAMPLE/.test(lineText);
}

export interface ScanOptions {
  /** Skip values that are clearly placeholders (sk_live_xxxx…, …your_key_here…). Default true. */
  ignorePlaceholders?: boolean;
}

/** Find secrets and public keys in one text. Same value twice in one text = one match (the first). */
export function scanText(text: string, opts: ScanOptions = {}): SecretMatch[] {
  const skipPlaceholders = opts.ignorePlaceholders !== false;
  const out: SecretMatch[] = [];
  const seen = new Set<string>();
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    for (let m = p.re.exec(text); m; m = p.re.exec(text)) {
      const value = p.group ? m[p.group] ?? "" : m[0];
      if (!value) continue;
      const index = p.group ? m.index + m[0].indexOf(value) : m.index;
      const verdict = typeof p.ruleId === "string" ? { ruleId: p.ruleId } : p.ruleId(value, text, index);
      if (!verdict) continue;
      if (skipPlaceholders && verdict.ruleId !== "secret.private_key" && isPlaceholder(value)) continue;
      if (skipPlaceholders && verdict.ruleId === "secret.private_key" && !hasKeyBody(text, index + value.length)) continue;
      const key = `${verdict.ruleId}|${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const pos = lineCol(text, index);
      out.push({
        ruleId: verdict.ruleId, line: pos.line, column: pos.column,
        masked: maskSecret(value), snippet: snippetAt(text, index, value.length), hash: sha(value),
        ...(verdict.meta ? { meta: verdict.meta } : {}),
      });
    }
  }
  return out.sort((a, b) => a.line - b.line || a.column - b.column);
}
