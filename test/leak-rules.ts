/**
 * What must never be in a public sōtem repository: credentials, private infrastructure, customer data and the private
 * engine's internals. Used by no-secrets.test.ts here, and by the private repo's guard over the whole oss/ folder.
 * Placeholders made of one repeated character (md_live_000…) are allowed: they are what the docs and tests use.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export interface LeakRule { id: string; re: RegExp; allow?: (match: string) => boolean }

const repeated = (m: string) => { const tail = m.replace(/^[a-z_]+_/i, ""); return tail.length > 0 && new Set(tail).size === 1; };
const ALLOWED_IPS = /^(127\.0\.0\.1|0\.0\.0\.0|192\.0\.2\.\d+|198\.51\.100\.\d+|203\.0\.113\.\d+)$/;
const PUBLIC_HOSTS = new Set(["api.mondaily.com", "www.mondaily.com", "app.mondaily.com", "mondaily.com"]);
const PUBLIC_EMAILS = new Set(["security@mondaily.com", "support@mondaily.com", "support@yof.io", "security@yof.io", "privacy@yof.io"]);

export const LEAK_RULES: LeakRule[] = [
  { id: "product-api-key", re: /md_live_[0-9a-f]{32}/g, allow: repeated },
  { id: "mcp-token", re: /msk_[A-Za-z0-9]{16,}/g, allow: repeated },
  { id: "webhook-secret", re: /whsec_[0-9a-f]{32,}/g, allow: repeated },
  { id: "payment-key", re: /\b(?:sk|rk|pk)_live_[A-Za-z0-9]{10,}/g },
  { id: "jwt", re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/g },
  { id: "private-key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { id: "cloud-key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "git-token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})/g },
  { id: "chat-token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { id: "database-host", re: /\b[a-z0-9]{20}\.supabase\.(?:co|in)\b/g },
  { id: "hosting-id", re: /\b(?:prj|team)_[A-Za-z0-9]{20,}\b/g },
  { id: "ip-address", re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, allow: (m) => ALLOWED_IPS.test(m) },
  { id: "internal-host", re: /\b[a-z0-9-]+\.(?:internal|lan|corp)\b/g },
  { id: "private-subdomain", re: /\b(?:[a-z0-9-]+\.)+mondaily\.com\b/g, allow: (m) => PUBLIC_HOSTS.has(m) },
  { id: "email-address", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, allow: (m) => PUBLIC_EMAILS.has(m.toLowerCase()) || /@example\.(?:com|org|net)$/i.test(m) || /^noreply@github\.com$/i.test(m) },
  { id: "server-secret-name", re: /\b(?:SUPABASE_SERVICE[A-Z_]*|SERVICE_ROLE[A-Z_]*|SOVEREIGN_[A-Z_]+|CRON_SECRET|STRIPE_SECRET[A-Z_]*|DATABASE_URL)\b/g },
  { id: "private-package", re: /@mondaily\//g },
  // "(?! extraction)": a public OWASP Juice Shop challenge title, named in the yof benchmark results (oss/yof/benchmark).
  { id: "engine-internals", re: /\b(?:agent-turn|team-turn|ALWAYS_APPROVE_TOOLS|autoApproves|askPromptBlocks|system prompt(?! extraction)|You are sōtem)\b/gi },
];

export interface LeakFinding { file: string; rule: string; match: string }

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === ".git" || name === "dist" || name === "coverage" || name === ".DS_Store") continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

/** Every rule match in every text file under `root`. The rules file itself is skipped (it spells the patterns). */
export function scanForLeaks(root: string): LeakFinding[] {
  const findings: LeakFinding[] = [];
  for (const file of walk(root)) {
    if (/leak-rules\.ts$/.test(file)) continue;
    const text = readFileSync(file, "utf8");
    if (text.includes("\u0000")) continue;   // binary
    for (const rule of LEAK_RULES) {
      for (const m of text.matchAll(rule.re)) {
        if (rule.allow?.(m[0])) continue;
        findings.push({ file: relative(root, file), rule: rule.id, match: m[0].slice(0, 12) + (m[0].length > 12 ? "…" : "") });
      }
    }
  }
  return findings;
}
