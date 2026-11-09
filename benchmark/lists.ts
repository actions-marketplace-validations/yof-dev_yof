/**
 * The official lists, parsed from the files pinned at the app's own commit. Plain line parsing, no YAML library: the
 * benchmark must not depend on more code than it needs. Anything unexpected is an error, never a guess.
 */
import type { ListFormat } from "./targets.ts";

export interface ListItem {
  key: string;
  name: string;
  category: string;
  /** Environments the app itself turns this item off in (Juice Shop's disabledEnv). */
  disabledEnv: string[];
}

export class ListError extends Error {}

/** A YAML scalar as Juice Shop writes them: 'single quoted' (with '' for a quote), "double quoted", or plain. */
export function yamlScalar(raw: string): string {
  const s = raw.trim();
  if (s.startsWith("'")) {
    let out = "";
    for (let i = 1; i < s.length; i++) {
      if (s[i] === "'") {
        if (s[i + 1] === "'") { out += "'"; i++; continue; }
        return out;
      }
      out += s[i];
    }
    throw new ListError(`Unclosed quote: ${s.slice(0, 60)}`);
  }
  if (s.startsWith('"')) {
    const end = s.indexOf('"', 1);
    if (end < 0) throw new ListError(`Unclosed quote: ${s.slice(0, 60)}`);
    return s.slice(1, end);
  }
  return s.replace(/\s+#.*$/, "").trim();
}

/** Juice Shop's data/static/challenges.yml: a top-level list of challenges with name, category, key, disabledEnv. */
export function parseJuiceShopChallenges(text: string): ListItem[] {
  const items: ListItem[] = [];
  let cur: Partial<ListItem> & { disabledEnv: string[] } | null = null;
  let inDisabled = false;
  const close = () => {
    if (!cur) return;
    if (!cur.key || !cur.name || !cur.category) throw new ListError(`A challenge without key, name or category: ${JSON.stringify(cur).slice(0, 120)}`);
    items.push({ key: cur.key, name: cur.name, category: cur.category, disabledEnv: cur.disabledEnv });
    cur = null;
  };
  for (const line of text.replace(/\r\n/g, "\n").split("\n")) {
    if (line === "-" || line.startsWith("- ")) {
      close();
      cur = { disabledEnv: [] };
      inDisabled = false;
      const rest = line.slice(1).trim();
      if (rest) throw new ListError(`Unexpected inline challenge: ${rest.slice(0, 60)}`);
      continue;
    }
    if (!cur) continue;
    const field = /^ {2}([A-Za-z]+):(.*)$/.exec(line);
    if (field) {
      const [, name, value = ""] = field;
      inDisabled = name === "disabledEnv";
      if (name === "key") cur.key = yamlScalar(value);
      else if (name === "name") cur.name = yamlScalar(value);
      else if (name === "category") cur.category = yamlScalar(value);
      continue;
    }
    const entry = /^ {2,6}- (.+)$/.exec(line);
    if (inDisabled && entry) cur.disabledEnv.push(yamlScalar(entry[1]!));
    else if (/^ {2}\S/.test(line)) inDisabled = false;
  }
  close();
  return checked(items);
}

/** NodeGoat's tutorial menu (app/views/tutorial/layout.html): one link per topic, /tutorial/<key>. */
export function parseNodeGoatTutorial(html: string): ListItem[] {
  const items: ListItem[] = [];
  for (const m of html.matchAll(/<a href="\/tutorial\/([a-z0-9]+)"[^>]*>(?:\s*<i[^>]*><\/i>)?\s*([^<]+?)\s*<\/a>/g)) {
    const key = m[1]!;
    items.push({ key, name: m[2]!.replace(/\s+/g, " ").trim(), category: /^a\d+$/.test(key) ? "OWASP Top 10 2013" : "Extra topic", disabledEnv: [] });
  }
  return checked(items);
}

function checked(items: ListItem[]): ListItem[] {
  if (!items.length) throw new ListError("The official list is empty: the pinned file changed shape.");
  const seen = new Set<string>();
  for (const it of items) {
    if (seen.has(it.key)) throw new ListError(`Duplicate key in the official list: ${it.key}`);
    seen.add(it.key);
  }
  return items;
}

export function parseList(format: ListFormat, text: string): ListItem[] {
  return format === "juice-shop-challenges" ? parseJuiceShopChallenges(text) : parseNodeGoatTutorial(text);
}
