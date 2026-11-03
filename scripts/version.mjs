#!/usr/bin/env node
/**
 * One version everywhere, before a release tag.
 *
 *   node scripts/version.mjs 0.2.1           set the version in package.json, both Actions' default `version` input and
 *                                            the CHANGELOG (the "Unreleased" notes move under "## 0.2.1 (YYYY-MM-DD)")
 *   node scripts/version.mjs --check 0.2.1   change nothing; exit 1 unless all of them already say 0.2.1
 *                                            (the release workflow runs this before it publishes anything)
 *
 * No dependencies, no network. Prints what it changed.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const FILES = { pkg: "package.json", action: "action.yml", attack: "attack/action.yml", changelog: "CHANGELOG.md" };
const read = (f) => readFileSync(join(ROOT, f), "utf8");

/** The `version` input's default in an action.yml (the @yof/cli version the Action runs). */
export function actionVersion(yml) {
  const m = yml.match(/\n {2}version:\n(?: {4}.*\n)*? {4}default: "([^"]+)"/);
  return m ? m[1] : null;
}
export function setActionVersion(yml, v) {
  if (!actionVersion(yml)) throw new Error("no version input with a default");
  return yml.replace(/(\n {2}version:\n(?: {4}.*\n)*? {4}default: ")[^"]+(")/, `$1${v}$2`);
}

/** Has the CHANGELOG a section for this version (with or without a date)? */
export const changelogHas = (md, v) => new RegExp(`^## ${v.replace(/\./g, "\\.")}(?: \\(|$)`, "m").test(md);

/**
 * Moves the notes under "## Unreleased" into the version's section. A section written ahead of time
 * ("## 0.2.0 (not published yet)") gets the date instead and keeps its notes, with the unreleased notes on top.
 */
export function releaseChangelog(md, v, date) {
  const lines = md.split("\n");
  const un = lines.findIndex((l) => l.trim() === "## Unreleased");
  if (un < 0) throw new Error('CHANGELOG.md has no "## Unreleased" heading');
  let end = lines.findIndex((l, i) => i > un && l.startsWith("## "));
  if (end < 0) end = lines.length;
  const notes = lines.slice(un + 1, end).join("\n").trim();
  const rest = lines.slice(end);
  const heading = `## ${v} (${date})`;
  const at = rest.findIndex((l) => new RegExp(`^## ${v.replace(/\./g, "\\.")}(?: \\(|$)`).test(l));
  if (at >= 0) {
    if (/^## \S+ \(\d{4}-\d{2}-\d{2}\)$/.test(rest[at])) throw new Error(`${v} is already released in CHANGELOG.md`);
    rest.splice(at, 1, heading, ...(notes ? ["", notes] : []));
  } else {
    if (!notes) throw new Error('Nothing under "## Unreleased" to release');
    rest.unshift(heading, "", notes, "");
  }
  return [...lines.slice(0, un + 1), "", ...rest].join("\n").replace(/\n{3,}/g, "\n\n");
}

export function state() {
  return {
    pkg: JSON.parse(read(FILES.pkg)).version,
    action: actionVersion(read(FILES.action)),
    attack: actionVersion(read(FILES.attack)),
  };
}

function main(argv) {
  const check = argv[0] === "--check";
  const v = (check ? argv[1] : argv[0])?.replace(/^v/, "");
  if (!v || !SEMVER.test(v)) {
    console.error("Usage: node scripts/version.mjs <x.y.z>   or   node scripts/version.mjs --check <x.y.z>");
    return 2;
  }
  if (check) {
    const s = state();
    const md = read(FILES.changelog);
    const wrong = Object.entries(s).filter(([, got]) => got !== v).map(([k, got]) => `${FILES[k]} says ${got}`);
    if (!changelogHas(md, v)) wrong.push(`CHANGELOG.md has no "## ${v}" section`);
    if (wrong.length) {
      console.error(`Version ${v} is not ready to release:\n  ${wrong.join("\n  ")}\nRun: node scripts/version.mjs ${v}`);
      return 1;
    }
    console.log(`Version ${v}: package.json, action.yml, attack/action.yml and CHANGELOG.md agree.`);
    return 0;
  }
  const pkg = JSON.parse(read(FILES.pkg));
  pkg.version = v;
  writeFileSync(join(ROOT, FILES.pkg), `${JSON.stringify(pkg, null, 2)}\n`);
  for (const f of [FILES.action, FILES.attack]) writeFileSync(join(ROOT, f), setActionVersion(read(f), v));
  const md = read(FILES.changelog);
  const date = new Date().toISOString().slice(0, 10);
  writeFileSync(join(ROOT, FILES.changelog), releaseChangelog(md, v, date));
  console.log(`Set ${v} in package.json, action.yml, attack/action.yml and CHANGELOG.md (${date}).`);
  console.log(`Next: commit, then tag v${v} on github.com/yof-dev/yof (the release workflow publishes from the tag).`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) process.exitCode = main(process.argv.slice(2));
