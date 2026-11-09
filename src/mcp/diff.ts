/**
 * yof_check_diff: scan only what changed. Input is either a unified diff the assistant passes in, or the working
 * tree's own changes (git diff against HEAD, plus new files git does not track yet). Only ADDED lines are scanned, at
 * their real line numbers in the new file, so a finding points at the line the assistant just wrote.
 * Read only: git is asked for a diff and a file list, nothing else.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { runGit, shouldSkipPath, looksBinary, MAX_FILE_BYTES, type GitRunner } from "../files";

/** At most this much diff text is read (larger diffs are refused with a clear message, never cut silently). */
export const MAX_DIFF_BYTES = 1_000_000;
/** At most this many changed files are scanned in one call. */
export const MAX_DIFF_FILES = 300;

export interface ChangedFile {
  path: string;
  /** The added lines: 1-based line number in the new file, and the text. */
  added: { line: number; text: string }[];
  /** True for a file git does not track yet (every line counts as added). */
  untracked?: boolean;
}

export class DiffError extends Error {}

/** Parse a unified diff (git diff, diff -u). Deleted files are skipped: there is nothing left to check. */
export function parseUnifiedDiff(diff: string): ChangedFile[] {
  if (Buffer.byteLength(diff, "utf8") > MAX_DIFF_BYTES) throw new DiffError(`The diff is larger than ${MAX_DIFF_BYTES} bytes. Scan a smaller change, or run yof_check on the folder.`);
  const files: ChangedFile[] = [];
  let cur: ChangedFile | null = null;
  let line = 0;
  let inHunk = false;
  const rows = diff.split(/\r?\n/);
  for (let i = 0; i < rows.length; i++) {
    const raw = rows[i]!;
    if (raw.startsWith("diff --git ")) { cur = null; inHunk = false; continue; }
    // A file header is "--- old" directly followed by "+++ new". Inside a hunk, a removed line "-- x" or an added
    // line "++ x" looks the same on its own, so the pair is what decides.
    if (raw.startsWith("--- ") && (rows[i + 1] ?? "").startsWith("+++ ")) {
      const target = rows[i + 1]!.slice(4).replace(/\t.*$/, "").trim();
      i++;
      inHunk = false;
      if (target === "/dev/null") { cur = null; continue; }
      const path = target.replace(/^"(.*)"$/, "$1").replace(/^b\//, "");
      cur = files.find((f) => f.path === path) ?? null;
      if (!cur) { cur = { path, added: [] }; files.push(cur); }
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) { line = Number(hunk[1]); inHunk = true; continue; }
    if (!cur || !inHunk) continue;
    if (raw.startsWith("+")) { cur.added.push({ line, text: raw.slice(1) }); line++; }
    else if (raw.startsWith(" ")) line++;
  }
  if (files.length > MAX_DIFF_FILES) throw new DiffError(`The diff changes ${files.length} files; yof_check_diff reads at most ${MAX_DIFF_FILES}. Run yof_check on the folder instead.`);
  return files;
}

/**
 * The added lines rebuilt as one text with every other line left empty, so the key rules report the real line
 * numbers of the new file.
 */
export function addedText(f: ChangedFile): string {
  if (!f.added.length) return "";
  const max = f.added[f.added.length - 1]!.line;
  const lines: string[] = new Array(max).fill("");
  for (const a of f.added) lines[a.line - 1] = a.text;
  return lines.join("\n");
}

/** The working tree's changes: `git diff HEAD` (or the staged diff in a repository with no commit yet) plus new files. */
export function workingTreeChanges(root: string, ignore: readonly string[], git: GitRunner = runGit): ChangedFile[] {
  let diff: string;
  try { diff = git(["diff", "HEAD", "--unified=0", "--no-color", "--no-ext-diff"], root).toString("utf8"); }
  catch {
    try { diff = git(["diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff"], root).toString("utf8"); }
    catch { throw new DiffError("This folder is not a git repository, so yof cannot tell what changed. Pass a diff, or run yof_check."); }
  }
  const files = parseUnifiedDiff(diff).filter((f) => !shouldSkipPath(f.path, ignore));
  let untracked: string[] = [];
  try { untracked = git(["ls-files", "--others", "--exclude-standard", "-z"], root).toString("utf8").split("\0").filter(Boolean); } catch { untracked = []; }
  for (const path of untracked) {
    if (files.length >= MAX_DIFF_FILES) break;
    if (shouldSkipPath(path, ignore) || files.some((f) => f.path === path)) continue;
    const abs = join(root, path);
    try {
      if (!existsSync(abs) || !statSync(abs).isFile() || statSync(abs).size > MAX_FILE_BYTES) continue;
      const buf = readFileSync(abs);
      if (looksBinary(buf)) continue;
      files.push({ path, untracked: true, added: buf.toString("utf8").split(/\r?\n/).map((text, i) => ({ line: i + 1, text })) });
    } catch { /* unreadable: skipped */ }
  }
  return files.slice(0, MAX_DIFF_FILES);
}
