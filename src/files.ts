/**
 * Which files yof reads. Full mode walks a folder; staged mode asks git for the files in the next commit and reads
 * their STAGED content (what will actually be committed), not the working copy.
 */
import { execFileSync } from "node:child_process";
import { lstatSync, openSync, readSync, closeSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { matchesGitignore, matchesIgnore } from "./config";

/** Folders never walked into. */
export const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", ".nuxt", ".svelte-kit", ".turbo", ".vercel", "coverage", ".venv", "venv", "__pycache__", ".yarn", ".pnpm-store",
  // Hidden tool folders that hold caches or copies of the project, never code of their own (0.3.1).
  ".cache", ".parcel-cache", ".wrangler", ".angular", ".expo", ".nx", ".docusaurus", ".history", ".terraform", ".serverless", ".netlify"]);
/**
 * Folders that are copies of the project made by a coding tool: Claude Code keeps a full git worktree per agent in
 * .claude/worktrees/, so a check read every file once per worktree and stopped at MAX_FILES before the real code
 * (measured on our own repository, 2026-11-09). The rest of .claude/ (settings, MCP config) is still read.
 */
const TOOL_COPY_PATH = /(?:^|\/)\.claude\/worktrees(?:\/|$)/;
/** A `.git` FILE that points into another repository's worktrees folder: this folder is a linked git worktree. */
const WORKTREE_GITDIR = /^gitdir:\s*.*[\\/]worktrees[\\/][^\\/\s]+\s*$/m;

/**
 * True when `dir` (a folder below the one being checked) is a linked git worktree: its `.git` is a file whose gitdir
 * points into a `worktrees/` folder. Its files are a second copy of a branch, so they are not read again. A submodule
 * (gitdir into `modules/`) and a plain nested repository are still read: their code is part of the project.
 */
export function isLinkedWorktree(dir: string): boolean {
  try {
    const dotGit = join(dir, ".git");
    const st = lstatSync(dotGit);
    if (!st.isFile() || st.size > 4096) return false;
    return WORKTREE_GITDIR.test(readFileSync(dotGit, "utf8"));
  } catch { return false; }
}
/** Files bigger than this are skipped. */
export const MAX_FILE_BYTES = 1_000_000;
/** A walk stops after this many files (it says so). */
export const MAX_FILES = 20_000;
/** Lock files hold hashes, not keys, and are large: not scanned. */
const LOCKFILE = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|poetry\.lock|Pipfile\.lock|uv\.lock|Cargo\.lock|composer\.lock|Gemfile\.lock)$/;
const BINARY_EXT = /\.(?:png|jpe?g|gif|webp|avif|ico|bmp|tiff?|psd|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|woff2?|ttf|otf|eot|mp[34]|m4a|wav|ogg|flac|mov|avi|mkv|webm|exe|dll|so|dylib|bin|o|a|class|pyc|wasm|sqlite3?|db)$/i;

export interface SourceFile { path: string; content: string }
export interface FileSet { files: SourceFile[]; skipped: number; truncated: boolean }

/** True when the bytes look binary (a NUL byte in the first 8 KB). */
export const looksBinary = (buf: Buffer) => buf.subarray(0, 8000).includes(0);

export function shouldSkipPath(path: string, ignore: readonly string[], gitignore: readonly string[] = []): boolean {
  if (path.split("/").some((s) => SKIP_DIRS.has(s)) || TOOL_COPY_PATH.test(path)) return true;
  if (LOCKFILE.test(path) || BINARY_EXT.test(path)) return true;
  if (ignore.some((g) => matchesIgnore(path, g))) return true;
  return gitignore.some((g) => matchesGitignore(path, g));
}

function readHead(full: string, size: number): Buffer {
  const fd = openSync(full, "r");
  try { const b = Buffer.alloc(Math.min(size, 8000)); readSync(fd, b, 0, b.length, 0); return b; } finally { closeSync(fd); }
}

/** Every text file under `root` (relative paths with "/"), minus the skip list, ignore entries and .gitignore. */
export function walkFiles(root: string, ignore: readonly string[] = [], gitignore: readonly string[] = []): FileSet {
  const files: SourceFile[] = [];
  let skipped = 0, truncated = false;
  const visit = (dir: string) => {
    let names: string[];
    try { names = readdirSync(dir).sort(); } catch { return; }
    for (const name of names) {
      if (files.length >= MAX_FILES) { truncated = true; return; }
      const full = join(dir, name);
      const rel = relative(root, full).split(sep).join("/");
      let st;
      try { st = lstatSync(full); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        if (SKIP_DIRS.has(name) || TOOL_COPY_PATH.test(rel) || isLinkedWorktree(full) || ignore.some((g) => matchesIgnore(rel, g) || matchesIgnore(`${rel}/`, g)) || gitignore.some((g) => matchesGitignore(`${rel}/\0`, g))) { skipped++; continue; }
        visit(full);
        continue;
      }
      if (!st.isFile()) continue;
      if (shouldSkipPath(rel, ignore, gitignore) || st.size > MAX_FILE_BYTES) { skipped++; continue; }
      try {
        if (looksBinary(readHead(full, st.size))) { skipped++; continue; }
        files.push({ path: rel, content: readFileSync(full, "utf8") });
      } catch { skipped++; }
    }
  };
  visit(root);
  return { files, skipped, truncated };
}

/** Runs git in `cwd`. Throws when git is missing or this is not a repository. */
export type GitRunner = (args: string[], cwd: string) => Buffer;
export const runGit: GitRunner = (args, cwd) => execFileSync("git", args, { cwd, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });

export function gitTopLevel(cwd: string, git: GitRunner = runGit): string {
  return git(["rev-parse", "--show-toplevel"], cwd).toString("utf8").trim();
}

/** Paths staged for the next commit that are added, copied or modified (deleted files are gone, so nothing to check). */
export function stagedPaths(repoRoot: string, git: GitRunner = runGit): string[] {
  return git(["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"], repoRoot).toString("utf8").split("\0").filter(Boolean);
}

/** The added lines of a staged file (for the package check: only dependencies this commit touches). */
export function stagedAddedText(repoRoot: string, path: string, git: GitRunner = runGit): string {
  const diff = git(["diff", "--cached", "-U0", "--no-color", "--", path], repoRoot).toString("utf8");
  return diff.split("\n").filter((l) => l.startsWith("+") && !l.startsWith("+++")).map((l) => l.slice(1)).join("\n");
}

/** The staged files' STAGED content (`git show :path`), minus the skip list, ignore entries, big and binary files. */
export function stagedFiles(repoRoot: string, ignore: readonly string[] = [], git: GitRunner = runGit): FileSet {
  const files: SourceFile[] = [];
  let skipped = 0;
  for (const path of stagedPaths(repoRoot, git)) {
    if (shouldSkipPath(path, ignore)) { skipped++; continue; }
    let buf: Buffer;
    try { buf = git(["show", `:${path}`], repoRoot); } catch { skipped++; continue; }
    if (buf.length > MAX_FILE_BYTES || looksBinary(buf)) { skipped++; continue; }
    files.push({ path, content: buf.toString("utf8") });
  }
  return { files, skipped, truncated: false };
}
