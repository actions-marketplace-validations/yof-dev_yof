<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/yof-logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset=".github/assets/yof-logo-light.svg">
    <img alt="yof" src=".github/assets/yof-logo-light.svg" width="220">
  </picture>
</p>

<p align="center"><strong>Security checks for apps you build with AI</strong></p>

<p align="center">Catch leaked keys, risky or made-up packages and access holes between accounts before you ship. Free and open source.</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@yof/cli"><img alt="@yof/cli on npm" src="https://img.shields.io/npm/v/@yof/cli?label=%40yof%2Fcli"></a>
  <a href="./LICENSE"><img alt="Licence" src="https://img.shields.io/npm/l/@yof/cli?label=licence"></a>
  <a href="https://yof.io/benchmark"><img alt="Benchmark" src="https://img.shields.io/badge/benchmark-results-36c98a"></a>
  <a href="https://yof.io"><img alt="yof.io" src="https://img.shields.io/badge/web-yof.io-0c0d11"></a>
</p>

<p align="center">

[![M8ven Score](https://m8ven.ai/badge/mcp/yof-dev-yof-13g2la?v=1a8862798a147668c1539ee48f620f49)](https://m8ven.ai/mcp/yof-dev-yof-13g2la?s=readme) [![mcptry](https://mcptry.com/badge/io.yof/yof)](https://mcptry.com/servers/io.yof/yof)

</p>

**Catch leaked keys and made-up packages before they ship.**

`yof` (yof by sōtem) is yof on your laptop: a small command-line check for apps built with AI assistants (and apps built any other way). It finds secret keys sitting in your code and dependencies that don't exist or imitate popular ones, before they reach a commit, a pull request or production.

It is rules only: exact patterns, fast, and private. It runs on your machine, needs no account, and never sends your code anywhere.

## Try it in 30 seconds

```sh
npx @yof/cli check
```

That checks the current folder. Node 20 or newer. Nothing to configure.

```
yof checked 2 files (profile: balanced)

Keys
  src/config.ts:1  Stripe live secret key  sk_live_FwIw••••••••  (fix now)
  A key that was ever committed or shipped counts as leaked: rotate it in the provider's dashboard,
  then keep it on the server only (an environment variable, not the code).

Packages
  package.json  reqeusts-helper (npm)  (fix now)
    This package doesn't exist on npm. AI assistants sometimes invent package names, and attackers register those names with malware. Check the spelling or remove it.
  package.json  expres (npm)  (fix this week)
    This name is one or two letters away from the popular package express. Make sure you meant this one and not express.

Found 3 problems: 2 to fix now, 1 to fix this week.
Want this on every pull request? https://yof.io
```

yof never prints a key in full. You see the prefix and four characters, enough to know which key it is.

Install it if you use it often:

```sh
npm install --save-dev @yof/cli
npx yof check
```

## Check every commit (pre-commit hook)

```sh
npx @yof/cli hook install
```

This adds `.git/hooks/pre-commit`, which runs `yof check --staged` before each commit. In staged mode yof reads exactly what is about to be committed (the staged content, not your working copy), and checks only the dependencies the commit adds. If something must be fixed now, the commit stops and yof says why.

- Remove it with `npx @yof/cli hook uninstall`.
- Skip it once with `git commit --no-verify`.
- If you already have a pre-commit hook, yof leaves it alone and tells you the one line to add to it.

## Check every push (GitHub Action)

```yaml
# .github/workflows/yof.yml
name: yof
on: [push, pull_request]
permissions:
  contents: read
jobs:
  yof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: yof-dev/yof@v0.2.0
        with:
          path: .          # optional, default .
          offline: false   # optional, true = keys only, no registry lookups
```

The job fails when yof finds something to fix now, so it shows up as a red check on the commit or pull request.

## Settings: `.yof.yml`

Optional. Put it in the root of your repository. It is the same file yof Guard reads on GitHub, so one file covers both.

```yaml
profile: balanced    # relaxed | balanced | strict

ignore:
  - fixtures/        # a folder
  - docs/examples.md # a file
  - "**/*.snap"      # a glob: * stays inside one folder, ** matches any depth
```

| Profile | Shows | Fails (exit 1) on |
| --- | --- | --- |
| `relaxed` | fix now | fix now |
| `balanced` (default) | fix now, fix this week | fix now |
| `strict` | everything, including public keys that are fine | fix now, fix this week |

`--profile strict` on the command line overrides the file. yof also skips `node_modules`, `.git`, `dist`, `build`, `.next` and similar folders, lock files, binary files, files over 1 MB, and what your root `.gitignore` lists (read simply: plain names, folders and globs; `!` lines are not applied).

## Accepted risks: `.yof/accepted.json`

Some findings are fine on purpose, like a revoked test key in a fixture. Accept one from your editor (VS Code: the quick fix "yof: Accept this risk…") with a one-sentence reason, and commit the file it writes:

```json
{ "version": 1, "accepted": [ { "rule": "secret.stripe_test", "file": "tests/pay.ts", "fingerprint": "…", "reason": "A test key in a fixture", "acceptedBy": "Ada", "acceptedAt": "2026-11-07T10:00:00.000Z" } ] }
```

`yof check` still prints an accepted finding, under "Accepted risks", with the reason, who and when; it no longer counts as open or fails the check. The fingerprint covers the rule, the file and the finding's line, so if that line changes the finding is open again. Remove the entry to reopen it. yof's signed reports list these entries in their "Accepted risks and why" appendix.

## What it checks

**Keys** (exact shapes only, so a random hash never raises an alarm):

| Fix now | Fix this week | Fine, public by design (shown in strict) |
| --- | --- | --- |
| Stripe live secret and restricted keys, Stripe webhook secrets | Stripe test secret keys | Stripe publishable keys |
| OpenAI, Anthropic, Groq, Hugging Face, Replicate | An AWS access key ID on its own | Firebase web keys |
| AWS access key with its secret next to it | Browser-visible settings named like a secret (`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_` … `SECRET` / `PASSWORD` / `PRIVATE`) | Supabase anon keys |
| Supabase service-role keys (the JWT is decoded, not guessed) | | |
| GitHub tokens, Slack tokens and webhook URLs | | |
| Resend, SendGrid, Mailgun, Twilio | | |
| Private keys (`BEGIN … PRIVATE KEY`) | | |

Placeholders such as `sk_live_xxxxxxxx` or `sk_live_your_key_here` are skipped, so docs and examples stay quiet.

**Packages** in `package.json`, `requirements*.txt` and `pyproject.toml`:

- **Made up**: the name does not exist on npm or PyPI. AI assistants sometimes invent package names, and attackers register those names with malware. (fix now)
- **Lookalike**: one or two letters away from a popular package (`expres`, `reqeusts`) and not well established itself. (fix this week)
- **Brand new**: first published in the last 14 days. (fix this week)
- **Known advisory**: an exact pinned version with a published advisory in the OSV database. High and critical are fix now, the rest fix this week.

If a registry does not answer, yof says so and claims nothing about that package.

**What it does not do**: it does not read git history, scan your running website, check your database rules, or review code logic. Those live in the yof app and Guard (below).

## Attack your own app: `yof attack`

`yof attack` tests YOUR OWN running app the way an attacker would, with two test accounts you create for it (A and B, plus an admin account if you have one). It reports only what it saw happen twice, and turns each finding into a regression test.

```sh
npx @yof/cli attack http://localhost:3000
npx @yof/cli attack --mode light
```

What it tries:

| Group | What it does |
| --- | --- |
| `auth` | Opens each signed-in route with no sign-in and with a broken token |
| `tenant` | Account A creates a test record, account B reads it by id, finds it in a list and changes it |
| `rbac` | Opens each admin route as a normal member |
| `ai` | Your own assistant route: asks for its hidden instructions, types a command into a message, hides one in a record it reads (an HTML comment, a link title, a "system" field), asks it for account B's record, to rename account B's record, and for admin data; checks whether account B's record steers account A's general answers (RAG poisoning); asks it to answer with live HTML or a picture link, to drop its rules for one harmless word, for its internal addresses and tool list, and to send an email to a `.invalid` address; and, only with `"limits": true`, sends 10 tiny messages two at a time and asks for one very long story |
| `surface` | Open redirects, security headers, the sign-in cookie flags, and (when you turn it on) twelve wrong passwords in a row |

Safe by design, and enforced in the code:

- **Only a host you proved is yours.** `localhost`; a preview that GitHub reports as a successful deployment of this repository for the commit under test; or your live host with the proof token from your yof app (`YOF_VERIFY_TOKEN`, the same file, meta tag or DNS record the yof app uses).
- **Written consent per app**, word for word in the config, naming the app.
- **Never production** unless the config turns it on for this app. Then a light run (read-only) may go any time, and a full run only inside the window you set.
- **No destructive requests.** GET and HEAD, plus POST only to the create, sign-in and assistant routes you name. PATCH, PUT and DELETE only touch records the run created itself, and those are deleted at the end, always.
- **Hard budgets**: 300 requests and 110 seconds by default (at most 2,000 and 15 minutes), a steady pace, a 10 second timeout. When a budget runs out the run stops and says so, after deleting its test records.
- **Stop it any time.** Ctrl+C (SIGINT) or SIGTERM, as an editor or CI sends on cancel: nothing new is sent, the test records the run created are deleted (within 10 seconds), it says what it deleted and anything it could not, and exits 130 or 143. A second Ctrl+C quits at once.
- **Mild, fixed assistant messages.** The assistant probes are the same fixed texts every run (the OWASP Top 10 for LLM Applications 2025 families). None asks for harmful content: the jailbreak asks only for a harmless test word, picture links point at `yof-canary.invalid` and the email probe at an `example.invalid` address, which never resolve. Rules decide every finding, never a model. For internal details only the kind is kept (a private address, a connection string, a server path, a tool list), never the text.
- **Usage limits are opt-in.** `"limits": true` on an `ai` entry adds a burst of 10 tiny messages and one request for a very long story, because it costs you a little model use. Without it, nothing of the kind is sent.
- **Your test accounts stay in your CI secrets.** The config names environment variables, never a token or password, and nothing is stored by yof.

The config lives at `.yof/attack.json`:

```json
{
  "app": "shop.example.com",
  "consent": "I own shop.example.com and allow yof attack to test it and its preview builds with my own test accounts.",
  "accounts": {
    "a": { "header": "Authorization", "env": "YOF_ATTACK_A" },
    "b": { "header": "Authorization", "env": "YOF_ATTACK_B" },
    "admin": { "header": "Authorization", "env": "YOF_ATTACK_ADMIN" }
  },
  "routes": ["/api/me", "/api/notes"],
  "admin": ["/api/admin/users"],
  "objects": [{
    "create": { "path": "/api/notes", "body": "{\"title\":\"{{marker}}\"}" },
    "idPath": "id",
    "read": "/api/notes/{id}",
    "list": "/api/notes",
    "update": { "method": "PATCH", "path": "/api/notes/{id}", "body": "{\"title\":\"{{marker}}\"}" },
    "delete": "/api/notes/{id}"
  }],
  "ai": [{
    "path": "/api/chat", "body": "{\"message\":\"{{message}}\"}", "replyPath": "reply",
    "ingest": { "create": { "path": "/api/notes", "body": "{\"title\":\"{{document}}\"}" }, "idPath": "id", "delete": "/api/notes/{id}" },
    "limits": false
  }],
  "surface": { "redirectPaths": ["/login"], "rateLimit": false },
  "production": { "enabled": false, "window": "02:00-04:00" },
  "budget": { "requests": 300, "seconds": 110, "perSecond": 8 }
}
```

An account can also sign in with an email and password from your CI secrets: `{ "login": { "path": "/api/login", "body": "{\"email\":\"{{email}}\",\"password\":\"{{password}}\"}", "tokenPath": "token" }, "emailEnv": "YOF_ATTACK_A_EMAIL", "passwordEnv": "YOF_ATTACK_A_PASSWORD" }`. Without `tokenPath` the session cookie is used.

### Regression tests

With `--write-tests`, every confirmed finding becomes a test in your own test framework (Vitest, Jest, Playwright or pytest, detected from your repository; a `node --test` file otherwise). It replays the recorded attack and expects the opposite: the test fails while the attack still works and passes once it is fixed. No AI writes it. It skips itself unless `YOF_ATTACK_TARGET` is set, so your normal test run is unaffected.

### On every pull request

```yaml
# .github/workflows/yof-attack.yml
name: yof attack
on: [pull_request]
permissions:
  contents: read
  deployments: read
  pull-requests: write
  issues: write
jobs:
  attack:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: yof-dev/yof/attack@v0.2.0
        env:
          YOF_ATTACK_A: ${{ secrets.YOF_ATTACK_A }}
          YOF_ATTACK_B: ${{ secrets.YOF_ATTACK_B }}
          YOF_ATTACK_ADMIN: ${{ secrets.YOF_ATTACK_ADMIN }}
```

It waits for the preview deployment of the pull request, then attacks only what the change can reach: the routes of the files it changes (Next.js app and pages routes, Hono and Express route files, and the routes that import a changed helper). The comment says "partial run: N attack groups". When shared code changes (middleware, auth, permissions, database access, dependencies) or the mapping is unsure, it runs everything and says why. Pull requests from forks are skipped.

The comment lists what was found. Comment `/patch apply` on the pull request and the yof GitHub App commits the regression tests (and the security-header fix, when one applies) to the pull request's own branch. It works only for people with write access, never on a fork, never on the default branch, and never force-pushes.

Set `YOF_HOOK_URL` (the deploy hook address from your yof app) and `yof attack --upload` sends the masked findings to your yof app, where they show with your other findings.

### Options

```
yof attack [url]          The address to test (or YOF_ATTACK_TARGET)
--config <file>           The attack config (default .yof/attack.json)
--mode <full|light>       light = read-only
--base <branch>           Pull request run: attack only what the change can reach
--write-tests             Write a regression test for every confirmed finding
--comment <file>          Write the pull-request comment to this file
--upload                  Send the masked results to your yof app (YOF_HOOK_URL)
--json                    Machine-readable output
```

## Inside your AI builder: `yof mcp`

`yof mcp` runs yof as a local MCP server (stdio), so the AI that writes your code can check it before it says "done". It works with any MCP client that starts a local command. The easiest way to connect is "Connect your AI builder" in the yof dashboard, which writes the config for you. By hand:

```
claude mcp add yof -- npx -y @yof/cli mcp          # Claude Code
codex mcp add yof -- npx -y @yof/cli mcp           # Codex CLI
```

Cursor, VS Code, Windsurf and Claude Desktop take the same command in their MCP settings: `npx -y @yof/cli mcp`. Always use the scoped name `@yof/cli`: the unscoped npm name `yof` belongs to someone else.

The tools:

| Tool | What it does | Where it runs |
| --- | --- | --- |
| `yof_check` | Scan the project folder (or a folder inside it) | Your machine |
| `yof_check_diff` | Scan only the lines that changed (a diff you pass, or the working tree against the last commit, plus new files) | Your machine |
| `yof_explain` | What a rule means, why it matters, the safe fix | Your machine |
| `yof_fix_prompt` | Exact fix steps for one finding | Your machine |
| `yof_verify` | Re-scan one file and say fixed or not | Your machine |
| `yof_findings` | Open findings from your yof.io account | yof.io, needs `YOF_API_KEY` |
| `yof_patch_status` | Patch's open pull requests and their CI state | yof.io, needs `YOF_API_KEY` |
| `yof_lessons` | Notes from merged Patch fixes | yof.io, needs `YOF_API_KEY` |

Every answer starts with a line that says it is untrusted data from the scanned project, so text inside your files is never read as instructions. Secret values always come back as a short prefix plus `REDACTED`. Limits: a diff is at most 1 MB and 300 files, a scan stops after 90 seconds, and paths must stay inside the project folder.

`YOF_API_KEY` is made by the yof dashboard for one connection and can be revoked there at any time. With it, the server sends one ping when it starts (so the dashboard can show that the connection works) and, for the three account tools, the tool name and its arguments (ids and rule ids). Never code or file contents.

## Privacy

`yof check` runs on your machine. It reads files, matches patterns and prints the result. Your code, file names and keys never leave your computer. (`yof attack` sends requests only to the app you proved is yours, and to GitHub's API to read this repository's deployments.)

The only network calls of `yof check` are package-registry lookups: package names (and exact pinned versions) go to `registry.npmjs.org`, `api.npmjs.org`, `pypi.org` and `api.osv.dev`, and to no other host. Skip them with `--offline`, and yof makes no network calls at all. There is no telemetry.

## Options

```
yof check [path]       Check a folder (default: the current one)
yof check --staged     Check only the files staged for the next commit
yof hook install       Run "yof check --staged" before every commit
yof hook uninstall     Remove that hook
yof diff               Check only what changed since the last commit (plus new files)
yof mcp [path]         Run yof as a local MCP server for AI builders
yof import <file> [path]  Read a findings.json and check each record's file and line here

--offline              Skip the package-registry lookups (keys only)
--json                 Machine-readable output (masked values only)
--format <name>        text | json | findings-json
--profile <name>       relaxed | balanced | strict
-v, --version          Print the version
-h, --help             Print help
```

Exit codes: `0` nothing to fix, `1` something to fix (per the profile), `2` usage or setup error.

With `--json`, every finding also carries `why` (what can happen, in plain words) and `fixPrompt` (what to change, ready to paste into the AI assistant that wrote the code, with the masked value only). The yof editor plugins show these as they are.

### findings.json (Cloudflare's security-audit format)

`yof check --format findings-json` writes the findings in the `findings.json` format of Cloudflare's security-audit skill (MIT licensed, see NOTICE), so the tools that read it can read yof too. Every record has a verdict: `confirmed` when the exact evidence is in the folder (a key in a provider's format, a package the registry does not have, an installed version an advisory names) and `needs_validation` when it is likely but not shown (a name one or two letters from a popular package, a package only days old). Keys that are public by design are hardening notes, not findings, and are left out. Nothing `yof check` finds is rated critical: it never runs your code or reaches a live app, so "high" is the most.

`yof import findings.json [path]` reads a findings.json strictly (a record with an unknown field, a missing field, a wrong value or a severity above its demonstrated impact is named and left out, never repaired) and checks each record against the folder, read only: does the file exist inside the folder, and does the line exist. Nothing is run and nothing is sent. Exit `2` when the file does not match the schema, `1` when a record needs a look, `0` when only rejected records are left.

You can also use it as a library: `import { scanText, checkPackages, runCheck } from "@yof/cli"`.

## Want more?

yof is the security watcher for AI-built apps. This CLI is its fast, private, rules-based part. The rest lives at [yof.io](https://yof.io):

- **The yof app** at [yof.io](https://yof.io) watches your live app, explains every finding in plain words, says what the fix is, and keeps track of your app over time.
- **Guard** reviews every pull request on GitHub and leaves one clear comment: [github.com/apps/yof-by-sotem](https://github.com/apps/yof-by-sotem).
- **Patch**, yof's AI agent, writes the fixes for you as a draft pull request.

## Contributing

Issues and pull requests are welcome, especially new key rules with a documented shape. See [CONTRIBUTING.md](./CONTRIBUTING.md). Security problems: [SECURITY.md](./SECURITY.md).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE). yof is published by Mondaily Ltd.
