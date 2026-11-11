# Changelog

All notable changes to `@yof/cli`. The format follows Keep a Changelog, and versions follow Semantic Versioning.

## Unreleased

- Security: a Vercel, Netlify or Cloudflare Pages preview counts as this repository's own only when the deployment status was written by that platform's own GitHub app. A repository name and a deployment status are both things anyone can write, so the name alone no longer proves the address. If you deploy from your own workflow instead of the platform's GitHub app, test a host on your app's own domain (proven with `YOF_VERIFY_TOKEN`).
- Security: "the same site as your app" no longer treats two customers of one hosting provider as one site. On `github.io`, `vercel.app`, `netlify.app`, `pages.dev`, `web.app`, `herokuapp.com`, `onrender.com`, `fly.dev`, `workers.dev` and similar, the site is your own name under the suffix; on `amazonaws.com`, `azurewebsites.net`, `run.app` and similar, only the exact host. The list is built in (no download).
- Privacy: `yof attack` evidence no longer holds a piece of your app's answer. Before, the first 200 characters of an answer were kept (keys and email addresses masked), so a name, a phone number or an address from a real record could reach the report, the pull-request run log and the yof app. Now the evidence is the shape of the answer in yof's own words (`a JSON object with 3 fields (id, email, plan), 71 characters`), a leaked-instructions finding keeps only the length of the answer, and phone numbers and other long numbers are masked like keys and email addresses.
- Security: `.yof/attack.json` may only name environment variables that start with `YOF_ATTACK_` (`env` in a header, `emailEnv`, `passwordEnv`, `login.totpEnv`). Before, a changed config (a pull request from a hostile branch, for example) could name `GITHUB_TOKEN` or any other CI secret and have it sent to the target. A config that names another variable is refused with a message that names the field. If your variables have other names, rename them (and the CI secrets you map to them) to `YOF_ATTACK_...`.
- `yof attack`: read-only member tests. With a `viewer` account the `rbac` group opens each admin route as the viewer and, in a full run, has the viewer try to create a test record and to change and delete a test record of account A. What works is reported as the new rule `attack.viewer_escalation`, confirmed twice, with a regression test. The viewer must be in account A's workspace.
- `yof attack --scope-doc`: prints the scope and rules-of-engagement document for your config (Markdown): hosts in scope, test accounts by role (variable names only), mode and production window, budget, the test groups that will run and those skipped and why, what is never done, and a signature block. It reads the config only and sends nothing.
- Security: `yof attack` no longer treats a GitHub deployment status alone as proof. The deployment's environment address must also be this repository's own: a Vercel, Netlify or Cloudflare Pages preview named after the repository, or a host on the config app's own domain after the app is proven with `YOF_VERIFY_TOKEN`. Only `environment_url` counts (not `target_url`). An environment named `prod`, `production` or `live`, and the app's own host, are production, so the production switch and the night window apply. A plain-http `GITHUB_API_URL` is refused.
- `yof attack`: accounts are optional. With no accounts the public tests run and each skipped group says what it needs (account A for sign-in and admin tests, A and B for the tenant barrier). Before, a config without A and B was refused.
- `yof attack`: one account can send several headers (`headers: [{ header, env }, ...]`, up to 8), for APIs that need a session cookie and a workspace header together. Header values stay out of reports, logs and recorded exchanges.
- `yof attack`: a sign-in account can use a one-time code from an authenticator secret (`login.totpEnv` and `{{totp}}` in the body, RFC 6238), and signs in fresh on each run, so short sessions need no stored token. Generated regression tests sign in the same way.
- `yof attack`: optional `viewer` account (a member who may only read).
- `yof attack`: an account entry with an unknown key (a `password` or `token` written into the file) is refused with a message that names the key.

## 0.3.2 (2026-11-10)

- MCP tools explain themselves: every tool description starts with what it does, says when to use it and which sibling tool to use instead, what leaves your computer (code never; package names and versions only, unless `offline` is true; the account tools need `YOF_API_KEY`) and what an empty result means. Parameter descriptions say their defaults and limits.
- Every MCP tool declares an `outputSchema` and returns `structuredContent` next to the text answer (secrets stay redacted). An account tool now reports an error when yof.io answers without data, instead of an empty result.

## 0.3.1 (2026-11-09)

- Every MCP tool states the four hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) explicitly.
- Development: vitest 3.2.7 (fixes GHSA-5xrq-8626-4rwp and GHSA-82fw-gwwq-j7x9 in the test tooling; nothing ships to users).
- `yof check` reads each file once: it no longer walks into linked git worktrees (a folder whose `.git` file points into `worktrees/`), `.claude/worktrees/`, or tool caches (`.cache`, `.parcel-cache`, `.wrangler`, `.angular`, `.expo`, `.nx`, `.docusaurus`, `.history`, `.terraform`, `.serverless`, `.netlify`). On our own repository the walk read four copies of the code and stopped at 20,000 files before reaching it. Submodules and the rest of `.claude/` are still read.
- Keys in a repository follow the same rule as the yof app: a browser setting flagged only for its secret-sounding name is not reported in tests, fixtures, mocks, examples, docs or demos; a value that starts like a placeholder (`demo`, `test`, `${...}`) or sits on a line that says `EXAMPLE` is not a key. Provider-shaped keys (`sk_live_`, `ghp_`, ...) are still reported everywhere. Applies to `yof check` and `yof_check_diff`.

- Security: the zod bundled with `yof mcp` (through the MCP SDK) moves from 3.25.76 to 4.6.7. GHSA-mrhx-c7xc-m3w5 (memory exhaustion while validating oversized constrained arrays) affects every zod before 4.6.6 and no 3.x release fixes it. The MCP SDK 1.32.2 accepts `^3.25 || ^4.0`; yof's own code does not import zod. 0.3.0 on npm still bundles 3.25.76 until the next release.

## 0.3.0 (2026-11-09)

- findings.json, the format of Cloudflare's security-audit skill (MIT, credited in NOTICE): `yof check --format findings-json` writes it with yof's verdicts (confirmed or needs validation; public-by-design keys are hardening notes and are left out; nothing is rated above high), and `yof import <file> [path]` reads one strictly and checks each record's file and line against the folder, read only. `--format text|json` is the same as before.
- `yof mcp [path]`: yof as a local MCP server over stdio, on the official MCP SDK (pinned). Tools: `yof_check`, `yof_check_diff`, `yof_explain`, `yof_fix_prompt`, `yof_verify`, and with `YOF_API_KEY` from the yof dashboard `yof_findings`, `yof_patch_status` and `yof_lessons`. Local scans never upload code. Every answer is labelled as untrusted data from the scanned project, secrets come back as a prefix plus REDACTED, and inputs are checked against strict schemas with limits on size, files and time. The SDK is bundled at build time, so installing the CLI still installs no other package, and only `yof mcp` loads it.
- `integrations/claude-code`: a Claude Code plugin (the MCP server, a "check before done" skill and a hook that runs the diff check), and `integrations/claude-desktop`: an MCP bundle manifest.

- `yof check`: one problem, one finding. When several rules catch the same value in a file (a Stripe key in a `VITE_..._SECRET` setting), the most urgent and most specific rule stays and the others are listed as `alsoMatched`; counts and the exit code see it once. A dependency named in several workspace manifests is asked once and reported once, with every manifest in `files`.
- `yof check --json`: `filePrompts`, one combined prompt per file with two or more problems ("Fix these N problems in <file> together", numbered, each with its rule and line), so an AI assistant edits the file once. The single prompts stay.
- Accepted risks in the repository: `yof check` reads `.yof/accepted.json` (written by the editor extensions' "Accept this risk" command, committed with your code). An accepted finding is still printed, under "Accepted risks", with the reason, who accepted it and when; it no longer counts as open or fails the check. Each entry matches one finding by a fingerprint of its rule, file and line, so a changed line is open again. `--json` adds `fingerprint` and `accepted` to every finding and `acceptedCount` to the report.
- `yof attack`, AI group: the rest of the OWASP Top 10 for LLM Applications 2025 that a runner can test with your own accounts. New rules: `attack.unsafe_output` (live HTML or a picture link in the answer), `attack.rag_poisoning` (account B's note with a hidden instruction steers account A's general answer), `attack.jailbreak` (a fixed "developer mode" message that asks only for a harmless word), `attack.data_disclosure` (internal addresses, connection strings, server paths or the tool list; only the kinds are kept), `attack.tool_cross_tenant_write` (account A's assistant renames account B's test record), `attack.excessive_agency` (it says it sent an email to an `example.invalid` address without asking) and `attack.ai_no_limit` (opt-in with `"limits": true`: 10 tiny messages two at a time and one very long story). Hidden instructions now also come in a markdown link title and a "system" field. Fixed texts, confirmed twice, rules only.
- Regression tests understand the new checks (`no_unsafe_markup`, `not_unlocked`, `no_internal`, `no_claimed_action`, `short_answer`), in JavaScript and Python.

## 0.2.0 (2026-11-02)

- `yof attack [url]`: attacks your own app with your own test accounts: sign-in bypass, one account reading or changing another's records by id, members on admin routes, your assistant (hidden-instruction extraction, typed and hidden commands, its tools reading other accounts' records or admin data), open redirects, security headers, sign-in cookie flags and sign-in rate limits. Only proven hosts (localhost, a GitHub deployment of the repository, or the yof proof token), written consent per app, production only when turned on (full runs only in its window), no destructive requests, hard request and time budgets, every test record deleted. Findings are reported only when they show twice.
- Stopping `yof attack` (Ctrl+C or SIGTERM) sends nothing new, deletes the run's test records within 10 seconds, says what was deleted or left, and exits 130 / 143. A second signal quits at once.
- `--write-tests`: every confirmed finding becomes a regression test in Vitest, Jest, Playwright, pytest or `node --test`, from the recorded attack with the expectation inverted. No AI.
- `--base <branch>`: pull-request runs attack only what the change can reach, and everything when shared code changes.
- `yof check --json`: every finding also carries `why` (plain words) and `fixPrompt` (ready to paste into an AI assistant, masked value only), for the editor plugins.
- Releases are published from a version tag by GitHub Actions with npm provenance (`.github/workflows/release.yml`).
- GitHub Action `yof-dev/yof/attack` (`attack/action.yml`): runs on pull requests against the preview deployment, skips forks, leaves one comment; `/patch apply` on the pull request commits the regression tests to its branch through the yof App.

## 0.1.0

First release.

- `yof check [path]`: finds leaked keys (Stripe, OpenAI, Anthropic, AWS, GitHub, Slack, Supabase service-role, Resend, SendGrid, Mailgun, Twilio, Hugging Face, Groq, Replicate, private keys and browser settings named like secrets), masked in every output.
- Package check for package.json, requirements.txt and pyproject.toml: made-up names, lookalikes of popular packages, packages published in the last 14 days, and known advisories for exact pins (OSV).
- `yof check --staged` for the pre-commit hook: reads the staged content and checks only the dependencies the commit adds.
- `yof hook install` / `yof hook uninstall`, which never overwrite a hook that is not yof's.
- `.yof.yml` with `profile` (relaxed, balanced, strict) and `ignore`, the same file yof Guard reads.
- `--offline`, `--json`, `--profile`, and exit codes 0 / 1 / 2.
- GitHub Action (`action.yml`).
