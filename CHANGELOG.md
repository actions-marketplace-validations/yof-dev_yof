# Changelog

All notable changes to `@yof/cli`. The format follows Keep a Changelog, and versions follow Semantic Versioning.

## Unreleased

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
