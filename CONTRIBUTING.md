# Contributing

Thanks for helping. Bug reports, new key rules, fixes and small improvements are welcome.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on the shape.
- A new key rule needs a fixed, documented shape (a prefix and a length). Keys that look like any random string are not guessed at: a rule that raises false alarms does more harm than good.
- Security problems go to security@yof.io, never to a public issue (see SECURITY.md).

## Working on it

```sh
npm install
npm run typecheck
npm test
npm run build
node dist/bin.js check .
```

Tests use a mocked registry. They never call npm, PyPI or OSV, and they need no key.

## Pull requests

- One change per pull request, with a test.
- Keep the package free of runtime dependencies.
- Never commit keys, tokens, real customer data or private hostnames, not even "just for a test". Build fake values at run time from pieces, the way `test/helpers.ts` does. The test suite scans the repository and fails if it finds a real-looking key.
- yof never prints a full secret. Any new output must show the masked value only.
- Add a line to CHANGELOG.md under "Unreleased".
- Write docs and messages in plain words.

By contributing you agree that your work is licensed under the Apache License 2.0, the licence of this project.
