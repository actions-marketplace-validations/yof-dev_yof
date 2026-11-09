# Security policy

## Reporting a problem

Please report security problems privately. Do not open a public issue.

- Email **security@yof.io**, or
- use GitHub's private vulnerability reporting on this repository (Security > Report a vulnerability).

Tell us what you found, how to reproduce it, and what an attacker could do with it. We reply within three working days and keep you posted until it is fixed. We credit reporters who want to be credited.

## Scope

This repository is the `yof` command-line tool and its GitHub Action only: the key rules, the package check, the pre-commit hook and the output. Examples of what we want to hear about:

- yof printing a secret in full anywhere (text output, JSON, errors).
- yof sending anything other than package names and pinned versions to the network, or reaching a host other than registry.npmjs.org, api.npmjs.org, pypi.org and api.osv.dev.
- A file or manifest that makes yof run code, write outside `.git/hooks/pre-commit`, or overwrite a hook that is not its own.

Problems in the yof app at yof.io or in yof Guard are welcome at the same address.

A key yof misses, or a false alarm, is a normal bug: please open an issue (with a fake value, never a real key).

## Supported versions

Security fixes go into the latest minor release of `@yof/cli`.

## If yof found a real key

Treat it as leaked even if the repository is private: rotate it in the provider's dashboard first, then remove it from the code and keep it on the server only. Removing it from the latest commit does not remove it from git history.
