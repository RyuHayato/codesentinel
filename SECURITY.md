# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a vulnerability

**Do not open a public issue.** Email the maintainers at `security@codesentinel.dev` with:

- a description of the vulnerability,
- steps to reproduce (a minimal scanner input / fixture),
- the expected and actual behavior,
- the impact and any suggested fix.

We aim to acknowledge reports within 72 hours and ship a fix or mitigation within 14 days for confirmed issues.

## Scope

CodeSentinel is a defensive tool. Reports that qualify include:

- the scanner fails to detect a publicly documented vulnerable pattern (false negative of a supported rule),
- a rule causes the scanner to execute or evaluate attacker-controlled input,
- crashes/hangs when scanning hostile source files (DoS of the scanner itself),
- credential leakage through scanner output or crafted fixtures.

Out of scope: findings CodeSentinel reports about *your* code — those are yours to fix.

## Safe handling of test fixtures

The repository intentionally contains vulnerable examples (`examples/vulnerable-app`, `tests/fixtures/vulnerable`). They are not executed, never deployed, and are used solely to verify detection logic. Do not treat any secret-like string in the repo as a live credential — they are fixtures.
