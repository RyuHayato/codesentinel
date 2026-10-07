# Contributing to CodeSentinel

Thanks for helping make CodeSentinel better. This document explains the workflow and the expectations for rule contributions.

## Development setup

```bash
npm install
npm run build       # compile TypeScript to dist/
npm test            # run the vitest suite
```

Run the local scanner against the demo fixture:

```bash
node dist/cli.js examples
```

## Project layout

| Path | Purpose |
| ---- | ------- |
| `src/cli.ts` | argument parsing, exit codes, error messages |
| `src/scanner/fileScanner.ts` | file discovery, ignore handling, inline ignores |
| `src/parser.ts`, `src/helpers.ts` | Babel parsing + AST utilities |
| `src/rules/*` | one file per rule |
| `src/scanner/ruleEngine.ts` | scan pipeline, normalization, severity calc |
| `src/reporters/*` | terminal / JSON / SARIF output |
| `tests/fixtures/vulnerable` | intentionally vulnerable samples (one per rule) |
| `tests/fixtures/safe` | corresponding safe samples that must stay silent |

## Adding or changing a rule

1. **Metadata first.** Every rule needs: ID (`CS-XXX`), title, description, default severity, CWE, detection logic, remediation advice, and fixtures.
2. Write the vulnerable fixture (`tests/fixtures/vulnerable/<name>.js`) and the safe counterpart (`tests/fixtures/safe/<name>.js`).
3. Implement the rule in `src/rules/<name>.ts`, AST-first. Use regexes only for token formats or keyword recognition.
4. Register it in `src/rules/index.ts`.
5. Add the pair to the `CASES` table in `tests/rules.test.ts`.
6. Document it in `RULES.md`.
7. Run `npm test` and `node dist/cli.js examples` — the vulnerable fixture must be flagged and the safe one must not.

Rules must not have side effects, must never execute scanned code, and must handle malformed ASTs gracefully (return `[]`, don't throw).

## Coding guidelines

- TypeScript strict mode is on; keep it that way.
- ESM with `.js` extension on relative imports (`import x from "./foo.js"`).
- Prefer small, pure functions; keep traversal logic in one `traverse` block per rule.
- No new runtime dependencies without discussion — the CLI currently needs only `@babel/*`.

## Testing requirements

- Both vulnerable and safe fixture tests for every rule pass.
- Integration tests in `tests/scanner.test.ts` still pass (severity filters, inline ignores, JSON/SARIF output).
- `npx tsc --noEmit` is clean.

## Pull requests

- Keep changes focused: one rule or one feature per PR.
- Update docs (`README.md`, `RULES.md`, `ARCHITECTURE.md`) alongside code changes.
- CI (`.github/workflows/ci.yml`) must be green.
