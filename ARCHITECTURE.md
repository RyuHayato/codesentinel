# CodeSentinel Architecture

CodeSentinel is organized as a linear pipeline with clear stage boundaries. Each stage is independently testable and replaceable.

```
CLI (src/cli.ts)
  ↓
File Scanner (src/scanner/fileScanner.ts)
  ↓
Parser / AST layer (src/parser.ts, src/helpers.ts)
  ↓
Rule Engine (src/rules/*, src/scanner/ruleEngine.ts, src/config.ts)
  ↓
Finding Normalizer (src/scanner/ruleEngine.ts)
  ↓
Severity Calculator (config overrides + rule defaults; src/types.ts)
  ↓
Reporters (src/reporters/{terminal,json,sarif}.ts)
```

## Stage details

### CLI — `src/cli.ts`

Parses arguments (`--severity`, `--format`, `--fail-on`, `--config`, `--baseline`, `--write-baseline`, `--list-rules`, `--no-color`, `--version`), resolves the scan root, loads the config, invokes the scanner, applies baseline suppression, picks a reporter, and computes the exit code. All user-facing error messages are produced here. Invalid flags fail fast with a helpful message.

### File Scanner — `src/scanner/fileScanner.ts`

Recursively walks the target directory. Always skips `node_modules`, `.git`, `dist`, `build`, `coverage`, etc. Honors the `ignore` list from config. Collects `.js/.jsx/.ts/.tsx/.mjs/.cjs` files plus `package.json` files (which feed the dependency rule). `parseInlineIgnores` extracts `// codesentinel-ignore` directives used later for suppression.

### Parser / AST layer — `src/parser.ts`, `src/helpers.ts`

Uses `@babel/parser` (Babel AST) with `typescript` and `jsx` plugins selected per file extension. Returns a typed error with line/column on parse failure (surfaced as a non-fatal `CS-E01` info finding so one bad file never aborts a scan). `helpers.ts` contains shared AST utilities: callee name resolution (`fs.readFileSync`, `crypto.createHash`), string literal extraction, dynamic-expression detection, and user-input (`req.query/...`) detection.

**Extension point for Python:** add a second parser module producing a normalized node shape, register it by file extension, and implement Python rules against that AST. The rule engine, normalizer, config, and reporters are language-agnostic.

### Rule Engine — `src/rules/*`, `src/scanner/ruleEngine.ts`

Each rule is a plain object implementing the `Rule` interface:

```ts
interface Rule {
  id: string;                 // "CS-001"
  title: string;
  description: string;
  severity: Severity;         // default, overridable via config
  cwe: string;                // "CWE-89"
  remediation: string;
  check(ctx: RuleContext): RawFinding[];           // AST-based detection
  checkPackageJson?(filePath, pkg): RawFinding[];  // dependency auditing
}
```

`ruleEngine.scan()` runs every enabled rule over each parsed file, applies inline-ignore suppression, catches per-rule crashes, and de-duplicates raw findings. Rules are registered in `src/rules/index.ts` (`ALL_RULES`).

Detection is AST-first: rules visit `CallExpression`, `MemberExpression`, `VariableDeclarator`, etc. Regex is used only where it genuinely belongs (token formats in `CS-002`, SQL keyword recognition in `CS-003`).

### Finding Normalizer

Converts `RawFinding` (rule output: location + message) into a full `Finding` by joining with rule metadata (title, description, CWE, remediation) and applying severity overrides. Unknown/internal findings (parse errors, rule crashes) get a safe fallback metadata block. A separate crash path (`CS-ERR`) prevents a broken rule from inheriting the crashed rule's severity/metadata.

### Baseline — `src/baseline.ts`

Fingerprints each finding (`ruleId|filePath|line|column`) and, when `--baseline` is used, strips findings already recorded in the baseline file. `--write-baseline` snapshots the current findings so existing tech debt can be grandfathered in while CI blocks new ones.

### Severity Calculator — `src/types.ts`, `src/config.ts`

Final severity = config override for the rule if present, else the rule's per-finding severity, else the rule default. Findings below `--severity` are filtered out, results are sorted critical→info, and `--fail-on` drives the process exit code (0 = pass, 1 = threshold hit, 2 = usage/scan error).

### Reporters — `src/reporters/`

- `terminal` — colorized, grouped findings with snippet + fix advice and a summary block; respects `NO_COLOR` and TTY detection.
- `json` — stable machine-readable document (`tool`, `version`, `summary`, `findings[]`).
- `sarif` — SARIF v2.1.0, compatible with GitHub code scanning and most IDE integrations.

## Data flow

```
files[] → AST[] → RawFinding[] → Finding[] → filter/sort/dedupe → ReportResult → string (terminal|json|sarif) → stdout + exit code
```

## Design decisions

- **Babel over raw regex** — survives formatting changes, comments, and minified-ish transformations; handles JS and TS with one parser.
- **ESM + NodeNext** — modern `node:*` imports, interoperable with `@babel/*` v7 typings.
- **Zero CLI framework dependency** — only `@babel/*` at runtime; `typescript`/`vitest` at dev time.
- **Config via JSON** — one obvious format, easy to validate, no runtime schema dependency.
