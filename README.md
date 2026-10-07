# CodeSentinel

A lightweight, open-source static-analysis security scanner for JavaScript and TypeScript. It catches common vulnerability classes — hardcoded secrets, SQL/command injection, unsafe deserialization, prototype pollution, and more — using Babel AST analysis instead of fragile regex alone.

## Features

- 17 built-in security rules (see [RULES.md](RULES.md)), each with a CWE reference and remediation advice
- AST-based detection for JavaScript, TypeScript, JSX and TSX
- Terminal, JSON, and SARIF output formats
- Configurable severity filtering, rule overrides, ignore paths and inline `// codesentinel-ignore` suppression comments
- CI-friendly exit codes (`--fail-on`)
- Baseline files to grandfather existing findings
- Extensible architecture — Python support can be added by registering new parser + rules

## Supported languages

- JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`)
- TypeScript (`.ts`, `.tsx`)
- Dependency audit of `package.json`

Python can be added later through the parser/rule registration extension point (see [ARCHITECTURE.md](ARCHITECTURE.md)).

## How it works

`codesentinel <path>` collects source files, parses each into a Babel AST, runs all registered rules over the AST, normalizes raw matches into findings joined with rule metadata (title, CWE, remediation), applies severity filtering and de-duplication, then renders the result through a reporter (terminal, JSON, or SARIF). Baseline files can suppress known findings. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full pipeline.

## Install

```bash
npm install
npm run build
```

Or run from source during development:

```bash
npx tsx src/cli.ts ./src        # (requires tsx) or use the built CLI:
node dist/cli.js ./src
```

Link the `codesentinel` binary locally:

```bash
npm link
codesentinel ./src
```

## Usage

```bash
codesentinel ./src                          # terminal report
codesentinel ./src --severity high          # only high + critical findings
codesentinel ./src --format json            # machine-readable JSON
codesentinel ./src --format sarif           # SARIF 2.1.0 for GitHub/code scanning
codesentinel ./src --fail-on high           # exit 1 in CI when high/critical findings exist
codesentinel ./src --write-baseline baseline.json  # snapshot current findings
codesentinel ./src --baseline baseline.json         # suppress them next runs
codesentinel --list-rules                   # show all rules
codesentinel --list-rules --format json     # ...as JSON
codesentinel ./src --no-color               # plain output
codesentinel --version                      # print version
```

## Example: real vulnerable code and real detection

`examples/vulnerable-app/server.js` contains genuinely insecure code:

```js
import { exec } from "child_process";
import crypto from "crypto";

const dbPassword = "Pr0dDbP@ssw0rd!";
const awsKey = "AKIAIOSFODNN7EXAMPLE";

export function getUserReport(req, res) {
  const name = req.query.name;
  // SQL injection
  db.query("SELECT * FROM users WHERE name = '" + name + "'").then(res.json);
  // Command injection
  exec(`ping ${req.query.host}`);
  // Weak crypto for a session token
  const token = crypto.createHash("md5").update(name).digest("hex");
  // Plaintext URL
  fetch("http://api.internal.corp/metrics");
  return token;
}
```

Running `codesentinel examples` produces (abridged):

```
[CRITICAL] CS-002 Exposed API key  CWE-798
  examples/vulnerable-app/server.js:6:16
  Possible AWS access key ID found in string literal.
  │ const awsKey = "AKIAIO***";
  Fix: Revoke and rotate the exposed credential immediately, then load it from an environment variable or secrets manager.

[CRITICAL] CS-003 SQL injection  CWE-89
  examples/vulnerable-app/server.js:11:3
  SQL query passed to db.query is built dynamically — possible SQL injection.
  │ db.query("SELECT * FROM users WHERE name = '" + name + "'").then(res.json);
  Fix: Use parameterized queries / prepared statements ...

[CRITICAL] CS-004 Command injection  CWE-78
  ...

[HIGH] CS-001 Hardcoded secret  CWE-798
  ...

Summary
  Files scanned: 1
  Findings:      7
  By severity:   critical=3 high=1 medium=3 low=0 info=0
```

## Configuration

Create `.codesentinelrc.json` in your project root:

```json
{
  "severity": "low",
  "format": "terminal",
  "failOn": "none",
  "ignore": ["scripts/legacy", "**/*.generated.js"],
  "rules": {
    "CS-006": "off",
    "CS-008": "high"
  }
}
```

- `severity` — minimum severity to report
- `ignore` — path fragments to exclude
- `rules` — `"off"`, `"on"`, or a severity override per rule id
- `failOn` — exit code 1 threshold for CI

### Suppressing findings inline

```js
const dbPassword = "Pr0dDbP@ssw0rd!";  // codesentinel-ignore CS-001
// codesentinel-ignore CS-009
const token = crypto.createHash("md5").update(name).digest("hex");
```

## CI (GitHub Actions)

See [.github/workflows/codesentinel.yml](.github/workflows/codesentinel.yml) for a ready-to-copy workflow: it builds CodeSentinel, runs the test suite, scans the repo, and uploads SARIF to GitHub code scanning.

To use CodeSentinel as a scanner in your own CI:

```yaml
- run: npm ci && npm run build
- run: node dist/cli.js . --format sarif --fail-on high > results.sarif
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md). Rules are listed in [RULES.md](RULES.md). Responsible disclosure policy in [SECURITY.md](SECURITY.md). Contributing guide in [CONTRIBUTING.md](CONTRIBUTING.md).

## Tests

```bash
npm test
```

75 tests cover every rule (vulnerable + safe fixtures), severity filtering, inline ignores, config validation, file-scanner ignore semantics, baseline round-trips, and the CLI/JSON/SARIF/terminal reporters.

## Roadmap

- Python rules via the parser extension point
- Taint-tracking through function calls across files
- Autofix patches for common findings
- GitHub App / pre-commit integration
- More rule families (XXE, SSRF, open redirect, log injection)

## License

MIT
