# CodeSentinel Rules

Each rule implements: rule ID, title, description, severity, CWE reference, detection logic, remediation advice, and test cases (vulnerable + safe fixtures under `tests/fixtures/`).

| ID | Title | Severity | CWE |
|----|-------|----------|-----|
| CS-001 | Hardcoded secret | high | CWE-798 |
| CS-002 | Exposed API key | critical | CWE-798 |
| CS-003 | SQL injection | critical | CWE-89 |
| CS-004 | Command injection | critical | CWE-78 |
| CS-005 | Unsafe eval usage | high | CWE-95 |
| CS-006 | Dangerous child-process execution | medium (high for `shell:true`) | CWE-78 |
| CS-007 | Path traversal | high | CWE-22 |
| CS-008 | Insecure HTTP usage | medium | CWE-319 |
| CS-009 | Weak cryptographic function | medium (high for weak ciphers) | CWE-327 |
| CS-010 | Prototype pollution | high (medium for computed-key write) | CWE-1321 |
| CS-011 | Unsafe deserialization | critical | CWE-502 |
| CS-012 | Suspicious or deprecated dependency | high | CWE-1104 |
| CS-013 | TLS verification disabled | high | CWE-295 |
| CS-014 | Unsafe JWT handling | high (medium for `jwt.decode`) | CWE-347 |
| CS-015 | Insecure randomness for security-sensitive values | medium | CWE-338 |
| CS-016 | NoSQL injection | high | CWE-943 |
| CS-017 | Insecure cookie configuration | medium (low when httpOnly missing) | CWE-614 |

## CS-001 — Hardcoded secret

**Detection:** AST scan for variables/properties/assignments whose name matches `password|secret|token|api[_-]?key|...` and whose value is a non-placeholder string literal.

**Flagged:**
```js
const dbPassword = "hunter2supersecret";
const config = { client_secret: "supersecretvalue123" };
```

**Safe:**
```js
const password = process.env.ADMIN_PASSWORD;
```

**Remediation:** load from environment variables or a secrets manager; rotate committed secrets.

## CS-002 — Exposed API key

**Detection:** token-format regexes (AWS `AKIA...`, GitHub `ghp_...`/`github_pat_...`, Slack `xox...`, Google `AIza...`, OpenAI `sk-...`, Stripe `sk_live_...`, webhooks, private key blocks) applied to string literals, template literals, and raw source lines.

**Remediation:** revoke + rotate, load from env, never commit.

## CS-003 — SQL injection

**Detection:** any `*.query/execute/raw/run/prepare(...)` call whose first argument is a template literal with interpolations or a `+` concatenation containing SQL keywords — including simple variable-propagation (`const q = "..." + x; db.query(q)`).

**Flagged:** `db.query("SELECT * FROM users WHERE id = " + id)`

**Safe:** `db.query("SELECT * FROM users WHERE id = ?", [id])`

**Remediation:** parameterized queries / query builders.

## CS-004 — Command injection

**Detection:** `exec/execSync/execFile/spawn/...` calls whose command argument is a template literal with expressions, a concatenation, or a variable — i.e. anything that could smuggle user input into a shell.

**Flagged:** `` exec(`ping -c 4 ${userInput}`) ``, `execSync("ls " + userInput)`

**Safe:** `execFile("ping", ["-c", "4", userInput])`

**Remediation:** pass argument arrays, avoid shells, validate input. Maps to CWE-78.

## CS-005 — Unsafe eval usage

**Detection:** call expressions named `eval`, `new Function(...)`, and `setTimeout/setInterval` with a string first argument.

**Remediation:** parse data with `JSON.parse`, pass real functions to timers, avoid dynamic code construction entirely (CWE-95).

## CS-006 — Dangerous child-process execution

**Detection:** any `exec`/`execSync` call (medium — shell-based), and `spawn/spawnSync` with `{ shell: true }` (high).

**Remediation:** prefer `execFile`/`spawn` with argument arrays and `shell: false` (CWE-78).

## CS-007 — Path traversal

**Detection:** filesystem calls (`readFile`, `readFileSync`, `createReadStream`, `open`, `unlink`, ...) whose path argument contains `../`, references `req.query/params/body`, or interpolates a template literal.

**Remediation:** `path.resolve` + prefix check against an allowed base; reject `..` segments (CWE-22).

## CS-008 — Insecure HTTP usage

**Detection:** `http://` string literals (excluding `localhost`/`127.0.0.1`), `require("http")`, and `import ... from "http"`.

**Remediation:** use HTTPS everywhere outside local development (CWE-319).

## CS-009 — Weak cryptographic function

**Detection:** `createHash("md5"|"sha1")`, `createHmac` with md5/sha1, deprecated `createCipher`, and `createCipheriv` with DES/RC4/RC2/Blowfish.

**Remediation:** SHA-256+ (or bcrypt/argon2 for passwords), AES-GCM via `createCipheriv` with a random key/IV (CWE-327).

## CS-010 — Prototype pollution

**Detection:** `__proto__` access, `constructor.prototype` access, computed-key writes `obj[req.body.key] = v`, and deep-merge calls (`merge`, `defaultsDeep`, `extend`, `assignDeep`, ...) on `req.body/query/params` or parsed JSON.

**Remediation:** validate/sanitize keys, use `Object.create(null)` or `Object.assign`, avoid deep-merging untrusted JSON (CWE-1321).

## CS-011 — Unsafe deserialization

**Detection:** `*.unserialize(...)` (node-serialize), `yaml.load(...)`, `eval(JSON.parse(...))`, `vm.runIn*(dynamicString)`, and imports of `node-serialize`/`pickle`.

**Remediation:** `JSON.parse`, safe YAML schemas, no eval/vm on untrusted data (CWE-502).

## CS-012 — Suspicious or deprecated dependency

**Detection:** `import`/`require` of known-risky packages (`node-serialize`, `event-stream`, `flatmap-stream`, `request`, `node-uuid`, `csurf`, `ua-parser-js`, `coa`, `rc`) and matching entries in `package.json` dependencies.

**Remediation:** remove, replace, or pin upgraded versions (CWE-1104).

## CS-017 — Insecure cookie configuration

**Detection:** `res.cookie()`/`setCookie()` calls whose options contain `httpOnly: false` or `secure: false`, and calls that omit `httpOnly` entirely (low severity).

**Remediation:** always set `{ httpOnly: true, secure: true, sameSite: 'Lax' }` on session cookies.

## CS-013 — TLS verification disabled

**Detection:** `rejectUnauthorized: false` in any options object, and `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"`.

**Remediation:** never disable verification in production; fix CA/hostname issues or pass a proper CA chain.

## CS-014 — Unsafe JWT handling

**Detection:** `jwt.decode(...)` (skips verification), `jwt.sign(..., { algorithm: "none" })`, and `algorithms: ["none", ...]` in verify options.

**Remediation:** always `jwt.verify()` with an explicit algorithm allow-list; never accept `none` for auth decisions.

## CS-015 — Insecure randomness for security-sensitive values

**Detection:** `Math.random()` assigned to a variable/property named like `token`, `secret`, `session`, `otp`, `salt`, `password`, ...

**Remediation:** use `crypto.randomBytes()`, `crypto.randomUUID()`, or `crypto.randomInt()`.

## CS-016 — NoSQL injection

**Detection:** `$where` properties in query objects, and Mongo-style query calls (`find`, `findOne`, `update*`, `delete*`) whose first argument is raw request input (`req.body`, `req.query`) — including one-step variable propagation.

**Remediation:** validate and cast input before querying; never pass `req.body`/`req.query` directly; strip `$`/`.` keys.

## Adding a new rule

1. Create `src/rules/myRule.ts` implementing the `Rule` interface.
2. Register it in `src/rules/index.ts`.
3. Add vulnerable + safe fixtures under `tests/fixtures/{vulnerable,safe}`.
4. Cover both fixtures in `tests/rules.test.ts` (the `CASES` table).
5. Document it in this file.

See [CONTRIBUTING.md](CONTRIBUTING.md).
