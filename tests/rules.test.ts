import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { parseSource } from "../src/parser";
import { ALL_RULES, RULES_BY_ID } from "../src/rules/index";
import type { Rule } from "../src/types";

function runRule(rule: Rule, file: string) {
  const source = readFileSync(file, "utf8");
  const { ast, error } = parseSource(file, source);
  if (error || !ast) throw new Error(error ?? "no ast");
  return rule.check({ filePath: file, source, ast });
}

const CASES: Array<{ ruleId: string; vulnerable: string | string[]; safe: string | string[] }> = [
  {
    ruleId: "CS-001",
    vulnerable: "tests/fixtures/vulnerable/hardcodedSecrets.js",
    safe: "tests/fixtures/safe/hardcodedSecrets.js",
  },
  {
    ruleId: "CS-002",
    vulnerable: "tests/fixtures/vulnerable/apiKeys.js",
    safe: "tests/fixtures/safe/apiKeys.js",
  },
  {
    ruleId: "CS-003",
    vulnerable: ["tests/fixtures/vulnerable/sqlInjection.js", "tests/fixtures/vulnerable/typescript.ts"],
    safe: ["tests/fixtures/safe/sqlInjection.js", "tests/fixtures/safe/typescript.ts"],
  },
  {
    ruleId: "CS-004",
    vulnerable: "tests/fixtures/vulnerable/commandInjection.js",
    safe: "tests/fixtures/safe/commandInjection.js",
  },
  {
    ruleId: "CS-005",
    vulnerable: "tests/fixtures/vulnerable/evalUsage.js",
    safe: "tests/fixtures/safe/evalUsage.js",
  },
  {
    ruleId: "CS-006",
    vulnerable: "tests/fixtures/vulnerable/childProcess.js",
    safe: "tests/fixtures/safe/childProcess.js",
  },
  {
    ruleId: "CS-007",
    vulnerable: "tests/fixtures/vulnerable/pathTraversal.js",
    safe: "tests/fixtures/safe/pathTraversal.js",
  },
  {
    ruleId: "CS-008",
    vulnerable: "tests/fixtures/vulnerable/insecureHttp.js",
    safe: "tests/fixtures/safe/insecureHttp.js",
  },
  {
    ruleId: "CS-009",
    vulnerable: "tests/fixtures/vulnerable/weakCrypto.js",
    safe: "tests/fixtures/safe/weakCrypto.js",
  },
  {
    ruleId: "CS-010",
    vulnerable: "tests/fixtures/vulnerable/prototypePollution.js",
    safe: "tests/fixtures/safe/prototypePollution.js",
  },
  {
    ruleId: "CS-011",
    vulnerable: "tests/fixtures/vulnerable/unsafeDeserialization.js",
    safe: "tests/fixtures/safe/unsafeDeserialization.js",
  },
  {
    ruleId: "CS-012",
    vulnerable: "tests/fixtures/vulnerable/suspiciousDependencies.js",
    safe: "tests/fixtures/safe/suspiciousDependencies.js",
  },
];

describe("rules", () => {
  for (const { ruleId, vulnerable, safe } of CASES) {
    const rule = RULES_BY_ID.get(ruleId)!;
    it(`${ruleId} detects vulnerable example`, () => {
      const files = Array.isArray(vulnerable) ? vulnerable : [vulnerable];
      const found = files.flatMap((f) => runRule(rule, f));
      expect(found.length, `expected ${ruleId} findings in ${files.join(", ")}`).toBeGreaterThan(0);
    });
    it(`${ruleId} does not flag safe example`, () => {
      const files = Array.isArray(safe) ? safe : [safe];
      const found = files.flatMap((f) => runRule(rule, f));
      expect(found, `unexpected ${ruleId} findings: ${JSON.stringify(found.map((f) => f.message))}`).toHaveLength(0);
    });
  }

  it("every rule has metadata and remediation", () => {
    for (const rule of ALL_RULES) {
      expect(rule.id).toMatch(/^CS-\d{3}$/);
      expect(rule.title.length).toBeGreaterThan(3);
      expect(rule.description.length).toBeGreaterThan(20);
      expect(rule.cwe).toMatch(/^CWE-\d+$/);
      expect(rule.remediation.length).toBeGreaterThan(10);
      expect(["critical", "high", "medium", "low", "info"]).toContain(rule.severity);
    }
  });
});

describe("CS-012 package.json check", () => {
  it("flags risky deps in package.json", () => {
    const rule = RULES_BY_ID.get("CS-012")!;
    const pkg = JSON.parse(readFileSync("tests/fixtures/vulnerable/package.json", "utf8"));
    const findings = rule.checkPackageJson!("tests/fixtures/vulnerable/package.json", pkg);
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });
});
