import { describe, it, expect } from "vitest";
import { scan } from "../src/scanner/ruleEngine";
import { reportJson } from "../src/reporters/json";
import { reportSarif } from "../src/reporters/sarif";
import { reportTerminal } from "../src/reporters/terminal";
import { severityAtLeast } from "../src/reporters/index";

describe("scanner integration", () => {
  it("finds vulnerabilities in the vulnerable fixture set", () => {
    const result = scan({ root: "tests/fixtures/vulnerable", minSeverity: "low" });
    const ids = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of ["CS-001", "CS-002", "CS-003", "CS-004", "CS-005", "CS-006", "CS-007", "CS-008", "CS-009", "CS-010", "CS-011", "CS-012"]) {
      expect(ids.has(expected), `missing finding ${expected}`).toBe(true);
    }
    expect(result.summary.total).toBeGreaterThan(10);
  });

  it("reports nothing in the safe fixture set", () => {
    const result = scan({ root: "tests/fixtures/safe", minSeverity: "low" });
    expect(result.findings).toHaveLength(0);
  });

  it("filters findings by severity", () => {
    const result = scan({ root: "tests/fixtures/vulnerable", minSeverity: "critical" });
    expect(result.findings.length).toBeGreaterThan(0);
    for (const f of result.findings) {
      expect(f.severity).toBe("critical");
    }
  });

  it("honors inline codesentinel-ignore comments", () => {
    const result = scan({ root: "tests/fixtures/vulnerable/withIgnoreComment.js", minSeverity: "low" });
    const suppressed = result.findings.find((f) => f.ruleId === "CS-001" && f.line === 3);
    expect(suppressed).toBeUndefined();
    const kept = result.findings.find((f) => f.ruleId === "CS-001" && f.line === 4);
    expect(kept).toBeDefined();
  });

  it("produces valid JSON output", () => {
    const result = scan({ root: "tests/fixtures/vulnerable", minSeverity: "low" });
    const parsed = JSON.parse(reportJson(result));
    expect(parsed.tool).toBe("CodeSentinel");
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect(parsed.summary.total).toBe(result.summary.total);
  });

  it("produces valid SARIF output", () => {
    const result = scan({ root: "tests/fixtures/vulnerable", minSeverity: "low" });
    const parsed = JSON.parse(reportSarif(result));
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0].tool.driver.name).toBe("CodeSentinel");
    expect(parsed.runs[0].results.length).toBe(result.summary.total);
  });

  it("produces terminal output containing rule ids and summary", () => {
    const result = scan({ root: "tests/fixtures/vulnerable", minSeverity: "low" });
    const text = reportTerminal(result, false);
    expect(text).toContain("CS-001");
    expect(text).toContain("Summary");
  });

  it("severity threshold logic works", () => {
    expect(severityAtLeast("critical", "high")).toBe(true);
    expect(severityAtLeast("low", "high")).toBe(false);
    expect(severityAtLeast("high", "none")).toBe(false);
  });
});
