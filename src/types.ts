import type { File } from "@babel/types";

/** Ordered from most to least severe. */
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export function severityIndex(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

/** A single match produced by a rule before normalization. */
export interface RawFinding {
  ruleId: string;
  filePath: string;
  line: number;
  column: number;
  message: string;
  snippet: string;
  /** Optional per-finding severity that overrides the rule default. */
  severity?: Severity;
}

/** A fully normalized finding emitted to reporters. */
export interface Finding {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  filePath: string;
  line: number;
  column: number;
  message: string;
  snippet: string;
  remediation: string;
}

/** Context handed to every rule. */
export interface RuleContext {
  filePath: string;
  source: string;
  ast: File;
}

export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  remediation: string;
  /** Run AST-based detection on a parsed JS/TS source file. */
  check(ctx: RuleContext): RawFinding[];
  /** Optional check for package.json files (suspicious dependencies). */
  checkPackageJson?(filePath: string, pkg: Record<string, unknown>): RawFinding[];
}

export interface ReportSummary {
  filesScanned: number;
  findingsBySeverity: Record<Severity, number>;
  total: number;
  elapsedMs: number;
}

export interface ScanResult {
  findings: Finding[];
  summary: ReportSummary;
}
