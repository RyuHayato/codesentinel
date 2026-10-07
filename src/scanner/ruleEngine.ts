import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { ALL_RULES } from "../rules/index.js";
import { parseSource, isScannableFile } from "../parser.js";
import { collectFiles, isSuppressed, parseInlineIgnores } from "./fileScanner.js";
import { CodeSentinelConfig, loadConfig } from "../config.js";
import type { Finding, RawFinding, Rule, ScanResult, Severity } from "../types.js";
import { severityIndex } from "../types.js";

export interface ScanOptions {
  root: string;
  minSeverity: Severity;
  enabledRules?: Set<string>;
  /** Rule -> severity override from config. */
  ruleOverrides?: Map<string, Severity>;
  disabledRules?: Set<string>;
  configPath?: string;
  /** Pre-loaded config (e.g. resolved from the project root). */
  config?: CodeSentinelConfig;
}

/** Run the full scan pipeline: collect files -> parse -> rules -> normalize -> filter. */
export function scan(options: ScanOptions): ScanResult {
  const start = Date.now();
  const config = options.config ?? loadConfig(options.root, options.configPath);
  const ignore = config.ignore;
  const files = collectFiles(options.root, ignore);

  const enabled = new Set<string>();
  for (const rule of ALL_RULES) {
    const setting = config.rules[rule.id];
    if (setting === "off") continue;
    enabled.add(rule.id);
  }
  if (options.disabledRules) for (const id of options.disabledRules) enabled.delete(id);
  if (options.enabledRules) for (const id of options.enabledRules) enabled.add(id);

  const overrides = new Map<string, Severity>();
  for (const [id, setting] of Object.entries(config.rules)) {
    if (setting !== "off" && setting !== "on") overrides.set(id, setting as Severity);
  }
  if (options.ruleOverrides) for (const [id, s] of options.ruleOverrides) overrides.set(id, s);

  const rawFindings: RawFinding[] = [];

  for (const file of files) {
    let source: string;
    try {
      source = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const rel = relative(process.cwd(), file).replace(/\\/g, "/");

    if (file.endsWith("package.json")) {
      try {
        const pkg = JSON.parse(source);
        for (const rule of ALL_RULES) {
          if (!enabled.has(rule.id) || !rule.checkPackageJson) continue;
          rawFindings.push(...rule.checkPackageJson(rel, pkg));
        }
      } catch {
        // invalid package.json, skip
      }
      continue;
    }

    if (!isScannableFile(file)) continue;
    const { ast, error } = parseSource(file, source);
    if (error || !ast) {
      // Surface parse errors as a low-severity info finding so CI logs are helpful.
      rawFindings.push({
        ruleId: "CS-E01",
        filePath: rel,
        line: 1,
        column: 1,
        message: `Failed to parse file: ${error}`,
        snippet: "",
      });
      continue;
    }

    const inlineIgnores = parseInlineIgnores(source);
    for (const rule of ALL_RULES) {
      if (!enabled.has(rule.id)) continue;
      let findings: RawFinding[] = [];
      try {
        findings = rule.check({ filePath: rel, source, ast });
      } catch (err) {
        findings = [
          {
            ruleId: "CS-ERR",
            filePath: rel,
            line: 1,
            column: 1,
            message: `Rule ${rule.id} crashed: ${(err as Error).message}`,
            snippet: "",
          },
        ];
      }
      for (const f of findings) {
        if (isSuppressed(rule.id, f.line, inlineIgnores)) continue;
        rawFindings.push({ ...f, filePath: rel });
      }
    }
  }

  const rulesById = new Map<string, Rule>(ALL_RULES.map((r) => [r.id, r]));
  const findings: Finding[] = [];
  for (const raw of rawFindings) {
    const rule = rulesById.get(raw.ruleId);
    let finding: Finding;
    if (rule) {
      const severity = overrides.get(raw.ruleId) ?? raw.severity ?? rule.severity;
      finding = {
        ruleId: rule.id,
        title: rule.title,
        description: rule.description,
        severity,
        cwe: rule.cwe,
        filePath: raw.filePath,
        line: raw.line,
        column: raw.column,
        message: raw.message,
        snippet: raw.snippet,
        remediation: rule.remediation,
      };
    } else {
      finding = {
        ruleId: raw.ruleId,
        title: "Scanner error",
        description: "An internal error occurred while scanning.",
        severity: "info",
        cwe: "N/A",
        filePath: raw.filePath,
        line: raw.line,
        column: raw.column,
        message: raw.message,
        snippet: raw.snippet,
        remediation: "Check the file syntax or report a scanner bug.",
      };
    }
    if (severityIndex(finding.severity) <= severityIndex(options.minSeverity)) {
      findings.push(finding);
    }
  }

  // De-duplicate (same rule, same location, same message).
  const seen = new Set<string>();
  const unique = findings.filter((f) => {
    const key = `${f.ruleId}|${f.filePath}|${f.line}|${f.column}|${f.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  unique.sort((a, b) => severityIndex(a.severity) - severityIndex(b.severity) || a.filePath.localeCompare(b.filePath) || a.line - b.line);

  const findingsBySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of unique) findingsBySeverity[f.severity]++;

  return {
    findings: unique,
    summary: {
      filesScanned: files.length,
      findingsBySeverity,
      total: unique.length,
      elapsedMs: Date.now() - start,
    },
  };
}
