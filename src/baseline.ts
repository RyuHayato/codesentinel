import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { Finding } from "./types.js";

/** A stable fingerprint for a finding that survives across runs. */
export interface BaselineEntry {
  ruleId: string;
  filePath: string;
  line: number;
  column: number;
}

export function findingKey(f: BaselineEntry): string {
  return `${f.ruleId}|${f.filePath}|${f.line}|${f.column}`;
}

/** Load a baseline file into a set of fingerprints. Missing file = empty set. */
export function loadBaseline(path: string): Set<string> {
  if (!existsSync(path)) return new Set();
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`Invalid baseline file ${path}: ${(err as Error).message}`);
  }
  const entries: BaselineEntry[] = Array.isArray(parsed)
    ? (parsed as BaselineEntry[])
    : Array.isArray((parsed as { findings?: BaselineEntry[] }).findings)
      ? (parsed as { findings: BaselineEntry[] }).findings
      : [];
  const keys = new Set<string>();
  for (const e of entries) {
    if (e && typeof e.ruleId === "string" && typeof e.filePath === "string" && typeof e.line === "number" && typeof e.column === "number") {
      keys.add(findingKey(e));
    }
  }
  return keys;
}

/** Drop findings present in the baseline. */
export function applyBaseline(findings: Finding[], baseline: Set<string>): Finding[] {
  return findings.filter((f) => !baseline.has(findingKey(f)));
}

/** Write the current findings as a new baseline file. */
export function writeBaseline(path: string, findings: Finding[]): void {
  const entries = findings.map((f) => ({ ruleId: f.ruleId, filePath: f.filePath, line: f.line, column: f.column }));
  writeFileSync(path, JSON.stringify(entries, null, 2) + "\n", "utf8");
}
