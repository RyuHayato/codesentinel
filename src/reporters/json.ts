import type { ScanResult } from "../types.js";

export function reportJson(result: ScanResult): string {
  return JSON.stringify(
    {
      tool: "CodeSentinel",
      version: "0.1.0",
      summary: result.summary,
      findings: result.findings,
    },
    null,
    2,
  );
}
