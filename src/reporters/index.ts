import type { ScanResult, Severity } from "../types.js";
import { reportTerminal } from "./terminal.js";
import { reportJson } from "./json.js";
import { reportSarif } from "./sarif.js";

export { reportTerminal, reportJson, reportSarif };

export type ReportFormat = "terminal" | "json" | "sarif";

export function formatResult(result: ScanResult, format: ReportFormat): string {
  switch (format) {
    case "json":
      return reportJson(result);
    case "sarif":
      return reportSarif(result);
    default:
      return reportTerminal(result);
  }
}

export function severityAtLeast(findingSeverity: Severity, threshold: Severity | "none"): boolean {
  if (threshold === "none") return false;
  const order: Severity[] = ["info", "low", "medium", "high", "critical"];
  return order.indexOf(findingSeverity) >= order.indexOf(threshold);
}
