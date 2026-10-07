import type { Finding, ScanResult, Severity } from "../types.js";

const COLORS: Record<Severity, string> = {
  critical: "\x1b[41m\x1b[37m", // red bg
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
};
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";

function supportsColor(): boolean {
  if (process.env.NO_COLOR) return false;
  return process.stdout.isTTY !== false;
}

export function reportTerminal(result: ScanResult, colorEnabled = supportsColor()): string {
  const lines: string[] = [];
  const c = (code: string, text: string) => (colorEnabled ? `${code}${text}${RESET}` : text);

  lines.push("");
  lines.push(c(BOLD, "CodeSentinel — security scan report"));
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(c("\x1b[32m", "✔ No findings.") + ` (${result.summary.filesScanned} files scanned in ${result.summary.elapsedMs}ms)`);
    lines.push("");
    return lines.join("\n");
  }

  for (const f of result.findings) {
    lines.push(
      `${c(COLORS[f.severity], `[${f.severity.toUpperCase()}]`)} ${c(BOLD, f.ruleId)} ${f.title}` +
        `  ${c("\x1b[90m", f.cwe)}`,
    );
    lines.push(`  ${f.filePath}:${f.line}:${f.column}`);
    lines.push(`  ${f.message}`);
    if (f.snippet) lines.push(`  ${c("\x1b[90m", "│ " + f.snippet)}`);
    lines.push(`  ${c("\x1b[32m", "Fix: ")}${f.remediation}`);
    lines.push("");
  }

  const s = result.summary;
  lines.push(c(BOLD, "Summary"));
  lines.push(`  Files scanned: ${s.filesScanned}`);
  lines.push(`  Findings:      ${s.total}`);
  lines.push(
    `  By severity:   critical=${s.findingsBySeverity.critical} high=${s.findingsBySeverity.high} medium=${s.findingsBySeverity.medium} low=${s.findingsBySeverity.low} info=${s.findingsBySeverity.info}`,
  );
  lines.push(`  Elapsed:       ${s.elapsedMs}ms`);
  lines.push("");
  return lines.join("\n");
}
