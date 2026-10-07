import type { Finding, ScanResult, Severity } from "../types.js";

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note" | "none"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

export function reportSarif(result: ScanResult): string {
  const rulesById = new Map<string, Finding>();
  for (const f of result.findings) {
    if (!rulesById.has(f.ruleId)) rulesById.set(f.ruleId, f);
  }

  const rules = [...rulesById.values()].map((f) => ({
    id: f.ruleId,
    name: f.title.replace(/\s+/g, ""),
    shortDescription: { text: f.title },
    fullDescription: { text: f.description },
    help: { text: f.remediation },
    properties: {
      tags: ["security", f.cwe],
      precision: "high",
    },
    defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
  }));

  const results = result.findings.map((f) => ({
    ruleId: f.ruleId,
    level: SARIF_LEVEL[f.severity],
    message: { text: `${f.message}\n\nRemediation: ${f.remediation}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.filePath.replace(/\\/g, "/"), uriBaseId: "%SRCROOT%" },
          region: { startLine: Math.max(f.line, 1), startColumn: Math.max(f.column, 1) },
        },
      },
    ],
    properties: { cwe: f.cwe, severity: f.severity },
  }));

  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "CodeSentinel",
              version: "0.1.0",
              informationUri: "https://github.com/codesentinel/codesentinel",
              rules,
            },
          },
          results,
        },
      ],
    },
    null,
    2,
  );
}
