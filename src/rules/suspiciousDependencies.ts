import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { lineSnippet } from "../helpers.js";

interface SuspiciousRule {
  name: string;
  reason: string;
  /** When set, only flag versions below this threshold. */
  vulnerableBelow?: string;
}

const SUSPICIOUS: SuspiciousRule[] = [
  { name: "node-serialize", reason: "arbitrary code execution during deserialization" },
  { name: "event-stream", reason: "history of a malicious payload (flatmap-stream incident)" },
  { name: "flatmap-stream", reason: "removed from npm due to malicious code" },
  { name: "request", reason: "deprecated and unmaintained" },
  { name: "node-uuid", reason: "renamed to 'uuid'; old package is unmaintained" },
  { name: "csurf", reason: "deprecated with known CSRF bypass issues" },
  { name: "coa", reason: "compromised release (protestware)" },
  { name: "rc", reason: "compromised release (malicious preinstall)" },
  { name: "ua-parser-js", reason: "compromised release installing malware" },
  { name: "lodash", reason: "prototype pollution (CVE-2019-10744)", vulnerableBelow: "4.17.12" },
  { name: "serialize-javascript", reason: "RCE via regex gadget (GHSA-hxcc-f52p-wc94)", vulnerableBelow: "6.0.2" },
  { name: "minimist", reason: "prototype pollution", vulnerableBelow: "1.2.6" },
  { name: "json-schema", reason: "prototype pollution", vulnerableBelow: "0.4.0" },
];

/** Extract dependency name from an import/require source string. */
function depName(source: string): string | null {
  if (source.startsWith("@")) {
    const parts = source.split("/");
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  }
  return source.split("/")[0];
}

function compareSemver(a: string, b: string): number {
  const pa = a.replace(/^[~^<>=\s]+/, "").split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/** Risk reason for a dependency name+version, or null when acceptable. */
function riskFor(name: string, version?: string): string | null {
  const rule = SUSPICIOUS.find((s) => s.name === name);
  if (!rule) return null;
  if (!rule.vulnerableBelow) return rule.reason;
  if (!version || version === "*" || version === "latest") return null;
  return compareSemver(version, rule.vulnerableBelow) < 0 ? `${rule.reason} (installed ${version}, fixed >= ${rule.vulnerableBelow})` : null;
}

const rule: Rule = {
  id: "CS-012",
  title: "Suspicious or deprecated dependency",
  description:
    "Detects imports/requires of packages with a history of compromise, deprecated APIs, or known vulnerability classes, and flags risky entries in package.json.",
  severity: "high",
  cwe: "CWE-1104",
  remediation: "Remove the dependency where possible, replace it with a maintained alternative, or upgrade to a patched version and pin it.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      ImportDeclaration(path) {
        const name = depName(path.node.source.value);
        const risk = name ? riskFor(name) : null;
        if (name && risk) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `Import of suspicious dependency "${name}" — ${risk}.`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
      CallExpression(path) {
        const callee = path.node.callee;
        if (t.isIdentifier(callee) && callee.name === "require") {
          const arg = path.node.arguments[0];
          if (arg && t.isStringLiteral(arg)) {
            const name = depName(arg.value);
            const risk = name ? riskFor(name) : null;
            if (name && risk) {
              findings.push({
                ruleId: rule.id,
                filePath: ctx.filePath,
                line: path.node.loc?.start.line ?? 0,
                column: (path.node.loc?.start.column ?? 0) + 1,
                message: `require("${name}") uses a suspicious dependency — ${risk}.`,
                snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
              });
            }
          }
        }
      },
    });
    return findings;
  },
  checkPackageJson(filePath, pkg) {
    const findings: RawFinding[] = [];
    const allDeps = {
      ...(pkg.dependencies as Record<string, string> | undefined),
      ...(pkg.devDependencies as Record<string, string> | undefined),
      ...(pkg.optionalDependencies as Record<string, string> | undefined),
    };
    for (const [name, version] of Object.entries(allDeps)) {
      const risk = riskFor(name, version);
      if (risk) {
        findings.push({
          ruleId: rule.id,
          filePath,
          line: 1,
          column: 1,
          message: `Dependency "${name}"@${version}: ${risk}.`,
          snippet: `"${name}": "${version}"`,
        });
      }
    }
    return findings;
  },
};

export default rule;
