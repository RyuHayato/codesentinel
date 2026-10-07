import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { lineSnippet } from "../helpers.js";

interface SuspiciousPackage {
  name: string;
  reason: string;
}

const SUSPICIOUS: SuspiciousPackage[] = [
  { name: "node-serialize", reason: "arbitrary code execution during deserialization" },
  { name: "event-stream", reason: "history of a malicious payload (flatmap-stream incident)" },
  { name: "flatmap-stream", reason: "removed from npm due to malicious code" },
  { name: "request", reason: "deprecated and unmaintained" },
  { name: "node-uuid", reason: "renamed to 'uuid'; old package is unmaintained" },
  { name: "csurf", reason: "deprecated with known CSRF bypass issues" },
  { name: "serialize-javascript@<4 || @<6.0.2", reason: "RCE via regex gadget in older versions" },
  { name: "lodash@<4.17.12", reason: "prototype pollution in older versions" },
  { name: "ua-parser-js@0.7.29", reason: "compromised release installing malware" },
  { name: "coa@2.0.4", reason: "compromised release (protestware)" },
  { name: "rc@1.2.9", reason: "compromised release (malicious preinstall)" },
  { name: "javascript-obfuscator@known", reason: "placeholder — obfuscation often hides malicious code" },
];

const RISKY_NAMES = new Set(["node-serialize", "event-stream", "flatmap-stream", "request", "node-uuid", "csurf", "coa", "rc", "ua-parser-js"]);

/** Extract dependency name from an import/require source string. */
function depName(source: string): string | null {
  if (source.startsWith("@")) {
    const parts = source.split("/");
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  }
  return source.split("/")[0];
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
        if (name && RISKY_NAMES.has(name)) {
          const info = SUSPICIOUS.find((s) => s.name === name);
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `Import of suspicious dependency "${name}" — ${info?.reason ?? "flagged by policy"}.`,
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
            if (name && RISKY_NAMES.has(name)) {
              const info = SUSPICIOUS.find((s) => s.name === name);
              findings.push({
                ruleId: rule.id,
                filePath: ctx.filePath,
                line: path.node.loc?.start.line ?? 0,
                column: (path.node.loc?.start.column ?? 0) + 1,
                message: `require("${name}") uses a suspicious dependency — ${info?.reason ?? "flagged by policy"}.`,
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
      if (RISKY_NAMES.has(name)) {
        const info = SUSPICIOUS.find((s) => s.name === name);
        findings.push({
          ruleId: rule.id,
          filePath,
          line: 1,
          column: 1,
          message: `Dependency "${name}"@${version}: ${info?.reason ?? "flagged by policy"}.`,
          snippet: `"${name}": "${version}"`,
        });
      }
    }
    return findings;
  },
};

export default rule;
