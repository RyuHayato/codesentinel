import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { lineSnippet } from "../helpers.js";

const rule: Rule = {
  id: "CS-008",
  title: "Insecure HTTP usage",
  description:
    "Detects plaintext http:// URLs and use of the Node 'http' module. Traffic over HTTP can be intercepted or modified (MITM).",
  severity: "medium",
  cwe: "CWE-319",
  remediation: "Use https:// URLs and the 'https' module. http:// is acceptable only for local development endpoints (localhost/127.0.0.1), never for external or production endpoints.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      StringLiteral(path) {
        const value = path.node.value;
        if (/^http:\/\//i.test(value) && !/^http:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?/i.test(value)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `Insecure plaintext URL: "${value}".`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
      CallExpression(path) {
        const callee = path.node.callee;
        if (t.isIdentifier(callee) && callee.name === "require") {
          const arg = path.node.arguments[0];
          if (arg && t.isStringLiteral(arg) && arg.value === "http") {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: "The 'http' module sends traffic in plaintext — prefer 'https'.",
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
            });
          }
        }
      },
      ImportDeclaration(path) {
        if (path.node.source.value === "http") {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "Importing the 'http' module — prefer 'https' for secure transport.",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
    });
    return findings;
  },
};

export default rule;
