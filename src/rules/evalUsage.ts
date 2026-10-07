import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, lineSnippet } from "../helpers.js";

const rule: Rule = {
  id: "CS-005",
  title: "Unsafe eval usage",
  description:
    "Detects eval(), new Function(), and string-based setTimeout/setInterval. These execute arbitrary code and enable code injection when fed untrusted input.",
  severity: "high",
  cwe: "CWE-95",
  remediation: "Replace eval/new Function with a safe parser or lookup table, and pass functions (not strings) to setTimeout/setInterval.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      CallExpression(path) {
        const name = calleeName(path.node.callee) ?? "";
        if (name === "eval") {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "eval() executes arbitrary strings as code.",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
        if ((name === "setTimeout" || name === "setInterval") && path.node.arguments[0]) {
          const first = path.node.arguments[0];
          if (t.isStringLiteral(first) || t.isTemplateLiteral(first)) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `${name} called with a string/template argument — implicit eval.`,
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
            });
          }
        }
      },
      NewExpression(path) {
        const name = calleeName(path.node.callee) ?? "";
        if (name === "Function") {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "new Function() compiles a string into executable code — prefer normal functions.",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
    });
    return findings;
  },
};

export default rule;
