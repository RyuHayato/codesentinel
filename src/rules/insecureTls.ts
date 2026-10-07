import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { getPropertyValue, lineSnippet } from "../helpers.js";

const rule: Rule = {
  id: "CS-013",
  title: "TLS verification disabled",
  description:
    "Detects options that disable TLS certificate validation (rejectUnauthorized: false) or set NODE_TLS_REJECT_UNAUTHORIZED=0. This exposes traffic to man-in-the-middle attacks.",
  severity: "high",
  cwe: "CWE-295",
  remediation:
    "Never disable certificate verification in production. Fix the underlying CA/hostname issue, or pass a proper CA chain via `ca` / `NODE_EXTRA_CA_CERTS`.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      ObjectExpression(path) {
        const value = getPropertyValue(path.node, "rejectUnauthorized");
        if (value && t.isBooleanLiteral(value) && value.value === false) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "rejectUnauthorized:false disables TLS certificate validation.",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
      AssignmentExpression(path) {
        // process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"
        const left = path.node.left;
        if (
          t.isMemberExpression(left) &&
          t.isIdentifier(left.property) &&
          left.property.name === "NODE_TLS_REJECT_UNAUTHORIZED" &&
          t.isStringLiteral(path.node.right) &&
          path.node.right.value === "0"
        ) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS verification process-wide.",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
    });
    return findings;
  },
};

export default rule;
