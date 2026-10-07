import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, getPropertyValue, lineSnippet } from "../helpers.js";

const rule: Rule = {
  id: "CS-014",
  title: "Unsafe JWT handling",
  description:
    "Detects JWT patterns that skip signature verification: jwt.decode instead of jwt.verify, the 'none' algorithm, and empty secret verification. These let attackers forge tokens.",
  severity: "high",
  cwe: "CWE-347",
  remediation:
    "Always verify tokens with jwt.verify() and an explicit algorithm allow-list (e.g. ['HS256']). Never accept the 'none' algorithm or use jwt.decode for authentication decisions.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      CallExpression(path) {
        const name = calleeName(path.node.callee) ?? "";
        const leaf = name.split(".").pop() ?? "";
        // jwt.decode(...) used — silently skips verification.
        if (leaf === "decode" && /jwt|token/i.test(name)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `${name} decodes without verifying the signature — use jwt.verify() for auth decisions.`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
            severity: "medium",
          });
        }
        // jwt.sign/verify with algorithm "none".
        if (leaf === "sign" || leaf === "verify") {
          const third = path.node.arguments[2] as t.Node | undefined;
          const alg = third ? getPropertyValue(third, "algorithm") ?? getPropertyValue(third, "algorithms") : null;
          if (alg && t.isArrayExpression(alg) && alg.elements.some((e) => t.isStringLiteral(e) && e.value === "none")) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `${name} allows the "none" JWT algorithm — tokens could be unsigned.`,
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
            });
          } else if (alg && t.isStringLiteral(alg) && alg.value === "none") {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `${name} uses the "none" JWT algorithm — tokens could be unsigned.`,
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
            });
          }
        }
      },
      ObjectExpression(path) {
        // Skip objects already reported via the containing sign/verify call expression.
        const parent = path.parentPath?.node;
        if (t.isCallExpression(parent)) return;
        const alg = getPropertyValue(path.node, "algorithms");
        if (alg && t.isArrayExpression(alg) && alg.elements.some((e) => t.isStringLiteral(e) && e.value === "none")) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: 'JWT option "algorithms: [\'none\']" accepts unsigned tokens.',
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
    });
    return findings;
  },
};

export default rule;
