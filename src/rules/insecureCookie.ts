import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeLeaf, getPropertyValue, lineSnippet } from "../helpers.js";

const rule: Rule = {
  id: "CS-017",
  title: "Insecure cookie configuration",
  description:
    "Detects session/auth cookies set without the Secure, HttpOnly, or SameSite=Strict/Lax attributes. Such cookies can be sent over plaintext HTTP, read by JavaScript (XSS theft), or sent cross-site (CSRF).",
  severity: "medium",
  cwe: "CWE-614",
  remediation:
    "Set cookies with { httpOnly: true, secure: true, sameSite: 'Lax' } (or 'Strict'), and use the __Host- or __Secure- prefix where possible.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      CallExpression(path) {
        const leaf = calleeLeaf(path.node.callee);
        if (leaf !== "cookie" && leaf !== "setCookie") return;
        const options = path.node.arguments[2] as t.Node | undefined;
        if (!options || !t.isObjectExpression(options)) return;

        const httpOnly = getPropertyValue(options, "httpOnly");
        if (httpOnly && t.isBooleanLiteral(httpOnly) && httpOnly.value === false) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "Cookie set with httpOnly:false — accessible to JavaScript (XSS theft).",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
        const secure = getPropertyValue(options, "secure");
        if (secure && t.isBooleanLiteral(secure) && secure.value === false) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "Cookie set with secure:false — transmitted over plaintext HTTP.",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
        // No httpOnly at all — risky for session cookies.
        if (!httpOnly) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "Cookie set without httpOnly — consider adding httpOnly:true.",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
            severity: "low",
          });
        }
      },
    });
    return findings;
  },
};

export default rule;
