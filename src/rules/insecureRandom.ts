import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, lineSnippet } from "../helpers.js";

const SECRET_NAME = /(token|secret|password|passwd|pwd|session|api[_-]?key|apikey|otp|pin|nonce|salt|hmac|sign)/i;

const rule: Rule = {
  id: "CS-015",
  title: "Insecure randomness for security-sensitive values",
  description:
    "Detects Math.random() used to generate tokens, secrets, session ids, or similar values. Math.random is not cryptographically secure and its outputs are predictable.",
  severity: "medium",
  cwe: "CWE-338",
  remediation:
    "Use crypto.randomBytes(), crypto.randomUUID(), or crypto.getRandomValues() for anything that must be unpredictable.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      VariableDeclarator(path) {
        const id = path.node.id;
        const init = path.node.init;
        if (t.isIdentifier(id) && SECRET_NAME.test(id.name) && containsMathRandom(init)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `Math.random() used to generate "${id.name}" — not cryptographically secure.`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
      AssignmentExpression(path) {
        const left = path.node.left;
        const name = t.isMemberExpression(left) && t.isIdentifier(left.property) ? left.property.name : t.isIdentifier(left) ? left.name : null;
        if (name && SECRET_NAME.test(name) && containsMathRandom(path.node.right)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `Math.random() used to generate "${name}" — not cryptographically secure.`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
      ObjectProperty(path) {
        const key = path.node.key;
        const name = t.isIdentifier(key) ? key.name : t.isStringLiteral(key) ? key.value : null;
        if (name && SECRET_NAME.test(name) && containsMathRandom(path.node.value)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `Math.random() used for security-sensitive property "${name}".`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
    });
    return findings;
  },
};

function containsMathRandom(node: t.Node | null | undefined): boolean {
  if (!node) return false;
  if (t.isCallExpression(node)) {
    const name = calleeName(node.callee) ?? "";
    if (name === "Math.random") return true;
    // e.g. Math.random().toString(36) — callee is a member of the call.
    if (t.isMemberExpression(node.callee)) return containsMathRandom(node.callee.object);
    return node.arguments.some((a) => containsMathRandom(a as t.Node));
  }
  if (t.isMemberExpression(node)) return containsMathRandom(node.object);
  if (t.isBinaryExpression(node)) return containsMathRandom(node.left) || containsMathRandom(node.right);
  if (t.isTemplateLiteral(node)) return node.expressions.some((e) => containsMathRandom(e));
  if (t.isUnaryExpression(node)) return containsMathRandom(node.argument);
  if (t.isLogicalExpression(node)) return containsMathRandom(node.left) || containsMathRandom(node.right);
  if (t.isConditionalExpression(node)) {
    return containsMathRandom(node.test) || containsMathRandom(node.consequent) || containsMathRandom(node.alternate);
  }
  return false;
}

export default rule;
