import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { isStringLiteral, lineSnippet } from "../helpers.js";

const SENSITIVE_NAME = /(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|session[_-]?secret)/i;

const PLACEHOLDER = /^(your[_-]?|example|changeme|change[_-]?me|xxx+|<.+>|\$\{?\w|%[A-Z_]|todo|fixme|test[_-]?|sample|dummy|placeholder|none|null)/i;

function looksLikeSecret(name: string, value: string): boolean {
  if (value.length < 8) return false;
  if (PLACEHOLDER.test(value)) return false;
  // Skip obvious template text like "my secret in words with spaces"
  if (/\s/.test(value) && /^[a-z ]+$/i.test(value) && value.length < 30) return false;
  return SENSITIVE_NAME.test(name);
}

const rule: Rule = {
  id: "CS-001",
  title: "Hardcoded secret",
  description:
    "Detects credentials (passwords, tokens, secrets) assigned directly in source code. Hardcoded secrets leak through version control and build artifacts.",
  severity: "high",
  cwe: "CWE-798",
  remediation:
    "Load secrets from environment variables or a dedicated secrets manager (e.g. Vault, AWS Secrets Manager). Rotate any secret that was ever committed.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      VariableDeclarator(path) {
        const id = path.node.id;
        const init = path.node.init;
        if (t.isIdentifier(id) && isStringLiteral(init) && looksLikeSecret(id.name, init.value)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `Hardcoded secret assigned to variable "${id.name}".`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
      ObjectProperty(path) {
        const key = path.node.key;
        const name = t.isIdentifier(key) ? key.name : isStringLiteral(key) ? key.value : null;
        if (name && isStringLiteral(path.node.value) && looksLikeSecret(name, path.node.value.value)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `Hardcoded secret assigned to property "${name}".`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
      AssignmentExpression(path) {
        const left = path.node.left;
        const right = path.node.right;
        const name = t.isMemberExpression(left) && t.isIdentifier(left.property) ? left.property.name : t.isIdentifier(left) ? left.name : null;
        if (name && isStringLiteral(right) && looksLikeSecret(name, right.value)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `Hardcoded secret assigned to "${name}".`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
    });
    return findings;
  },
};

export default rule;
