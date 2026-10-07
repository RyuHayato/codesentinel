import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, lineSnippet } from "../helpers.js";

const SQL_KEYWORD = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER|FROM|WHERE)\b/i;
const QUERY_METHOD = /(query|execute|raw|run|prepare)$/i;

/** SQL text appears in the expression and it is dynamically built (template or concat). */
function isDynamicSql(node: t.Node): boolean {
  if (t.isTemplateLiteral(node) && node.expressions.length > 0) {
    return node.quasis.some((q) => SQL_KEYWORD.test(q.value.cooked ?? ""));
  }
  if (t.isBinaryExpression(node) && node.operator === "+") {
    const hasKeyword = JSON.stringify(node).match(SQL_KEYWORD) !== null;
    const dynamic =
      !t.isStringLiteral(node.left) || !t.isStringLiteral(node.right) || isDynamicSql(node.left) || isDynamicSql(node.right);
    return hasKeyword && dynamic;
  }
  return false;
}

const rule: Rule = {
  id: "CS-003",
  title: "SQL injection",
  description:
    "Detects SQL queries built by string concatenation or template interpolation instead of parameterized queries. Attacker-controlled input can alter the query's meaning.",
  severity: "critical",
  cwe: "CWE-89",
  remediation:
    "Use parameterized queries / prepared statements (e.g. db.query('SELECT * FROM users WHERE id = ?', [id])) or a query builder instead of string concatenation.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    // name -> initializer expression for simple variable propagation.
    const vars = new Map<string, t.Node>();
    traverse(ctx.ast, {
      VariableDeclarator(path) {
        if (t.isIdentifier(path.node.id) && path.node.init) vars.set(path.node.id.name, path.node.init as t.Node);
      },
    });
    traverse(ctx.ast, {
      CallExpression(path) {
        const name = calleeName(path.node.callee) ?? "";
        if (!QUERY_METHOD.test(name)) return;
        let arg = path.node.arguments[0] as t.Node | undefined;
        if (arg && t.isIdentifier(arg)) arg = vars.get(arg.name);
        if (arg && isDynamicSql(arg)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `SQL query passed to ${name} is built dynamically — possible SQL injection.`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
    });
    return findings;
  },
};

export default rule;
