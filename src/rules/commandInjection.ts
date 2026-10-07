import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, lineSnippet } from "../helpers.js";

const EXEC_FUNCS = /^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$/;

function isDangerousArg(node: t.Node, source: string): boolean {
  if (t.isTemplateLiteral(node) && node.expressions.length > 0) return true;
  if (t.isBinaryExpression(node) && node.operator === "+") return true;
  if (t.isIdentifier(node) || t.isMemberExpression(node) || t.isCallExpression(node)) {
    const text = source.slice(node.start ?? 0, node.end ?? 0);
    return !/^"[^"]*"$/.test(text) && !/^'[^']*'$/.test(text);
  }
  return false;
}

const rule: Rule = {
  id: "CS-004",
  title: "Command injection",
  description:
    "Detects child_process calls whose command argument is built dynamically (template literal, concatenation, or a variable). Unsanitized input lets attackers execute arbitrary OS commands.",
  severity: "critical",
  cwe: "CWE-78",
  remediation:
    "Avoid shell commands where possible; if needed, pass arguments as an array to spawn/execFile without shell interpolation, and validate/sanitize all user input.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      CallExpression(path) {
        const name = calleeName(path.node.callee) ?? "";
        const leaf = name.split(".").pop() ?? "";
        if (!EXEC_FUNCS.test(leaf)) return;
        const arg = path.node.arguments[0];
        if (arg && isDangerousArg(arg as t.Node, ctx.source)) {
          // Require the callee to look like a child_process import or plain exec/execSync.
          const looksProcess = /(child_process)?\.?(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$/.test(name);
          if (looksProcess) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `${name} called with a dynamically constructed command — possible command injection.`,
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
            });
          }
        }
      },
    });
    return findings;
  },
};

export default rule;
