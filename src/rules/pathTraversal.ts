import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, lineSnippet } from "../helpers.js";

const FS_FUNCS = /^(readFile|readFileSync|createReadStream|createWriteStream|open|access|stat|unlink)$/;

function isSuspiciousPathArg(node: t.Node | undefined, source: string): boolean {
  if (!node) return false;
  const text = source.slice(node.start ?? 0, node.end ?? 0);
  // Explicit traversal sequences in the expression.
  if (text.includes("../") || text.includes("..\\")) return true;
  // User input (HTTP request data) used directly as a path.
  if (/\b(req|request|ctx|context)\s*\.\s*(query|params|body|cookies)\b/.test(text)) return true;
  // Template literal interpolation (e.g. `/var/www/${name}`).
  if (t.isTemplateLiteral(node) && node.expressions.length > 0) return true;
  // Concatenation involving request input.
  if (t.isBinaryExpression(node) && node.operator === "+" && /\b(req|request)\b/.test(text)) return true;
  return false;
}

const rule: Rule = {
  id: "CS-007",
  title: "Path traversal",
  description:
    "Detects filesystem access where the path is built from variables or user input without validation. Attackers can supply '../' sequences to read or write files outside the intended directory.",
  severity: "high",
  cwe: "CWE-22",
  remediation:
    "Validate and normalize user-supplied paths, reject '..' segments, and ensure the resolved path stays within an allowed base directory (path.resolve + prefix check).",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      CallExpression(path) {
        const name = calleeName(path.node.callee) ?? "";
        const leaf = name.split(".").pop() ?? "";
        if (!FS_FUNCS.test(leaf)) return;
        for (const arg of path.node.arguments) {
          if (isSuspiciousPathArg(arg as t.Node, ctx.source)) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `${name} receives a dynamically built path — validate against traversal sequences.`,
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
            });
            break;
          }
        }
      },
    });
    return findings;
  },
};

export default rule;
