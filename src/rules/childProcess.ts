import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, lineSnippet } from "../helpers.js";

const rule: Rule = {
  id: "CS-006",
  title: "Dangerous child-process execution",
  description:
    "Detects use of child_process.exec/execSync (spawns a shell) and spawn with shell:true. These are risky primitives; command interpolation is a frequent source of RCE vulnerabilities.",
  severity: "medium",
  cwe: "CWE-78",
  remediation:
    "Prefer execFile/spawn with an argument array and shell:false. Never interpolate user input into shell commands.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      CallExpression(path) {
        const name = calleeName(path.node.callee) ?? "";
        const leaf = name.split(".").pop() ?? "";
        if (leaf === "exec" || leaf === "execSync") {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `${name} runs commands through a shell — audit every argument for user input.`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
        if ((leaf === "spawn" || leaf === "spawnSync") && path.node.arguments.length >= 2) {
          const opts = path.node.arguments[path.node.arguments.length - 1];
          if (t.isObjectExpression(opts)) {
            for (const prop of opts.properties) {
              if (t.isObjectProperty(prop) && t.isIdentifier(prop.key) && prop.key.name === "shell" && t.isBooleanLiteral(prop.value) && prop.value.value === true) {
                findings.push({
                  ruleId: rule.id,
                  filePath: ctx.filePath,
                  line: path.node.loc?.start.line ?? 0,
                  column: (path.node.loc?.start.column ?? 0) + 1,
                  message: `${name} called with shell:true — command strings will be interpreted by a shell.`,
                  snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
                  severity: "high",
                });
              }
            }
          }
        }
      },
    });
    return findings;
  },
};

export default rule;
