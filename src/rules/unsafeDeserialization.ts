import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, lineSnippet } from "../helpers.js";

const rule: Rule = {
  id: "CS-011",
  title: "Unsafe deserialization",
  description:
    "Detects deserialization of untrusted data via dangerous libraries (node-serialize), js-yaml .load() (code execution via !!js/function in old versions), and vm execution of dynamic strings. These can achieve remote code execution.",
  severity: "critical",
  cwe: "CWE-502",
  remediation:
    "Use safe formats (JSON.parse), a safe YAML schema (yaml.load from 'yaml', or yaml.safeLoad from js-yaml v3), and never deserialize untrusted input with node-serialize, eval, or vm.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    const source = ctx.source;
    traverse(ctx.ast, {
      CallExpression(path) {
        const name = calleeName(path.node.callee) ?? "";

        if (/\.?unserialize$/.test(name)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `"${name}" performs unsafe deserialization — untrusted data can execute code.`,
            snippet: lineSnippet(source, path.node.loc?.start.line ?? 0),
          });
        }

        if (/(^|\.)load$/.test(name)) {
          const calleeText = source.slice(path.node.callee.start ?? 0, path.node.callee.end ?? 0);
          if (/yaml/i.test(calleeText)) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: "yaml.load() with untrusted data can construct arbitrary JS objects/functions — prefer yaml.load with a safe schema or JSON.",
              snippet: lineSnippet(source, path.node.loc?.start.line ?? 0),
            });
          }
        }

        if (name === "eval") {
          const arg = path.node.arguments[0];
          if (arg && t.isCallExpression(arg) && calleeName(arg.callee) === "JSON.parse") {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: "eval(JSON.parse(...)) executes parsed JSON as code — never do this.",
              snippet: lineSnippet(source, path.node.loc?.start.line ?? 0),
            });
          }
        }

        if (/^vm\.(runInNewContext|runInThisContext|runInContext)$/.test(name)) {
          const arg = path.node.arguments[0];
          if (arg && !t.isStringLiteral(arg)) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `${name} executes a dynamic string — untrusted input leads to RCE.`,
              snippet: lineSnippet(source, path.node.loc?.start.line ?? 0),
            });
          }
        }
      },
      ImportDeclaration(path) {
        const src = path.node.source.value;
        if (src === "node-serialize" || src === "pickle") {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `Importing unsafe deserialization library "${src}".`,
            snippet: lineSnippet(source, path.node.loc?.start.line ?? 0),
          });
        }
      },
    });
    return findings;
  },
};

export default rule;
