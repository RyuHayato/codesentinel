import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, lineSnippet } from "../helpers.js";

const MERGE_FUNCS = /^(merge|mergeWith|defaultsDeep|extend|extendDeep|assignDeep|deepMerge|deepAssign|deepExtend)$/;

const rule: Rule = {
  id: "CS-010",
  title: "Prototype pollution",
  description:
    "Detects patterns that allow attackers to pollute Object.prototype: '__proto__'/'constructor.prototype' writes, computed-key assignments from user input, and deep-merge of untrusted objects.",
  severity: "high",
  cwe: "CWE-1321",
  remediation:
    "Use Object.create(null) for dictionaries, sanitize keys (reject __proto__/constructor/prototype), use Object.assign or structuredClone, and avoid deep-merging untrusted JSON.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      MemberExpression(path) {
        // obj.__proto__ or obj["__proto__"] or obj.constructor.prototype
        const propText = path.node.computed
          ? (t.isStringLiteral(path.node.property) ? path.node.property.value : null)
          : t.isIdentifier(path.node.property)
            ? path.node.property.name
            : null;
        if (propText === "__proto__") {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "Direct access/assignment to '__proto__' can lead to prototype pollution.",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
        if (!path.node.computed && t.isIdentifier(path.node.property) && path.node.property.name === "prototype" && t.isMemberExpression(path.node.object)) {
          const inner = path.node.object;
          if (t.isIdentifier(inner.property) && inner.property.name === "constructor") {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: "Accessing 'constructor.prototype' is a common prototype pollution vector.",
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
            });
          }
        }
      },
      AssignmentExpression(path) {
        // target[userControlledKey] = value
        const left = path.node.left;
        if (t.isMemberExpression(left) && left.computed) {
          const text = ctx.source.slice(left.property.start ?? 0, left.property.end ?? 0);
          if (/\b(req|request)\s*\.\s*(body|query|params)\b/.test(text) || t.isMemberExpression(left.property)) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `Computed-key assignment with key from "${text}" — validate keys before writing.`,
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
              severity: "medium",
            });
          }
        }
      },
      CallExpression(path) {
        const name = calleeName(path.node.callee) ?? "";
        const leaf = name.split(".").pop() ?? "";
        if (MERGE_FUNCS.test(leaf)) {
          const argsText = path.node.arguments
            .map((a) => ctx.source.slice(a.start ?? 0, a.end ?? 0))
            .join(", ");
          if (/\b(req|request)\s*\.\s*(body|query|params)\b|JSON\.parse/.test(argsText)) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `Deep merge (${name}) on untrusted input — prototypes can be polluted.`,
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
