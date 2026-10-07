import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, containsRequestInput, lineSnippet } from "../helpers.js";

const QUERY_METHODS = /^(find|findOne|findOneAndUpdate|findOneAndDelete|update|updateOne|updateMany|deleteOne|deleteMany|aggregate)$/;

const rule: Rule = {
  id: "CS-016",
  title: "NoSQL injection",
  description:
    "Detects MongoDB-style query objects built from request bodies or containing $where / operator injection from user input. Attackers can alter queries (e.g. bypass auth with { $gt: '' }).",
  severity: "high",
  cwe: "CWE-943",
  remediation:
    "Validate and cast request input before building queries, never pass req.body/req.query directly to find()/update(), and strip keys starting with '$' or '.' from untrusted input.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    const vars = new Map<string, t.Node>();
    traverse(ctx.ast, {
      VariableDeclarator(path) {
        if (t.isIdentifier(path.node.id) && path.node.init) vars.set(path.node.id.name, path.node.init as t.Node);
      },
    });
    traverse(ctx.ast, {
      ObjectProperty(path) {
        // { $where: "..." } anywhere
        const key = path.node.key;
        const name = t.isIdentifier(key) ? key.name : t.isStringLiteral(key) ? key.value : null;
        if (name === "$where") {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "$where evaluates JavaScript on the database server — avoid, especially with user input.",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
      CallExpression(path) {
        const name = calleeName(path.node.callee) ?? "";
        const leaf = name.split(".").pop() ?? "";
        if (!QUERY_METHODS.test(leaf)) return;
        // Guard against false positives: the query method must be called on a
        // database-ish receiver (collection/model/db/sequelize/prisma), otherwise
        // crypto.createHash(...).update(x) or map.update(y) would match.
        if (!t.isMemberExpression(path.node.callee)) return;
        const receiverText = ctx.source.slice(path.node.callee.object.start ?? 0, path.node.callee.object.end ?? 0);
        if (!/collection|\.model\(|^model\.|\bdb\b|mongo|sequelize|prisma|table/i.test(receiverText)) return;
        let arg = path.node.arguments[0] as t.Node | undefined;
        if (arg && t.isIdentifier(arg)) arg = vars.get(arg.name) ?? arg;
        if (!arg) return;
        const text = ctx.source.slice(arg.start ?? 0, arg.end ?? 0);
        // Direct use of request input as the query filter.
        if (containsRequestInput(text)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: `${name} called with raw request data (${text.slice(0, 40)}) — operator injection possible.`,
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
      },
    });
    return findings;
  },
};

export default rule;
