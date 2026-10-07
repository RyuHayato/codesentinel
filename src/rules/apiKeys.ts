import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { isStringLiteral, lineSnippet } from "../helpers.js";

interface KeyPattern {
  name: string;
  pattern: RegExp;
}

const KEY_PATTERNS: KeyPattern[] = [
  { name: "AWS access key ID", pattern: /AKIA[0-9A-Z]{16}/ },
  { name: "GitHub personal access token", pattern: /ghp_[A-Za-z0-9]{36,}/ },
  { name: "GitHub fine-grained token", pattern: /github_pat_[A-Za-z0-9_]{22,}/ },
  { name: "GitHub OAuth/app token", pattern: /gho_[A-Za-z0-9]{36,}|ghu_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,}/ },
  { name: "Slack token", pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: "Google API key", pattern: /AIza[0-9A-Za-z_-]{35}/ },
  { name: "OpenAI API key", pattern: /sk-[A-Za-z0-9]{20,}/ },
  { name: "Stripe live key", pattern: /(sk|rk)_live_[A-Za-z0-9]{20,}/ },
  { name: "Slack webhook", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/ },
  { name: "Discord webhook", pattern: /https:\/\/discord(app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/ },
  { name: "Twilio SID", pattern: /AC[a-f0-9]{32}/ },
  { name: "Private key material", pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { name: "Generic API key assignment", pattern: /"?(api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)"?\s*[:=]\s*"[A-Za-z0-9_\-]{16,}"/i },
];

const rule: Rule = {
  id: "CS-002",
  title: "Exposed API key",
  description:
    "Detects well-known API key and token formats (AWS, GitHub, Slack, Google, OpenAI, Stripe, private keys) embedded in source.",
  severity: "critical",
  cwe: "CWE-798",
  remediation:
    "Revoke and rotate the exposed credential immediately, then load it from an environment variable or secrets manager.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      StringLiteral(path) {
        for (const { name, pattern } of KEY_PATTERNS) {
          if (pattern.test(path.node.value)) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `Possible ${name} found in string literal.`,
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0).replace(/([A-Za-z0-9]{6})[A-Za-z0-9_\-]+/g, "$1***"),
            });
          }
        }
      },
      TemplateLiteral(path) {
        for (const q of path.node.quasis) {
          const text = q.value.cooked ?? "";
          for (const { name, pattern } of KEY_PATTERNS) {
            if (pattern.test(text)) {
              findings.push({
                ruleId: rule.id,
                filePath: ctx.filePath,
                line: path.node.loc?.start.line ?? 0,
                column: (path.node.loc?.start.column ?? 0) + 1,
                message: `Possible ${name} found in template literal.`,
                snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
              });
            }
          }
        }
      },
    });
    // Also scan raw source (catches keys in comments, regexes, etc.)
    const lines = ctx.source.split(/\r?\n/);
    lines.forEach((text, i) => {
      for (const { name, pattern } of KEY_PATTERNS) {
        if (pattern.test(text)) {
          const already = findings.some((f) => f.line === i + 1);
          if (!already) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: i + 1,
              column: 1,
              message: `Possible ${name} found in source text.`,
              snippet: text.trim().slice(0, 200),
            });
          }
        }
      }
    });
    return findings;
  },
};

export default rule;
