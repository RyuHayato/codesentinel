import traverse from "@babel/traverse";
import * as t from "@babel/types";
import type { RawFinding, Rule, RuleContext } from "../types.js";
import { calleeName, lineSnippet } from "../helpers.js";

const WEAK_HASHES = new Set(["md5", "sha1"]);
const WEAK_CIPHERS = /^(des|des-ede|des-ede3|rc4|rc2|blowfish)$/i;

const rule: Rule = {
  id: "CS-009",
  title: "Weak cryptographic function",
  description:
    "Detects use of broken or deprecated crypto primitives: MD5, SHA-1, DES, RC4, and the deprecated createCipher API. These are vulnerable to collision/brute-force/key-recovery attacks.",
  severity: "medium",
  cwe: "CWE-327",
  remediation:
    "Use SHA-256+ for hashing (or bcrypt/argon2 for passwords), AES-GCM for encryption, and crypto.createCipheriv with a random IV/key instead of createCipher.",
  check(ctx: RuleContext): RawFinding[] {
    const findings: RawFinding[] = [];
    traverse(ctx.ast, {
      CallExpression(path) {
        const name = calleeName(path.node.callee) ?? "";
        if (/\.?createHash$/.test(name)) {
          const arg = path.node.arguments[0];
          if (arg && t.isStringLiteral(arg) && WEAK_HASHES.has(arg.value.toLowerCase())) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `createHash("${arg.value}") uses a weak hashing algorithm.`,
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
            });
          }
        }
        if (/\.?createCipher$/.test(name)) {
          findings.push({
            ruleId: rule.id,
            filePath: ctx.filePath,
            line: path.node.loc?.start.line ?? 0,
            column: (path.node.loc?.start.column ?? 0) + 1,
            message: "createCipher is deprecated and derives a key insecurely — use createCipheriv with a random key/IV.",
            snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
          });
        }
        if (/\.?createCipheriv$/.test(name)) {
          const arg = path.node.arguments[0];
          if (arg && t.isStringLiteral(arg) && WEAK_CIPHERS.test(arg.value)) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `createCipheriv("${arg.value}") uses a weak cipher.`,
              snippet: lineSnippet(ctx.source, path.node.loc?.start.line ?? 0),
              severity: "high",
            });
          }
        }
        if (/\.?createHmac$/.test(name)) {
          const arg = path.node.arguments[0];
          if (arg && t.isStringLiteral(arg) && WEAK_HASHES.has(arg.value.toLowerCase())) {
            findings.push({
              ruleId: rule.id,
              filePath: ctx.filePath,
              line: path.node.loc?.start.line ?? 0,
              column: (path.node.loc?.start.column ?? 0) + 1,
              message: `createHmac("${arg.value}") uses a weak hash.`,
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
