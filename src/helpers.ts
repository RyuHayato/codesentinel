import * as t from "@babel/types";

/** Best-effort dotted name for a callee, e.g. "db.query", "child_process.exec". */
export function calleeName(node: t.Node): string | null {
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node)) {
    const obj = calleeName(node.object);
    const prop = t.isIdentifier(node.property) ? node.property.name : null;
    if (!prop) return obj;
    return obj ? `${obj}.${prop}` : prop;
  }
  if (t.isOptionalMemberExpression(node)) return calleeName(node as unknown as t.Node);
  return null;
}

/** Get the call name including a member chain depth (e.g. "fs.readFileSync"). */
export function getCallName(callee: t.Node): string | null {
  return calleeName(callee);
}

export function isStringLiteral(node: t.Node | null | undefined): node is t.StringLiteral {
  return !!node && t.isStringLiteral(node);
}

/** Collect all string literal parts of an expression (handles templates & binary concat). */
export function stringParts(node: t.Node, out: string[] = []): string[] {
  if (t.isStringLiteral(node)) out.push(node.value);
  else if (t.isTemplateLiteral(node)) {
    for (const q of node.quasis) out.push(q.value.cooked ?? "");
  } else if (t.isBinaryExpression(node) && node.operator === "+") {
    stringParts(node.left, out);
    stringParts(node.right, out);
  }
  return out;
}

/** True if the expression interpolates or concatenates at least one non-literal. */
export function hasDynamicPart(node: t.Node): boolean {
  if (t.isTemplateLiteral(node)) return node.expressions.length > 0;
  if (t.isBinaryExpression(node) && node.operator === "+") {
    return !(t.isStringLiteral(node.left) && t.isStringLiteral(node.right)) && (hasDynamicPart(node.left) || hasDynamicPart(node.right) || !t.isStringLiteral(node.left) || !t.isStringLiteral(node.right));
  }
  if (t.isIdentifier(node) || t.isMemberExpression(node) || t.isCallExpression(node)) return true;
  return false;
}

export function sourceLines(source: string): string[] {
  return source.split(/\r?\n/);
}

export function lineSnippet(source: string, line: number): string {
  const lines = sourceLines(source);
  const text = lines[line - 1] ?? "";
  return text.trim().slice(0, 200);
}

/** Babel plugins based on file extension. */
export function parserPlugins(filePath: string): Array<string | [string, Record<string, unknown>]> {
  const p: Array<string | [string, Record<string, unknown>]> = [];
  if (/\.tsx?$/.test(filePath)) p.push("typescript");
  if (/\.[jt]sx$/.test(filePath)) p.push("jsx");
  return p;
}

/** True when the node's source text references req/query/params/body (user input). */
export function referencesRequestInput(node: t.Node, source: string): boolean {
  const start = node.start ?? 0;
  const end = node.end ?? 0;
  if (end <= start) return false;
  const text = source.slice(start, end);
  return /\b(req|request|ctx|context)\s*\.\s*(query|params|body|cookies|headers)\b/.test(text);
}
