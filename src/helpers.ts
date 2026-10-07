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
  if (t.isOptionalMemberExpression(node)) {
    const obj = calleeName(node.object);
    const prop = t.isIdentifier(node.property) ? node.property.name : null;
    if (!prop) return obj;
    return obj ? `${obj}.${prop}` : prop;
  }
  return null;
}

/** Last segment of a dotted callee name, e.g. "execSync" for "child_process.execSync". */
export function calleeLeaf(node: t.Node): string {
  return (calleeName(node) ?? "").split(".").pop() ?? "";
}

export function isStringLiteral(node: t.Node | null | undefined): node is t.StringLiteral {
  return !!node && t.isStringLiteral(node);
}

/** Strip the "node:" prefix from a module id, e.g. "node:fs" -> "fs". */
export function bareModuleId(id: string): string {
  return id.startsWith("node:") ? id.slice(5) : id;
}

/** True when text references HTTP request data (req.body, request.query, ...). */
export function containsRequestInput(text: string): boolean {
  return /\b(req|request|ctx|context)\s*\.\s*(query|params|body|cookies|headers)\b/.test(text);
}

/** Collect every module id imported/required in the file (normalized, no "node:" prefix). */
export function importedModules(ast: t.File): Set<string> {
  const modules = new Set<string>();
  function visit(node: t.Node): void {
    if (t.isImportDeclaration(node)) {
      modules.add(bareModuleId(node.source.value));
      return;
    }
    if (t.isCallExpression(node)) {
      const callee = node.callee;
      const isRequire =
        (t.isIdentifier(callee) && callee.name === "require") ||
        (t.isMemberExpression(callee) &&
          t.isIdentifier(callee.object) &&
          callee.object.name === "module" &&
          t.isIdentifier(callee.property) &&
          callee.property.name === "require");
      if (isRequire) {
        const arg = node.arguments[0];
        if (arg && t.isStringLiteral(arg)) modules.add(bareModuleId(arg.value));
      }
    }
    // Recurse into children via a lightweight DFS over object values.
    for (const key of Object.keys(node)) {
      if (key === "loc" || key === "start" || key === "end" || key === "leadingComments" || key === "trailingComments" || key === "innerComments") continue;
      const child = (node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(child)) {
        for (const c of child) if (c && typeof c === "object" && "type" in (c as object)) visit(c as t.Node);
      } else if (child && typeof child === "object" && "type" in (child as object)) {
        visit(child as t.Node);
      }
    }
  }
  visit(ast);
  return modules;
}

/** Key name of an object property node, e.g. { rejectUnauthorized: false } -> "rejectUnauthorized". */
export function propertyName(prop: t.Node): string | null {
  if (t.isObjectProperty(prop) || t.isObjectMethod(prop)) {
    if (t.isIdentifier(prop.key)) return prop.key.name;
    if (t.isStringLiteral(prop.key)) return prop.key.value;
  }
  return null;
}

/** Find a property value in an object expression by key name. */
export function getPropertyValue(obj: t.Node | null | undefined, key: string): t.Node | null {
  if (!obj || !t.isObjectExpression(obj)) return null;
  for (const prop of obj.properties) {
    if (propertyName(prop) === key) {
      return t.isObjectProperty(prop) ? (prop.value as t.Node) : null;
    }
  }
  return null;
}

/** Extract source text of a node, or "" when positions are missing. */
export function nodeText(node: t.Node | null | undefined, source: string): string {
  if (!node) return "";
  const start = node.start ?? 0;
  const end = node.end ?? 0;
  if (end <= start) return "";
  return source.slice(start, end);
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
