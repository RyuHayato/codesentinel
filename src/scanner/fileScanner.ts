import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { isScannableFile } from "../parser.js";

const ALWAYS_SKIP = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", "out", ".turbo"]);

/** True if the path contains any ignored fragment as a path segment substring. */
export function isIgnored(filePath: string, ignore: string[]): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  const segments = normalized.split("/");
  return ignore.some((entry) => {
    const e = entry.replace(/\\/g, "/").replace(/^\/|\/$/g, "");
    if (e.length === 0) return false;
    if (e.includes("/")) return normalized.includes(`/${e}/`) || normalized.endsWith(`/${e}`);
    return segments.includes(e);
  });
}

/** Recursively collect scannable source files + package.json files under root. */
export function collectFiles(root: string, ignore: string[]): string[] {
  const out: string[] = [];
  let stats: ReturnType<typeof statSync>;
  try {
    stats = statSync(root);
  } catch {
    return out;
  }
  if (stats.isFile()) {
    if (isScannableFile(root) || root.endsWith("package.json")) out.push(root);
    return out;
  }

  function walk(dir: string): void {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      if (ALWAYS_SKIP.has(entry)) continue;
      let isDir = false;
      try {
        isDir = statSync(full).isDirectory();
      } catch {
        continue;
      }
      if (isDir) {
        walk(full);
        continue;
      }
      if (isIgnored(full, ignore)) continue;
      if (isScannableFile(full)) out.push(full);
      else if (entry === "package.json") out.push(full);
    }
  }
  walk(root);
  return out.sort();
}

/** Extract per-line inline ignore directives: // codesentinel-ignore [CS-001, CS-002] */
export function parseInlineIgnores(source: string): Map<number, Set<string>> {
  const map = new Map<number, Set<string>>();
  const lines = source.split(/\r?\n/);
  lines.forEach((text, i) => {
    const match = text.match(/codesentinel-ignore([^\r\n]*)/);
    if (!match) return;
    const ruleIds = match[1]
      .split(/[,\s]+/)
      .map((s) => s.trim().toUpperCase())
      .filter((s) => /^CS-\d{3}$/.test(s));
    const suppressed = map.get(i + 1) ?? new Set<string>();
    if (ruleIds.length === 0) suppressed.add("*");
    else for (const id of ruleIds) suppressed.add(id);
    map.set(i + 1, suppressed);
  });
  return map;
}

/** True if a finding at (ruleId, line) is suppressed by an inline ignore on the same line or the line above. */
export function isSuppressed(ruleId: string, line: number, ignores: Map<number, Set<string>>): boolean {
  for (const target of [line, line - 1]) {
    const set = ignores.get(target);
    if (set && (set.has("*") || set.has(ruleId))) return true;
  }
  return false;
}
