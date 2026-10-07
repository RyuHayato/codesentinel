import { describe, it, expect } from "vitest";
import { mkdirSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { collectFiles, isIgnored, isSuppressed, parseInlineIgnores } from "../src/scanner/fileScanner";

describe("isIgnored", () => {
  it("matches exact segments", () => {
    expect(isIgnored("/app/node_modules/pkg/index.js", ["node_modules"])).toBe(true);
    expect(isIgnored("/app/src/index.js", ["node_modules"])).toBe(false);
  });

  it("matches nested paths", () => {
    expect(isIgnored("C:\\app\\tests\\fixtures\\a.js", ["tests/fixtures"])).toBe(true);
    expect(isIgnored("C:\\app\\src\\a.js", ["tests/fixtures"])).toBe(false);
  });

  it("ignores empty entries", () => {
    expect(isIgnored("/app/src/a.js", [""])).toBe(false);
  });
});

describe("collectFiles", () => {
  it("finds source files and package.json, skipping node_modules", () => {
    const dir = mkdtempSync(join(tmpdir(), "codesentinel-files-"));
    try {
      mkdirSync(join(dir, "src"), { recursive: true });
      mkdirSync(join(dir, "node_modules", "dep"), { recursive: true });
      writeFileSync(join(dir, "src", "index.js"), "console.log(1)");
      writeFileSync(join(dir, "src", "app.ts"), "export {}");
      writeFileSync(join(dir, "package.json"), "{}");
      writeFileSync(join(dir, "node_modules", "dep", "index.js"), "x");
      const files = collectFiles(dir, []);
      expect(files.some((f) => f.endsWith("index.js") && f.includes("src"))).toBe(true);
      expect(files.some((f) => f.endsWith("app.ts"))).toBe(true);
      expect(files.some((f) => f.endsWith("package.json"))).toBe(true);
      expect(files.some((f) => f.includes("node_modules"))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns a single file when root is a file", () => {
    const dir = mkdtempSync(join(tmpdir(), "codesentinel-files-"));
    try {
      const file = join(dir, "a.js");
      writeFileSync(file, "1");
      expect(collectFiles(file, [])).toEqual([file]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("inline ignores", () => {
  it("suppresses matching rule on the same line", () => {
    const source = 'const password = "x"; // codesentinel-ignore CS-001\n';
    const ignores = parseInlineIgnores(source);
    expect(isSuppressed("CS-001", 1, ignores)).toBe(true);
  });

  it("suppresses on the following line when ignore is on its own line", () => {
    const source = "// codesentinel-ignore CS-009\nconst x = crypto.createHash('md5')\n";
    const ignores = parseInlineIgnores(source);
    expect(isSuppressed("CS-009", 2, ignores)).toBe(true);
  });

  it("suppresses everything with a bare directive", () => {
    const source = "// codesentinel-ignore\nconst a = 1;\n";
    const ignores = parseInlineIgnores(source);
    expect(isSuppressed("CS-001", 2, ignores)).toBe(true);
    expect(isSuppressed("CS-012", 2, ignores)).toBe(true);
  });

  it("does not suppress other rules", () => {
    const source = "// codesentinel-ignore CS-001\nconst a = 1;\n";
    const ignores = parseInlineIgnores(source);
    expect(isSuppressed("CS-009", 2, ignores)).toBe(false);
  });
});
