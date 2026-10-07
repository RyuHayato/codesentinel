import { parse } from "@babel/parser";
import type { File } from "@babel/types";
import { parserPlugins } from "./helpers.js";

export interface ParseResult {
  ast: File | null;
  error: string | null;
}

/** Parse JS/TS(X) source into a Babel AST, returning a helpful error on failure. */
export function parseSource(filePath: string, source: string): ParseResult {
  try {
    const ast = parse(source, {
      sourceType: "unambiguous",
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      errorRecovery: false,
      plugins: parserPlugins(filePath) as never,
    });
    return { ast, error: null };
  } catch (err) {
    const e = err as Error & { loc?: { line: number; column: number } };
    const where = e.loc ? ` (line ${e.loc.line}, column ${e.loc.column})` : "";
    return { ast: null, error: `${e.message}${where}` };
  }
}

export const SCANNABLE_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];

export function isScannableFile(filePath: string): boolean {
  return SCANNABLE_EXTENSIONS.some((ext) => filePath.endsWith(ext));
}
