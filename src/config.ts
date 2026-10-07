import { readFileSync, existsSync } from "node:fs";
import { join, isAbsolute } from "node:path";
import { SEVERITIES, Severity } from "./types.js";

export interface CodeSentinelConfig {
  /** Minimum severity to report. Default "low". */
  severity: Severity;
  /** Glob-ish path fragments to ignore (matched as substrings). */
  ignore: string[];
  /** Rule id -> "off" | "on" | severity override. */
  rules: Record<string, "off" | "on" | Severity>;
  /** Default output format. */
  format: "terminal" | "json" | "sarif";
  /** Exit 1 when findings at or above this severity exist. */
  failOn: Severity | "none";
}

export const DEFAULT_CONFIG: CodeSentinelConfig = {
  severity: "low",
  ignore: ["node_modules", ".git", "dist", "build", "coverage", ".next", "out"],
  rules: {},
  format: "terminal",
  failOn: "none",
};

const CONFIG_CANDIDATES = [".codesentinelrc.json", "codesentinel.config.json"];

/** Load and validate a config file, merging with defaults. Returns defaults if none found. */
export function loadConfig(root: string, explicitPath?: string): CodeSentinelConfig {
  let path: string | null = null;
  if (explicitPath) {
    path = isAbsolute(explicitPath) ? explicitPath : join(root, explicitPath);
    if (!existsSync(path)) throw new Error(`Config file not found: ${path}`);
  } else {
    for (const candidate of CONFIG_CANDIDATES) {
      const p = join(root, candidate);
      if (existsSync(p)) {
        path = p;
        break;
      }
    }
  }
  if (!path) return { ...DEFAULT_CONFIG, ignore: [...DEFAULT_CONFIG.ignore] };

  let parsed: Partial<CodeSentinelConfig>;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`Invalid JSON in config file ${path}: ${(err as Error).message}`);
  }

  const config: CodeSentinelConfig = {
    severity: isValidSeverity(parsed.severity) ? parsed.severity : DEFAULT_CONFIG.severity,
    ignore: Array.isArray(parsed.ignore) ? [...new Set([...DEFAULT_CONFIG.ignore, ...parsed.ignore])] : [...DEFAULT_CONFIG.ignore],
    rules: typeof parsed.rules === "object" && parsed.rules ? parsed.rules : {},
    format: parsed.format === "json" || parsed.format === "sarif" ? parsed.format : "terminal",
    failOn: isValidSeverity(parsed.failOn as Severity) || parsed.failOn === "none" ? (parsed.failOn as Severity | "none") : "none",
  };
  return config;
}

function isValidSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value);
}
