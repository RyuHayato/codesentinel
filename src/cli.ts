#!/usr/bin/env node
import { resolve, isAbsolute } from "node:path";
import { existsSync, statSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { scan, ScanOptions } from "./scanner/ruleEngine.js";
import { loadConfig } from "./config.js";
import { formatResult, severityAtLeast } from "./reporters/index.js";
import { applyBaseline, loadBaseline, writeBaseline } from "./baseline.js";
import { ALL_RULES } from "./rules/index.js";
import { SEVERITIES, Severity } from "./types.js";

const USAGE = `
CodeSentinel — lightweight static-analysis security scanner

Usage:
  codesentinel <path> [options]

Arguments:
  <path>                    File or directory to scan (e.g. ./src)

Options:
  --format <terminal|json|sarif>   Output format (default: terminal)
  --severity <severity>            Minimum severity to report
                                   (critical|high|medium|low|info, default: low)
  --fail-on <severity|none>        Exit 1 when findings at/above severity occur
                                   (default: none)
  --config <path>                  Path to config file (default: .codesentinelrc.json)
  --baseline <path>                Suppress findings already recorded in this baseline
  --write-baseline <path>          Save current findings as the baseline file
  --list-rules                     List all rules and exit
  --no-color                       Disable colored terminal output
  -v, --version                    Print version and exit
  -h, --help                       Show this help

Examples:
  codesentinel ./src
  codesentinel ./src --severity high
  codesentinel ./src --format json
  codesentinel ./src --format sarif --fail-on high
`;

export const VERSION = "0.2.0";

interface ParsedArgs {
  path: string | null;
  format?: "terminal" | "json" | "sarif";
  severity?: Severity;
  failOn?: Severity | "none";
  configPath?: string;
  baselinePath?: string;
  writeBaselinePath?: string;
  listRules: boolean;
  noColor: boolean;
  version: boolean;
  help: boolean;
}

class ArgError extends Error {}

const VALUE_OPTIONS = new Set(["--format", "--severity", "--fail-on", "--config"]);

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { path: null, listRules: false, noColor: false, version: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--") break;
    switch (arg) {
      case "--help":
      case "-h":
        out.help = true;
        break;
      case "--version":
      case "-v":
        out.version = true;
        break;
      case "--list-rules":
        out.listRules = true;
        break;
      case "--no-color":
        out.noColor = true;
        break;
      case "--format":
      case "--severity":
      case "--fail-on":
      case "--config":
      case "--baseline":
      case "--write-baseline": {
        const value = argv[++i];
        if (value === undefined || (value.startsWith("--") && value !== "-v")) {
          throw new ArgError(`Option ${arg} requires a value.`);
        }
        if (arg === "--format") out.format = value as ParsedArgs["format"];
        else if (arg === "--severity") out.severity = value as Severity;
        else if (arg === "--fail-on") out.failOn = value as Severity | "none";
        else if (arg === "--config") out.configPath = value;
        else if (arg === "--baseline") out.baselinePath = value;
        else out.writeBaselinePath = value;
        break;
      }
      default:
        if (arg.startsWith("--")) throw new ArgError(`Unknown option: ${arg}`);
        if (out.path === null) out.path = arg;
        else throw new ArgError(`Unexpected extra argument: ${arg}`);
    }
  }
  return out;
}

export function main(argv: string[]): number {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}\n` + USAGE);
    return 2;
  }
  if (args.help) {
    console.log(USAGE);
    return 0;
  }
  if (args.version) {
    console.log(`CodeSentinel ${VERSION}`);
    return 0;
  }
  if (args.listRules) {
    if (args.format === "json") {
      console.log(
        JSON.stringify(
          ALL_RULES.map((r) => ({ id: r.id, title: r.title, severity: r.severity, cwe: r.cwe, description: r.description })),
          null,
          2,
        ),
      );
    } else {
      for (const r of ALL_RULES) {
        console.log(`${r.id}  [${r.severity}]  ${r.title} (${r.cwe})`);
        console.log(`      ${r.description.slice(0, 110)}`);
      }
    }
    return 0;
  }
  if (!args.path) {
    console.error("Error: no path provided.\n" + USAGE);
    return 2;
  }

  // Validate flags before doing any work so mistakes fail fast.
  if (args.severity && !(SEVERITIES as readonly string[]).includes(args.severity)) {
    console.error(`Error: invalid --severity "${args.severity}". Expected one of: ${SEVERITIES.join(", ")}`);
    return 2;
  }
  if (args.format && !["terminal", "json", "sarif"].includes(args.format)) {
    console.error(`Error: invalid --format "${args.format}". Expected terminal|json|sarif.`);
    return 2;
  }
  if (args.failOn && args.failOn !== "none" && !(SEVERITIES as readonly string[]).includes(args.failOn)) {
    console.error(`Error: invalid --fail-on "${args.failOn}". Expected one of: ${[...SEVERITIES, "none"].join(", ")}`);
    return 2;
  }

  const root = isAbsolute(args.path) ? args.path : resolve(process.cwd(), args.path);
  if (!existsSync(root)) {
    console.error(`Error: path does not exist: ${args.path}`);
    return 2;
  }

  // Config is discovered from the scan target's directory (its parent for files), falling back to cwd.
  let configProbe = root;
  try {
    if (statSync(root).isFile()) configProbe = resolve(root, "..");
  } catch {
    /* use root */
  }
  let config: ReturnType<typeof loadConfig>;
  try {
    if (args.configPath) {
      config = loadConfig(configProbe, args.configPath);
    } else {
      const hasConfig = (dir: string) =>
        existsSync(resolve(dir, ".codesentinelrc.json")) || existsSync(resolve(dir, "codesentinel.config.json"));
      const base = hasConfig(configProbe) ? configProbe : process.cwd();
      config = loadConfig(base);
    }
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    return 2;
  }

  const minSeverity = args.severity ?? config.severity;
  const scanOptions: ScanOptions = { root, minSeverity, configPath: args.configPath, config };

  let result;
  try {
    result = scan(scanOptions);
  } catch (err) {
    console.error(`Error scanning ${args.path}: ${(err as Error).message}`);
    return 2;
  }

  if (args.writeBaselinePath) {
    try {
      writeBaseline(args.writeBaselinePath, result.findings);
      console.error(`Baseline written: ${args.writeBaselinePath} (${result.findings.length} findings recorded)`);
    } catch (err) {
      console.error(`Error writing baseline: ${(err as Error).message}`);
      return 2;
    }
  }

  if (args.baselinePath) {
    let suppressed;
    try {
      suppressed = loadBaseline(args.baselinePath);
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      return 2;
    }
    const kept = applyBaseline(result.findings, suppressed);
    const findingsBySeverity = { ...result.summary.findingsBySeverity };
    for (const key of Object.keys(findingsBySeverity) as Severity[]) {
      const removedHere = result.findings.filter((f) => !kept.includes(f) && f.severity === key).length;
      findingsBySeverity[key] -= removedHere;
    }
    result = { findings: kept, summary: { ...result.summary, findingsBySeverity, total: kept.length } };
  }

  if (args.noColor) process.env.NO_COLOR = "1";
  const format = args.format ?? config.format;
  process.stdout.write(formatResult(result, format) + "\n");

  const failOn = args.failOn ?? config.failOn;
  const shouldFail = result.findings.some((f) => severityAtLeast(f.severity, failOn));
  return shouldFail ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exit(main(process.argv.slice(2)));
}
