#!/usr/bin/env node
import { resolve, isAbsolute } from "node:path";
import { existsSync, statSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { scan, ScanOptions } from "./scanner/ruleEngine.js";
import { loadConfig } from "./config.js";
import { formatResult, severityAtLeast } from "./reporters/index.js";
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
  --list-rules                     List all rules and exit
  -h, --help                       Show this help

Examples:
  codesentinel ./src
  codesentinel ./src --severity high
  codesentinel ./src --format json
  codesentinel ./src --format sarif --fail-on high
`;

interface ParsedArgs {
  path: string | null;
  format?: "terminal" | "json" | "sarif";
  severity?: Severity;
  failOn?: Severity | "none";
  configPath?: string;
  listRules: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { path: null, listRules: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => argv[++i];
    switch (arg) {
      case "--help":
      case "-h":
        out.help = true;
        break;
      case "--list-rules":
        out.listRules = true;
        break;
      case "--format":
        out.format = next() as "terminal" | "json" | "sarif";
        break;
      case "--severity":
        out.severity = next() as Severity;
        break;
      case "--fail-on":
        out.failOn = next() as Severity | "none";
        break;
      case "--config":
        out.configPath = next();
        break;
      default:
        if (arg.startsWith("--")) {
          console.error(`Unknown option: ${arg}`);
          process.exit(2);
        }
        if (out.path === null) out.path = arg;
        else {
          console.error(`Unexpected extra argument: ${arg}`);
          process.exit(2);
        }
    }
  }
  return out;
}

export function main(argv: string[]): number {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(USAGE);
    return 0;
  }
  if (args.listRules) {
    for (const r of ALL_RULES) {
      console.log(`${r.id}  [${r.severity}]  ${r.title} (${r.cwe})`);
      console.log(`      ${r.description.slice(0, 110)}`);
    }
    return 0;
  }
  if (!args.path) {
    console.error("Error: no path provided.\n" + USAGE);
    return 2;
  }

  const root = isAbsolute(args.path) ? args.path : resolve(process.cwd(), args.path);
  // Config is discovered from the scan target's directory (its parent for files), falling back to cwd.
  let configProbe = root;
  try {
    if (existsSync(root) && statSync(root).isFile()) configProbe = resolve(root, "..");
  } catch {
    /* use root */
  }
  let config: ReturnType<typeof loadConfig>;
  try {
    if (args.configPath) {
      config = loadConfig(configProbe, args.configPath);
    } else {
      // Prefer the scan target's directory; fall back to the working directory.
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
  if (args.severity && !(SEVERITIES as readonly string[]).includes(args.severity)) {
    console.error(`Error: invalid --severity "${args.severity}". Expected one of: ${SEVERITIES.join(", ")}`);
    return 2;
  }
  if (args.format && !["terminal", "json", "sarif"].includes(args.format)) {
    console.error(`Error: invalid --format "${args.format}". Expected terminal|json|sarif.`);
    return 2;
  }

  const scanOptions: ScanOptions = {
    root,
    minSeverity,
    configPath: args.configPath,
    config,
  };

  let result;
  try {
    result = scan(scanOptions);
  } catch (err) {
    console.error(`Error scanning ${args.path}: ${(err as Error).message}`);
    return 2;
  }

  const format = args.format ?? config.format;
  process.stdout.write(formatResult(result, format) + "\n");

  const failOn = args.failOn ?? config.failOn;
  const shouldFail = result.findings.some((f) => severityAtLeast(f.severity, failOn));
  return shouldFail ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exit(main(process.argv.slice(2)));
}
