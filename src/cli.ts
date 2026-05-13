#!/usr/bin/env node
import path from "node:path";
import { writeReports } from "./report-generator";
import { defaultScanOptions } from "./scanner-core/options";
import { runScan } from "./scanner-core/orchestrator";

interface CliArgs {
  target?: string;
  out?: string;
  confirmAuthorization: boolean;
  includeExternal: boolean;
  rateLimitRps?: number;
  timeoutMs?: number;
  nucleiTemplates: string[];
  kevCatalogPath?: string;
  refreshKev: boolean;
  help: boolean;
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  if (args.help || !args.target) {
    printHelp();
    process.exitCode = args.target ? 0 : 1;
    return;
  }

  const options = defaultScanOptions({
    outputDir: path.resolve(args.out ?? "reports/latest"),
    confirmAuthorization: args.confirmAuthorization,
    includeExternal: args.includeExternal,
    rateLimitRps: args.rateLimitRps ?? 1,
    timeoutMs: args.timeoutMs ?? 15000,
    nucleiTemplates: args.nucleiTemplates,
    kevCatalogPath: args.kevCatalogPath,
    refreshKev: args.refreshKev
  });

  const result = await runScan(args.target, options, console);
  const outputs = await writeReports(result, options.outputDir);

  console.log(`Scan complete. Findings: ${result.findings.length}`);
  console.log(`Reports written to ${options.outputDir}`);
  for (const [format, file] of Object.entries(outputs)) {
    console.log(`- ${format}: ${file}`);
  }
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    target: envString("npm_config_target"),
    out: envString("npm_config_out"),
    confirmAuthorization: envBoolean("npm_config_confirm_authorization"),
    includeExternal: envBoolean("npm_config_include_external"),
    nucleiTemplates: [],
    refreshKev: envBoolean("npm_config_refresh_kev"),
    help: false
  };
  const rateLimit = envString("npm_config_rate_limit_rps");
  const timeout = envString("npm_config_timeout_ms");
  const kevCatalog = envString("npm_config_kev_catalog");
  if (rateLimit) args.rateLimitRps = parsePositiveNumber(rateLimit, "--rate-limit-rps");
  if (timeout) args.timeoutMs = parsePositiveNumber(timeout, "--timeout-ms");
  if (kevCatalog) args.kevCatalogPath = path.resolve(kevCatalog);
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--":
        break;
      case "--target":
      case "-t":
        args.target = requireValue(argv, ++i, arg);
        break;
      case "--out":
      case "-o":
        args.out = requireValue(argv, ++i, arg);
        break;
      case "--confirm-authorization":
        args.confirmAuthorization = true;
        break;
      case "--include-external":
        args.includeExternal = true;
        break;
      case "--rate-limit-rps":
        args.rateLimitRps = parsePositiveNumber(requireValue(argv, ++i, arg), arg);
        break;
      case "--timeout-ms":
        args.timeoutMs = parsePositiveNumber(requireValue(argv, ++i, arg), arg);
        break;
      case "--nuclei-template":
        args.nucleiTemplates.push(requireValue(argv, ++i, arg));
        break;
      case "--kev-catalog":
        args.kevCatalogPath = path.resolve(requireValue(argv, ++i, arg));
        break;
      case "--refresh-kev":
        args.refreshKev = true;
        break;
      case "--help":
      case "-h":
        args.help = true;
        break;
      default:
        if (!arg.startsWith("-")) {
          positional.push(arg);
          break;
        }
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!args.target && positional[0]) {
    args.target = positional[0];
  }
  if (!args.out && positional[1]) {
    args.out = positional[1];
  }
  if (positional.length > 2) {
    throw new Error(`Unexpected positional arguments: ${positional.slice(2).join(", ")}`);
  }

  return args;
}

function requireValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${flag} requires a value.`);
  }
  return value;
}

function parsePositiveNumber(value: string, flag: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${flag} must be a positive number.`);
  }
  return parsed;
}

function envString(name: string): string | undefined {
  const value = process.env[name];
  return value && value !== "true" ? value : undefined;
}

function envBoolean(name: string): boolean {
  return process.env[name] === "true";
}

function printHelp(): void {
  console.log(`BTS Sec defensive security auditing toolkit

Usage:
  bts-sec --target <url-or-directory> [options]

Options:
  -t, --target <value>          Authorized URL or local project directory
  -o, --out <dir>               Output directory (default: reports/latest)
      --confirm-authorization   Required for URL scans
      --include-external        Run installed external adapters
      --rate-limit-rps <n>      Built-in HTTP request rate limit (default: 1)
      --timeout-ms <n>          Request and adapter timeout (default: 15000)
      --nuclei-template <id>    Allowlisted safe Nuclei template, repeatable
      --kev-catalog <path>      Local CISA KEV JSON catalog
      --refresh-kev             Fetch CISA KEV JSON catalog
  -h, --help                    Show help
`);
}

main(process.argv.slice(2)).catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
