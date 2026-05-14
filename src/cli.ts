#!/usr/bin/env node
import path from "node:path";
import fs from "node:fs/promises";
import { renderHtmlReport, renderJsonReport, renderMarkdownReport, renderSarifReport, writeReports } from "./report-generator";
import { defaultScanOptions } from "./scanner-core/options";
import { runScan, runScanTargets } from "./scanner-core/orchestrator";
import { ScanProfile, ScanResult } from "./scanner-core/types";

interface CliArgs {
  command: "scan" | "report";
  target?: string;
  url?: string;
  dir?: string;
  out?: string;
  input?: string;
  format?: "html" | "markdown" | "json" | "sarif";
  apiSpecPath?: string;
  profile: ScanProfile;
  confirmAuthorization: boolean;
  authorizationConfirmation?: string;
  includeExternal: boolean;
  rateLimitRps?: number;
  timeoutMs?: number;
  nucleiTemplates: string[];
  kevCatalogPath?: string;
  refreshKev: boolean;
  epssCsvPath?: string;
  refreshEpss: boolean;
  maxCrawlDepth?: number;
  maxCrawlPages?: number;
  help: boolean;
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return;
  }

  if (args.command === "report") {
    await runReportCommand(args);
    return;
  }

  if (!args.target && !args.url && !args.dir && !args.apiSpecPath) {
    printHelp();
    process.exitCode = 1;
    return;
  }

  const options = defaultScanOptions({
    profile: args.profile,
    outputDir: path.resolve(args.out ?? "reports/latest"),
    confirmAuthorization: args.confirmAuthorization || args.authorizationConfirmation === AUTHORIZATION_CONFIRMATION,
    includeExternal: args.includeExternal,
    rateLimitRps: args.rateLimitRps ?? 1,
    timeoutMs: args.timeoutMs ?? 15000,
    nucleiTemplates: args.nucleiTemplates,
    kevCatalogPath: args.kevCatalogPath,
    refreshKev: args.refreshKev,
    epssCsvPath: args.epssCsvPath,
    refreshEpss: args.refreshEpss,
    apiSpecPath: args.apiSpecPath,
    maxCrawlDepth: args.maxCrawlDepth ?? 1,
    maxCrawlPages: args.maxCrawlPages ?? 25
  });

  if ((args.url || looksLikeUrl(args.target ?? "")) && !options.confirmAuthorization) {
    throw new Error(`URL scans require this exact confirmation: "${AUTHORIZATION_CONFIRMATION}"`);
  }

  const targetUrl = args.url ?? (args.target && looksLikeUrl(args.target) ? args.target : undefined);
  const targetDir = args.dir ?? (args.target && !looksLikeUrl(args.target) ? args.target : undefined);
  const result = targetUrl || targetDir || args.apiSpecPath
    ? await runScanTargets({ url: targetUrl, dir: targetDir, apiSpec: args.apiSpecPath }, options, console)
    : await runScan(args.target as string, options, console);
  const outputs = await writeReports(result, options.outputDir);

  console.log(`Scan complete. Findings: ${result.findings.length}`);
  console.log(`Reports written to ${options.outputDir}`);
  for (const [format, file] of Object.entries(outputs)) {
    console.log(`- ${format}: ${file}`);
  }
}

function parseArgs(argv: string[]): CliArgs {
  const command = argv[0] === "scan" || argv[0] === "report" ? argv.shift() as "scan" | "report" : "scan";
  const args: CliArgs = {
    command,
    target: envString("npm_config_target"),
    url: envString("npm_config_url"),
    dir: envString("npm_config_dir"),
    out: envString("npm_config_out"),
    input: envString("npm_config_input"),
    format: parseFormat(envString("npm_config_format")),
    apiSpecPath: envString("npm_config_api_spec") ? path.resolve(envString("npm_config_api_spec") as string) : undefined,
    profile: parseProfile(envString("npm_config_profile")),
    confirmAuthorization: envBoolean("npm_config_confirm_authorization"),
    authorizationConfirmation: envString("npm_config_authorization_confirmation"),
    includeExternal: envBoolean("npm_config_include_external"),
    nucleiTemplates: [],
    refreshKev: envBoolean("npm_config_refresh_kev"),
    refreshEpss: envBoolean("npm_config_refresh_epss"),
    help: false
  };
  const rateLimit = envString("npm_config_rate_limit_rps");
  const timeout = envString("npm_config_timeout_ms");
  const kevCatalog = envString("npm_config_kev_catalog");
  const epssCsv = envString("npm_config_epss_csv");
  const maxCrawlDepth = envString("npm_config_max_crawl_depth");
  const maxCrawlPages = envString("npm_config_max_crawl_pages");
  if (rateLimit) args.rateLimitRps = parsePositiveNumber(rateLimit, "--rate-limit-rps");
  if (timeout) args.timeoutMs = parsePositiveNumber(timeout, "--timeout-ms");
  if (kevCatalog) args.kevCatalogPath = path.resolve(kevCatalog);
  if (epssCsv) args.epssCsvPath = path.resolve(epssCsv);
  if (maxCrawlDepth) args.maxCrawlDepth = parseNonNegativeInteger(maxCrawlDepth, "--max-crawl-depth");
  if (maxCrawlPages) args.maxCrawlPages = parsePositiveInteger(maxCrawlPages, "--max-crawl-pages");
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
      case "--url":
        args.url = requireValue(argv, ++i, arg);
        break;
      case "--dir":
        args.dir = requireValue(argv, ++i, arg);
        break;
      case "--out":
      case "-o":
        args.out = requireValue(argv, ++i, arg);
        break;
      case "--input":
        args.input = requireValue(argv, ++i, arg);
        break;
      case "--api-spec":
        args.apiSpecPath = path.resolve(requireValue(argv, ++i, arg));
        break;
      case "--format":
        args.format = parseFormat(requireValue(argv, ++i, arg));
        break;
      case "--profile":
        args.profile = parseProfile(requireValue(argv, ++i, arg));
        break;
      case "--confirm-authorization":
        if (argv[i + 1] && !argv[i + 1].startsWith("-")) {
          args.authorizationConfirmation = argv[++i];
        } else {
          args.confirmAuthorization = true;
        }
        break;
      case "--authorization-confirmation":
        args.authorizationConfirmation = requireValue(argv, ++i, arg);
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
      case "--epss-csv":
        args.epssCsvPath = path.resolve(requireValue(argv, ++i, arg));
        break;
      case "--refresh-epss":
        args.refreshEpss = true;
        break;
      case "--max-crawl-depth":
        args.maxCrawlDepth = parseNonNegativeInteger(requireValue(argv, ++i, arg), arg);
        break;
      case "--max-crawl-pages":
        args.maxCrawlPages = parsePositiveInteger(requireValue(argv, ++i, arg), arg);
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

  let remaining = stripNpmConfigDuplicates(positional, args);

  if (!args.target && remaining[0]) {
    args.target = remaining.shift();
  }
  if (remaining[0] === "baseline" || remaining[0] === "vibe-risk") {
    args.profile = parseProfile(remaining.shift());
  }
  if (!args.out && remaining[0]) {
    args.out = remaining.shift();
  }
  if (remaining[0] === "baseline" || remaining[0] === "vibe-risk") {
    args.profile = parseProfile(remaining.shift());
  }
  if (!args.rateLimitRps && remaining[0] && isPositiveNumberText(remaining[0])) {
    args.rateLimitRps = parsePositiveNumber(remaining.shift() as string, "--rate-limit-rps");
  }
  if (!args.timeoutMs && remaining[0] && isPositiveNumberText(remaining[0])) {
    args.timeoutMs = parsePositiveNumber(remaining.shift() as string, "--timeout-ms");
  }
  remaining = stripNpmConfigDuplicates(remaining, args);
  if (remaining.length > 0) {
    throw new Error(`Unexpected positional arguments: ${remaining.join(", ")}`);
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

async function runReportCommand(args: CliArgs): Promise<void> {
  const input = path.resolve(args.input ?? path.join(args.out ?? "reports/latest", "report.json"));
  const format = args.format ?? "markdown";
  const raw = await fs.readFile(input, "utf8");
  const result = reviveScanResult(JSON.parse(raw) as ScanResult);
  const content = renderReportByFormat(result, format);
  const extension = format === "markdown" ? "md" : format === "sarif" ? "sarif" : format;
  const outputDir = path.resolve(args.out ?? path.dirname(input));
  const outputFile = path.join(outputDir, `report.${extension}`);
  await fs.mkdir(outputDir, { recursive: true });
  await fs.writeFile(outputFile, content, "utf8");
  console.log(`Report written: ${outputFile}`);
}

function renderReportByFormat(result: ScanResult, format: NonNullable<CliArgs["format"]>): string {
  switch (format) {
    case "html":
      return renderHtmlReport(result);
    case "json":
      return renderJsonReport(result);
    case "sarif":
      return renderSarifReport(result);
    case "markdown":
      return renderMarkdownReport(result);
  }
}

function reviveScanResult(result: ScanResult): ScanResult {
  if (result.target.kind === "url" && typeof result.target.url === "string") {
    return {
      ...result,
      target: {
        ...result.target,
        url: new URL(result.target.url)
      }
    };
  }
  if (result.target.kind === "combined" && result.target.url && typeof result.target.url.url === "string") {
    return {
      ...result,
      target: {
        ...result.target,
        url: {
          ...result.target.url,
          url: new URL(result.target.url.url)
        }
      }
    };
  }
  return result;
}

function parsePositiveNumber(value: string, flag: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${flag} must be a positive number.`);
  }
  return parsed;
}

function parsePositiveInteger(value: string, flag: string): number {
  const parsed = parsePositiveNumber(value, flag);
  if (!Number.isInteger(parsed)) {
    throw new Error(`${flag} must be an integer.`);
  }
  return parsed;
}

function parseNonNegativeInteger(value: string, flag: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${flag} must be a non-negative integer.`);
  }
  return parsed;
}

function isPositiveNumberText(value: string): boolean {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0;
}

function envString(name: string): string | undefined {
  const value = process.env[name];
  return value && value !== "true" ? value : undefined;
}

function envBoolean(name: string): boolean {
  return process.env[name] === "true";
}

function parseProfile(value: string | undefined): ScanProfile {
  if (!value || value === "baseline") return "baseline";
  if (value === "vibe-risk") return "vibe-risk";
  throw new Error(`Unsupported profile: ${value}`);
}

function parseFormat(value: string | undefined): CliArgs["format"] {
  if (!value) return undefined;
  if (value === "html" || value === "markdown" || value === "json" || value === "sarif") return value;
  throw new Error(`Unsupported report format: ${value}`);
}

function looksLikeUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

function stripNpmConfigDuplicates(positional: string[], args: CliArgs): string[] {
  const remaining = [...positional];
  const duplicateValues = [
    args.target,
    args.url,
    args.dir,
    args.out,
    args.profile,
    args.authorizationConfirmation,
    args.rateLimitRps?.toString(),
    args.timeoutMs?.toString(),
    args.kevCatalogPath,
    args.epssCsvPath,
    args.apiSpecPath,
    args.maxCrawlDepth?.toString(),
    args.maxCrawlPages?.toString(),
    ...args.nucleiTemplates
  ].filter((value): value is string => Boolean(value));

  while (remaining.length > 0 && duplicateValues.includes(remaining[0])) {
    remaining.shift();
  }

  return remaining;
}

const AUTHORIZATION_CONFIRMATION = "I confirm I own or am authorized to test this target.";

function printHelp(): void {
  console.log(`VibeSec defensive security auditing toolkit

Usage:
  vibesec scan --url <authorized-url> --profile vibe-risk --authorization-confirmation "${AUTHORIZATION_CONFIRMATION}"
  vibesec scan --dir <project-path> --profile vibe-risk
  vibesec scan --api-spec <openapi-json-or-yaml>
  vibesec scan --url <authorized-url> --dir <project-path> --profile vibe-risk
  vibesec report --format html --input reports/latest/report.json
  bts-sec --target <url-or-directory> [options]

Options:
  -t, --target <value>          Authorized URL or local project directory
      --url <value>             Authorized URL target
      --dir <path>              Local project directory target
      --api-spec <file>         Passive OpenAPI/Swagger JSON or YAML specification scan
      --profile <name>          baseline or vibe-risk (default: baseline)
  -o, --out <dir>               Output directory (default: reports/latest)
      --confirm-authorization   Backward-compatible URL authorization confirmation
      --authorization-confirmation <text>
                                Required phrase for URL scans: "${AUTHORIZATION_CONFIRMATION}"
      --include-external        Run installed external adapters
      --format <format>         report command format: html, markdown, json, sarif
      --input <file>            report command input JSON report
      --rate-limit-rps <n>      Built-in HTTP request rate limit (default: 1)
      --timeout-ms <n>          Request and adapter timeout (default: 15000)
      --max-crawl-depth <n>     Same-origin passive crawler depth (default: 1)
      --max-crawl-pages <n>     Same-origin passive crawler page cap (default: 25)
      --nuclei-template <id>    Allowlisted safe Nuclei template, repeatable
      --kev-catalog <path>      Local CISA KEV JSON catalog
      --refresh-kev             Fetch CISA KEV JSON catalog
      --epss-csv <path>         Local FIRST EPSS CSV for CVE enrichment
      --refresh-epss            Fetch FIRST EPSS API data for reported CVEs
  -h, --help                    Show help
`);
}

main(process.argv.slice(2)).catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
