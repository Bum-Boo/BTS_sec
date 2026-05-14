import { apiScannerAdapters } from "../api-scanner";
import { codeScannerAdapters } from "../code-scanner";
import { dependencyScannerAdapters, generateSbom } from "../dependency-scanner";
import { loadKevCveSet } from "../knowledge-base/kev";
import { secretScannerAdapters } from "../secret-scanner";
import { vibeRiskLocalAdapters, vibeRiskUrlAdapters } from "../vibe-scanner";
import { ScopedHttpClient, webScannerAdapters } from "../web-scanner";
import { aggregateScanResult } from "./aggregation";
import { runAdapterSafely } from "./task-runner";
import { validateApiSpecTarget, validateDirectoryTarget, validateTarget, validateUrlTarget } from "./target";
import { ApiSpecTarget, CombinedTarget, DirectoryTarget, Logger, ScanOptions, ScannerAdapter, ScanResult, ScanTarget, UrlTarget } from "./types";

export async function runScan(rawTarget: string, options: ScanOptions, logger: Logger = console): Promise<ScanResult> {
  if (!options.noDestructive) {
    throw new Error("Destructive scan mode is not implemented.");
  }

  const startedAt = new Date().toISOString();
  const target = validateTarget(rawTarget, { confirmAuthorization: options.confirmAuthorization });
  if (target.kind === "combined") {
    throw new Error("Combined targets must be provided through runScanTargets.");
  }
  return runValidatedTargets([target], options, logger, startedAt, target);
}

export async function runScanTargets(
  input: { url?: string; dir?: string; apiSpec?: string },
  options: ScanOptions,
  logger: Logger = console
): Promise<ScanResult> {
  if (!options.noDestructive) {
    throw new Error("Destructive scan mode is not implemented.");
  }
  if (!input.url && !input.dir && !input.apiSpec) {
    throw new Error("A URL, directory, OpenAPI spec, or combination is required.");
  }

  const targets: Array<UrlTarget | DirectoryTarget | ApiSpecTarget> = [];
  if (input.url) targets.push(validateUrlTarget(input.url, options.confirmAuthorization));
  if (input.dir) targets.push(validateDirectoryTarget(input.dir));
  if (input.apiSpec) targets.push(validateApiSpecTarget(input.apiSpec));

  const reportTarget: ScanTarget = targets.length === 1
    ? targets[0]
    : {
        kind: "combined",
        raw: targets.map((target) => target.raw).join(" + "),
        url: targets.find((target): target is UrlTarget => target.kind === "url"),
        directory: targets.find((target): target is DirectoryTarget => target.kind === "directory"),
        apiSpec: targets.find((target): target is ApiSpecTarget => target.kind === "api-spec")
      } satisfies CombinedTarget;

  return runValidatedTargets(targets, options, logger, new Date().toISOString(), reportTarget);
}

async function runValidatedTargets(
  targets: Array<UrlTarget | DirectoryTarget | ApiSpecTarget>,
  options: ScanOptions,
  logger: Logger,
  startedAt: string,
  reportTarget: ScanTarget
): Promise<ScanResult> {
  const metadata: Record<string, unknown> = {
    safety: {
      noDestructive: true,
      urlAuthorizationRequired: true,
      externalAdaptersEnabled: options.includeExternal,
      rateLimitRps: options.rateLimitRps,
      profile: options.profile,
      localProjectScriptsExecuted: false,
      arbitraryTargetCodeExecuted: false,
      localOnlyLogging: true
    },
    scanOptions: {
      profile: options.profile,
      includeExternal: options.includeExternal,
      rateLimitRps: options.rateLimitRps,
      timeoutMs: options.timeoutMs,
      outputDir: options.outputDir,
      refreshKev: options.refreshKev,
      kevCatalogPath: options.kevCatalogPath,
      refreshEpss: options.refreshEpss,
      epssCsvPath: options.epssCsvPath,
      apiSpecPath: options.apiSpecPath,
      maxCrawlDepth: options.maxCrawlDepth,
      maxCrawlPages: options.maxCrawlPages,
      noDestructive: true
    },
    suppressedFindings: []
  };

  const kevCves = await loadKevCveSet(options);
  if (kevCves.size > 0) {
    metadata.kevCves = [...kevCves];
  }

  const directoryTarget = targets.find((target): target is DirectoryTarget => target.kind === "directory");
  if (directoryTarget) {
    metadata.sbom = await generateSbom(directoryTarget.path);
  }

  const results = [];
  for (const target of targets) {
    const context = {
      target,
      options,
      logger,
      httpClient: target.kind === "url"
        ? new ScopedHttpClient(target, options.rateLimitRps, options.timeoutMs)
        : undefined
    };
    for (const adapter of adaptersForTarget(target.kind, options.profile)) {
      results.push(await runAdapterSafely(adapter, context));
    }
  }
  metadata.adapterMetadata = results
    .map((result) => result.metadata)
    .filter((item): item is Record<string, unknown> => Boolean(item));
  metadata.suppressedFindings = results.flatMap((result) => {
    const suppressed = result.metadata?.suppressedFindings;
    return Array.isArray(suppressed) ? suppressed : [];
  });

  return aggregateScanResult(
    reportTarget,
    startedAt,
    results.flatMap((result) => result.findings),
    metadata
  );
}

function adaptersForTarget(kind: "url" | "directory" | "api-spec", profile: ScanOptions["profile"]): ScannerAdapter[] {
  if (kind === "url") {
    return [
      ...webScannerAdapters(),
      ...(profile === "vibe-risk" ? vibeRiskUrlAdapters() : [])
    ];
  }
  if (kind === "api-spec") {
    return apiScannerAdapters();
  }
  return [
    ...codeScannerAdapters(),
    ...dependencyScannerAdapters(),
    ...secretScannerAdapters(),
    ...(profile === "vibe-risk" ? vibeRiskLocalAdapters() : [])
  ];
}
