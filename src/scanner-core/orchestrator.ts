import { codeScannerAdapters } from "../code-scanner";
import { dependencyScannerAdapters, generateSbom } from "../dependency-scanner";
import { loadKevCveSet } from "../knowledge-base/kev";
import { secretScannerAdapters } from "../secret-scanner";
import { ScopedHttpClient, webScannerAdapters } from "../web-scanner";
import { aggregateScanResult } from "./aggregation";
import { runAdapterSafely } from "./task-runner";
import { validateTarget } from "./target";
import { Logger, ScanOptions, ScannerAdapter, ScanResult } from "./types";

export async function runScan(rawTarget: string, options: ScanOptions, logger: Logger = console): Promise<ScanResult> {
  if (!options.noDestructive) {
    throw new Error("Destructive scan mode is not implemented.");
  }

  const startedAt = new Date().toISOString();
  const target = validateTarget(rawTarget, { confirmAuthorization: options.confirmAuthorization });
  const metadata: Record<string, unknown> = {
    safety: {
      noDestructive: true,
      urlAuthorizationRequired: true,
      externalAdaptersEnabled: options.includeExternal,
      rateLimitRps: options.rateLimitRps
    }
  };

  const kevCves = await loadKevCveSet(options);
  if (kevCves.size > 0) {
    metadata.kevCves = [...kevCves];
  }

  if (target.kind === "directory") {
    metadata.sbom = await generateSbom(target.path);
  }

  const context = {
    target,
    options,
    logger,
    httpClient: target.kind === "url"
      ? new ScopedHttpClient(target, options.rateLimitRps, options.timeoutMs)
      : undefined
  };

  const adapters = adaptersForTarget(target.kind);
  const results = [];
  for (const adapter of adapters) {
    results.push(await runAdapterSafely(adapter, context));
  }

  return aggregateScanResult(
    target,
    startedAt,
    results.flatMap((result) => result.findings),
    metadata
  );
}

function adaptersForTarget(kind: "url" | "directory"): ScannerAdapter[] {
  if (kind === "url") {
    return webScannerAdapters();
  }
  return [
    ...codeScannerAdapters(),
    ...dependencyScannerAdapters(),
    ...secretScannerAdapters()
  ];
}
