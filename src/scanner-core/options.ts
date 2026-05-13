import { ScanOptions } from "./types";

export function defaultScanOptions(overrides: Partial<ScanOptions> = {}): ScanOptions {
  const { noDestructive: _ignoredNoDestructive, ...safeOverrides } = overrides;
  const options: Omit<ScanOptions, "noDestructive"> = {
    profile: "baseline",
    outputDir: "reports/latest",
    formats: ["markdown", "html", "json", "sarif"],
    rateLimitRps: 1,
    timeoutMs: 15000,
    includeExternal: false,
    confirmAuthorization: false,
    nucleiTemplates: [],
    refreshKev: false,
    ...safeOverrides
  };

  return {
    ...options,
    noDestructive: true
  };
}
