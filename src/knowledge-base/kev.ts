import fs from "node:fs/promises";
import { Finding, ScanOptions } from "../scanner-core/types";

const CISA_KEV_JSON_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevEntry {
  cveID?: string;
}

interface KevCatalog {
  vulnerabilities?: KevEntry[];
}

export async function loadKevCveSet(options: Pick<ScanOptions, "kevCatalogPath" | "refreshKev" | "timeoutMs">): Promise<Set<string>> {
  if (!options.kevCatalogPath && !options.refreshKev) {
    return new Set();
  }

  const catalog = options.kevCatalogPath
    ? JSON.parse(await fs.readFile(options.kevCatalogPath, "utf8")) as KevCatalog
    : await fetchKevCatalog(options.timeoutMs);

  return new Set(
    (catalog.vulnerabilities ?? [])
      .map((entry) => entry.cveID)
      .filter((cve): cve is string => Boolean(cve))
  );
}

export async function applyKevEnrichment(
  findings: Finding[],
  metadata: Record<string, unknown>
): Promise<Finding[]> {
  const rawKev = metadata.kevCves;
  const kevSet = rawKev instanceof Set
    ? rawKev
    : Array.isArray(rawKev)
      ? new Set(rawKev.filter((value): value is string => typeof value === "string"))
      : new Set<string>();

  if (kevSet.size === 0) {
    return findings;
  }

  return findings.map((finding) => ({
    ...finding,
    kevKnownExploited: finding.cve ? kevSet.has(finding.cve) : finding.kevKnownExploited,
    cisaKevPriority: finding.cve ? kevSet.has(finding.cve) : finding.cisaKevPriority
  }));
}

async function fetchKevCatalog(timeoutMs: number): Promise<KevCatalog> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(CISA_KEV_JSON_URL, {
      signal: controller.signal,
      headers: { "User-Agent": "bts-sec/0.1 defensive-audit" }
    });
    if (!response.ok) {
      throw new Error(`CISA KEV fetch failed with HTTP ${response.status}`);
    }
    return await response.json() as KevCatalog;
  } finally {
    clearTimeout(timeout);
  }
}
