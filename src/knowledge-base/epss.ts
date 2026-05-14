import fs from "node:fs/promises";
import path from "node:path";
import { Finding, ScanOptions } from "../scanner-core/types";

const EPSS_API_URL = "https://api.first.org/data/v1/epss";
const MAX_CVE_QUERY_CHARS = 1800;

interface EpssEntry {
  cve: string;
  epss: number;
  percentile: number;
  date?: string;
}

interface FirstEpssResponse {
  data?: FirstEpssItem[];
}

interface FirstEpssItem {
  cve?: string;
  epss?: string;
  percentile?: string;
  date?: string;
}

export async function applyEpssEnrichment(
  findings: Finding[],
  options: Pick<ScanOptions, "epssCsvPath" | "refreshEpss" | "timeoutMs" | "outputDir">
): Promise<Finding[]> {
  const cves = [...new Set(findings.map((finding) => finding.cve).filter((cve): cve is string => Boolean(cve)))];
  if (cves.length === 0 || (!options.epssCsvPath && !options.refreshEpss)) {
    return findings;
  }

  const epssMap = options.epssCsvPath
    ? await loadEpssCsv(options.epssCsvPath)
    : await fetchEpssWithCache(cves, options);

  return findings.map((finding) => {
    if (!finding.cve) return finding;
    const epss = epssMap.get(finding.cve);
    if (!epss) return finding;
    return {
      ...finding,
      epssScore: epss.epss,
      epssPercentile: epss.percentile
    };
  });
}

async function loadEpssCsv(filePath: string): Promise<Map<string, EpssEntry>> {
  const content = await fs.readFile(filePath, "utf8");
  const map = new Map<string, EpssEntry>();
  for (const line of content.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#") || /^cve,/i.test(line)) continue;
    const [cve, epss, percentile, date] = line.split(",").map((part) => part.trim());
    if (!/^CVE-\d{4}-\d{4,}$/i.test(cve)) continue;
    map.set(cve.toUpperCase(), {
      cve: cve.toUpperCase(),
      epss: Number(epss),
      percentile: Number(percentile),
      date
    });
  }
  return map;
}

async function fetchEpssWithCache(
  cves: string[],
  options: Pick<ScanOptions, "timeoutMs" | "outputDir">
): Promise<Map<string, EpssEntry>> {
  const cachePath = path.join(options.outputDir, ".cache", "epss.json");
  const cached = await readCache(cachePath);
  const missing = cves.filter((cve) => !cached.has(cve));
  if (missing.length === 0) {
    return cached;
  }

  for (const chunk of cveChunks(missing)) {
    const entries = await fetchEpssChunk(chunk, options.timeoutMs);
    for (const entry of entries) {
      cached.set(entry.cve, entry);
    }
  }

  await writeCache(cachePath, cached);
  return cached;
}

async function readCache(cachePath: string): Promise<Map<string, EpssEntry>> {
  try {
    const parsed = JSON.parse(await fs.readFile(cachePath, "utf8")) as EpssEntry[];
    return new Map(parsed.map((entry) => [entry.cve, entry]));
  } catch {
    return new Map();
  }
}

async function writeCache(cachePath: string, entries: Map<string, EpssEntry>): Promise<void> {
  await fs.mkdir(path.dirname(cachePath), { recursive: true });
  await fs.writeFile(cachePath, JSON.stringify([...entries.values()], null, 2), "utf8");
}

async function fetchEpssChunk(cves: string[], timeoutMs: number): Promise<EpssEntry[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const url = `${EPSS_API_URL}?cve=${encodeURIComponent(cves.join(","))}`;
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "bts-sec/0.1 defensive-audit" }
    });
    if (!response.ok) {
      throw new Error(`FIRST EPSS fetch failed with HTTP ${response.status}`);
    }
    const parsed = await response.json() as FirstEpssResponse;
    return (parsed.data ?? [])
      .filter((entry): entry is Required<Pick<FirstEpssItem, "cve" | "epss" | "percentile">> & { date?: string } =>
        Boolean(entry.cve && entry.epss && entry.percentile)
      )
      .map((entry) => ({
        cve: entry.cve.toUpperCase(),
        epss: Number(entry.epss),
        percentile: Number(entry.percentile),
        date: entry.date
      }));
  } finally {
    clearTimeout(timeout);
  }
}

function cveChunks(cves: string[]): string[][] {
  const chunks: string[][] = [];
  let current: string[] = [];
  let currentLength = 0;
  for (const cve of cves) {
    const nextLength = currentLength + cve.length + (current.length > 0 ? 1 : 0);
    if (current.length > 0 && nextLength > MAX_CVE_QUERY_CHARS) {
      chunks.push(current);
      current = [];
      currentLength = 0;
    }
    current.push(cve);
    currentLength += cve.length + (current.length > 1 ? 1 : 0);
  }
  if (current.length > 0) chunks.push(current);
  return chunks;
}
