import { Finding, SecurityMapping } from "../scanner-core/types";
import { OWASP_API_TOP_10_2023, OWASP_TOP_10_2025, CWE } from "./mappings";

export type CoverageStatus = "covered" | "partial" | "not_covered";

export interface CoverageMatrixItem {
  standard: "OWASP Top 10:2025" | "OWASP API Security Top 10:2023" | "MITRE CWE Top 25:2025" | "MITRE CWE Top 10 KEV Weaknesses:2025";
  id: string;
  name: string;
  status: CoverageStatus;
  relatedFindings: number;
  sourceUrl?: string;
  notes: string;
}

export interface CoverageReport {
  generatedAt: string;
  model: "standards-aligned passive coverage with explicit known gaps";
  matrix: CoverageMatrixItem[];
  knownGaps: string[];
}

const CWE_TOP25_2025_IDS = [
  "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787",
  "CWE-22", "CWE-416", "CWE-125", "CWE-78", "CWE-94",
  "CWE-120", "CWE-434", "CWE-476", "CWE-121", "CWE-502",
  "CWE-122", "CWE-863", "CWE-20", "CWE-284", "CWE-200",
  "CWE-306", "CWE-918", "CWE-77", "CWE-639", "CWE-770"
];

const CWE_KEV_TOP10_2025_IDS = [
  "CWE-78", "CWE-416", "CWE-787", "CWE-306", "CWE-502",
  "CWE-22", "CWE-94", "CWE-288", "CWE-122", "CWE-79"
];

const STATUS_OVERRIDES: Record<string, CoverageStatus> = {
  "A03:2025": "covered",
  "API9:2023": "covered",
  "CWE-416": "not_covered",
  "CWE-787": "not_covered",
  "CWE-125": "not_covered",
  "CWE-120": "not_covered",
  "CWE-121": "not_covered",
  "CWE-122": "not_covered",
  "CWE-476": "not_covered"
};

export const KNOWN_GAPS = [
  "BTS_sec performs passive/static checks; it does not prove exploitability, bypass authorization, brute force, submit destructive requests, or extract data.",
  "Business-logic and authorization findings are heuristic and require code review or authorized application tests to verify.",
  "Memory-safety CWEs such as use-after-free, out-of-bounds read/write, and buffer overflows are not deeply analyzed without external SAST/compiler tooling.",
  "Dependency CVE enrichment depends on local lockfiles and optional external adapters or opt-in KEV/EPSS data sources.",
  "OpenAPI YAML support includes a conservative fallback parser; JSON/OpenAPI objects provide richer schema checks.",
  "The same-origin crawler is GET/HEAD/OPTIONS only and does not authenticate, submit forms, run exploit payloads, or crawl third-party origins."
];

export function buildCoverageReport(findings: Finding[], generatedAt = new Date().toISOString()): CoverageReport {
  return {
    generatedAt,
    model: "standards-aligned passive coverage with explicit known gaps",
    matrix: [
      ...matrixFromRecord("OWASP Top 10:2025", OWASP_TOP_10_2025, findings),
      ...matrixFromRecord("OWASP API Security Top 10:2023", OWASP_API_TOP_10_2023, findings),
      ...CWE_TOP25_2025_IDS.map((id) => matrixFromCwe("MITRE CWE Top 25:2025", id, findings)),
      ...CWE_KEV_TOP10_2025_IDS.map((id) => matrixFromCwe("MITRE CWE Top 10 KEV Weaknesses:2025", id, findings))
    ],
    knownGaps: KNOWN_GAPS
  };
}

export function cweTop25Ids(): readonly string[] {
  return CWE_TOP25_2025_IDS;
}

export function cweKevTop10Ids(): readonly string[] {
  return CWE_KEV_TOP10_2025_IDS;
}

function matrixFromRecord(
  standard: CoverageMatrixItem["standard"],
  record: Record<string, SecurityMapping>,
  findings: Finding[]
): CoverageMatrixItem[] {
  return Object.values(record).map((mapping) => ({
    standard,
    id: mapping.id,
    name: mapping.name,
    status: STATUS_OVERRIDES[mapping.id] ?? statusForMapping(mapping.id, findings),
    relatedFindings: countRelated(mapping.id, findings),
    sourceUrl: mapping.url,
    notes: notesFor(mapping.id)
  }));
}

function matrixFromCwe(standard: CoverageMatrixItem["standard"], id: string, findings: Finding[]): CoverageMatrixItem {
  const mapping = CWE[id] ?? { id, name: id, url: `https://cwe.mitre.org/data/definitions/${id.replace("CWE-", "")}.html` };
  return {
    standard,
    id,
    name: mapping.name,
    status: STATUS_OVERRIDES[id] ?? statusForMapping(id, findings),
    relatedFindings: countRelated(id, findings),
    sourceUrl: mapping.url,
    notes: notesFor(id)
  };
}

function statusForMapping(id: string, findings: Finding[]): CoverageStatus {
  if (countRelated(id, findings) > 0) {
    return "covered";
  }
  return "partial";
}

function countRelated(id: string, findings: Finding[]): number {
  return findings.filter((finding) =>
    finding.owaspTop10_2025?.includes(id) ||
    finding.owaspAPITop10_2023?.includes(id) ||
    finding.cweTop25_2025?.includes(id) ||
    finding.cweMapping.some((mapping) => mapping.id === id)
  ).length;
}

function notesFor(id: string): string {
  if (STATUS_OVERRIDES[id] === "not_covered") {
    return "No built-in deep static analysis for this weakness class; use dedicated SAST/compiler/runtime tooling.";
  }
  if (id === "A03:2025") return "Lockfile SBOM, dependency advisory adapters, KEV/EPSS enrichment, and supply-chain hygiene checks.";
  if (id === "API9:2023") return "OpenAPI inventory, deprecated/internal endpoint heuristics, and same-origin passive discovery.";
  if (/^API/.test(id)) return "OpenAPI/static API heuristics only; no active authorization bypass or destructive request testing.";
  if (/^CWE/.test(id)) return "Mapped through passive code, API, dependency, secret, or web heuristics where applicable.";
  return "Passive/static checks provide review signals; manual validation may still be required.";
}
