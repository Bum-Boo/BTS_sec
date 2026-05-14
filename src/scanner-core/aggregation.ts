import { applyEpssEnrichment } from "../knowledge-base/epss";
import { applyKevEnrichment } from "../knowledge-base/kev";
import { buildCoverageReport } from "../knowledge-base/standards";
import { calculatePriorityScore, sortFindingsByRisk, summarizeSeverity } from "./risk";
import { Finding, ScanResult, ScanTarget } from "./types";

export async function aggregateScanResult(
  target: ScanTarget,
  startedAt: string,
  findings: Finding[],
  metadata: Record<string, unknown>
): Promise<ScanResult> {
  const scanOptions = metadata.scanOptions as {
    epssCsvPath?: string;
    refreshEpss?: boolean;
    timeoutMs?: number;
    outputDir?: string;
  } | undefined;
  const kevEnriched = await applyKevEnrichment(findings, metadata);
  const epssEnriched = await applyEpssEnrichment(kevEnriched, {
    epssCsvPath: scanOptions?.epssCsvPath,
    refreshEpss: scanOptions?.refreshEpss ?? false,
    timeoutMs: scanOptions?.timeoutMs ?? 15000,
    outputDir: scanOptions?.outputDir ?? "reports/latest"
  });
  const dependencyEnriched = enrichDependencyRelations(epssEnriched, metadata);
  const prioritized = dependencyEnriched.map((finding) => ({
    ...finding,
    priorityScore: calculatePriorityScore(finding)
  }));
  const sorted = sortFindingsByRisk(prioritized);
  metadata.coverage = buildCoverageReport(sorted);
  return {
    target,
    findings: sorted,
    summary: summarizeSeverity(sorted),
    startedAt,
    finishedAt: new Date().toISOString(),
    metadata
  };
}

function enrichDependencyRelations(findings: Finding[], metadata: Record<string, unknown>): Finding[] {
  const components = (metadata.sbom as { components?: Array<{ name?: string; version?: string; relation?: string }> } | undefined)?.components ?? [];
  if (components.length === 0) return findings;

  return findings.map((finding) => {
    if (finding.category !== "dependency" && finding.category !== "supply-chain") {
      return finding;
    }
    const name = finding.dependencyName ?? extractPackageName(finding);
    if (!name) return finding;
    const component = components.find((candidate) => candidate.name === name);
    if (!component) return finding;
    return {
      ...finding,
      dependencyName: finding.dependencyName ?? component.name,
      dependencyVersion: finding.dependencyVersion ?? component.version,
      dependencyRelation: finding.dependencyRelation ?? (
        component.relation === "direct" || component.relation === "transitive" ? component.relation : "unknown"
      )
    };
  });
}

function extractPackageName(finding: Finding): string | undefined {
  const raw = finding.rawSource;
  if (raw && typeof raw === "object") {
    const record = raw as Record<string, unknown>;
    if (typeof record.package === "string") return record.package;
    if (typeof record.dependency === "string") return record.dependency;
    if (typeof record.PkgName === "string") return record.PkgName;
    if (record.package && typeof record.package === "object" && typeof (record.package as Record<string, unknown>).name === "string") {
      return (record.package as Record<string, string>).name;
    }
  }
  return undefined;
}
