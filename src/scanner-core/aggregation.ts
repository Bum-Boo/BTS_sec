import { applyKevEnrichment } from "../knowledge-base/kev";
import { sortFindingsByRisk, summarizeSeverity } from "./risk";
import { Finding, ScanResult, ScanTarget } from "./types";

export async function aggregateScanResult(
  target: ScanTarget,
  startedAt: string,
  findings: Finding[],
  metadata: Record<string, unknown>
): Promise<ScanResult> {
  const enriched = await applyKevEnrichment(findings, metadata);
  const sorted = sortFindingsByRisk(enriched);
  return {
    target,
    findings: sorted,
    summary: summarizeSeverity(sorted),
    startedAt,
    finishedAt: new Date().toISOString(),
    metadata
  };
}
