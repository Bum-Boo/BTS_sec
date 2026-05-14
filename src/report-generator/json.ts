import { buildCoverageReport } from "../knowledge-base/standards";
import { ScanResult } from "../scanner-core/types";
import { renderAgentFixPrompt } from "./agent-prompt";
import { sanitizeFindingsForReport, redactDeep } from "./sanitize";

export function renderJsonReport(result: ScanResult): string {
  const findings = sanitizeFindingsForReport(result.findings);
  const coverage = (result.metadata.coverage as ReturnType<typeof buildCoverageReport> | undefined) ?? buildCoverageReport(findings);
  return JSON.stringify({
    ...result,
    findings,
    coverage,
    knownGaps: coverage.knownGaps,
    suppressedFindingsSummary: redactDeep(result.metadata.suppressedFindings ?? []),
    scannerConfiguration: redactDeep(result.metadata.scanOptions ?? {}),
    metadata: redactDeep(result.metadata),
    agentFixPrompt: renderAgentFixPrompt(result)
  }, null, 2);
}
