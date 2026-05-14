import { Finding, Severity, SeveritySummary } from "./types";

export const severityWeight: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function summarizeSeverity(findings: Finding[]): SeveritySummary {
  return findings.reduce<SeveritySummary>(
    (summary, finding) => {
      summary[finding.severity] += 1;
      return summary;
    },
    { info: 0, low: 0, medium: 0, high: 0, critical: 0 }
  );
}

export function sortFindingsByRisk(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const priorityDelta = b.priorityScore - a.priorityScore;
    if (priorityDelta !== 0) return priorityDelta;
    const severityDelta = severityWeight[b.severity] - severityWeight[a.severity];
    if (severityDelta !== 0) return severityDelta;
    return a.id.localeCompare(b.id);
  });
}

export function calculatePriorityScore(finding: Pick<
  Finding,
  "severity" | "kevKnownExploited" | "cisaKevPriority" | "epssPercentile" | "fixAvailable" | "dependencyRelation"
>): number {
  const severity = severityWeight[finding.severity] * 25;
  const kev = finding.kevKnownExploited || finding.cisaKevPriority ? 25 : 0;
  const epss = finding.epssPercentile ? Math.round(Math.max(0, Math.min(1, finding.epssPercentile)) * 20) : 0;
  const fix = finding.fixAvailable ? 5 : 0;
  const relation = finding.dependencyRelation === "direct" ? 5 : finding.dependencyRelation === "transitive" ? 2 : 0;
  return Math.min(100, severity + kev + epss + fix + relation);
}
