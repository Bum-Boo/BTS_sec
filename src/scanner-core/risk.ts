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
    const severityDelta = severityWeight[b.severity] - severityWeight[a.severity];
    if (severityDelta !== 0) return severityDelta;
    return a.id.localeCompare(b.id);
  });
}
