import { redactSecrets } from "../scanner-core/redaction";
import { Finding } from "../scanner-core/types";

export function sanitizeFindingForReport(finding: Finding): Finding {
  return {
    ...finding,
    evidence: finding.redactedEvidence,
    redactedEvidence: finding.redactedEvidence,
    rawSource: finding.rawSource ? redactDeep(finding.rawSource) : undefined
  };
}

export function sanitizeFindingsForReport(findings: Finding[]): Finding[] {
  return findings.map(sanitizeFindingForReport);
}

export function redactDeep(value: unknown): unknown {
  if (typeof value === "string") {
    return redactSecrets(value);
  }
  if (Array.isArray(value)) {
    return value.map(redactDeep);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, redactDeep(entry)])
    );
  }
  return value;
}
