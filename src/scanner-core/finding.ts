import { enrichFindingMappings } from "../knowledge-base/mappings";
import { redactSecrets } from "./redaction";
import { Finding, FindingInput } from "./types";

export function normalizeFinding(input: FindingInput): Finding {
  const mapped = enrichFindingMappings(input);
  const evidence = input.evidence || "";
  const redactedEvidence = input.redactedEvidence
    ? redactSecrets(input.redactedEvidence)
    : redactSecrets(evidence);

  return {
    ...input,
    severity: input.severity,
    confidence: input.confidence,
    evidence,
    redactedEvidence,
    owaspMapping: input.owaspMapping ?? mapped.owaspMapping,
    cweMapping: input.cweMapping ?? mapped.cweMapping,
    kevKnownExploited: input.kevKnownExploited ?? false
  };
}

export function adapterInfoFinding(
  sourceTool: string,
  target: string,
  evidence: string,
  title = `${sourceTool} adapter skipped`
): Finding {
  return normalizeFinding({
    id: `adapter.${sourceTool.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.info`,
    title,
    severity: "info",
    confidence: "high",
    category: "adapter",
    sourceTool,
    target,
    evidence,
    recommendation: "Install and configure the adapter tool if this coverage is required.",
    verification: "Re-run the scan after installing the tool or supplying the required configuration."
  });
}

export function adapterFailureFinding(
  sourceTool: string,
  target: string,
  error: unknown
): Finding {
  const message = error instanceof Error ? error.message : String(error);
  return normalizeFinding({
    id: `adapter.${sourceTool.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.failure`,
    title: `${sourceTool} adapter failed safely`,
    severity: "info",
    confidence: "high",
    category: "adapter",
    sourceTool,
    target,
    evidence: message,
    recommendation: "Inspect local adapter configuration and rerun. The scan continued without destructive fallback behavior.",
    verification: "Confirm the adapter exits successfully with its safe configuration."
  });
}
