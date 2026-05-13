import { enrichFindingMappings } from "../knowledge-base/mappings";
import { redactSecrets } from "./redaction";
import { Finding, FindingInput, FindingTargetType } from "./types";

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
    sourceTool: input.sourceTool ?? "bts-sec",
    targetType: input.targetType ?? inferTargetType(input),
    evidence,
    redactedEvidence,
    owaspMapping: input.owaspMapping ?? mapped.owaspMapping,
    cweMapping: input.cweMapping ?? mapped.cweMapping,
    owaspTop10_2025: input.owaspTop10_2025 ?? mapped.owaspTop10_2025,
    owaspLLMTop10_2025: input.owaspLLMTop10_2025 ?? mapped.owaspLLMTop10_2025,
    owaspAPITop10_2023: input.owaspAPITop10_2023 ?? mapped.owaspAPITop10_2023,
    cweTop25_2025: input.cweTop25_2025 ?? mapped.cweTop25_2025,
    kevKnownExploited: input.kevKnownExploited ?? false,
    cisaKevPriority: input.cisaKevPriority ?? input.kevKnownExploited ?? false,
    remediationPromptForCodex: input.remediationPromptForCodex ?? codexPromptFor(input)
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
    targetType: "config",
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
    targetType: "config",
    target,
    evidence: message,
    recommendation: "Inspect local adapter configuration and rerun. The scan continued without destructive fallback behavior.",
    verification: "Confirm the adapter exits successfully with its safe configuration."
  });
}

function inferTargetType(input: FindingInput): FindingTargetType {
  if (input.targetType) return input.targetType;
  if (input.category === "dependency") return "dependency";
  if (input.agentConfigRisk || input.category === "agent-config") return "agent-artifact";
  if (input.file) return "local";
  if (input.endpoint) return "url";
  if (input.category === "configuration" || input.category === "adapter") return "config";
  return "local";
}

function codexPromptFor(input: FindingInput): string {
  const location = input.file
    ? `${input.file}${input.line ? `:${input.line}` : ""}`
    : input.endpoint ?? input.target;
  return [
    `Fix the security finding "${input.title}" (${input.id}) in ${location}.`,
    `Use a minimal, deterministic change that addresses: ${input.recommendation}`,
    `Verify with: ${input.verification}`,
    "Do not run exploits, exfiltrate data, validate live credentials, or scan outside the authorized scope."
  ].join(" ");
}
