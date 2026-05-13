import { describe, expect, it } from "vitest";
import { normalizeFinding } from "../src/scanner-core/finding";

describe("finding normalization", () => {
  it("redacts evidence and adds knowledge-base mappings", () => {
    const finding = normalizeFinding({
      id: "code.hardcoded-secret",
      title: "Hardcoded secret",
      severity: "high",
      confidence: "high",
      category: "secrets",
      sourceTool: "test",
      target: "fixture",
      evidence: "API_KEY=\"super-secret-value\"",
      recommendation: "Move the secret.",
      verification: "Re-run the scanner."
    });

    expect(finding.redactedEvidence).toContain("API_KEY=[REDACTED]");
    expect(finding.redactedEvidence).not.toContain("super-secret-value");
    expect(finding.owaspMapping.map((mapping) => mapping.id)).toContain("A04:2025");
    expect(finding.cweMapping.map((mapping) => mapping.id)).toContain("CWE-798");
    expect(finding.kevKnownExploited).toBe(false);
  });
});
