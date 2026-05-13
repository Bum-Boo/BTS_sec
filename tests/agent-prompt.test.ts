import { describe, expect, it } from "vitest";
import { renderAgentFixPrompt, renderJsonReport } from "../src/report-generator";
import { normalizeFinding } from "../src/scanner-core/finding";
import { ScanResult } from "../src/scanner-core/types";

describe("agent fix prompt generation", () => {
  it("creates an English fix prompt with redacted actionable findings", () => {
    const result = scanResultFixture([
      normalizeFinding({
        id: "web.missing-security-header.content-security-policy",
        title: "Content-Security-Policy header is missing",
        severity: "medium",
        confidence: "high",
        category: "web-headers",
        sourceTool: "custom-http-header-checker",
        target: "https://example.com",
        endpoint: "https://example.com/",
        evidence: "Header missing. TOKEN=abc123456789",
        recommendation: "Set a narrow Content-Security-Policy header.",
        verification: "Repeat a HEAD request and confirm the header is present."
      }),
      normalizeFinding({
        id: "adapter.nuclei.info",
        title: "nuclei adapter skipped",
        severity: "info",
        confidence: "high",
        category: "adapter",
        sourceTool: "nuclei",
        target: "https://example.com",
        evidence: "External adapters are disabled.",
        recommendation: "Install nuclei if required.",
        verification: "Re-run the scan."
      })
    ]);

    const prompt = renderAgentFixPrompt(result);
    const json = renderJsonReport(result);

    expect(prompt).toContain("You are working on the application");
    expect(prompt).toContain("Content-Security-Policy header is missing");
    expect(prompt).toContain("Set a narrow Content-Security-Policy header.");
    expect(prompt).toContain("TOKEN=[REDACTED]");
    expect(prompt).not.toContain("abc123456789");
    expect(prompt).not.toContain("nuclei adapter skipped");
    expect(prompt).toContain("Do not run exploits");
    expect(json).toContain("\"agentFixPrompt\"");
  });
});

function scanResultFixture(findings: ScanResult["findings"]): ScanResult {
  return {
    target: {
      kind: "url",
      raw: "https://example.com",
      url: new URL("https://example.com"),
      scopeOrigins: ["https://example.com"],
      authorizationConfirmed: true
    },
    findings,
    summary: { critical: 0, high: 0, medium: 1, low: 0, info: 1 },
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    metadata: {}
  };
}
