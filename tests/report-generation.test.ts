import { describe, expect, it } from "vitest";
import { normalizeFinding } from "../src/scanner-core/finding";
import { renderJsonReport, renderMarkdownReport, renderSarifReport } from "../src/report-generator";
import { ScanResult } from "../src/scanner-core/types";

describe("report generation", () => {
  it("renders Markdown, JSON, and SARIF with redacted evidence", () => {
    const finding = normalizeFinding({
      id: "secret.detected",
      title: "Secret detected",
      severity: "high",
      confidence: "medium",
      category: "secrets",
      sourceTool: "test",
      target: "fixture",
      file: "/tmp/app/.env",
      line: 1,
      evidence: "TOKEN=abc123456789",
      recommendation: "Rotate it.",
      verification: "Scan again.",
      rawSource: { token: "Bearer abc123456789" }
    });
    const result: ScanResult = {
      target: { kind: "directory", raw: "fixture", path: "/tmp/app" },
      findings: [finding],
      summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      startedAt: "2026-01-01T00:00:00.000Z",
      finishedAt: "2026-01-01T00:00:01.000Z",
      metadata: {}
    };

    const markdown = renderMarkdownReport(result);
    const json = renderJsonReport(result);
    const sarif = renderSarifReport(result);

    expect(markdown).toContain("TOKEN=[REDACTED]");
    expect(json).toContain("TOKEN=[REDACTED]");
    expect(sarif).toContain("TOKEN=[REDACTED]");
    expect(markdown + json + sarif).not.toContain("abc123456789");
  });
});
