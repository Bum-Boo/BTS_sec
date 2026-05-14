import { buildCoverageReport, CoverageReport } from "../knowledge-base/standards";
import { ScanResult } from "../scanner-core/types";
import { sanitizeFindingsForReport } from "./sanitize";
import { targetLabel } from "./target-label";

export function renderHtmlReport(result: ScanResult): string {
  const findings = sanitizeFindingsForReport(result.findings);
  const target = targetLabel(result.target);
  const coverage = (result.metadata.coverage as CoverageReport | undefined) ?? buildCoverageReport(findings);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Audit Report</title>
  <style>
    :root { color-scheme: light dark; --border: #c8ccd3; --muted: #667085; --bg: #fff; --fg: #16181d; }
    body { font-family: Arial, sans-serif; margin: 0; color: var(--fg); background: var(--bg); }
    main { max-width: 1120px; margin: 0 auto; padding: 32px 20px 56px; }
    h1, h2, h3 { line-height: 1.2; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0 28px; }
    th, td { border: 1px solid var(--border); padding: 8px 10px; text-align: left; }
    th:last-child, td:last-child { text-align: right; }
    article { border-top: 1px solid var(--border); padding: 22px 0; }
    code, pre { font-family: Consolas, Monaco, monospace; }
    pre { white-space: pre-wrap; border: 1px solid var(--border); padding: 12px; overflow: auto; }
    .meta { color: var(--muted); }
    .pill { display: inline-block; border: 1px solid var(--border); border-radius: 999px; padding: 2px 8px; margin-right: 6px; }
  </style>
</head>
<body>
<main>
  <h1>Security Audit Report</h1>
  <p class="meta">Target: <code>${escapeHtml(target)}</code> | Type: <code>${result.target.kind}</code></p>
  <p class="meta">Started: ${escapeHtml(result.startedAt)} | Finished: ${escapeHtml(result.finishedAt)}</p>

  <h2>Severity Summary</h2>
  <table>
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>
      <tr><td>Critical</td><td>${result.summary.critical}</td></tr>
      <tr><td>High</td><td>${result.summary.high}</td></tr>
      <tr><td>Medium</td><td>${result.summary.medium}</td></tr>
      <tr><td>Low</td><td>${result.summary.low}</td></tr>
      <tr><td>Info</td><td>${result.summary.info}</td></tr>
    </tbody>
  </table>

  <h2>Scanner Configuration</h2>
  <table>
    <thead><tr><th>Setting</th><th>Value</th></tr></thead>
    <tbody>${scannerConfigurationRows(result)}</tbody>
  </table>

  <h2>Coverage & Known Gaps</h2>
  <p class="meta">Coverage model: <code>${escapeHtml(coverage.model)}</code></p>
  <table>
    <thead><tr><th>Standard</th><th>ID</th><th>Name</th><th>Status</th><th>Findings</th><th>Notes</th></tr></thead>
    <tbody>${coverage.matrix.map((item) => `<tr><td>${escapeHtml(item.standard)}</td><td><code>${escapeHtml(item.id)}</code></td><td>${escapeHtml(item.name)}</td><td><code>${escapeHtml(item.status)}</code></td><td>${item.relatedFindings}</td><td>${escapeHtml(item.notes)}</td></tr>`).join("")}</tbody>
  </table>
  <h3>Known Gaps</h3>
  <ul>${coverage.knownGaps.map((gap) => `<li>${escapeHtml(gap)}</li>`).join("")}</ul>

  <h2>Suppressed Findings Summary</h2>
  ${suppressedHtml(result)}

  <h2>Findings</h2>
  ${findings.length === 0 ? "<p>No findings were reported by the enabled safe checks.</p>" : findings.map(renderFinding).join("\n")}
</main>
</body>
</html>`;
}

function renderFinding(finding: ReturnType<typeof sanitizeFindingsForReport>[number]): string {
  return `<article>
    <h3>${escapeHtml(finding.title)}</h3>
    <p>
      <span class="pill">${escapeHtml(finding.severity)}</span>
      <span class="pill">${escapeHtml(finding.confidence)} confidence</span>
      <span class="pill">priority ${escapeHtml(finding.priorityScore)}</span>
      <span class="pill">${escapeHtml(finding.sourceTool)}</span>
      <span class="pill">${escapeHtml(finding.targetType)}</span>
    </p>
    <p><strong>ID:</strong> <code>${escapeHtml(finding.id)}</code></p>
    ${finding.vibeRiskCategory ? `<p><strong>Vibe risk:</strong> <code>${escapeHtml(finding.vibeRiskCategory)}</code></p>` : ""}
    ${finding.affectedDataType ? `<p><strong>Affected data type:</strong> <code>${escapeHtml(finding.affectedDataType)}</code></p>` : ""}
    ${finding.platformHint ? `<p><strong>Platform hint:</strong> <code>${escapeHtml(finding.platformHint)}</code></p>` : ""}
    ${finding.file ? `<p><strong>File:</strong> <code>${escapeHtml(finding.file)}${finding.line ? `:${finding.line}` : ""}</code></p>` : ""}
    ${finding.endpoint ? `<p><strong>Endpoint:</strong> <code>${escapeHtml(finding.endpoint)}</code></p>` : ""}
    ${finding.cve ? `<p><strong>CVE:</strong> <code>${escapeHtml(finding.cve)}</code>${finding.kevKnownExploited ? " (CISA KEV known exploited)" : ""}</p>` : ""}
    ${finding.cvssScore !== undefined ? `<p><strong>CVSS:</strong> <code>${escapeHtml(finding.cvssScore)}</code>${finding.cvssVector ? ` <code>${escapeHtml(finding.cvssVector)}</code>` : ""}</p>` : ""}
    ${finding.epssScore !== undefined || finding.epssPercentile !== undefined ? `<p><strong>EPSS:</strong> score <code>${escapeHtml(finding.epssScore ?? "unknown")}</code>, percentile <code>${escapeHtml(finding.epssPercentile ?? "unknown")}</code></p>` : ""}
    ${finding.dependencyName ? `<p><strong>Dependency:</strong> <code>${escapeHtml(finding.dependencyName)}${finding.dependencyVersion ? `@${escapeHtml(finding.dependencyVersion)}` : ""}</code> (${escapeHtml(finding.dependencyRelation ?? "unknown")})</p>` : ""}
    <p><strong>OWASP:</strong> ${escapeHtml(formatMappings(finding.owaspMapping))}</p>
    <p><strong>CWE:</strong> ${escapeHtml(formatMappings(finding.cweMapping))}</p>
    <h4>Evidence</h4>
    <pre>${escapeHtml(finding.redactedEvidence || "No evidence text provided.")}</pre>
    <h4>Recommendation</h4>
    <p>${escapeHtml(finding.recommendation)}</p>
    <h4>Verification</h4>
    <p>${escapeHtml(finding.verification)}</p>
  </article>`;
}

function scannerConfigurationRows(result: ScanResult): string {
  const config = result.metadata.scanOptions as Record<string, unknown> | undefined;
  const safety = result.metadata.safety as Record<string, unknown> | undefined;
  const entries = {
    profile: config?.profile,
    includeExternal: config?.includeExternal,
    noDestructive: config?.noDestructive ?? safety?.noDestructive,
    rateLimitRps: config?.rateLimitRps ?? safety?.rateLimitRps,
    timeoutMs: config?.timeoutMs,
    maxCrawlDepth: config?.maxCrawlDepth,
    maxCrawlPages: config?.maxCrawlPages,
    refreshKev: config?.refreshKev,
    refreshEpss: config?.refreshEpss,
    apiSpecPath: config?.apiSpecPath
  };
  return Object.entries(entries)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => `<tr><td>${escapeHtml(key)}</td><td><code>${escapeHtml(String(value))}</code></td></tr>`)
    .join("");
}

function suppressedHtml(result: ScanResult): string {
  const suppressed = result.metadata.suppressedFindings;
  if (!Array.isArray(suppressed) || suppressed.length === 0) {
    return "<p>No findings were suppressed.</p>";
  }
  return `<ul>${suppressed.map((item) => {
    const record = item as Record<string, unknown>;
    return `<li><code>${escapeHtml(record.id)}</code> at <code>${escapeHtml(record.file)}:${escapeHtml(record.line)}</code>: ${escapeHtml(record.reason)}</li>`;
  }).join("")}</ul>`;
}

function formatMappings(mappings: Array<{ id: string; name: string }>): string {
  return mappings.length > 0
    ? mappings.map((mapping) => `${mapping.id} ${mapping.name}`).join(", ")
    : "None";
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
