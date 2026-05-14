import { buildCoverageReport } from "../knowledge-base/standards";
import { ScanResult } from "../scanner-core/types";
import { redactDeep, sanitizeFindingsForReport } from "./sanitize";

export function renderSarifReport(result: ScanResult): string {
  const findings = sanitizeFindingsForReport(result.findings);
  const coverage = (result.metadata.coverage as ReturnType<typeof buildCoverageReport> | undefined) ?? buildCoverageReport(findings);
  const rules = new Map(findings.map((finding) => [finding.id, {
    id: finding.id,
    name: finding.title,
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.recommendation },
    help: { text: finding.verification },
    properties: {
      category: finding.category,
      vibeRiskCategory: finding.vibeRiskCategory,
      severity: finding.severity,
      confidence: finding.confidence,
      owasp: finding.owaspMapping.map((mapping) => mapping.id),
      apiTop10: finding.owaspAPITop10_2023,
      owaspTop10_2025: finding.owaspTop10_2025,
      owaspLLMTop10_2025: finding.owaspLLMTop10_2025,
      owaspAPITop10_2023: finding.owaspAPITop10_2023,
      cwe: finding.cweMapping.map((mapping) => mapping.id),
      kevKnownExploited: finding.kevKnownExploited,
      epss: finding.epssScore ?? null,
      epssPercentile: finding.epssPercentile ?? null,
      priorityScore: finding.priorityScore
    }
  }]));

  return JSON.stringify({
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "bts-sec",
            informationUri: "https://github.com/Bum-Boo/BTS_sec",
            rules: [...rules.values()]
          }
        },
        properties: {
          coverageMatrix: coverage.matrix,
          knownGaps: coverage.knownGaps,
          scannerConfiguration: redactDeep(result.metadata.scanOptions ?? {}),
          suppressedFindingsSummary: redactDeep(result.metadata.suppressedFindings ?? [])
        },
        results: findings.map((finding) => ({
          ruleId: finding.id,
          level: sarifLevel(finding.severity),
          message: {
            text: finding.redactedEvidence || finding.title
          },
          locations: [
            finding.file
              ? {
                  physicalLocation: {
                    artifactLocation: { uri: finding.file },
                    region: finding.line ? { startLine: finding.line } : undefined
                  }
                }
              : {
                  physicalLocation: {
                    artifactLocation: { uri: finding.endpoint ?? finding.target }
                  }
                }
          ],
          properties: {
            sourceTool: finding.sourceTool,
            targetType: finding.targetType,
            vibeRiskCategory: finding.vibeRiskCategory,
            cve: finding.cve,
            cvssScore: finding.cvssScore,
            cvssVector: finding.cvssVector,
            epss: finding.epssScore ?? null,
            epssPercentile: finding.epssPercentile ?? null,
            priorityScore: finding.priorityScore,
            owasp: finding.owaspMapping.map((mapping) => mapping.id),
            apiTop10: finding.owaspAPITop10_2023,
            cwe: finding.cweMapping.map((mapping) => mapping.id),
            kevKnownExploited: finding.kevKnownExploited,
            cisaKevPriority: finding.cisaKevPriority,
            fixAvailable: finding.fixAvailable,
            dependencyName: finding.dependencyName,
            dependencyVersion: finding.dependencyVersion,
            dependencyRelation: finding.dependencyRelation,
            recommendation: finding.recommendation,
            verification: finding.verification
          }
        }))
      }
    ]
  }, null, 2);
}

function sarifLevel(severity: string): "none" | "note" | "warning" | "error" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  if (severity === "info") return "note";
  return "none";
}
