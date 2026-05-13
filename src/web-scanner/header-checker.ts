import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { remediationFor } from "../knowledge-base/remediation";

interface HeaderRule {
  header: string;
  title: string;
  severity: "low" | "medium";
  expected?: RegExp;
}

const HEADER_RULES: HeaderRule[] = [
  { header: "content-security-policy", title: "Content-Security-Policy header is missing", severity: "medium" },
  { header: "x-content-type-options", title: "X-Content-Type-Options header is missing or not nosniff", severity: "low", expected: /^nosniff$/i },
  { header: "referrer-policy", title: "Referrer-Policy header is missing", severity: "low" },
  { header: "permissions-policy", title: "Permissions-Policy header is missing", severity: "low" }
];

export const headerChecker: ScannerAdapter = {
  name: "custom-http-header-checker",
  async scan(context: ScanContext) {
    if (context.target.kind !== "url" || !context.httpClient) {
      return { findings: [] };
    }

    const response = await context.httpClient.request(context.target.url.pathname || "/", {
      method: "HEAD",
      bodySnippetLimit: 0
    });
    const findings: Finding[] = [];

    for (const rule of HEADER_RULES) {
      const value = response.headers[rule.header];
      const normalized = Array.isArray(value) ? value.join(",") : value;
      if (!normalized || (rule.expected && !rule.expected.test(normalized))) {
        const remediation = remediationFor(
          "web.missing-security-header",
          "Set the missing security header.",
          "Repeat the request and confirm the header is present."
        );
        findings.push(normalizeFinding({
          id: `web.missing-security-header.${rule.header}`,
          title: rule.title,
          severity: rule.severity,
          confidence: "high",
          category: "web-headers",
          sourceTool: "custom-http-header-checker",
          target: context.target.raw,
          endpoint: response.url,
          evidence: `HTTP ${response.status}; header ${rule.header} was ${normalized ? `set to ${normalized}` : "absent"}.`,
          recommendation: remediation.recommendation,
          verification: remediation.verification
        }));
      }
    }

    if (context.target.url.protocol === "https:" && !response.headers["strict-transport-security"]) {
      const remediation = remediationFor(
        "web.missing-security-header",
        "Enable Strict-Transport-Security after confirming all subdomains support HTTPS.",
        "Repeat the request over HTTPS and confirm Strict-Transport-Security is present."
      );
      findings.push(normalizeFinding({
        id: "web.missing-security-header.strict-transport-security",
        title: "Strict-Transport-Security header is missing",
        severity: "medium",
        confidence: "high",
        category: "web-headers",
        sourceTool: "custom-http-header-checker",
        target: context.target.raw,
        endpoint: response.url,
        evidence: `HTTP ${response.status}; strict-transport-security header was absent.`,
        recommendation: remediation.recommendation,
        verification: remediation.verification
      }));
    }

    return { findings };
  }
};
