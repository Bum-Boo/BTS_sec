import { remediationFor } from "../knowledge-base/remediation";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";

export const cookieFlagChecker: ScannerAdapter = {
  name: "custom-cookie-flag-checker",
  async scan(context: ScanContext) {
    if (context.target.kind !== "url" || !context.httpClient) {
      return { findings: [] };
    }

    const response = await context.httpClient.request(context.target.url.pathname || "/", {
      method: "GET",
      bodySnippetLimit: 0
    });

    const setCookie = response.headers["set-cookie"];
    if (!setCookie) {
      return { findings: [] };
    }

    const cookies = splitSetCookie(Array.isArray(setCookie) ? setCookie.join(",") : setCookie);
    const findings: Finding[] = [];
    const remediation = remediationFor(
      "web.insecure-cookie",
      "Set Secure, HttpOnly, and SameSite flags on sensitive cookies.",
      "Inspect Set-Cookie headers and confirm required flags are present."
    );

    for (const cookie of cookies) {
      const name = cookie.split("=")[0]?.trim() || "unknown";
      const lower = cookie.toLowerCase();
      const missing = [
        lower.includes("secure") ? undefined : "Secure",
        lower.includes("httponly") ? undefined : "HttpOnly",
        lower.includes("samesite") ? undefined : "SameSite"
      ].filter((value): value is string => Boolean(value));

      if (missing.length > 0) {
        findings.push(normalizeFinding({
          id: "web.insecure-cookie",
          title: `Cookie ${name} is missing recommended security flags`,
          severity: "medium",
          confidence: "high",
          category: "configuration",
          sourceTool: "custom-cookie-flag-checker",
          target: context.target.raw,
          endpoint: response.url,
          evidence: `Cookie ${name} is missing ${missing.join(", ")}.`,
          recommendation: remediation.recommendation,
          verification: remediation.verification
        }));
      }
    }

    return { findings };
  }
};

function splitSetCookie(header: string): string[] {
  return header.split(/,(?=\s*[^;,=\s]+=[^;,]+)/g).map((cookie) => cookie.trim()).filter(Boolean);
}
