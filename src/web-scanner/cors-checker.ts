import { remediationFor } from "../knowledge-base/remediation";
import { normalizeFinding } from "../scanner-core/finding";
import { ScannerAdapter, ScanContext } from "../scanner-core/types";

const UNTRUSTED_ORIGIN = "https://bts-sec.invalid";

export const corsChecker: ScannerAdapter = {
  name: "custom-cors-checker",
  async scan(context: ScanContext) {
    if (context.target.kind !== "url" || !context.httpClient) {
      return { findings: [] };
    }

    const response = await context.httpClient.request(context.target.url.pathname || "/", {
      method: "OPTIONS",
      headers: {
        Origin: UNTRUSTED_ORIGIN,
        "Access-Control-Request-Method": "GET"
      },
      bodySnippetLimit: 0
    });

    const allowOrigin = headerValue(response.headers["access-control-allow-origin"]);
    const allowCredentials = headerValue(response.headers["access-control-allow-credentials"]);

    if (!allowOrigin) {
      return { findings: [] };
    }

    const wildcard = allowOrigin === "*";
    const reflectsUntrusted = allowOrigin === UNTRUSTED_ORIGIN;
    const credentials = /^true$/i.test(allowCredentials ?? "");

    if (!wildcard && !reflectsUntrusted) {
      return { findings: [] };
    }

    const remediation = remediationFor(
      "web.unsafe-cors",
      "Replace wildcard or reflected CORS with an explicit trusted origin allowlist.",
      "Send preflight requests from untrusted origins and confirm they are rejected."
    );

    return {
      findings: [
        normalizeFinding({
          id: "web.unsafe-cors",
          title: credentials ? "CORS allows credentials for a broad origin" : "CORS allows a broad origin",
          severity: credentials ? "high" : "medium",
          confidence: "high",
          category: "cors",
          sourceTool: "custom-cors-checker",
          target: context.target.raw,
          endpoint: response.url,
          evidence: `Preflight from an untrusted origin returned access-control-allow-origin=${allowOrigin}${allowCredentials ? ` and access-control-allow-credentials=${allowCredentials}` : ""}.`,
          recommendation: remediation.recommendation,
          verification: remediation.verification
        })
      ]
    };
  }
};

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value.join(",") : value;
}
