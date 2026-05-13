import { FindingInput, SecurityMapping } from "../scanner-core/types";

export const OWASP_TOP_10_2025: Record<string, SecurityMapping> = {
  A01: {
    id: "A01:2025",
    name: "Broken Access Control",
    url: "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/"
  },
  A02: {
    id: "A02:2025",
    name: "Security Misconfiguration",
    url: "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/"
  },
  A03: {
    id: "A03:2025",
    name: "Software Supply Chain Failures",
    url: "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"
  },
  A04: {
    id: "A04:2025",
    name: "Cryptographic Failures",
    url: "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/"
  },
  A05: {
    id: "A05:2025",
    name: "Injection",
    url: "https://owasp.org/Top10/2025/A05_2025-Injection/"
  },
  A06: {
    id: "A06:2025",
    name: "Insecure Design",
    url: "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/"
  },
  A07: {
    id: "A07:2025",
    name: "Authentication Failures",
    url: "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/"
  },
  A08: {
    id: "A08:2025",
    name: "Software or Data Integrity Failures",
    url: "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/"
  },
  A09: {
    id: "A09:2025",
    name: "Security Logging and Alerting Failures",
    url: "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/"
  },
  A10: {
    id: "A10:2025",
    name: "Mishandling of Exceptional Conditions",
    url: "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/"
  }
};

export const OWASP_API_TOP_10_2023: Record<string, SecurityMapping> = {
  API1: { id: "API1:2023", name: "Broken Object Level Authorization", url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/" },
  API2: { id: "API2:2023", name: "Broken Authentication", url: "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/" },
  API3: { id: "API3:2023", name: "Broken Object Property Level Authorization", url: "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/" },
  API4: { id: "API4:2023", name: "Unrestricted Resource Consumption", url: "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/" },
  API5: { id: "API5:2023", name: "Broken Function Level Authorization", url: "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/" },
  API6: { id: "API6:2023", name: "Unrestricted Access to Sensitive Business Flows", url: "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/" },
  API7: { id: "API7:2023", name: "Server Side Request Forgery", url: "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/" },
  API8: { id: "API8:2023", name: "Security Misconfiguration", url: "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/" },
  API9: { id: "API9:2023", name: "Improper Inventory Management", url: "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/" },
  API10: { id: "API10:2023", name: "Unsafe Consumption of APIs", url: "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/" }
};

export const CWE: Record<string, SecurityMapping> = {
  "CWE-22": cwe("CWE-22", "Path Traversal"),
  "CWE-77": cwe("CWE-77", "Command Injection"),
  "CWE-78": cwe("CWE-78", "OS Command Injection"),
  "CWE-79": cwe("CWE-79", "Cross-site Scripting"),
  "CWE-89": cwe("CWE-89", "SQL Injection"),
  "CWE-94": cwe("CWE-94", "Code Injection"),
  "CWE-200": cwe("CWE-200", "Exposure of Sensitive Information"),
  "CWE-284": cwe("CWE-284", "Improper Access Control"),
  "CWE-306": cwe("CWE-306", "Missing Authentication for Critical Function"),
  "CWE-352": cwe("CWE-352", "Cross-Site Request Forgery"),
  "CWE-434": cwe("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
  "CWE-502": cwe("CWE-502", "Deserialization of Untrusted Data"),
  "CWE-639": cwe("CWE-639", "Authorization Bypass Through User-Controlled Key"),
  "CWE-770": cwe("CWE-770", "Allocation of Resources Without Limits or Throttling"),
  "CWE-798": cwe("CWE-798", "Use of Hard-coded Credentials"),
  "CWE-862": cwe("CWE-862", "Missing Authorization"),
  "CWE-863": cwe("CWE-863", "Incorrect Authorization"),
  "CWE-918": cwe("CWE-918", "Server-Side Request Forgery"),
  "CWE-117": cwe("CWE-117", "Improper Output Neutralization for Logs"),
  "CWE-532": cwe("CWE-532", "Insertion of Sensitive Information into Log File")
};

const CATEGORY_MAP: Record<string, { owasp: string[]; cwe: string[] }> = {
  "access-control": { owasp: ["A01", "API1", "API5"], cwe: ["CWE-862", "CWE-863", "CWE-284", "CWE-639"] },
  "adapter": { owasp: [], cwe: [] },
  "authentication": { owasp: ["A07", "API2"], cwe: ["CWE-306"] },
  "code-execution": { owasp: ["A05"], cwe: ["CWE-78", "CWE-94", "CWE-77"] },
  "configuration": { owasp: ["A02", "API8"], cwe: [] },
  "cors": { owasp: ["A02", "API8"], cwe: [] },
  "dependency": { owasp: ["A03", "API10"], cwe: [] },
  "exposure": { owasp: ["A02", "API8"], cwe: ["CWE-200"] },
  "file-upload": { owasp: ["A05", "A06"], cwe: ["CWE-434"] },
  "injection": { owasp: ["A05"], cwe: ["CWE-89", "CWE-78", "CWE-94"] },
  "logging": { owasp: ["A09"], cwe: ["CWE-117", "CWE-532"] },
  "secrets": { owasp: ["A04", "A02"], cwe: ["CWE-798", "CWE-200"] },
  "ssrf": { owasp: ["A05", "API7"], cwe: ["CWE-918"] },
  "supply-chain": { owasp: ["A03", "A08", "API10"], cwe: [] },
  "web-headers": { owasp: ["A02", "API8"], cwe: [] }
};

export function enrichFindingMappings(input: Pick<FindingInput, "id" | "category">): {
  owaspMapping: SecurityMapping[];
  cweMapping: SecurityMapping[];
} {
  const category = CATEGORY_MAP[input.category] ?? inferMappingFromId(input.id);
  return {
    owaspMapping: category.owasp.map(toOwaspMapping).filter(Boolean),
    cweMapping: category.cwe.map((id) => CWE[id]).filter(Boolean)
  };
}

function inferMappingFromId(id: string): { owasp: string[]; cwe: string[] } {
  if (/cors/i.test(id)) return CATEGORY_MAP.cors;
  if (/secret|credential|token|key/i.test(id)) return CATEGORY_MAP.secrets;
  if (/sql|command|eval|shell/i.test(id)) return CATEGORY_MAP.injection;
  if (/auth|access/i.test(id)) return CATEGORY_MAP["access-control"];
  if (/dependency|cve|vulnerab/i.test(id)) return CATEGORY_MAP.dependency;
  return { owasp: [], cwe: [] };
}

function toOwaspMapping(key: string): SecurityMapping {
  if (key.startsWith("API")) {
    return OWASP_API_TOP_10_2023[key];
  }
  return OWASP_TOP_10_2025[key];
}

function cwe(id: string, name: string): SecurityMapping {
  return {
    id,
    name,
    url: `https://cwe.mitre.org/data/definitions/${id.replace("CWE-", "")}.html`
  };
}
