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

export const OWASP_LLM_TOP_10_2025: Record<string, SecurityMapping> = {
  LLM01: { id: "LLM01:2025", name: "Prompt Injection", url: "https://genai.owasp.org/llm-top-10/" },
  LLM02: { id: "LLM02:2025", name: "Sensitive Information Disclosure", url: "https://genai.owasp.org/llm-top-10/" },
  LLM03: { id: "LLM03:2025", name: "Supply Chain", url: "https://genai.owasp.org/llm-top-10/" },
  LLM04: { id: "LLM04:2025", name: "Data and Model Poisoning", url: "https://genai.owasp.org/llm-top-10/" },
  LLM05: { id: "LLM05:2025", name: "Improper Output Handling", url: "https://genai.owasp.org/llm-top-10/" },
  LLM06: { id: "LLM06:2025", name: "Excessive Agency", url: "https://genai.owasp.org/llm-top-10/" },
  LLM07: { id: "LLM07:2025", name: "System Prompt Leakage", url: "https://genai.owasp.org/llm-top-10/" },
  LLM08: { id: "LLM08:2025", name: "Vector and Embedding Weaknesses", url: "https://genai.owasp.org/llm-top-10/" },
  LLM09: { id: "LLM09:2025", name: "Misinformation", url: "https://genai.owasp.org/llm-top-10/" },
  LLM10: { id: "LLM10:2025", name: "Unbounded Consumption", url: "https://genai.owasp.org/llm-top-10/" }
};

export const CWE: Record<string, SecurityMapping> = {
  "CWE-20": cwe("CWE-20", "Improper Input Validation"),
  "CWE-22": cwe("CWE-22", "Path Traversal"),
  "CWE-77": cwe("CWE-77", "Command Injection"),
  "CWE-78": cwe("CWE-78", "OS Command Injection"),
  "CWE-79": cwe("CWE-79", "Cross-site Scripting"),
  "CWE-89": cwe("CWE-89", "SQL Injection"),
  "CWE-94": cwe("CWE-94", "Code Injection"),
  "CWE-120": cwe("CWE-120", "Classic Buffer Overflow"),
  "CWE-121": cwe("CWE-121", "Stack-based Buffer Overflow"),
  "CWE-122": cwe("CWE-122", "Heap-based Buffer Overflow"),
  "CWE-125": cwe("CWE-125", "Out-of-bounds Read"),
  "CWE-200": cwe("CWE-200", "Exposure of Sensitive Information"),
  "CWE-209": cwe("CWE-209", "Information Exposure Through an Error Message"),
  "CWE-284": cwe("CWE-284", "Improper Access Control"),
  "CWE-288": cwe("CWE-288", "Authentication Bypass Using an Alternate Path or Channel"),
  "CWE-306": cwe("CWE-306", "Missing Authentication for Critical Function"),
  "CWE-327": cwe("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
  "CWE-352": cwe("CWE-352", "Cross-Site Request Forgery"),
  "CWE-400": cwe("CWE-400", "Uncontrolled Resource Consumption"),
  "CWE-416": cwe("CWE-416", "Use After Free"),
  "CWE-434": cwe("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
  "CWE-476": cwe("CWE-476", "NULL Pointer Dereference"),
  "CWE-502": cwe("CWE-502", "Deserialization of Untrusted Data"),
  "CWE-601": cwe("CWE-601", "URL Redirection to Untrusted Site"),
  "CWE-611": cwe("CWE-611", "Improper Restriction of XML External Entity Reference"),
  "CWE-639": cwe("CWE-639", "Authorization Bypass Through User-Controlled Key"),
  "CWE-770": cwe("CWE-770", "Allocation of Resources Without Limits or Throttling"),
  "CWE-787": cwe("CWE-787", "Out-of-bounds Write"),
  "CWE-798": cwe("CWE-798", "Use of Hard-coded Credentials"),
  "CWE-862": cwe("CWE-862", "Missing Authorization"),
  "CWE-863": cwe("CWE-863", "Incorrect Authorization"),
  "CWE-915": cwe("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
  "CWE-918": cwe("CWE-918", "Server-Side Request Forgery"),
  "CWE-117": cwe("CWE-117", "Improper Output Neutralization for Logs"),
  "CWE-532": cwe("CWE-532", "Insertion of Sensitive Information into Log File")
};

const CWE_TOP25_2025 = new Set([
  "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787",
  "CWE-22", "CWE-416", "CWE-125", "CWE-78", "CWE-94",
  "CWE-120", "CWE-434", "CWE-476", "CWE-121", "CWE-502",
  "CWE-122", "CWE-863", "CWE-20", "CWE-284", "CWE-200",
  "CWE-306", "CWE-918", "CWE-77", "CWE-639", "CWE-770"
]);

interface MappingSet {
  owasp: string[];
  llm: string[];
  cwe: string[];
}

const CATEGORY_MAP: Record<string, MappingSet> = {
  "access-control": { owasp: ["A01", "API1", "API5"], llm: [], cwe: ["CWE-862", "CWE-863", "CWE-284", "CWE-639"] },
  "adapter": { owasp: [], llm: [], cwe: [] },
  "agent-config": { owasp: ["A06", "A08"], llm: ["LLM01", "LLM06", "LLM07"], cwe: ["CWE-94", "CWE-200"] },
  "authentication": { owasp: ["A07", "API2"], llm: [], cwe: ["CWE-306"] },
  "business-logic": { owasp: ["A01", "A06", "API1", "API5"], llm: [], cwe: ["CWE-862", "CWE-863", "CWE-639"] },
  "code-execution": { owasp: ["A05"], llm: ["LLM05", "LLM06"], cwe: ["CWE-78", "CWE-94", "CWE-77"] },
  "configuration": { owasp: ["A02", "API8"], llm: [], cwe: [] },
  "cors": { owasp: ["A02", "API8"], llm: [], cwe: [] },
  "dependency": { owasp: ["A03", "API10"], llm: ["LLM03", "LLM09"], cwe: [] },
  "deserialization": { owasp: ["A05", "A08"], llm: [], cwe: ["CWE-502"] },
  "exposure": { owasp: ["A02", "API8"], llm: ["LLM02"], cwe: ["CWE-200"] },
  "exception-leak": { owasp: ["A10", "API8"], llm: [], cwe: ["CWE-209", "CWE-200"] },
  "file-upload": { owasp: ["A05", "A06"], llm: [], cwe: ["CWE-434"] },
  "injection": { owasp: ["A05"], llm: ["LLM05"], cwe: ["CWE-89", "CWE-78", "CWE-94"] },
  "jwt-oauth-misuse": { owasp: ["A07", "API2"], llm: [], cwe: ["CWE-306", "CWE-288"] },
  "logging": { owasp: ["A09"], llm: ["LLM02"], cwe: ["CWE-117", "CWE-532"] },
  "missing-authz": { owasp: ["A01", "API1", "API5"], llm: [], cwe: ["CWE-862", "CWE-863", "CWE-639"] },
  "path-traversal": { owasp: ["A05"], llm: [], cwe: ["CWE-22"] },
  "resource-consumption": { owasp: ["A06", "API4", "API6"], llm: ["LLM10"], cwe: ["CWE-770", "CWE-400"] },
  "secrets": { owasp: ["A04", "A02"], llm: ["LLM02"], cwe: ["CWE-798", "CWE-200"] },
  "ssrf": { owasp: ["A05", "API7"], llm: [], cwe: ["CWE-918"] },
  "csrf": { owasp: ["A01"], llm: [], cwe: ["CWE-352"] },
  "supply-chain": { owasp: ["A03", "A08", "API10"], llm: ["LLM03"], cwe: [] },
  "weak-crypto": { owasp: ["A04"], llm: [], cwe: ["CWE-327"] },
  "web-headers": { owasp: ["A02", "API8"], llm: [], cwe: [] }
};

export function enrichFindingMappings(input: Pick<FindingInput, "id" | "category">): {
  owaspMapping: SecurityMapping[];
  cweMapping: SecurityMapping[];
  owaspTop10_2025: string[];
  owaspLLMTop10_2025: string[];
  owaspAPITop10_2023: string[];
  cweTop25_2025: string[];
} {
  const category = CATEGORY_MAP[input.category] ?? inferMappingFromId(input.id);
  const owaspMappings = category.owasp.map(toOwaspMapping).filter(Boolean);
  const cweMappings = category.cwe.map((id) => CWE[id]).filter(Boolean);
  return {
    owaspMapping: owaspMappings,
    cweMapping: cweMappings,
    owaspTop10_2025: owaspMappings.filter((mapping) => mapping.id.startsWith("A")).map((mapping) => mapping.id),
    owaspLLMTop10_2025: category.llm.map((key) => OWASP_LLM_TOP_10_2025[key]?.id).filter(Boolean),
    owaspAPITop10_2023: owaspMappings.filter((mapping) => mapping.id.startsWith("API")).map((mapping) => mapping.id),
    cweTop25_2025: cweMappings.map((mapping) => mapping.id).filter((id) => CWE_TOP25_2025.has(id))
  };
}

function inferMappingFromId(id: string): MappingSet {
  if (/cors/i.test(id)) return CATEGORY_MAP.cors;
  if (/secret|credential|token|key/i.test(id)) return CATEGORY_MAP.secrets;
  if (/sql|command|eval|shell/i.test(id)) return CATEGORY_MAP.injection;
  if (/csrf/i.test(id)) return CATEGORY_MAP.csrf;
  if (/crypto|md5|sha1/i.test(id)) return CATEGORY_MAP["weak-crypto"];
  if (/ssrf|url/i.test(id)) return CATEGORY_MAP.ssrf;
  if (/path|traversal/i.test(id)) return CATEGORY_MAP["path-traversal"];
  if (/auth|access/i.test(id)) return CATEGORY_MAP["access-control"];
  if (/dependency|cve|vulnerab/i.test(id)) return CATEGORY_MAP.dependency;
  return { owasp: [], llm: [], cwe: [] };
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
