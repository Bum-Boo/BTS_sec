import fs from "node:fs/promises";
import path from "node:path";
import { CWE } from "../knowledge-base/mappings";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext, Severity } from "../scanner-core/types";

type HttpMethod = "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace";

interface OpenApiDocument {
  openapi?: string;
  swagger?: string;
  security?: unknown[];
  paths?: Record<string, Record<string, OpenApiOperation | unknown>>;
  components?: { schemas?: Record<string, unknown> };
  definitions?: Record<string, unknown>;
}

interface OpenApiOperation {
  summary?: string;
  description?: string;
  deprecated?: boolean;
  security?: unknown[];
  parameters?: Array<{ name?: string; in?: string; schema?: unknown }>;
  requestBody?: {
    content?: Record<string, { schema?: unknown }>;
  };
  responses?: Record<string, unknown>;
  [key: string]: unknown;
}

interface OperationEntry {
  pathName: string;
  method: HttpMethod;
  operation: OpenApiOperation;
}

const HTTP_METHODS = new Set<HttpMethod>(["get", "post", "put", "patch", "delete", "head", "options", "trace"]);
const OBJECT_ID_PATH = /(?:\{[^}]*\bid\b[^}]*\}|\/:[^/]*\bid\b|\/(?:users?|accounts?|orders?|projects?|tenants?|customers?)\/\{[^}]+\})/i;
const SENSITIVE_PATH = /\/(?:admin|internal|manage|management|actuator|debug|ops|superuser|staff|root)(?:\/|$)/i;
const UNDOCUMENTED_PATH = /\/(?:old|legacy|deprecated|debug|test|tmp|temp|internal)(?:\/|$)/i;
const MASS_ASSIGNMENT_PROPERTY = /^(?:isAdmin|admin|role|roles|permissions|scopes|ownerId|tenantId|accountId|userId|createdAt|updatedAt|deletedAt|passwordHash|status)$/i;
const USER_CONTROLLED_URL_PROPERTY = /(?:url|uri|callback|webhook|redirect|returnTo|next|endpoint|host|avatar|image|remote|fetch)/i;
const PAGINATION_PARAMETER = /^(?:page|perPage|pageSize|limit|offset|cursor|after|before|take|skip)$/i;

export const openApiScanner: ScannerAdapter = {
  name: "openapi-passive-scanner",
  async scan(context: ScanContext) {
    if (context.target.kind !== "api-spec") {
      return { findings: [] };
    }

    const content = await fs.readFile(context.target.path, "utf8");
    const document = parseOpenApi(content);
    const operations = collectOperations(document);
    const findings: Finding[] = [];
    const hasGlobalSecurity = hasSecurityRequirements(document.security);

    for (const entry of operations) {
      const opSecurity = hasSecurityRequirements(entry.operation.security);
      const explicitlyPublic = Array.isArray(entry.operation.security) && entry.operation.security.length === 0;
      if (!hasGlobalSecurity && !opSecurity || explicitlyPublic) {
        findings.push(apiFinding(context, entry, {
          id: "api.openapi.missing-security",
          title: "OpenAPI operation lacks security requirements",
          severity: sensitiveOperation(entry) ? "high" : "medium",
          confidence: "high",
          category: "authentication",
          owaspTop10_2025: ["A07:2025"],
          owaspAPITop10_2023: ["API2:2023"],
          cwe: ["CWE-306"],
          evidence: `${entry.method.toUpperCase()} ${entry.pathName} has no global or operation-level security requirement.`
        }));
      }

      if (OBJECT_ID_PATH.test(entry.pathName) && ["get", "put", "patch", "delete"].includes(entry.method)) {
        findings.push(apiFinding(context, entry, {
          id: "api.openapi.bola-candidate",
          title: "Object-id endpoint likely requires BOLA checks",
          severity: "high",
          confidence: "medium",
          category: "missing-authz",
          owaspTop10_2025: ["A01:2025"],
          owaspAPITop10_2023: ["API1:2023"],
          cwe: ["CWE-639"],
          evidence: `${entry.method.toUpperCase()} ${entry.pathName} exposes an object identifier in the route.`
        }));
      }

      if (SENSITIVE_PATH.test(entry.pathName)) {
        findings.push(apiFinding(context, entry, {
          id: "api.openapi.function-authz-sensitive-path",
          title: "Sensitive function-level authorization path",
          severity: opSecurity || hasGlobalSecurity ? "medium" : "high",
          confidence: "medium",
          category: "missing-authz",
          owaspTop10_2025: ["A01:2025"],
          owaspAPITop10_2023: ["API5:2023"],
          cwe: ["CWE-862"],
          evidence: `${entry.method.toUpperCase()} ${entry.pathName} appears to expose an admin/internal function.`
        }));
      }

      const requestSchemas = requestBodySchemas(entry.operation);
      if (requestSchemas.some((schema) => schemaPropertyNames(schema, document).some((name) => MASS_ASSIGNMENT_PROPERTY.test(name)))) {
        findings.push(apiFinding(context, entry, {
          id: "api.openapi.mass-assignment-risk",
          title: "Request schema exposes privileged object properties",
          severity: "high",
          confidence: "medium",
          category: "missing-authz",
          owaspTop10_2025: ["A01:2025"],
          owaspAPITop10_2023: ["API3:2023"],
          cwe: ["CWE-915"],
          evidence: `${entry.method.toUpperCase()} ${entry.pathName} request schema includes role, ownership, tenant, lifecycle, or privileged fields.`
        }));
      }

      if (requestSchemas.some((schema) => schemaPropertyNames(schema, document).some((name) => USER_CONTROLLED_URL_PROPERTY.test(name)))) {
        findings.push(apiFinding(context, entry, {
          id: "api.openapi.user-controlled-url-field",
          title: "Request schema contains user-controlled URL-like fields",
          severity: "medium",
          confidence: "medium",
          category: "ssrf",
          owaspTop10_2025: ["A05:2025"],
          owaspAPITop10_2023: ["API7:2023"],
          cwe: ["CWE-918"],
          evidence: `${entry.method.toUpperCase()} ${entry.pathName} request schema includes URL, callback, redirect, host, or endpoint-style fields.`
        }));
      }

      if (entry.method === "get" && looksLikeCollection(entry) && !hasPaginationOrRateLimitHints(entry.operation)) {
        findings.push(apiFinding(context, entry, {
          id: "api.openapi.collection-missing-pagination-rate-limit",
          title: "Collection endpoint lacks pagination or rate-limit hints",
          severity: "medium",
          confidence: "medium",
          category: "resource-consumption",
          owaspTop10_2025: ["A06:2025"],
          owaspAPITop10_2023: ["API4:2023"],
          cwe: ["CWE-770"],
          evidence: `${entry.method.toUpperCase()} ${entry.pathName} looks like a collection endpoint without documented pagination parameters, 429 response, or rate-limit extensions.`
        }));
      }

      if (entry.operation.deprecated || UNDOCUMENTED_PATH.test(entry.pathName) || !entry.operation.summary && !entry.operation.description) {
        findings.push(apiFinding(context, entry, {
          id: "api.openapi.deprecated-or-undocumented",
          title: "Deprecated or weakly documented API operation",
          severity: entry.operation.deprecated || UNDOCUMENTED_PATH.test(entry.pathName) ? "medium" : "low",
          confidence: "medium",
          category: "exposure",
          owaspTop10_2025: ["A02:2025"],
          owaspAPITop10_2023: ["API9:2023"],
          cwe: [],
          evidence: `${entry.method.toUpperCase()} ${entry.pathName} is deprecated, internal-looking, or lacks operation summary/description.`
        }));
      }
    }

    return { findings };
  }
};

function parseOpenApi(content: string): OpenApiDocument {
  try {
    return JSON.parse(content) as OpenApiDocument;
  } catch {
    return parseYamlFallback(content);
  }
}

function parseYamlFallback(content: string): OpenApiDocument {
  const paths: OpenApiDocument["paths"] = {};
  let currentPath: string | undefined;
  let currentMethod: HttpMethod | undefined;
  let inPaths = false;
  let rootSecurity = false;

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/\t/g, "  ");
    if (/^security:\s*$/.test(line)) rootSecurity = true;
    if (/^paths:\s*$/.test(line)) {
      inPaths = true;
      continue;
    }
    if (inPaths && /^\S/.test(line) && !/^paths:\s*$/.test(line)) {
      inPaths = false;
    }
    if (!inPaths) continue;

    const pathMatch = line.match(/^\s{2}(['"]?)(\/[^:'"]+.*?)\1:\s*$/);
    if (pathMatch) {
      currentPath = pathMatch[2];
      paths[currentPath] = {};
      currentMethod = undefined;
      continue;
    }

    const methodMatch = line.match(/^\s{4}(get|post|put|patch|delete|head|options|trace):\s*$/i);
    if (currentPath && methodMatch) {
      currentMethod = methodMatch[1].toLowerCase() as HttpMethod;
      paths[currentPath][currentMethod] = {};
      continue;
    }

    if (currentPath && currentMethod) {
      const operation = paths[currentPath][currentMethod] as OpenApiOperation;
      const valueMatch = line.match(/^\s{6}(summary|description):\s*(.+)$/i);
      if (valueMatch) operation[valueMatch[1].toLowerCase()] = valueMatch[2].trim();
      if (/^\s{6}deprecated:\s*true\s*$/i.test(line)) operation.deprecated = true;
      if (/^\s{6}security:\s*\[\]\s*$/i.test(line)) operation.security = [];
      if (/^\s{6}security:\s*$/.test(line)) operation.security = [{}];
    }
  }

  return {
    openapi: content.match(/^openapi:\s*([^\s]+)/m)?.[1],
    swagger: content.match(/^swagger:\s*([^\s]+)/m)?.[1],
    security: rootSecurity ? [{}] : undefined,
    paths
  };
}

function collectOperations(document: OpenApiDocument): OperationEntry[] {
  const entries: OperationEntry[] = [];
  for (const [pathName, pathItem] of Object.entries(document.paths ?? {})) {
    if (!pathItem || typeof pathItem !== "object") continue;
    for (const [method, operation] of Object.entries(pathItem)) {
      const lower = method.toLowerCase() as HttpMethod;
      if (!HTTP_METHODS.has(lower) || !operation || typeof operation !== "object") continue;
      entries.push({ pathName, method: lower, operation: operation as OpenApiOperation });
    }
  }
  return entries;
}

function hasSecurityRequirements(security: unknown): boolean {
  return Array.isArray(security) && security.length > 0;
}

function sensitiveOperation(entry: OperationEntry): boolean {
  return SENSITIVE_PATH.test(entry.pathName) || ["post", "put", "patch", "delete"].includes(entry.method);
}

function requestBodySchemas(operation: OpenApiOperation): unknown[] {
  return Object.values(operation.requestBody?.content ?? {})
    .map((contentType) => contentType.schema)
    .filter(Boolean);
}

function schemaPropertyNames(schema: unknown, document: OpenApiDocument, seen = new Set<unknown>()): string[] {
  if (!schema || typeof schema !== "object" || seen.has(schema)) return [];
  seen.add(schema);
  const record = schema as Record<string, unknown>;
  const ref = typeof record.$ref === "string" ? resolveRef(record.$ref, document) : undefined;
  if (ref) return schemaPropertyNames(ref, document, seen);
  const properties = record.properties && typeof record.properties === "object"
    ? Object.keys(record.properties as Record<string, unknown>)
    : [];
  const nested = [
    ...arrayOfSchemas(record.allOf),
    ...arrayOfSchemas(record.anyOf),
    ...arrayOfSchemas(record.oneOf),
    record.items
  ].flatMap((nestedSchema) => schemaPropertyNames(nestedSchema, document, seen));
  return [...properties, ...nested];
}

function resolveRef(ref: string, document: OpenApiDocument): unknown {
  const prefix = "#/";
  if (!ref.startsWith(prefix)) return undefined;
  return ref
    .slice(prefix.length)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce<unknown>((current, part) => {
      if (!current || typeof current !== "object") return undefined;
      return (current as Record<string, unknown>)[part];
    }, document);
}

function arrayOfSchemas(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function looksLikeCollection(entry: OperationEntry): boolean {
  if (OBJECT_ID_PATH.test(entry.pathName)) return false;
  const lastSegment = entry.pathName.split("/").filter(Boolean).at(-1) ?? "";
  return /s$/.test(lastSegment) || /list|search|query/i.test(entry.operation.summary ?? "");
}

function hasPaginationOrRateLimitHints(operation: OpenApiOperation): boolean {
  const params = operation.parameters ?? [];
  const hasPagination = params.some((param) => param.in === "query" && param.name && PAGINATION_PARAMETER.test(param.name));
  const hasRateLimitExtension = Object.keys(operation).some((key) => /rate.?limit/i.test(key));
  const hasTooManyRequests = Boolean(operation.responses?.["429"]);
  return hasPagination || hasRateLimitExtension || hasTooManyRequests;
}

function apiFinding(
  context: ScanContext,
  entry: OperationEntry,
  input: {
    id: string;
    title: string;
    severity: Severity;
    confidence: "low" | "medium" | "high";
    category: string;
    owaspTop10_2025: string[];
    owaspAPITop10_2023: string[];
    cwe: string[];
    evidence: string;
  }
): Finding {
  return normalizeFinding({
    ...input,
    sourceTool: "openapi-passive-scanner",
    targetType: "api",
    target: context.target.raw,
    file: context.target.kind === "api-spec" ? context.target.path : undefined,
    endpoint: `${entry.method.toUpperCase()} ${entry.pathName}`,
    evidence: `${input.evidence} No exploit payloads or destructive requests were sent.`,
    cweMapping: input.cwe.map((id) => CWE[id]).filter((mapping) => Boolean(mapping)),
    cweTop25_2025: input.cwe.filter((id) => [
      "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787",
      "CWE-22", "CWE-416", "CWE-125", "CWE-78", "CWE-94",
      "CWE-120", "CWE-434", "CWE-476", "CWE-121", "CWE-502",
      "CWE-122", "CWE-863", "CWE-20", "CWE-284", "CWE-200",
      "CWE-306", "CWE-918", "CWE-77", "CWE-639", "CWE-770"
    ].includes(id)),
    recommendation: recommendationFor(input.id),
    verification: verificationFor(input.id),
    rawSource: {
      spec: context.target.kind === "api-spec" ? path.basename(context.target.path) : context.target.raw,
      method: entry.method,
      path: entry.pathName
    }
  });
}

function recommendationFor(ruleId: string): string {
  if (ruleId.includes("missing-security")) return "Define global or operation-level OpenAPI security requirements and implement the matching authentication middleware.";
  if (ruleId.includes("bola")) return "Enforce object ownership or tenant authorization for each object-id lookup before returning or mutating data.";
  if (ruleId.includes("function-authz")) return "Require explicit role or privilege checks for admin/internal operations.";
  if (ruleId.includes("mass-assignment")) return "Use explicit input DTOs/allowlists and keep privileged or server-owned fields out of client-writable schemas.";
  if (ruleId.includes("user-controlled-url")) return "Validate and constrain outbound URL destinations with allowlists, safe schemes, DNS/IP protections, and timeouts.";
  if (ruleId.includes("pagination")) return "Document and enforce pagination, request limits, and rate-limit behavior for collection endpoints.";
  return "Document ownership, lifecycle status, and intended exposure for this endpoint, and remove stale operations from the published spec.";
}

function verificationFor(ruleId: string): string {
  if (ruleId.includes("missing-security")) return "Review generated routes/middleware and confirm the OpenAPI security requirement matches enforced authentication.";
  if (ruleId.includes("bola")) return "Add unit or integration tests proving one user or tenant cannot access another user's object by changing only the identifier.";
  if (ruleId.includes("function-authz")) return "Add authorization tests for regular, privileged, and unauthenticated callers.";
  if (ruleId.includes("mass-assignment")) return "Submit a safe local test request with privileged fields and confirm they are rejected or ignored.";
  if (ruleId.includes("user-controlled-url")) return "Add local validation tests for allowed and disallowed URL destinations without contacting attacker-controlled hosts.";
  if (ruleId.includes("pagination")) return "Confirm API handlers enforce bounded page sizes and return documented 429 or equivalent throttling behavior.";
  return "Review the API inventory and confirm deprecated/internal operations are removed, protected, or intentionally documented.";
}
