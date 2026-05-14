import path from "node:path";
import { CWE, OWASP_API_TOP_10_2023, OWASP_TOP_10_2025 } from "../knowledge-base/mappings";
import { remediationFor } from "../knowledge-base/remediation";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext, SecurityMapping, Severity } from "../scanner-core/types";
import { redactSecrets } from "../scanner-core/redaction";
import { readFileLines, walkFiles } from "../utils/fs";

interface CodeRule {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  pattern: RegExp;
  extensions?: Set<string>;
  windowLines?: number;
  owasp: string[];
  apiTop10: string[];
  cwe: string[];
  recommendation: string;
  verification: string;
  validator?: (context: RuleMatchContext) => boolean;
}

interface SuppressedFindingSummary {
  id: string;
  title: string;
  file: string;
  line: number;
  reason: string;
  sourceTool: string;
}

interface RuleMatchContext {
  file: string;
  lines: string[];
  index: number;
  snippet: string;
}

const CODE_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".java", ".kt", ".go", ".rb", ".php",
  ".cs", ".rs", ".yml", ".yaml", ".json", ".env",
  ".properties", ".scala", ".gradle"
]);

const RULES: CodeRule[] = [
  rule("code.hardcoded-secret", "Hardcoded secret-like value", "secrets", "high", "high", /\b(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"][^'"]{8,}['"]/i, {
    owasp: ["A04", "A02"], cwe: ["CWE-798", "CWE-200"],
    recommendation: "Move secrets to a managed secret store, rotate exposed values, and keep only placeholders in source.",
    verification: "Re-run secret scanning and confirm only redacted placeholders remain."
  }),
  rule("code.weak-jwt", "Weak JWT handling pattern", "jwt-oauth-misuse", "high", "medium", /\b(?:jwt|jsonwebtoken)\.(?:decode|verify)\s*\(|ignoreExpiration\s*:\s*true|algorithms\s*:\s*\[\s*['"]none['"]/i, {
    owasp: ["A07"], apiTop10: ["API2"], cwe: ["CWE-306", "CWE-288"],
    recommendation: "Verify JWT signatures, expected issuer/audience, expiration, and an explicit safe algorithm allowlist.",
    verification: "Add tests for expired, wrong-issuer, wrong-audience, and unsigned tokens."
  }),
  rule("code.unsafe-cors", "Unsafe CORS configuration", "cors", "medium", "high", /\bcors\s*\(\s*\)|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|@CrossOrigin\s*\([^)]*origins\s*=\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*,\s*['"]\*/i, {
    owasp: ["A02"], apiTop10: ["API8"],
    recommendation: "Use an explicit trusted origin allowlist and avoid wildcard or reflected origins for credentialed APIs.",
    verification: "Send a safe preflight from an untrusted origin and confirm it is rejected."
  }),
  rule("code.unsafe-upload", "Potentially unsafe file upload handling", "file-upload", "medium", "medium", /\bmulter\s*\([^)]*dest\s*:\s*['"]public|upload\.(?:single|array|fields)\s*\(|MultipartFile\b|UploadFile\b/i, {
    owasp: ["A05", "A06"], cwe: ["CWE-434"],
    recommendation: "Validate file type and size server-side, store uploads outside executable paths, and randomize stored names.",
    verification: "Add safe upload tests for rejected extensions, oversized files, and non-public storage paths."
  }),
  rule("code.shell-execution", "Shell execution reachable in application code", "code-execution", "high", "medium", /\bchild_process\.(?:exec|execSync)\s*\(|\bexec\s*\(|os\.system\s*\(|subprocess\.(?:Popen|run|call)\s*\([^)]*shell\s*=\s*True|Runtime\.getRuntime\(\)\.exec/i, {
    owasp: ["A05"], cwe: ["CWE-78", "CWE-77"],
    recommendation: "Avoid shell invocation for request-influenced data; use fixed command arrays and strict allowlists when process execution is required.",
    verification: "Review call sites and add tests proving user input cannot influence executable names or arguments."
  }),
  rule("code.eval-usage", "Dynamic code evaluation", "code-execution", "high", "high", /\beval\s*\(|new\s+Function\s*\(|vm\.runIn(?:This|New)?Context\s*\(|ScriptEngineManager\b/i, {
    owasp: ["A05"], cwe: ["CWE-94"],
    recommendation: "Remove dynamic code evaluation or replace it with a constrained parser/interpreter for the intended data format.",
    verification: "Add tests proving untrusted input is treated as data, not executable code."
  }),
  rule("code.raw-sql", "Raw SQL string construction", "injection", "high", "medium", /(?:query|execute|raw)\s*\(\s*(?:`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{|['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*\+)|(?:^|[=\s(])f['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i, {
    owasp: ["A05"], cwe: ["CWE-89"],
    recommendation: "Use parameterized queries or ORM query builders and avoid string concatenation for SQL.",
    verification: "Add tests for representative input containing SQL metacharacters and confirm parameters are bound safely."
  }),
  rule("code.missing-authorization", "Privileged route may be missing authorization middleware", "missing-authz", "medium", "low", /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['"]\/(?:admin|api\/admin|internal|users\/:id|account)|@(Get|Post|Put|Patch|Delete)Mapping\s*\([^)]*\/(?:admin|internal|users\/\{id\})|@app\.(?:get|post|put|patch|delete)\(['"]\/(?:admin|internal|users\/\{)/i, {
    owasp: ["A01"], apiTop10: ["API1", "API5"], cwe: ["CWE-862", "CWE-863", "CWE-639"],
    recommendation: "Add explicit authentication, role, ownership, or tenant checks for privileged and object-id routes.",
    verification: "Add tests for unauthenticated, wrong-role, wrong-user, and wrong-tenant access."
  }),
  rule("code.dangerous-logging", "Sensitive values may be written to logs", "logging", "medium", "medium", /\b(?:console|logger|log)\.(?:log|debug|info|warn|error)\s*\([^)]*(?:authorization|cookie|password|passwd|token|secret|api[_-]?key)/i, {
    owasp: ["A09"], cwe: ["CWE-117", "CWE-532"],
    recommendation: "Remove sensitive fields from logs or use structured redaction before logging.",
    verification: "Run tests or local requests and confirm logs contain no raw credentials, tokens, or cookies."
  }),
  rule("code.next-dangerous-html", "Next.js dangerous HTML rendering", "xss-template-rendering", "medium", "medium", /dangerouslySetInnerHTML\s*=/i, {
    owasp: ["A05"], cwe: ["CWE-79"],
    recommendation: "Avoid raw HTML rendering or sanitize trusted markup with a vetted sanitizer at the server boundary.",
    verification: "Add rendering tests with HTML metacharacters and confirm output is escaped or sanitized."
  }),
  rule("code.fastapi-debug", "FastAPI debug mode enabled", "configuration", "medium", "high", /\bFastAPI\s*\([^)]*debug\s*=\s*True/i, {
    extensions: [".py"], owasp: ["A02"], apiTop10: ["API8"],
    recommendation: "Disable debug mode outside local development and ensure production settings are environment-specific.",
    verification: "Start the application with production settings and confirm debug tracebacks are disabled."
  }),
  rule("code.spring-csrf-disabled", "Spring Security CSRF disabled", "csrf", "medium", "medium", /\.csrf\s*\([^)]*\)\s*\.disable\s*\(|csrf\s*->\s*csrf\.disable\s*\(\s*\)/i, {
    extensions: [".java", ".kt"], owasp: ["A01"], cwe: ["CWE-352"],
    recommendation: "Keep CSRF protection enabled for browser-session flows or document why only non-cookie bearer-token APIs are exposed.",
    verification: "Add browser-session form/API tests proving cross-site requests cannot mutate state."
  }),
  rule("code.csrf-disabled", "CSRF protection appears disabled or absent for state-changing routes", "csrf", "medium", "low", /csrf\s*:\s*false|csurf\s*\([^)]*ignoreMethods\s*:\s*\[[^\]]*(?:POST|PUT|PATCH|DELETE)|CSRF_TRUSTED_ORIGINS\s*=\s*\[\s*['"]\*|@csrf_exempt|csrf_exempt\s*\(/i, {
    owasp: ["A01"], cwe: ["CWE-352"],
    recommendation: "Require CSRF tokens or SameSite-protected non-cookie auth patterns for browser-originated state changes.",
    verification: "Add safe local tests showing cross-site form submissions are rejected."
  }),
  rule("code.ssrf-user-controlled-url", "Possible user-controlled outbound request", "ssrf", "high", "low", /\b(?:fetch|axios\.(?:get|post|request)|got\s*\(|request\s*\(|requests\.(?:get|post|request)|httpx\.(?:get|post|request)|RestTemplate\(\)\.getForObject|WebClient\.create|http\.Get)\s*\([^)]*(?:req\.|request\.|params|query|body|RequestParam|r\.URL\.Query)/i, {
    owasp: ["A05"], apiTop10: ["API7"], cwe: ["CWE-918"],
    recommendation: "Validate outbound destinations with an allowlist, safe schemes, DNS/IP protections, and strict timeouts.",
    verification: "Add local tests for allowed and disallowed destinations without contacting attacker-controlled infrastructure."
  }),
  rule("code.path-traversal", "Possible user-controlled file path access", "path-traversal", "high", "low", /\b(?:readFile|createReadStream|sendFile|open|FileInputStream|Paths\.get|Files\.read|os\.Open)\s*\([^)]*(?:req\.|request\.|params|query|body|RequestParam|r\.URL\.Query)/i, {
    owasp: ["A05"], cwe: ["CWE-22"],
    recommendation: "Resolve paths against a fixed base directory, reject traversal segments, and enforce extension or object-key allowlists.",
    verification: "Add tests for traversal segments and absolute paths and confirm they are rejected."
  }),
  rule("code.deserialization-untrusted", "Untrusted deserialization pattern", "deserialization", "high", "medium", /\b(?:pickle\.loads?|yaml\.load\s*\(|marshal\.loads?|ObjectInputStream|readObject\s*\(|node-serialize\.unserialize|serialize-javascript|BinaryFormatter|JsonConvert\.DeserializeObject)\b[^;\n]*(?:req\.|request\.|body|data|params|InputStream|RequestBody)?/i, {
    owasp: ["A05", "A08"], cwe: ["CWE-502"],
    recommendation: "Avoid native object deserialization for untrusted input; use simple data DTOs and safe parsers.",
    verification: "Add parser tests proving untrusted data cannot instantiate arbitrary classes or invoke code paths."
  }),
  rule("code.weak-crypto", "Weak cryptographic primitive or randomness", "weak-crypto", "medium", "medium", /\b(?:md5|sha1)\s*\(|createHash\s*\(\s*['"](?:md5|sha1)['"]|MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-1)['"]|Math\.random\s*\(\s*\)|random\.random\s*\(\s*\)/i, {
    owasp: ["A04"], cwe: ["CWE-327"],
    recommendation: "Use modern primitives and cryptographically secure randomness for security decisions, tokens, and signatures.",
    verification: "Review all call sites and add tests or static checks preventing MD5/SHA-1 and non-CSPRNG token generation.",
    validator: weakCryptoMatchIsSecurityRelevant
  }),
  rule("code.jwt-oauth-misuse", "OAuth or JWT validation may be incomplete", "jwt-oauth-misuse", "high", "medium", /(?:verifyIdToken|jwt\.verify|JwtDecoder|oauth2ResourceServer)[\s\S]{0,240}(?:audience\s*:\s*undefined|ignoreExpiration|validateIssuer\s*=\s*false|setValidateIssuer\s*\(\s*false|algorithms\s*:\s*\[\s*['"]none['"])/i, {
    windowLines: 6, owasp: ["A07"], apiTop10: ["API2"], cwe: ["CWE-306", "CWE-288"],
    recommendation: "Validate issuer, audience, expiration, signature, and allowed algorithms for every token-bearing flow.",
    verification: "Add token validation tests covering wrong issuer, wrong audience, expired, tampered, and unsigned tokens."
  }),
  rule("code.xss-template-rendering", "Template rendering may include user-controlled HTML", "xss-template-rendering", "high", "low", /\b(?:res\.send|reply\.send|render_template_string|template\.HTML|innerHTML\s*=)\s*\([^)]*(?:req\.|request\.|params|query|body|r\.URL\.Query)/i, {
    owasp: ["A05"], cwe: ["CWE-79"],
    recommendation: "Render user-controlled data through escaping templates and avoid HTML-safe wrappers unless content is sanitized.",
    verification: "Add rendering tests with script tags and event attributes and confirm they are escaped or stripped."
  }),
  rule("code.exception-leak", "Exception or stack trace may be returned to clients", "exception-leak", "medium", "medium", /\b(?:res\.status\s*\(\s*500\s*\)\.send|ResponseEntity\.status\s*\(\s*500|HTTPException|JSONResponse|return\s+Response)\s*\([^)]*(?:err|error|exception|stack|traceback)|traceback\.format_exc\s*\(|err\.stack|error\.stack/i, {
    owasp: ["A10"], apiTop10: ["API8"], cwe: ["CWE-209", "CWE-200"],
    recommendation: "Return generic client errors and log detailed exceptions only through redacted server-side logs.",
    verification: "Add tests that trigger handled errors and confirm responses do not include stack traces or internals."
  }),
  rule("code.resource-consumption", "Potential unbounded resource consumption", "resource-consumption", "medium", "low", /\b(?:express\.json\s*\(\s*\{|bodyParser\.(?:json|urlencoded)\s*\(\s*\{)[^)]*limit\s*:\s*['"](?:[5-9]\d|[1-9]\d{2,})mb|findMany\s*\(\s*\{\s*\}|readAllBytes\s*\(|io\.ReadAll\s*\(\s*r\.Body|while\s*\(\s*true\s*\)/i, {
    windowLines: 4, owasp: ["A06"], apiTop10: ["API4", "API6"], cwe: ["CWE-770"],
    recommendation: "Add bounded request sizes, pagination, loop exits, timeouts, and concurrency/rate limits for user-triggered work.",
    verification: "Add tests that enforce maximum page size, body size, and timeout behavior.",
    validator: resourceConsumptionMatchIsActionable
  })
];

export const customCodeScanner: ScannerAdapter = {
  name: "custom-code-scanner",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }

    const files = await walkFiles(context.target.path, {
      extensions: CODE_EXTENSIONS,
      maxBytes: 1024 * 1024
    });
    const findings: Finding[] = [];
    const suppressedFindings: SuppressedFindingSummary[] = [];

    for (const file of files) {
      const ext = path.extname(file).toLowerCase();
      const lines = await readFileLines(file);
      for (let index = 0; index < lines.length; index += 1) {
        for (const ruleDef of RULES) {
          if (ruleDef.extensions && !ruleDef.extensions.has(ext)) {
            continue;
          }

          const snippet = lines.slice(index, index + (ruleDef.windowLines ?? 1)).join("\n");
          if (!ruleDef.pattern.test(snippet)) {
            continue;
          }
          if (ruleDef.validator && !ruleDef.validator({ file, lines, index, snippet })) {
            continue;
          }

          const suppression = suppressionFor(lines, index, ruleDef.id);
          if (suppression) {
            suppressedFindings.push({
              id: ruleDef.id,
              title: ruleDef.title,
              file,
              line: index + 1,
              reason: suppression.reason,
              sourceTool: "custom-code-scanner"
            });
            continue;
          }

          const remediation = remediationFor(ruleDef.id, ruleDef.recommendation, ruleDef.verification);
          findings.push(normalizeFinding({
            id: ruleDef.id,
            title: ruleDef.title,
            severity: ruleDef.severity,
            confidence: ruleDef.confidence,
            category: ruleDef.category,
            sourceTool: "custom-code-scanner",
            target: context.target.raw,
            file,
            line: index + 1,
            evidence: `Matched ${ruleDef.id} in ${path.relative(context.target.path, file)}:${index + 1}: ${redactSecrets(firstMeaningfulLine(snippet))}`,
            owaspMapping: [
              ...ruleDef.owasp.map((key) => OWASP_TOP_10_2025[key]).filter(isMapping),
              ...ruleDef.apiTop10.map((key) => OWASP_API_TOP_10_2023[key]).filter(isMapping)
            ],
            cweMapping: ruleDef.cwe.map((id) => CWE[id]).filter(isMapping),
            owaspTop10_2025: ruleDef.owasp.map((key) => OWASP_TOP_10_2025[key]?.id).filter(isString),
            owaspAPITop10_2023: ruleDef.apiTop10.map((key) => OWASP_API_TOP_10_2023[key]?.id).filter(isString),
            cweTop25_2025: ruleDef.cwe.filter((id) => [
              "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787",
              "CWE-22", "CWE-416", "CWE-125", "CWE-78", "CWE-94",
              "CWE-120", "CWE-434", "CWE-476", "CWE-121", "CWE-502",
              "CWE-122", "CWE-863", "CWE-20", "CWE-284", "CWE-200",
              "CWE-306", "CWE-918", "CWE-77", "CWE-639", "CWE-770"
            ].includes(id)),
            recommendation: remediation.recommendation,
            verification: remediation.verification,
            rawSource: { ruleId: ruleDef.id }
          }));
        }
      }
    }

    return {
      findings,
      metadata: { suppressedFindings }
    };
  }
};

function rule(
  id: string,
  title: string,
  category: string,
  severity: Severity,
  confidence: "low" | "medium" | "high",
  pattern: RegExp,
  options: {
    extensions?: string[];
    windowLines?: number;
    owasp?: string[];
    apiTop10?: string[];
    cwe?: string[];
    recommendation: string;
    verification: string;
    validator?: (context: RuleMatchContext) => boolean;
  }
): CodeRule {
  return {
    id,
    title,
    category,
    severity,
    confidence,
    pattern,
    extensions: options.extensions ? new Set(options.extensions) : undefined,
    windowLines: options.windowLines,
    owasp: options.owasp ?? [],
    apiTop10: options.apiTop10 ?? [],
    cwe: options.cwe ?? [],
    recommendation: options.recommendation,
    verification: options.verification,
    validator: options.validator
  };
}

function weakCryptoMatchIsSecurityRelevant(context: RuleMatchContext): boolean {
  if (/\b(?:md5|sha1)\s*\(|createHash\s*\(\s*['"](?:md5|sha1)['"]|MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-1)['"]/i.test(context.snippet)) {
    return true;
  }
  if (!/\b(?:Math\.random|random\.random)\s*\(/i.test(context.snippet)) {
    return true;
  }

  return /\b(?:auth|csrf|nonce|token|secret|password|passwd|session|cookie|credential|api[_-]?key|private[_-]?key|salt|signature|jwt|oauth|reset|verification|invite|otp|mfa)\b/i.test(context.snippet);
}

function resourceConsumptionMatchIsActionable(context: RuleMatchContext): boolean {
  if (!/while\s*\(\s*true\s*\)/i.test(context.snippet)) {
    return true;
  }

  const following = context.lines.slice(context.index, context.index + 12).join("\n");
  if (/\b(?:break|return|throw)\b/.test(following)) {
    return false;
  }

  const surrounding = context.lines.slice(Math.max(0, context.index - 5), context.index + 12).join("\n");
  return /\b(?:req|request|response|fetch|http|api|route|handler|socket|stream|queue|worker|job|body|upload|download)\b/i.test(surrounding);
}

function suppressionFor(lines: string[], index: number, ruleId: string): { reason: string } | undefined {
  const candidates = [lines[index], index > 0 ? lines[index - 1] : ""];
  for (const line of candidates) {
    const match = line.match(/\/\/\s*bts-sec-ignore\s+([a-z0-9_.:-]+|\*)\s+(.+)$/i);
    if (!match) continue;
    if (match[1] === "*" || match[1] === ruleId) {
      return { reason: match[2].trim() || "No reason provided." };
    }
  }
  return undefined;
}

function firstMeaningfulLine(snippet: string): string {
  return snippet.split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? "";
}

function isMapping(value: SecurityMapping | undefined): value is SecurityMapping {
  return Boolean(value);
}

function isString(value: string | undefined): value is string {
  return Boolean(value);
}
