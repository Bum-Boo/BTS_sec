import path from "node:path";
import { remediationFor } from "../knowledge-base/remediation";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext, Severity } from "../scanner-core/types";
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
  recommendation: string;
  verification: string;
}

const CODE_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".java", ".kt", ".go", ".rb", ".php",
  ".cs", ".rs", ".yml", ".yaml", ".json", ".env",
  ".properties"
]);

const RULES: CodeRule[] = [
  rule("code.hardcoded-secret", "Hardcoded secret-like value", "secrets", "high", "high", /\b(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"][^'"]{8,}['"]/i),
  rule("code.weak-jwt", "Weak JWT handling pattern", "authentication", "high", "medium", /\b(?:jwt|jsonwebtoken)\.(?:decode|verify)\s*\(|ignoreExpiration\s*:\s*true|algorithms\s*:\s*\[\s*['"]none['"]/i),
  rule("code.unsafe-cors", "Unsafe CORS configuration", "cors", "medium", "high", /\bcors\s*\(\s*\)|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|@CrossOrigin\s*\([^)]*origins\s*=\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*,\s*['"]\*/i),
  rule("code.unsafe-upload", "Potentially unsafe file upload handling", "file-upload", "medium", "medium", /\bmulter\s*\([^)]*dest\s*:\s*['"]public|upload\.(?:single|array|fields)\s*\(|MultipartFile\b|UploadFile\b/i),
  rule("code.shell-execution", "Shell execution reachable in application code", "code-execution", "high", "medium", /\bchild_process\.(?:exec|execSync)\s*\(|\bexec\s*\(|os\.system\s*\(|subprocess\.(?:Popen|run|call)\s*\([^)]*shell\s*=\s*True|Runtime\.getRuntime\(\)\.exec/i),
  rule("code.eval-usage", "Dynamic code evaluation", "code-execution", "high", "high", /\beval\s*\(|new\s+Function\s*\(|vm\.runIn(?:This|New)?Context\s*\(|ScriptEngineManager\b/i),
  rule("code.raw-sql", "Raw SQL string construction", "injection", "high", "medium", /(?:query|execute|raw)\s*\(\s*(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{|['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*\+)|f['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)/i),
  rule("code.missing-authorization", "Privileged route may be missing authorization middleware", "access-control", "medium", "low", /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['"]\/(?:admin|api\/admin|internal|users\/:id|account)/i),
  rule("code.dangerous-logging", "Sensitive values may be written to logs", "logging", "medium", "medium", /\b(?:console|logger)\.(?:log|debug|info|warn|error)\s*\([^)]*(?:authorization|cookie|password|passwd|token|secret|api[_-]?key)/i),
  rule("code.next-dangerous-html", "Next.js dangerous HTML rendering", "injection", "medium", "medium", /dangerouslySetInnerHTML\s*=/i),
  rule("code.fastapi-debug", "FastAPI debug mode enabled", "configuration", "medium", "high", /\bFastAPI\s*\([^)]*debug\s*=\s*True/i, new Set([".py"])),
  rule("code.spring-csrf-disabled", "Spring Security CSRF disabled", "configuration", "medium", "medium", /\.csrf\s*\([^)]*\)\s*\.disable\s*\(|csrf\s*->\s*csrf\.disable\s*\(\s*\)/i, new Set([".java", ".kt"])),
  rule("code.ssrf-user-controlled-url", "Possible user-controlled outbound request", "ssrf", "high", "low", /\b(?:fetch|axios\.get|axios\.post|requests\.get|requests\.post|RestTemplate\(\)\.getForObject)\s*\([^)]*(?:req\.|request\.|params|query|body)/i),
  rule("code.path-traversal", "Possible user-controlled file path access", "injection", "high", "low", /\b(?:readFile|createReadStream|sendFile|open|FileInputStream)\s*\([^)]*(?:req\.|request\.|params|query|body)/i)
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

    for (const file of files) {
      const ext = path.extname(file).toLowerCase();
      const lines = await readFileLines(file);
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        for (const ruleDef of RULES) {
          if (ruleDef.extensions && !ruleDef.extensions.has(ext)) {
            continue;
          }
          if (!ruleDef.pattern.test(line)) {
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
            evidence: `Matched ${ruleDef.id} in ${path.relative(context.target.path, file)}:${index + 1}: ${redactSecrets(line.trim())}`,
            recommendation: remediation.recommendation,
            verification: remediation.verification,
            rawSource: { ruleId: ruleDef.id }
          }));
        }
      }
    }

    return { findings };
  }
};

function rule(
  id: string,
  title: string,
  category: string,
  severity: Severity,
  confidence: "low" | "medium" | "high",
  pattern: RegExp,
  extensions?: Set<string>
): CodeRule {
  return {
    id,
    title,
    category,
    severity,
    confidence,
    pattern,
    extensions,
    recommendation: "Review this pattern and replace it with a safer application-specific implementation.",
    verification: "Add a focused test or code review check proving the risky pattern is absent or safely constrained."
  };
}
