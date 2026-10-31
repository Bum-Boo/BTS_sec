import path from "node:path";
import { remediationFor } from "../knowledge-base/remediation";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext, Severity } from "../scanner-core/types";
import { redactSecrets } from "../scanner-core/redaction";
import { hasSecretAssignment } from "../secret-scanner/secret-patterns";
import { fileTypeKey, readFileLines, walkFiles } from "../utils/fs";

interface CodeRule {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  pattern: RegExp | ((line: string) => boolean);
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

const JS_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

const SQL_STATEMENT = String.raw`(?:SELECT\b[^'"\x60]*\bFROM\b|INSERT\s+INTO\b|UPDATE\s+[\w."\x60]+\s+SET\b|DELETE\s+FROM\b)`;
const USER_INPUT = /\b(?:req|request)\.|\b(?:params|query|body|query_params|args)\s*[.[]/;
const AUTH_MIDDLEWARE = /['"]\s*,\s*\[?\s*[\w$.]*(?:auth|guard|protect|permission|role|verify|jwt|loggedin|isadmin|requireadmin|adminonly)[\w$.]*\s*[,(\]]/i;
const SENSITIVE_LOG_VALUE = /authorization|cookie|password|passwd|token|secret|api[_-]?key/i;

const RULES: CodeRule[] = [
  rule("code.hardcoded-secret", "Hardcoded secret-like value", "secrets", "high", "high", (line) => hasSecretAssignment(line, { allowUnquoted: false })),
  rule("code.weak-jwt", "Weak JWT handling pattern", "authentication", "high", "medium", /\b(?:jwt|jsonwebtoken)\.decode\s*\(|ignoreExpiration\s*:\s*true|algorithms\s*:\s*\[[^\]]*['"]none['"]/i, JS_EXTENSIONS),
  rule("code.weak-jwt", "Weak JWT handling pattern", "authentication", "high", "medium", /verify_signature['"]?\s*:\s*False|algorithms\s*=\s*\[[^\]]*['"]none['"]/, new Set([".py"])),
  rule("code.unsafe-cors", "Unsafe CORS configuration", "cors", "medium", "high", /\bcors\s*\(\s*\)|\borigin\s*:\s*['"]\*['"]|\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*true|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|@CrossOrigin\s*\([^)]*origins\s*=\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*,\s*['"]\*/i),
  rule("code.unsafe-upload", "Potentially unsafe file upload handling", "file-upload", "medium", "medium", /\bmulter\s*\([^)]*dest\s*:\s*['"](?:\.\/)?public|upload\.(?:single|array|fields)\s*\(|MultipartFile\b|UploadFile\b/i),
  rule("code.shell-execution", "Shell execution reachable in application code", "code-execution", "high", "medium", /\b(?:child_process|childProcess|cp)\.(?:exec|execSync)\s*\(|(?<![.\w$])exec(?:Sync)?\s*\(|\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true|os\.(?:system|popen)\s*\(|subprocess\.(?:Popen|run|call|check_call|check_output)\s*\([^)]*shell\s*=\s*True|Runtime\.getRuntime\(\)\.exec/i),
  rule("code.eval-usage", "Dynamic code evaluation", "code-execution", "high", "high", /(?<![.\w$])eval\s*\(|\b(?:window|globalThis|global|self)\.eval\s*\(|new\s+Function\s*\(|vm\.runIn(?:This|New)?Context\s*\(|ScriptEngineManager\b/i),
  rule("code.raw-sql", "Raw SQL string construction", "injection", "high", "medium", new RegExp(
    String.raw`(?:query|execute|raw)\s*\(\s*(?:\x60[^\x60]*${SQL_STATEMENT}[^\x60]*\$\{|(?:"[^"]*${SQL_STATEMENT}[^"]*"|'[^']*${SQL_STATEMENT}[^']*')\s*(?:\+|%|\.format\s*\())|\bf(?:"[^"]*${SQL_STATEMENT}[^"]*\{|'[^']*${SQL_STATEMENT}[^']*\{)`,
    "i"
  )),
  rule("code.missing-authorization", "Privileged route may be missing authorization middleware", "access-control", "medium", "low", (line) =>
    /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['"]\/(?:admin|api\/admin|internal|users\/:id|account)/i.test(line) && !AUTH_MIDDLEWARE.test(line)),
  rule("code.dangerous-logging", "Sensitive values may be written to logs", "logging", "medium", "medium", (line) =>
    callArgumentsOf(line, /\b(?:console|logger|logging|log)\.(?:log|debug|info|warn|warning|error)\s*\(/g)
      .some((args) => SENSITIVE_LOG_VALUE.test(stripStringLiterals(args)))),
  rule("code.next-dangerous-html", "Next.js dangerous HTML rendering", "injection", "medium", "medium", (line) =>
    /dangerouslySetInnerHTML\s*=/i.test(line) && !/\b(?:DOMPurify\.sanitize|sanitizeHtml)\s*\(/.test(line)),
  rule("code.fastapi-debug", "FastAPI debug mode enabled", "configuration", "medium", "high", /\bFastAPI\s*\([^)]*debug\s*=\s*True/i, new Set([".py"])),
  rule("code.spring-csrf-disabled", "Spring Security CSRF disabled", "configuration", "medium", "medium", /\.csrf\s*\([^)]*\)\s*\.disable\s*\(|csrf\s*->\s*csrf\.disable\s*\(\s*\)|\.csrf\s*\(\s*AbstractHttpConfigurer::disable\s*\)|\bcsrf\s*\{\s*disable\s*\(\s*\)/i, new Set([".java", ".kt"])),
  rule("code.ssrf-user-controlled-url", "Possible user-controlled outbound request", "ssrf", "high", "low", (line) =>
    firstArgumentsOf(line, /\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got|https?\.(?:get|request)|requests\.(?:get|post|put|request)|httpx\.(?:get|post)|urlopen|RestTemplate\(\)\.getForObject)\s*\(/g)
      .some(isUserControlledNonRelative)),
  rule("code.path-traversal", "Possible user-controlled file path access", "injection", "high", "low", (line) =>
    firstArgumentsOf(line, /\b(?:readFile(?:Sync)?|createReadStream|sendFile|open|FileInputStream|send_file)\s*\(/g)
      .some(isUserControlledNonRelative))
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
      const ext = fileTypeKey(file);
      const lines = await readFileLines(file);
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        for (const ruleDef of RULES) {
          if (ruleDef.extensions && !ruleDef.extensions.has(ext)) {
            continue;
          }
          if (!matchesRule(ruleDef, line)) {
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
  pattern: CodeRule["pattern"],
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

function matchesRule(ruleDef: CodeRule, line: string): boolean {
  return typeof ruleDef.pattern === "function" ? ruleDef.pattern(line) : ruleDef.pattern.test(line);
}

function isUserControlledNonRelative(argument: string): boolean {
  // A literal starting with "/" is a same-origin path or a fixed local path.
  return !/^\s*[`'"]\//.test(argument) && USER_INPUT.test(argument);
}

function firstArgumentsOf(line: string, callPattern: RegExp): string[] {
  return [...line.matchAll(callPattern)].map((match) => scanArguments(line, match.index + match[0].length, true));
}

function callArgumentsOf(line: string, callPattern: RegExp): string[] {
  return [...line.matchAll(callPattern)].map((match) => scanArguments(line, match.index + match[0].length, false));
}

// Returns the text from `start` up to the closing parenthesis of the call (or the
// first top-level comma when `firstOnly`), skipping over nested brackets and strings.
function scanArguments(line: string, start: number, firstOnly: boolean): string {
  let depth = 0;
  let quote: string | undefined;
  for (let index = start; index < line.length; index += 1) {
    const char = line[index];
    if (quote) {
      if (char === "\\") index += 1;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") quote = char;
    else if ("([{".includes(char)) depth += 1;
    else if (")]}".includes(char)) {
      if (depth === 0) return line.slice(start, index);
      depth -= 1;
    } else if (char === "," && depth === 0 && firstOnly) {
      return line.slice(start, index);
    }
  }
  return line.slice(start);
}

// Removes literal text so that log messages such as "Token refreshed" do not match,
// while keeping interpolated expressions (`${token}`, f"{token}").
function stripStringLiterals(args: string): string {
  return args
    .replace(/\bf(["'])((?:(?!\1).)*)\1/g, (_match, _quote, body: string) => (body.match(/\{[^}]*\}/g) ?? []).join(" "))
    .replace(/`(?:[^`\\]|\\.)*`/g, (match) => (match.match(/\$\{[^}]*\}/g) ?? []).join(" "))
    .replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, '""');
}
