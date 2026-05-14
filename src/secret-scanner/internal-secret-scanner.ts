import path from "node:path";
import { normalizeFinding } from "../scanner-core/finding";
import { redactSecrets } from "../scanner-core/redaction";
import { Confidence, Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { readFileLines, walkFiles } from "../utils/fs";

interface SecretPattern {
  id: string;
  title: string;
  pattern: RegExp;
  confidence: Confidence;
}

const SECRET_PATTERNS: SecretPattern[] = [
  provider("secret.aws-access-key", "AWS access key detected", /\bAKIA[0-9A-Z]{16}\b/, "high"),
  provider("secret.aws-secret-key", "AWS secret access key-like value detected", /\baws(.{0,20})?(?:secret|access).{0,20}['"]?[A-Za-z0-9/+=]{40}['"]?/i, "medium"),
  provider("secret.gcp-service-account", "GCP service account private key detected", /"type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[a-f0-9]{16,}"/i, "high"),
  provider("secret.azure-connection-string", "Azure connection string detected", /\bDefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}/i, "high"),
  provider("secret.github-token", "GitHub token detected", /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/, "high"),
  provider("secret.gitlab-token", "GitLab token detected", /\bglpat-[A-Za-z0-9_-]{20,}\b/, "high"),
  provider("secret.slack-token", "Slack token detected", /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/, "high"),
  provider("secret.stripe-key", "Stripe secret key detected", /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/, "high"),
  provider("secret.npm-token", "npm token detected", /\bnpm_[A-Za-z0-9]{20,}\b/, "high"),
  provider("secret.pypi-token", "PyPI token detected", /\bpypi-[A-Za-z0-9_-]{20,}\b/, "high"),
  provider("secret.private-key", "Private key block detected", /-----BEGIN [A-Z ]*PRIVATE KEY-----/, "high"),
  provider("secret.database-url", "Database URL with credentials detected", /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s/]+:[^@\s/]+@[^\s'"]+/i, "high"),
  provider("secret.jwt", "JWT-like token detected", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, "medium"),
  provider("secret.oauth-client-secret", "OAuth client secret-like value detected", /\b(?:client[_-]?secret|oauth[_-]?secret)\b\s*[:=]\s*['"]?[^'"\s]{16,}/i, "high"),
  provider("secret.generic-assignment", "Secret-like assignment detected", /\b[A-Z0-9_]*(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret)[A-Z0-9_]*\s*(?:=|:\s*)\s*(?:['"][^'"]{8,}['"]|[A-Za-z0-9+/=_.-]{16,})/i, "medium")
];

const TEXT_EXTENSIONS = new Set([
  ".env", ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".properties",
  ".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".go", ".rb", ".php", ".cs",
  ".xml", ".gradle", ".kts"
]);

const ALLOWLIST = /(?:example|sample|dummy|placeholder|changeme|not-a-secret|redacted|localhost|127\.0\.0\.1|test[_-]?key|public[_-]?key)/i;
const SECRET_CONTEXT = /\b[A-Z0-9_]*(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|connection[_-]?string|dsn)[A-Z0-9_]*\b/i;

export const internalSecretScanner: ScannerAdapter = {
  name: "internal-secret-scanner",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }

    const files = await walkFiles(context.target.path, {
      extensions: TEXT_EXTENSIONS,
      maxBytes: 1024 * 1024
    });
    const findings: Finding[] = [];

    for (const file of files) {
      const lines = await readFileLines(file);
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        if (ALLOWLIST.test(line)) continue;

        for (const pattern of SECRET_PATTERNS) {
          if (pattern.pattern.test(line)) {
            findings.push(secretFinding(context, file, index + 1, line, pattern.id, pattern.title, pattern.confidence));
          }
        }

        const entropyCandidate = highEntropyCandidate(line);
        if (entropyCandidate) {
          findings.push(secretFinding(
            context,
            file,
            index + 1,
            line,
            "secret.generic-high-entropy",
            "High-entropy secret-like value detected",
            entropyCandidate.confidence
          ));
        }
      }
    }

    return { findings };
  }
};

function provider(id: string, title: string, pattern: RegExp, confidence: Confidence): SecretPattern {
  return { id, title, pattern, confidence };
}

function highEntropyCandidate(line: string): { confidence: Confidence } | undefined {
  if (!SECRET_CONTEXT.test(line) || ALLOWLIST.test(line)) return undefined;
  const candidates = secretValueCandidates(line);
  const candidate = candidates.find((value) => entropy(value) >= 4.0 && uniqueRatio(value) >= 0.45);
  if (!candidate) return undefined;
  return { confidence: entropy(candidate) >= 4.5 ? "high" : "medium" };
}

function secretValueCandidates(line: string): string[] {
  const candidates: string[] = [];
  for (const match of line.matchAll(/(?:=|:)\s*['"]([^'"]{20,})['"]/g)) {
    candidates.push(match[1]);
  }
  for (const match of line.matchAll(/(?:=|:)\s*([A-Za-z0-9+/=_-]{20,})(?:\s|$|[,;}])/g)) {
    candidates.push(match[1]);
  }
  return candidates;
}

function secretFinding(
  context: ScanContext,
  file: string,
  lineNumber: number,
  line: string,
  id: string,
  title: string,
  confidence: Confidence
): Finding {
  const relative = context.target.kind === "directory" ? path.relative(context.target.path, file) : file;
  return normalizeFinding({
    id,
    title,
    severity: "high",
    confidence,
    category: "secrets",
    sourceTool: "internal-secret-scanner",
    target: context.target.raw,
    file,
    line: lineNumber,
    evidence: `Secret-like value in ${relative}:${lineNumber}: ${redactSecrets(line.trim())}`,
    recommendation: "Move the secret to a managed secret store, rotate it if it was committed, and keep only non-sensitive placeholders in source control.",
    verification: "Re-run secret scanning and confirm the redacted finding no longer appears.",
    rawSource: { pattern: id }
  });
}

function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let total = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    total -= p * Math.log2(p);
  }
  return total;
}

function uniqueRatio(value: string): number {
  return new Set(value).size / value.length;
}
