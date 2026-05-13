import path from "node:path";
import { normalizeFinding } from "../scanner-core/finding";
import { redactSecrets } from "../scanner-core/redaction";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { readFileLines, walkFiles } from "../utils/fs";

const SECRET_PATTERNS = [
  /\b(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"]?[^'"\s]{8,}/i,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/
];

const TEXT_EXTENSIONS = new Set([
  ".env", ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".properties",
  ".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".go", ".rb", ".php", ".cs"
]);

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
        if (!SECRET_PATTERNS.some((pattern) => pattern.test(line))) {
          continue;
        }
        findings.push(normalizeFinding({
          id: "secret.detected",
          title: "Secret-like value detected",
          severity: "high",
          confidence: "medium",
          category: "secrets",
          sourceTool: "internal-secret-scanner",
          target: context.target.raw,
          file,
          line: index + 1,
          evidence: `Secret-like value in ${path.relative(context.target.path, file)}:${index + 1}: ${redactSecrets(line.trim())}`,
          recommendation: "Move the secret to a managed secret store, rotate it if it was committed, and keep only non-sensitive placeholders in source control.",
          verification: "Re-run secret scanning and confirm the redacted finding no longer appears."
        }));
      }
    }

    return { findings };
  }
};
