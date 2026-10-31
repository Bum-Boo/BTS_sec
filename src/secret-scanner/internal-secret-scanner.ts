import path from "node:path";
import { normalizeFinding } from "../scanner-core/finding";
import { redactSecrets } from "../scanner-core/redaction";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { fileTypeKey, readFileLines, walkFiles } from "../utils/fs";
import { hasSecretAssignment, hasSecretToken } from "./secret-patterns";

// File types where a bare `KEY=value` is a literal rather than a code expression.
const CONFIG_EXTENSIONS = new Set([
  ".env", ".txt", ".md", ".yaml", ".yml", ".toml", ".ini", ".properties", ".npmrc", ".cfg", ".conf", ".sh"
]);

const TEXT_EXTENSIONS = new Set([
  ...CONFIG_EXTENSIONS,
  ".json", ".pem", ".key", ".tf", ".tfvars", ".xml",
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs"
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
      const allowUnquoted = CONFIG_EXTENSIONS.has(fileTypeKey(file));
      const lines = await readFileLines(file);
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        if (!hasSecretToken(line) && !hasSecretAssignment(line, { allowUnquoted })) {
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
