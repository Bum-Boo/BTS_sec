import path from "node:path";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { readFileLines, walkFiles } from "../utils/fs";

const TEXT_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".env", ".yml", ".yaml", ".toml", ".sql", ".rules"]);

const PLATFORM_HINTS: Array<{ platform: string; pattern: RegExp }> = [
  { platform: "Lovable", pattern: /lovable(?:\.dev)?|data-lovable/i },
  { platform: "Replit", pattern: /replit|\.replit|replit\.app/i },
  { platform: "Base44", pattern: /base44/i },
  { platform: "Netlify", pattern: /netlify\.toml|netlify/i },
  { platform: "Vercel", pattern: /vercel\.json|VERCEL_|_next/i },
  { platform: "Bolt", pattern: /bolt\.new|stackblitz/i },
  { platform: "v0", pattern: /v0\.dev|v0-generated/i },
  { platform: "Cursor", pattern: /cursor-generated|\.cursor\/rules|\.cursorrules/i }
];

const PUBLIC_PROVIDER_CONFIGS: Array<{ provider: string; pattern: RegExp; affected?: "credential" | "internal-business" }> = [
  { provider: "Supabase", pattern: /\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_)?SUPABASE_(?:URL|ANON_KEY)\b/i, affected: "credential" },
  { provider: "Firebase", pattern: /\b(?:apiKey|authDomain|projectId|storageBucket)\b/i, affected: "credential" },
  { provider: "Clerk", pattern: /\b(?:NEXT_PUBLIC_)?CLERK_PUBLISHABLE_KEY\b/i, affected: "credential" },
  { provider: "Stripe", pattern: /\b(?:NEXT_PUBLIC_)?STRIPE_PUBLISHABLE_KEY\b/i, affected: "credential" },
  { provider: "OpenAI", pattern: /\bOPENAI_API_KEY\b/i, affected: "credential" },
  { provider: "Resend", pattern: /\bRESEND_API_KEY\b/i, affected: "credential" }
];

const SENSITIVE_DATA_TERMS: Array<{ type: "pii" | "medical" | "financial" | "customer-conversation" | "internal-business"; pattern: RegExp }> = [
  { type: "pii", pattern: /\b(?:ssn|social security|email|phone|address|dateOfBirth|dob)\b/i },
  { type: "medical", pattern: /\b(?:patient|diagnosis|medical|hipaa|prescription|lab result)\b/i },
  { type: "financial", pattern: /\b(?:cardNumber|bankAccount|invoice|paymentIntent|stripeCustomer|taxId)\b/i },
  { type: "customer-conversation", pattern: /\b(?:conversation|chat transcript|support ticket|message history)\b/i },
  { type: "internal-business", pattern: /\b(?:internal note|admin note|crm|customer list|sales pipeline)\b/i }
];

export const localVibeConfigScanner: ScannerAdapter = {
  name: "vibe-local-config-scanner",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }

    const root = context.target.path;
    const target = context.target.raw;
    const files = await walkFiles(root, { extensions: TEXT_EXTENSIONS, maxBytes: 768 * 1024 });
    const findings: Finding[] = [];
    for (const file of files) {
      const lines = await readFileLines(file);
      lines.forEach((line, index) => {
        findings.push(...scanLine(root, target, file, index + 1, line));
      });
    }
    return { findings };
  }
};

function scanLine(root: string, target: string, file: string, lineNumber: number, line: string): Finding[] {
  const rel = path.relative(root, file);
  const findings: Finding[] = [];

  for (const provider of PUBLIC_PROVIDER_CONFIGS) {
    if (provider.pattern.test(line)) {
      const publicPrefix = /\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_)/i.test(line);
      findings.push(normalizeFinding({
        id: publicPrefix ? "vibe.config.public-provider-key" : "vibe.config.provider-secret-reference",
        title: publicPrefix ? `Public ${provider.provider} configuration is exposed to client code` : `${provider.provider} secret reference found`,
        severity: publicPrefix ? "medium" : "low",
        confidence: "medium",
        category: publicPrefix ? "exposure" : "secrets",
        vibeRiskCategory: "public-provider-configuration",
        targetType: "config",
        sourceTool: "vibe-local-config-scanner",
        target,
        file,
        line: lineNumber,
        evidence: `${rel}:${lineNumber} references ${provider.provider} configuration. Values are redacted and not stored.`,
        affectedDataType: provider.affected,
        recommendation: publicPrefix
          ? "Confirm the public key is intentionally client-safe and backed by server-side authorization, RLS, or provider-side restrictions."
          : "Keep provider secrets server-side only and ensure they are not bundled into client code.",
        verification: "Inspect the built client bundle and provider access rules to confirm no privileged secret or broad access is exposed."
      }));
    }
  }

  for (const hint of PLATFORM_HINTS) {
    if (hint.pattern.test(line) || rel.toLowerCase().includes(hint.platform.toLowerCase())) {
      findings.push(normalizeFinding({
        id: "vibe.config.platform-hint",
        title: `${hint.platform} project or deployment hint detected`,
        severity: "info",
        confidence: "low",
        category: "configuration",
        vibeRiskCategory: "platform-hint",
        targetType: "config",
        sourceTool: "vibe-local-config-scanner",
        target,
        file,
        line: lineNumber,
        evidence: `${rel}:${lineNumber} contains a ${hint.platform} platform hint.`,
        platformHint: hint.platform,
        recommendation: "Review platform defaults for public deployments, preview URLs, environment variable exposure, and access controls.",
        verification: "Confirm the deployment platform does not expose internal pages, debug output, or public-by-default data stores."
      }));
    }
  }

  for (const sensitive of SENSITIVE_DATA_TERMS) {
    if (sensitive.pattern.test(line)) {
      findings.push(normalizeFinding({
        id: "vibe.config.sensitive-data-indicator",
        title: "Sensitive data type appears in application code or configuration",
        severity: "low",
        confidence: "low",
        category: "exposure",
        vibeRiskCategory: "sensitive-data-indicator",
        targetType: "config",
        sourceTool: "vibe-local-config-scanner",
        target,
        file,
        line: lineNumber,
        evidence: `${rel}:${lineNumber} references ${sensitive.type} data handling. Raw sensitive data is not stored.`,
        affectedDataType: sensitive.type,
        recommendation: "Review authorization, retention, logging, and field filtering around this data type.",
        verification: "Confirm sensitive data is only accessible after server-side authorization and is excluded from logs and public responses."
      }));
    }
  }

  if (/\b(?:debug\s*[:=]\s*true|NODE_ENV\s*=\s*development|traceback|stack trace|console\.trace)\b/i.test(line)) {
    findings.push(normalizeFinding({
      id: "vibe.config.debug-mode-indicator",
      title: "Debug or stack trace indicator found",
      severity: "medium",
      confidence: "medium",
      category: "configuration",
      vibeRiskCategory: "debug-exposure",
      targetType: "config",
      sourceTool: "vibe-local-config-scanner",
      target,
      file,
      line: lineNumber,
      evidence: `${rel}:${lineNumber} references debug or stack trace behavior.`,
      recommendation: "Disable debug output in production and ensure exception handlers return generic errors.",
      verification: "Run the app in production mode and confirm stack traces and debug pages are not exposed."
    }));
  }

  return findings;
}
