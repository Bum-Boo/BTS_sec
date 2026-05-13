import path from "node:path";
import { adapterInfoFinding, normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { commandExists, runCommand, summarizeCommandFailure } from "../utils/command";
import { pathExists } from "../utils/fs";

interface SemgrepResult {
  check_id: string;
  path: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: {
      cwe?: string[] | string;
      owasp?: string[] | string;
    };
    lines?: string;
  };
}

interface SemgrepJson {
  results?: SemgrepResult[];
}

export const semgrepAdapter: ScannerAdapter = {
  name: "semgrep",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }
    if (!context.options.includeExternal) {
      return {
        findings: [
          adapterInfoFinding("semgrep", context.target.raw, "External adapters are disabled. Pass --include-external to run Semgrep.")
        ]
      };
    }
    if (!(await commandExists("semgrep"))) {
      return {
        findings: [
          adapterInfoFinding("semgrep", context.target.raw, "semgrep executable was not found on PATH.")
        ]
      };
    }

    const config = await resolveSemgrepConfig(context.target.path);
    if (!config) {
      return {
        findings: [
          adapterInfoFinding("semgrep", context.target.raw, "No local .semgrep.yml, semgrep.yml, or semgrep.yaml config was found.")
        ]
      };
    }

    const result = await runCommand("semgrep", [
      "--config", config,
      "--json",
      "--quiet",
      "--disable-version-check",
      context.target.path
    ], { timeoutMs: context.options.timeoutMs * 4 });

    if (result.exitCode !== 0 && !result.stdout) {
      throw new Error(summarizeCommandFailure(result));
    }

    const parsed = JSON.parse(result.stdout) as SemgrepJson;
    const root = context.target.path;
    const rawTarget = context.target.raw;
    return {
      findings: (parsed.results ?? []).map((item) => toFinding(item, rawTarget, root))
    };
  }
};

async function resolveSemgrepConfig(projectPath: string): Promise<string | undefined> {
  for (const name of [".semgrep.yml", "semgrep.yml", "semgrep.yaml"]) {
    const candidate = path.join(projectPath, name);
    if (await pathExists(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

function toFinding(item: SemgrepResult, target: string, root: string): Finding {
  return normalizeFinding({
    id: `semgrep.${item.check_id}`,
    title: item.extra?.message ?? item.check_id,
    severity: semgrepSeverity(item.extra?.severity),
    confidence: "medium",
    category: inferCategory(item.check_id),
    sourceTool: "semgrep",
    target,
    file: path.resolve(root, item.path),
    line: item.start?.line,
    evidence: item.extra?.lines ?? item.extra?.message ?? item.check_id,
    recommendation: "Review the Semgrep finding and apply the referenced secure coding remediation.",
    verification: "Re-run Semgrep with the same local config and confirm the finding is resolved.",
    rawSource: item
  });
}

function semgrepSeverity(value: string | undefined): "info" | "low" | "medium" | "high" | "critical" {
  switch (value?.toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    case "INFO":
      return "low";
    default:
      return "info";
  }
}

function inferCategory(checkId: string): string {
  if (/secret|credential|token/i.test(checkId)) return "secrets";
  if (/sql|injection|xss|eval|command/i.test(checkId)) return "injection";
  if (/auth|access/i.test(checkId)) return "access-control";
  if (/cors/i.test(checkId)) return "cors";
  return "configuration";
}
