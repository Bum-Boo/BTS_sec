import path from "node:path";
import { adapterInfoFinding, normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { commandExists, runCommand } from "../utils/command";
import { pathExists } from "../utils/fs";

interface PipAuditJson {
  dependencies?: Array<{
    name?: string;
    version?: string;
    vulns?: Array<{
      id?: string;
      aliases?: string[];
      description?: string;
      fix_versions?: string[];
    }>;
  }>;
}

export const pipAuditAdapter: ScannerAdapter = {
  name: "pip-audit",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }
    if (!context.options.includeExternal) {
      return { findings: [adapterInfoFinding("pip-audit", context.target.raw, "External adapters are disabled. Pass --include-external to run pip-audit.")] };
    }
    if (!(await commandExists("pip-audit"))) {
      return { findings: [adapterInfoFinding("pip-audit", context.target.raw, "pip-audit executable was not found on PATH.")] };
    }

    const requirementsPath = path.join(context.target.path, "requirements.txt");
    if (!(await pathExists(requirementsPath))) {
      return { findings: [adapterInfoFinding("pip-audit", context.target.raw, "requirements.txt was not found; pip-audit was skipped.")] };
    }

    const result = await runCommand("pip-audit", [
      "-r", requirementsPath,
      "-f", "json",
      "-l"
    ], { cwd: context.target.path, timeoutMs: context.options.timeoutMs * 4 });

    const parsed = JSON.parse(result.stdout || "{}") as PipAuditJson;
    const findings: Finding[] = [];
    for (const dependency of parsed.dependencies ?? []) {
      for (const vulnerability of dependency.vulns ?? []) {
        findings.push(normalizeFinding({
          id: `pip-audit.${vulnerability.id ?? dependency.name ?? "vulnerability"}`,
          title: `${dependency.name ?? "Python dependency"} vulnerability`,
          severity: "medium",
          confidence: "high",
          category: "dependency",
          sourceTool: "pip-audit",
          target: context.target.raw,
          file: requirementsPath,
          cve: vulnerability.aliases?.find((alias) => alias.startsWith("CVE-")) ?? (vulnerability.id?.startsWith("CVE-") ? vulnerability.id : undefined),
          evidence: `${dependency.name ?? "package"} ${dependency.version ?? ""}: ${vulnerability.description ?? vulnerability.id ?? ""}`.trim(),
          recommendation: vulnerability.fix_versions?.length
            ? `Upgrade ${dependency.name} to one of: ${vulnerability.fix_versions.join(", ")}.`
            : "Upgrade the affected Python dependency or apply the advisory workaround.",
          verification: "Re-run pip-audit and confirm the vulnerability is no longer reported.",
          rawSource: {
            id: vulnerability.id,
            aliases: vulnerability.aliases,
            dependency: dependency.name
          }
        }));
      }
    }

    return { findings };
  }
};
