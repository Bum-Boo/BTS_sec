import { adapterInfoFinding, normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { commandExists, runCommand, summarizeCommandFailure } from "../utils/command";

interface OsvJson {
  results?: Array<{
    source?: { path?: string };
    packages?: Array<{
      package?: { name?: string; version?: string; ecosystem?: string };
      vulnerabilities?: Array<{
        id?: string;
        aliases?: string[];
        summary?: string;
        details?: string;
      }>;
    }>;
  }>;
}

export const osvScannerAdapter: ScannerAdapter = {
  name: "osv-scanner",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }
    if (!context.options.includeExternal) {
      return { findings: [adapterInfoFinding("osv-scanner", context.target.raw, "External adapters are disabled. Pass --include-external to run OSV-Scanner.")] };
    }
    if (!(await commandExists("osv-scanner"))) {
      return { findings: [adapterInfoFinding("osv-scanner", context.target.raw, "osv-scanner executable was not found on PATH.")] };
    }

    const result = await runCommand("osv-scanner", [
      "--format", "json",
      "--recursive",
      context.target.path
    ], { timeoutMs: context.options.timeoutMs * 4 });

    if (result.exitCode !== 0 && !result.stdout) {
      throw new Error(summarizeCommandFailure(result));
    }
    const parsed = JSON.parse(result.stdout || "{}") as OsvJson;
    const findings: Finding[] = [];
    for (const resultItem of parsed.results ?? []) {
      for (const packageItem of resultItem.packages ?? []) {
        for (const vulnerability of packageItem.vulnerabilities ?? []) {
          findings.push(normalizeFinding({
            id: `osv.${vulnerability.id ?? "vulnerability"}`,
            title: vulnerability.summary ?? `${packageItem.package?.name ?? "Dependency"} vulnerability`,
            severity: "medium",
            confidence: "high",
            category: "dependency",
            sourceTool: "osv-scanner",
            target: context.target.raw,
            file: resultItem.source?.path,
            cve: vulnerability.aliases?.find((alias) => alias.startsWith("CVE-")),
            dependencyName: packageItem.package?.name,
            dependencyVersion: packageItem.package?.version,
            evidence: `${packageItem.package?.ecosystem ?? "package"}:${packageItem.package?.name ?? "unknown"}@${packageItem.package?.version ?? "unknown"} ${vulnerability.details ?? vulnerability.id ?? ""}`,
            recommendation: "Upgrade the affected package to a non-vulnerable version or apply the advisory workaround.",
            verification: "Re-run OSV-Scanner and confirm the vulnerability is no longer reported.",
            rawSource: {
              id: vulnerability.id,
              aliases: vulnerability.aliases,
              package: packageItem.package
            }
          }));
        }
      }
    }
    return { findings };
  }
};
