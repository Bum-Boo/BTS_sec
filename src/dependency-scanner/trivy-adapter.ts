import { adapterInfoFinding, normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { commandExists, runCommand, summarizeCommandFailure } from "../utils/command";

interface TrivyJson {
  Results?: Array<{
    Target?: string;
    Vulnerabilities?: TrivyVulnerability[];
  }>;
}

interface TrivyVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Title?: string;
  Severity?: string;
  Description?: string;
  PrimaryURL?: string;
}

export const trivyAdapter: ScannerAdapter = {
  name: "trivy",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }
    if (!context.options.includeExternal) {
      return { findings: [adapterInfoFinding("trivy", context.target.raw, "External adapters are disabled. Pass --include-external to run Trivy.")] };
    }
    if (!(await commandExists("trivy"))) {
      return { findings: [adapterInfoFinding("trivy", context.target.raw, "trivy executable was not found on PATH.")] };
    }

    const result = await runCommand("trivy", [
      "fs",
      "--format", "json",
      "--quiet",
      "--scanners", "vuln",
      context.target.path
    ], { timeoutMs: context.options.timeoutMs * 6 });

    if (result.exitCode !== 0 && !result.stdout) {
      throw new Error(summarizeCommandFailure(result));
    }

    const parsed = JSON.parse(result.stdout || "{}") as TrivyJson;
    return {
      findings: (parsed.Results ?? []).flatMap((entry) =>
        (entry.Vulnerabilities ?? []).map((vulnerability) => toFinding(vulnerability, entry.Target, context.target.raw))
      )
    };
  }
};

function toFinding(vuln: TrivyVulnerability, file: string | undefined, target: string): Finding {
  return normalizeFinding({
    id: `trivy.${vuln.VulnerabilityID ?? vuln.PkgName ?? "vulnerability"}`,
    title: vuln.Title ?? `${vuln.PkgName ?? "Dependency"} vulnerability`,
    severity: normalizeSeverity(vuln.Severity),
    confidence: "high",
    category: "dependency",
    sourceTool: "trivy",
    target,
    file,
    cve: vuln.VulnerabilityID?.startsWith("CVE-") ? vuln.VulnerabilityID : undefined,
    dependencyName: vuln.PkgName,
    dependencyVersion: vuln.InstalledVersion,
    fixAvailable: Boolean(vuln.FixedVersion),
    evidence: `${vuln.PkgName ?? "package"} ${vuln.InstalledVersion ?? ""}${vuln.FixedVersion ? ` fixed in ${vuln.FixedVersion}` : ""}. ${vuln.Description ?? ""}`.trim(),
    recommendation: vuln.FixedVersion ? `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion} or later.` : "Review the vulnerable dependency and apply the vendor remediation.",
    verification: "Re-run Trivy and confirm the vulnerability is no longer reported.",
    rawSource: {
      VulnerabilityID: vuln.VulnerabilityID,
      PkgName: vuln.PkgName,
      InstalledVersion: vuln.InstalledVersion,
      FixedVersion: vuln.FixedVersion,
      PrimaryURL: vuln.PrimaryURL
    }
  });
}

function normalizeSeverity(value: string | undefined): "info" | "low" | "medium" | "high" | "critical" {
  const lower = value?.toLowerCase();
  if (lower === "critical" || lower === "high" || lower === "medium" || lower === "low") return lower;
  return "info";
}
