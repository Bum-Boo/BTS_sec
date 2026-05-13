import path from "node:path";
import { adapterInfoFinding, normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { commandExists, runCommand } from "../utils/command";
import { pathExists } from "../utils/fs";

interface NpmAuditJson {
  vulnerabilities?: Record<string, NpmVulnerability>;
}

interface NpmVulnerability {
  name?: string;
  severity?: string;
  via?: Array<string | { source?: number; name?: string; title?: string; url?: string; severity?: string; range?: string }>;
  range?: string;
  fixAvailable?: boolean | { name?: string; version?: string; isSemVerMajor?: boolean };
}

export const npmAuditAdapter: ScannerAdapter = {
  name: "npm-audit",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }
    if (!context.options.includeExternal) {
      return { findings: [adapterInfoFinding("npm-audit", context.target.raw, "External adapters are disabled. Pass --include-external to run npm audit.")] };
    }
    if (!(await commandExists("npm"))) {
      return { findings: [adapterInfoFinding("npm-audit", context.target.raw, "npm executable was not found on PATH.")] };
    }
    if (!(await pathExists(path.join(context.target.path, "package-lock.json")))) {
      return { findings: [adapterInfoFinding("npm-audit", context.target.raw, "package-lock.json was not found; npm audit was skipped.")] };
    }

    const result = await runCommand("npm", ["audit", "--json", "--audit-level=low"], {
      cwd: context.target.path,
      timeoutMs: context.options.timeoutMs * 4
    });
    const parsed = JSON.parse(result.stdout || "{}") as NpmAuditJson;
    return {
      findings: Object.entries(parsed.vulnerabilities ?? {}).flatMap(([name, vulnerability]) =>
        toFindings(name, vulnerability, context.target.raw)
      )
    };
  }
};

function toFindings(name: string, vulnerability: NpmVulnerability, target: string): Finding[] {
  const advisories = (vulnerability.via ?? []).filter((item): item is Exclude<typeof item, string> => typeof item !== "string");
  if (advisories.length === 0) {
    advisories.push({ name, title: `${name} vulnerability`, severity: vulnerability.severity });
  }
  return advisories.map((advisory) => normalizeFinding({
    id: `npm-audit.${advisory.source ?? advisory.name ?? name}`,
    title: advisory.title ?? `${name} vulnerability`,
    severity: normalizeSeverity(advisory.severity ?? vulnerability.severity),
    confidence: "high",
    category: "dependency",
    sourceTool: "npm-audit",
    target,
    file: "package-lock.json",
    evidence: `${name} ${vulnerability.range ?? advisory.range ?? ""}${advisory.url ? ` ${advisory.url}` : ""}`.trim(),
    recommendation: npmFixRecommendation(name, vulnerability.fixAvailable),
    verification: "Re-run npm audit and confirm the advisory is no longer reported.",
    rawSource: {
      package: name,
      source: advisory.source,
      url: advisory.url
    }
  }));
}

function npmFixRecommendation(name: string, fixAvailable: NpmVulnerability["fixAvailable"]): string {
  if (typeof fixAvailable === "object" && fixAvailable.version) {
    return `Upgrade ${fixAvailable.name ?? name} to ${fixAvailable.version}.`;
  }
  if (fixAvailable === true) {
    return `Run npm audit fix for ${name} after reviewing the dependency change.`;
  }
  return `Review ${name} and upgrade or replace the vulnerable dependency.`;
}

function normalizeSeverity(value: string | undefined): "info" | "low" | "medium" | "high" | "critical" {
  const lower = value?.toLowerCase();
  if (lower === "critical" || lower === "high" || lower === "medium" || lower === "low") return lower;
  return "info";
}
