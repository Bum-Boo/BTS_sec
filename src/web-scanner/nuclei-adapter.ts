import { adapterInfoFinding, normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { commandExists, runCommand, summarizeCommandFailure } from "../utils/command";
import { assertAllowedNucleiTemplates } from "./nuclei-allowlist";

interface NucleiJsonLine {
  "template-id"?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    remediation?: string;
  };
  matched?: string;
  host?: string;
  "matcher-name"?: string;
  "curl-command"?: string;
}

export const nucleiAdapter: ScannerAdapter = {
  name: "nuclei-safe-allowlist",
  async scan(context: ScanContext) {
    if (context.target.kind !== "url") {
      return { findings: [] };
    }
    if (!context.options.includeExternal) {
      return {
        findings: [
          adapterInfoFinding("nuclei", context.target.raw, "External adapters are disabled. Pass --include-external to run Nuclei safe templates.")
        ]
      };
    }

    assertAllowedNucleiTemplates(context.options.nucleiTemplates);
    if (context.options.nucleiTemplates.length === 0) {
      return {
        findings: [
          adapterInfoFinding("nuclei", context.target.raw, "No allowlisted Nuclei templates were supplied.")
        ]
      };
    }
    if (!(await commandExists("nuclei"))) {
      return {
        findings: [
          adapterInfoFinding("nuclei", context.target.raw, "nuclei executable was not found on PATH.")
        ]
      };
    }

    const args = [
      "-u", context.target.url.toString(),
      "-jsonl",
      "-rl", String(Math.max(1, context.options.rateLimitRps)),
      "-c", "1",
      "-retries", "0",
      "-no-interactsh",
      "-disable-update-check"
    ];
    for (const template of context.options.nucleiTemplates) {
      args.push("-t", template);
    }

    const result = await runCommand("nuclei", args, { timeoutMs: context.options.timeoutMs });
    if (result.exitCode !== 0 && !result.stdout) {
      throw new Error(summarizeCommandFailure(result));
    }

    return {
      findings: parseNucleiJsonl(result.stdout, context.target.raw)
    };
  }
};

function parseNucleiJsonl(output: string, target: string): Finding[] {
  return output
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line) as NucleiJsonLine)
    .map((item) => normalizeFinding({
      id: `nuclei.${item["template-id"] ?? "finding"}`,
      title: item.info?.name ?? item["template-id"] ?? "Nuclei finding",
      severity: normalizeSeverity(item.info?.severity),
      confidence: "medium",
      category: inferCategory(item["template-id"] ?? ""),
      sourceTool: "nuclei",
      target,
      endpoint: item.matched ?? item.host,
      evidence: `${item.info?.description ?? "Nuclei template matched."}${item["matcher-name"] ? ` Matcher: ${item["matcher-name"]}.` : ""}`,
      recommendation: item.info?.remediation ?? "Review the matched safe-template result and apply the recommended configuration fix.",
      verification: "Re-run the same allowlisted Nuclei template and confirm it no longer matches.",
      rawSource: item
    }));
}

function normalizeSeverity(value: string | undefined): "info" | "low" | "medium" | "high" | "critical" {
  if (value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info") {
    return value;
  }
  return "info";
}

function inferCategory(templateId: string): string {
  if (/cors/i.test(templateId)) return "cors";
  if (/exposure|env|git|backup|listing/i.test(templateId)) return "exposure";
  return "configuration";
}
