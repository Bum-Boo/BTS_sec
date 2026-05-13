import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { adapterInfoFinding, normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { commandExists, runCommand, summarizeCommandFailure } from "../utils/command";

interface ZapAlert {
  alert?: string;
  riskcode?: string;
  riskdesc?: string;
  desc?: string;
  solution?: string;
  instances?: Array<{ uri?: string; evidence?: string }>;
}

export const zapBaselineAdapter: ScannerAdapter = {
  name: "owasp-zap-baseline",
  async scan(context: ScanContext) {
    if (context.target.kind !== "url") {
      return { findings: [] };
    }
    if (!context.options.includeExternal) {
      return {
        findings: [
          adapterInfoFinding("owasp-zap-baseline", context.target.raw, "External adapters are disabled. Pass --include-external to run OWASP ZAP Baseline.")
        ]
      };
    }
    if (!(await commandExists("zap-baseline.py"))) {
      return {
        findings: [
          adapterInfoFinding("owasp-zap-baseline", context.target.raw, "zap-baseline.py was not found on PATH.")
        ]
      };
    }

    const reportPath = path.join(os.tmpdir(), `bts-sec-zap-${Date.now()}.json`);
    const result = await runCommand("zap-baseline.py", [
      "-t", context.target.url.toString(),
      "-J", reportPath,
      "-m", "1",
      "-I",
      "-z", `-config spider.threadCount=1 -config spider.maxDuration=1 -config spider.delayInMs=${Math.ceil(1000 / Math.max(1, context.options.rateLimitRps))}`
    ], { timeoutMs: context.options.timeoutMs * 4 });

    if (result.exitCode !== 0 && result.exitCode !== 1 && result.exitCode !== 2) {
      throw new Error(summarizeCommandFailure(result));
    }

    const report = JSON.parse(await fs.readFile(reportPath, "utf8")) as { site?: Array<{ alerts?: ZapAlert[] }> };
    await fs.rm(reportPath, { force: true });

    return {
      findings: parseZapFindings(report.site?.flatMap((site) => site.alerts ?? []) ?? [], context.target.raw)
    };
  }
};

function parseZapFindings(alerts: ZapAlert[], target: string): Finding[] {
  return alerts.map((alert) => {
    const firstInstance = alert.instances?.[0];
    return normalizeFinding({
      id: `zap.${slug(alert.alert ?? "alert")}`,
      title: alert.alert ?? "ZAP baseline alert",
      severity: zapSeverity(alert.riskcode, alert.riskdesc),
      confidence: "medium",
      category: "configuration",
      sourceTool: "owasp-zap-baseline",
      target,
      endpoint: firstInstance?.uri,
      evidence: `${alert.desc ?? "ZAP passive baseline alert."}${firstInstance?.evidence ? ` Evidence: ${firstInstance.evidence}` : ""}`,
      recommendation: alert.solution ?? "Review the passive ZAP baseline alert and apply the recommended configuration fix.",
      verification: "Re-run OWASP ZAP Baseline and confirm the alert is no longer reported.",
      rawSource: alert
    });
  });
}

function zapSeverity(riskCode: string | undefined, riskDesc: string | undefined): "info" | "low" | "medium" | "high" | "critical" {
  if (riskDesc?.toLowerCase().includes("high") || riskCode === "3") return "high";
  if (riskDesc?.toLowerCase().includes("medium") || riskCode === "2") return "medium";
  if (riskDesc?.toLowerCase().includes("low") || riskCode === "1") return "low";
  return "info";
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}
