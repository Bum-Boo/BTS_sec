import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { adapterInfoFinding, normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { commandExists, runCommand, summarizeCommandFailure } from "../utils/command";

interface GitleaksFinding {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Secret?: string;
  Match?: string;
}

export const gitleaksAdapter: ScannerAdapter = {
  name: "gitleaks",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }
    if (!context.options.includeExternal) {
      return {
        findings: [
          adapterInfoFinding("gitleaks", context.target.raw, "External adapters are disabled. Pass --include-external to run Gitleaks.")
        ]
      };
    }
    if (!(await commandExists("gitleaks"))) {
      return {
        findings: [
          adapterInfoFinding("gitleaks", context.target.raw, "gitleaks executable was not found on PATH.")
        ]
      };
    }

    const reportPath = path.join(os.tmpdir(), `bts-sec-gitleaks-${Date.now()}.json`);
    const result = await runCommand("gitleaks", [
      "detect",
      "--source", context.target.path,
      "--no-git",
      "--redact",
      "--report-format", "json",
      "--report-path", reportPath
    ], { timeoutMs: context.options.timeoutMs * 4 });

    if (result.exitCode !== 0 && result.exitCode !== 1) {
      throw new Error(summarizeCommandFailure(result));
    }

    const raw = await fs.readFile(reportPath, "utf8").catch(() => "[]");
    await fs.rm(reportPath, { force: true });
    const parsed = JSON.parse(raw || "[]") as GitleaksFinding[];
    return { findings: parsed.map((item) => toFinding(item, context.target.raw)) };
  }
};

function toFinding(item: GitleaksFinding, target: string): Finding {
  return normalizeFinding({
    id: `gitleaks.${item.RuleID ?? "secret"}`,
    title: item.Description ?? "Gitleaks secret finding",
    severity: "high",
    confidence: "high",
    category: "secrets",
    sourceTool: "gitleaks",
    target,
    file: item.File,
    line: item.StartLine,
    evidence: item.Match ?? item.Secret ?? "Gitleaks reported a redacted secret.",
    recommendation: "Rotate any exposed credential and move it to a managed secret store.",
    verification: "Re-run Gitleaks and confirm the finding is gone.",
    rawSource: {
      RuleID: item.RuleID,
      Description: item.Description,
      File: item.File,
      StartLine: item.StartLine
    }
  });
}
