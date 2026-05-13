import { adapterInfoFinding, normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { commandExists, runCommand, summarizeCommandFailure } from "../utils/command";

interface TruffleHogFinding {
  SourceMetadata?: {
    Data?: {
      Filesystem?: {
        file?: string;
        line?: number;
      };
    };
  };
  DetectorName?: string;
  Redacted?: string;
  Verified?: boolean;
}

export const truffleHogAdapter: ScannerAdapter = {
  name: "trufflehog",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }
    if (!context.options.includeExternal) {
      return {
        findings: [
          adapterInfoFinding("trufflehog", context.target.raw, "External adapters are disabled. Pass --include-external to run TruffleHog.")
        ]
      };
    }
    if (!(await commandExists("trufflehog"))) {
      return {
        findings: [
          adapterInfoFinding("trufflehog", context.target.raw, "trufflehog executable was not found on PATH.")
        ]
      };
    }

    const result = await runCommand("trufflehog", [
      "filesystem",
      context.target.path,
      "--json",
      "--no-update",
      "--no-verification"
    ], { timeoutMs: context.options.timeoutMs * 4 });

    if (result.exitCode !== 0 && !result.stdout) {
      throw new Error(summarizeCommandFailure(result));
    }

    return {
      findings: parseTruffleHogJsonl(result.stdout, context.target.raw)
    };
  }
};

function parseTruffleHogJsonl(output: string, target: string): Finding[] {
  return output
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line) as TruffleHogFinding)
    .map((item) => {
      const fsMeta = item.SourceMetadata?.Data?.Filesystem;
      return normalizeFinding({
        id: `trufflehog.${item.DetectorName ?? "secret"}`,
        title: `${item.DetectorName ?? "Secret"} detected by TruffleHog`,
        severity: "high",
        confidence: item.Verified ? "high" : "medium",
        category: "secrets",
        sourceTool: "trufflehog",
        target,
        file: fsMeta?.file,
        line: fsMeta?.line,
        evidence: item.Redacted ?? "TruffleHog reported a redacted secret. Live credential validation is disabled by default.",
        recommendation: "Rotate any exposed credential and move it to a managed secret store.",
        verification: "Re-run TruffleHog with --no-verification and confirm the finding is gone.",
        rawSource: {
          DetectorName: item.DetectorName,
          Verified: item.Verified,
          SourceMetadata: item.SourceMetadata
        }
      });
    });
}
