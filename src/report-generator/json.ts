import { ScanResult } from "../scanner-core/types";
import { sanitizeFindingsForReport, redactDeep } from "./sanitize";

export function renderJsonReport(result: ScanResult): string {
  return JSON.stringify({
    ...result,
    findings: sanitizeFindingsForReport(result.findings),
    metadata: redactDeep(result.metadata)
  }, null, 2);
}
