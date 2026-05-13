import { ScanResult } from "../scanner-core/types";
import { renderAgentFixPrompt } from "./agent-prompt";
import { sanitizeFindingsForReport, redactDeep } from "./sanitize";

export function renderJsonReport(result: ScanResult): string {
  return JSON.stringify({
    ...result,
    findings: sanitizeFindingsForReport(result.findings),
    metadata: redactDeep(result.metadata),
    agentFixPrompt: renderAgentFixPrompt(result)
  }, null, 2);
}
