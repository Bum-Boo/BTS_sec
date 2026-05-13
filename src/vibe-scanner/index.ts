import { ScannerAdapter } from "../scanner-core/types";
import { aiArtifactScanner } from "./ai-artifact-scanner";
import { authFlowScanner } from "./auth-flow-scanner";
import { dependencyRiskScanner } from "./dependency-risk-scanner";
import { localVibeConfigScanner } from "./local-vibe-config-scanner";
import { preAgentChecklistScanner } from "./pre-agent-checklist";
import { vibeUrlScanner } from "./url-vibe-scanner";

export function vibeRiskLocalAdapters(): ScannerAdapter[] {
  return [
    localVibeConfigScanner,
    aiArtifactScanner,
    dependencyRiskScanner,
    authFlowScanner,
    preAgentChecklistScanner
  ];
}

export function vibeRiskUrlAdapters(): ScannerAdapter[] {
  return [
    vibeUrlScanner
  ];
}

export { aiArtifactScanner } from "./ai-artifact-scanner";
export { authFlowScanner } from "./auth-flow-scanner";
export { analyzeDependencyRisks, dependencyRiskScanner, findPopularPackageLookalike } from "./dependency-risk-scanner";
export { buildPreAgentChecklist, preAgentChecklistScanner } from "./pre-agent-checklist";
export { vibeUrlScanner } from "./url-vibe-scanner";
