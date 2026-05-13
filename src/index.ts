export { runScan, runScanTargets } from "./scanner-core/orchestrator";
export { defaultScanOptions } from "./scanner-core/options";
export { validateTarget, assertUrlInScope } from "./scanner-core/target";
export { normalizeFinding } from "./scanner-core/finding";
export { RateLimiter } from "./scanner-core/rate-limiter";
export { redactSecrets } from "./scanner-core/redaction";
export { renderAgentFixPrompt, writeReports } from "./report-generator";
export { analyzeDependencyRisks, buildPreAgentChecklist, findPopularPackageLookalike } from "./vibe-scanner";
export type {
  AffectedDataType,
  Confidence,
  Finding,
  FindingTargetType,
  FindingInput,
  ScanProfile,
  ScanOptions,
  ScanResult,
  ScanTarget,
  ScannerAdapter,
  Severity
} from "./scanner-core/types";
