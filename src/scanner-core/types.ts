export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type TargetKind = "url" | "directory" | "combined";
export type ReportFormat = "markdown" | "html" | "json" | "sarif";
export type ScanProfile = "baseline" | "vibe-risk";
export type FindingTargetType = "url" | "local" | "config" | "dependency" | "agent-artifact" | "api";
export type DependencyRelation = "direct" | "transitive" | "unknown";
export type AffectedDataType =
  | "pii"
  | "medical"
  | "financial"
  | "credential"
  | "customer-conversation"
  | "internal-business"
  | "unknown";

export interface SecurityMapping {
  id: string;
  name: string;
  url?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  vibeRiskCategory?: string;
  sourceTool?: string;
  targetType: FindingTargetType;
  target: string;
  file?: string;
  line?: number;
  endpoint?: string;
  evidence: string;
  redactedEvidence: string;
  affectedDataType?: AffectedDataType;
  platformHint?: string;
  authBoundaryRisk?: boolean;
  agentConfigRisk?: boolean;
  hallucinatedDependencyRisk?: boolean;
  businessLogicRisk?: boolean;
  owaspTop10_2025?: string[];
  owaspLLMTop10_2025?: string[];
  owaspAPITop10_2023?: string[];
  cweTop25_2025?: string[];
  cisaKevPriority?: boolean;
  remediationPromptForCodex?: string;
  owaspMapping: SecurityMapping[];
  cweMapping: SecurityMapping[];
  cve?: string;
  cvssScore?: number;
  cvssVector?: string;
  epssScore?: number;
  epssPercentile?: number;
  fixAvailable?: boolean;
  dependencyName?: string;
  dependencyVersion?: string;
  dependencyRelation?: DependencyRelation;
  priorityScore: number;
  kevKnownExploited: boolean;
  recommendation: string;
  verification: string;
  rawSource?: unknown;
}

export type FindingInput = Omit<
  Finding,
  | "redactedEvidence"
  | "owaspMapping"
  | "cweMapping"
  | "kevKnownExploited"
  | "priorityScore"
  | "targetType"
> & {
  redactedEvidence?: string;
  owaspMapping?: SecurityMapping[];
  cweMapping?: SecurityMapping[];
  kevKnownExploited?: boolean;
  priorityScore?: number;
  targetType?: FindingTargetType;
};

export interface UrlTarget {
  kind: "url";
  raw: string;
  url: URL;
  scopeOrigins: string[];
  authorizationConfirmed: boolean;
}

export interface DirectoryTarget {
  kind: "directory";
  raw: string;
  path: string;
}

export interface ApiSpecTarget {
  kind: "api-spec";
  raw: string;
  path: string;
}

export interface CombinedTarget {
  kind: "combined";
  raw: string;
  url?: UrlTarget;
  directory?: DirectoryTarget;
  apiSpec?: ApiSpecTarget;
}

export type ScanTarget = UrlTarget | DirectoryTarget | ApiSpecTarget | CombinedTarget;

export interface ScanOptions {
  profile: ScanProfile;
  outputDir: string;
  formats: ReportFormat[];
  rateLimitRps: number;
  timeoutMs: number;
  includeExternal: boolean;
  confirmAuthorization: boolean;
  noDestructive: true;
  nucleiTemplates: string[];
  kevCatalogPath?: string;
  refreshKev: boolean;
  epssCsvPath?: string;
  refreshEpss: boolean;
  apiSpecPath?: string;
  maxCrawlDepth: number;
  maxCrawlPages: number;
}

export interface Logger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

export interface HttpResponseSnapshot {
  url: string;
  status: number;
  headers: Record<string, string | string[] | undefined>;
  bodySnippet?: string;
}

export interface SafeHttpClient {
  request(pathOrUrl: string, init?: SafeRequestInit): Promise<HttpResponseSnapshot>;
}

export interface SafeRequestInit {
  method?: "GET" | "HEAD" | "OPTIONS";
  headers?: Record<string, string>;
  bodySnippetLimit?: number;
}

export interface ScanContext {
  target: ScanTarget;
  options: ScanOptions;
  logger: Logger;
  httpClient?: SafeHttpClient;
}

export interface AdapterResult {
  findings: Finding[];
  metadata?: Record<string, unknown>;
}

export interface ScannerAdapter {
  name: string;
  scan(context: ScanContext): Promise<AdapterResult>;
}

export interface ScanResult {
  target: ScanTarget;
  findings: Finding[];
  summary: SeveritySummary;
  startedAt: string;
  finishedAt: string;
  metadata: Record<string, unknown>;
}

export type SeveritySummary = Record<Severity, number>;
