export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type TargetKind = "url" | "directory";
export type ReportFormat = "markdown" | "html" | "json" | "sarif";

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
  sourceTool: string;
  target: string;
  file?: string;
  line?: number;
  endpoint?: string;
  evidence: string;
  redactedEvidence: string;
  owaspMapping: SecurityMapping[];
  cweMapping: SecurityMapping[];
  cve?: string;
  kevKnownExploited: boolean;
  recommendation: string;
  verification: string;
  rawSource?: unknown;
}

export type FindingInput = Omit<
  Finding,
  "redactedEvidence" | "owaspMapping" | "cweMapping" | "kevKnownExploited"
> & {
  redactedEvidence?: string;
  owaspMapping?: SecurityMapping[];
  cweMapping?: SecurityMapping[];
  kevKnownExploited?: boolean;
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

export type ScanTarget = UrlTarget | DirectoryTarget;

export interface ScanOptions {
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
