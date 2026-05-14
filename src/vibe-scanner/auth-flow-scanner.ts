import path from "node:path";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { readFileLines, walkFiles } from "../utils/fs";

const APP_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".java", ".kt", ".sql", ".rules"]);

export const authFlowScanner: ScannerAdapter = {
  name: "vibe-auth-payment-db-flow-scanner",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }

    const files = await walkFiles(context.target.path, { extensions: APP_EXTENSIONS, maxBytes: 1024 * 1024 });
    const findings: Finding[] = [];
    for (const file of files) {
      const lines = await readFileLines(file);
      const content = lines.join("\n");
      findings.push(...scanFile(context.target.path, file, lines, content, context.target.raw));
    }
    return { findings };
  }
};

function scanFile(root: string, file: string, lines: string[], content: string, target: string): Finding[] {
  const rel = path.relative(root, file).replace(/\\/g, "/");
  const findings: Finding[] = [];
  const authPresent = hasServerSideAuthCheck(content);
  const rolePresent = /\b(role|isAdmin|admin|permission|authorize|policy|canAccess|hasPermission)\b/i.test(content);

  const methods = apiMethods(content);
  if (isApiRoute(rel, content) && !authPresent && methods.length > 0 && shouldFlagMissingApiSession(rel, content, methods)) {
    findings.push(businessFinding({
      id: "vibe.auth.api-route-missing-session",
      title: "API route may lack a server-side session check",
      severity: "high",
      confidence: "medium",
      file,
      target,
      evidence: `${rel} appears to define an API handler without an obvious server-side session or auth check.`,
      recommendation: "Add server-side session validation before reading or mutating user-specific data.",
      verification: "Add a negative test proving unauthenticated requests are rejected."
    }));
  }

  if (/["']use server["']/.test(content) && !authPresent) {
    findings.push(businessFinding({
      id: "vibe.auth.server-action-missing-session",
      title: "Server action may lack user or session validation",
      severity: "high",
      confidence: "medium",
      file,
      target,
      evidence: `${rel} contains a server action marker without an obvious server-side auth/session check.`,
      recommendation: "Validate the user/session inside the server action before accessing data or performing mutations.",
      verification: "Add a test or review step confirming unauthenticated server action calls fail closed."
    }));
  }

  if (/\/(?:admin|dashboard|internal|support|customer)/i.test(rel + "\n" + content) && !rolePresent) {
    findings.push(businessFinding({
      id: "vibe.auth.admin-route-missing-role-check",
      title: "Privileged route may lack a role or authorization check",
      severity: "high",
      confidence: "low",
      file,
      target,
      evidence: `${rel} references a privileged route or page without an obvious role/permission check.`,
      recommendation: "Add explicit role or ownership checks for privileged dashboard, admin, support, customer, and internal routes.",
      verification: "Add tests for low-privilege users and confirm they cannot access privileged routes."
    }));
  }

  lines.forEach((line, index) => {
    if (/\b(?:userId|accountId|ownerId|organizationId|orgId)\b/i.test(line) && /\b(?:findMany|findFirst|findUnique|select|from|where|query)\b/i.test(line) && !/\b(?:userId|accountId|ownerId|organizationId|orgId)\b\s*[:=]/i.test(line)) {
      findings.push(businessFinding({
        id: "vibe.auth.query-missing-owner-filter",
        title: "Database query may be missing owner or tenant filter",
        severity: "high",
        confidence: "low",
        file,
        line: index + 1,
        target,
        evidence: `${rel}:${index + 1} references owner/account identifiers near a query but no obvious ownership filter was found.`,
        recommendation: "Ensure queries for user, account, owner, organization, or tenant-scoped data include a server-validated ownership filter.",
        verification: "Add tests proving users cannot read or modify records owned by another user or tenant."
      }));
    }

    if (/\bparams\.(?:id|userId|accountId|ownerId)|req\.params\.(?:id|userId|accountId|ownerId)|PathVariable\b/i.test(line) && !/owner|authorize|permission|session|user\.id|auth/i.test(content)) {
      findings.push(businessFinding({
        id: "vibe.auth.object-id-without-ownership-check",
        title: "Object ID route parameter may be used without ownership validation",
        severity: "high",
        confidence: "low",
        file,
        line: index + 1,
        target,
        evidence: `${rel}:${index + 1} uses an object identifier from route parameters without an obvious ownership check in the file.`,
        recommendation: "Validate that the authenticated user is authorized to access the object identified by route parameters.",
        verification: "Add IDOR regression tests for objects owned by another user."
      }));
    }
  });

  if (/stripe/i.test(rel + content) && /webhook/i.test(rel + content) && !/constructEvent|stripe-signature|Stripe-Signature|webhooks\.constructEvent/i.test(content)) {
    findings.push(businessFinding({
      id: "vibe.payment.stripe-webhook-missing-signature",
      title: "Stripe webhook handler may lack signature verification",
      severity: "critical",
      confidence: "medium",
      file,
      target,
      evidence: `${rel} appears to handle Stripe webhooks without an obvious signature verification call.`,
      recommendation: "Verify Stripe webhook signatures with the raw request body before trusting event data.",
      verification: "Add tests proving unsigned or incorrectly signed webhook requests are rejected."
    }));
  }

  if (/success|checkout|payment/i.test(rel + content) && /window\.location|searchParams|query|client/i.test(content) && !/webhook|constructEvent|server/i.test(content)) {
    findings.push(businessFinding({
      id: "vibe.payment.client-only-success",
      title: "Payment success may be handled only on the client",
      severity: "high",
      confidence: "low",
      file,
      target,
      evidence: `${rel} appears to rely on client-side payment success state without obvious server-side webhook confirmation.`,
      recommendation: "Use server-side webhook confirmation as the source of truth for payment or subscription state.",
      verification: "Confirm payment state changes only after verified provider webhook processing."
    }));
  }

  if (/supabase/i.test(content) && /createClient/i.test(content) && /(NEXT_PUBLIC|VITE_|PUBLIC_)/.test(content) && /from\(/.test(content)) {
    findings.push(businessFinding({
      id: "vibe.database.client-direct-access",
      title: "Client code may access database directly",
      severity: "medium",
      confidence: "medium",
      file,
      target,
      evidence: `${rel} initializes Supabase with public configuration and performs direct table access.`,
      recommendation: "Ensure Supabase RLS is enabled and move privileged data access behind server-side authorization checks.",
      verification: "Confirm RLS policies deny cross-user reads/writes and add tests for unauthorized access."
    }));
  }

  if (/alter\s+table[\s\S]{0,120}disable\s+row\s+level\s+security/i.test(content) || /using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(content)) {
    findings.push(businessFinding({
      id: "vibe.database.supabase-rls-broad-policy",
      title: "Supabase RLS policy may be disabled or overly broad",
      severity: "critical",
      confidence: "high",
      file,
      target,
      evidence: `${rel} contains SQL that disables RLS or uses an always-true policy condition.`,
      recommendation: "Enable RLS and replace broad policies with user or tenant-scoped predicates.",
      verification: "Run policy tests proving anonymous or cross-user reads/writes are denied."
    }));
  }

  if (/service\s+cloud\.firestore|firebase/i.test(content) && /allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true/i.test(content)) {
    findings.push(businessFinding({
      id: "vibe.database.firebase-open-rules",
      title: "Firebase rules allow open read or write",
      severity: "critical",
      confidence: "high",
      file,
      target,
      evidence: `${rel} contains Firebase rules that allow read/write if true.`,
      recommendation: "Require request.auth and resource ownership checks in Firebase rules.",
      verification: "Use Firebase rules tests to confirm unauthenticated and cross-user access is denied."
    }));
  }

  if (isApiRoute(rel, content) && /return\s+(?:Response\.json|json\(|res\.json)\s*\([^)]*(?:password|token|secret|ssn|email|phone|medical|diagnosis|payment|card)/i.test(content)) {
    findings.push(businessFinding({
      id: "vibe.auth.sensitive-api-response-unfiltered",
      title: "API handler may return sensitive fields without filtering",
      severity: "high",
      confidence: "low",
      file,
      target,
      evidence: `${rel} appears to return sensitive field names from an API handler. Raw data is not collected.`,
      affectedDataType: inferAffectedDataType(content),
      recommendation: "Use explicit response DTOs or field allowlists and avoid returning credentials, PII, medical, financial, or internal fields.",
      verification: "Add response-shape tests that assert sensitive fields are omitted."
    }));
  }

  return findings;
}

function businessFinding(input: {
  id: string;
  title: string;
  severity: "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  file: string;
  line?: number;
  target: string;
  evidence: string;
  recommendation: string;
  verification: string;
  affectedDataType?: "pii" | "medical" | "financial" | "credential" | "customer-conversation" | "internal-business" | "unknown";
}): Finding {
  return normalizeFinding({
    ...input,
    category: "business-logic",
    vibeRiskCategory: "auth-payment-database-flow",
    targetType: "local",
    sourceTool: "vibe-auth-payment-db-flow-scanner",
    authBoundaryRisk: true,
    businessLogicRisk: true
  });
}

function isApiRoute(rel: string, content: string): boolean {
  return /(?:^|\/)(?:app\/api\/.*route|pages\/api\/|api\/)/.test(rel)
    || /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(/.test(content)
    || /@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)/.test(content)
    || /@app\.(get|post|put|patch|delete)\s*\(/.test(content);
}

function apiMethods(content: string): string[] {
  const methods = new Set<string>();
  for (const match of content.matchAll(/\bexport\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b/g)) {
    methods.add(match[1]);
  }
  for (const match of content.matchAll(/\b(?:app|router)\.(get|post|put|patch|delete)\s*\(/gi)) {
    methods.add(match[1].toUpperCase());
  }
  for (const match of content.matchAll(/@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)/g)) {
    const method = match[1].replace("Mapping", "").toUpperCase();
    methods.add(method === "REQUEST" ? "UNKNOWN" : method);
  }
  for (const match of content.matchAll(/@app\.(get|post|put|patch|delete)\s*\(/gi)) {
    methods.add(match[1].toUpperCase());
  }
  return [...methods];
}

function shouldFlagMissingApiSession(rel: string, content: string, methods: string[]): boolean {
  if (methods.some((method) => method !== "GET")) {
    return true;
  }
  if (isPrivilegedOrSensitiveApi(rel, content)) {
    return true;
  }
  return !isPublicCacheableGet(content);
}

function isPrivilegedOrSensitiveApi(rel: string, content: string): boolean {
  return /\/(?:admin|dashboard|internal|support|customer|customers|account|users|settings|billing|payment|stripe)\b/i.test(rel)
    || /\b(?:password|token|secret|ssn|medical|diagnosis|payment|card|invoice|stripe|userId|accountId|ownerId|organizationId|orgId|findMany|findUnique|select\s*\(|from\s*\()\b/i.test(content);
}

function isPublicCacheableGet(content: string): boolean {
  return /\bexport\s+const\s+revalidate\s*=|Cache-Control["']?\s*:\s*["'][^"']*\b(?:public|max-age|s-maxage|stale-while-revalidate)\b/i.test(content);
}

function hasServerSideAuthCheck(content: string): boolean {
  return /\b(auth|currentUser|getServerSession|getSession|getToken|requireAuth|verifySession|verifyIdToken|clerkClient|supabase\.auth\.getUser|request\.user|Depends\([^)]*auth|SecurityContextHolder|Principal)\b/i.test(content);
}

function inferAffectedDataType(content: string): "pii" | "medical" | "financial" | "credential" | "customer-conversation" | "internal-business" | "unknown" {
  if (/password|token|secret|apiKey/i.test(content)) return "credential";
  if (/medical|diagnosis|patient|hipaa/i.test(content)) return "medical";
  if (/payment|card|bank|invoice|stripe/i.test(content)) return "financial";
  if (/message|conversation|chat|transcript/i.test(content)) return "customer-conversation";
  if (/email|phone|ssn|address|name/i.test(content)) return "pii";
  return "unknown";
}
