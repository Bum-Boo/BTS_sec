import { normalizeFinding } from "../scanner-core/finding";
import { Finding, HttpResponseSnapshot, ScannerAdapter, ScanContext } from "../scanner-core/types";

interface CrawledPage {
  url: string;
  path: string;
  depth: number;
  response: HttpResponseSnapshot;
}

const DEBUG_LEAKAGE = /(?:stack trace|traceback|exception|at\s+[A-Za-z0-9_.]+\s*\(|debug\s*mode|SQL syntax|Warning:\s|Fatal error|NullPointerException|ReferenceError|TypeError)/i;
const FORM = /<form\b[\s\S]*?<\/form>/gi;
const POST_METHOD = /\bmethod\s*=\s*['"]?post['"]?/i;
const CSRF_SIGNAL = /\b(?:csrf|xsrf|authenticity_token|_token|requestverificationtoken)\b/i;
const MIXED_CONTENT = /\b(?:src|href|action)\s*=\s*['"]http:\/\//i;
const REDIRECT_HINT = /\b(?:redirect|returnUrl|return_to|next|continue|callback|url)=https?:\/\//i;
const GRAPHQL_HINT = /(?:\/graphql\b|graphql-playground|apollo-server|graphiql)/i;

export const passiveCrawler: ScannerAdapter = {
  name: "same-origin-passive-crawler",
  async scan(context: ScanContext) {
    if (context.target.kind !== "url" || !context.httpClient) {
      return { findings: [] };
    }

    const findings: Finding[] = [];
    const pages: CrawledPage[] = [];
    const seen = new Set<string>();
    const queue: Array<{ path: string; depth: number }> = [{ path: context.target.url.pathname || "/", depth: 0 }];
    const maxDepth = Math.max(0, context.options.maxCrawlDepth);
    const maxPages = Math.max(1, context.options.maxCrawlPages);

    while (queue.length > 0 && pages.length < maxPages) {
      const next = queue.shift() as { path: string; depth: number };
      const normalizedPath = normalizePath(next.path);
      if (seen.has(normalizedPath) || next.depth > maxDepth) continue;
      seen.add(normalizedPath);

      const response = await context.httpClient.request(normalizedPath, {
        method: "GET",
        bodySnippetLimit: 16 * 1024
      });
      const page: CrawledPage = { url: response.url, path: normalizedPath, depth: next.depth, response };
      pages.push(page);
      findings.push(...analyzePage(context, page));

      if (next.depth < maxDepth) {
        for (const link of extractSameOriginLinks(response.bodySnippet ?? "", context.target.url)) {
          if (!seen.has(link)) {
            queue.push({ path: link, depth: next.depth + 1 });
          }
        }
      }
    }

    findings.push(...await informationalWellKnownChecks(context));
    findings.push(...await graphqlPassiveChecks(context, pages));
    return {
      findings,
      metadata: {
        crawler: {
          pagesVisited: pages.length,
          maxCrawlDepth: maxDepth,
          maxCrawlPages: maxPages,
          methods: ["GET", "HEAD", "OPTIONS"],
          scope: "same-origin"
        }
      }
    };
  }
};

function analyzePage(context: ScanContext, page: CrawledPage): Finding[] {
  const body = page.response.bodySnippet ?? "";
  const findings: Finding[] = [];
  const htmlLike = isLikelyHtmlPage(page);

  if (htmlLike && DEBUG_LEAKAGE.test(body)) {
    findings.push(webFinding(context, "web.passive.debug-error-leakage", "Reflected error or debug leakage hint", "medium", "medium", page, "Page content matched a debug, stack trace, or framework error marker. Response body was not stored."));
  }

  const server = header(page.response, "server");
  const poweredBy = header(page.response, "x-powered-by");
  const generator = htmlLike ? body.match(/<meta[^>]+name\s*=\s*['"]generator['"][^>]+content\s*=\s*['"]([^'"]+)['"]/i)?.[1] : undefined;
  if (server || poweredBy || generator) {
    findings.push(webFinding(context, "web.passive.version-banner-disclosure", "Version or banner disclosure hint", "low", "high", page, `Headers or HTML disclose server/framework metadata: ${[
      server ? "server header" : undefined,
      poweredBy ? "x-powered-by header" : undefined,
      generator ? "generator meta tag" : undefined
    ].filter(Boolean).join(", ")}.`));
  }

  const forms = body.match(FORM) ?? [];
  if (htmlLike && forms.some((form) => POST_METHOD.test(form) && !CSRF_SIGNAL.test(form))) {
    findings.push(webFinding(context, "web.passive.form-missing-csrf-signal", "State-changing form lacks anti-CSRF signal", "medium", "medium", page, "A POST form did not include a visible CSRF token naming pattern. No form was submitted."));
  }

  if (htmlLike && context.target.kind === "url" && context.target.url.protocol === "https:" && MIXED_CONTENT.test(body)) {
    findings.push(webFinding(context, "web.passive.mixed-content-hint", "Mixed content hint in HTML", "low", "medium", page, "HTTPS page contains http:// asset, link, or form action references."));
  }

  const location = header(page.response, "location");
  if (location && isExternalUrl(location, context.target.kind === "url" ? context.target.url : undefined)) {
    findings.push(webFinding(context, "web.passive.unsafe-redirect-hint", "Cross-origin redirect hint", "medium", "medium", page, "A same-origin request returned a redirect Location outside the target origin."));
  }
  if (htmlLike && REDIRECT_HINT.test(body)) {
    findings.push(webFinding(context, "web.passive.unsafe-redirect-hint", "Unsafe redirect parameter hint", "low", "low", page, "Page content contains redirect-style parameters with absolute URLs."));
  }

  return findings;
}

function isLikelyHtmlPage(page: CrawledPage): boolean {
  const contentType = header(page.response, "content-type");
  if (contentType) {
    return /\btext\/html\b|application\/xhtml\+xml/i.test(contentType);
  }
  if (/\.(?:js|mjs|css|map|json|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf)(?:$|[?#])/i.test(page.url)) {
    return false;
  }
  const body = page.response.bodySnippet?.trimStart() ?? "";
  return body.length === 0 || body.startsWith("<") || /<html|<!doctype html/i.test(body);
}

async function informationalWellKnownChecks(context: ScanContext): Promise<Finding[]> {
  if (context.target.kind !== "url" || !context.httpClient) return [];
  const findings: Finding[] = [];
  for (const item of [
    { path: "/robots.txt", id: "web.info.robots-txt", title: "robots.txt is present" },
    { path: "/.well-known/security.txt", id: "web.info.security-txt", title: "security.txt is present" }
  ]) {
    const response = await context.httpClient.request(item.path, { method: "GET", bodySnippetLimit: 512 });
    if (response.status >= 200 && response.status < 300) {
      findings.push(normalizeFinding({
        id: item.id,
        title: item.title,
        severity: "info",
        confidence: "high",
        category: "exposure",
        sourceTool: "same-origin-passive-crawler",
        target: context.target.raw,
        endpoint: response.url,
        evidence: `${item.path} returned HTTP ${response.status}. This is informational only and was not treated as a vulnerability.`,
        recommendation: "Review the file for accidental disclosure of sensitive paths or stale contacts.",
        verification: "Confirm the file contents are intentional and do not expose private routes or credentials."
      }));
    }
  }
  return findings;
}

async function graphqlPassiveChecks(context: ScanContext, pages: CrawledPage[]): Promise<Finding[]> {
  if (context.target.kind !== "url" || !context.httpClient) return [];
  const findings: Finding[] = [];
  const staticHint = pages.some((page) => GRAPHQL_HINT.test(page.response.bodySnippet ?? ""));
  for (const candidate of ["/graphql", "/api/graphql"]) {
    const response = await context.httpClient.request(candidate, { method: "HEAD", bodySnippetLimit: 0 });
    if (response.status < 404) {
      findings.push(normalizeFinding({
        id: "web.passive.graphql-exposure-hint",
        title: "GraphQL endpoint exposure hint",
        severity: "info",
        confidence: "medium",
        category: "exposure",
        sourceTool: "same-origin-passive-crawler",
        target: context.target.raw,
        endpoint: response.url,
        evidence: `HEAD ${candidate} returned HTTP ${response.status}. Introspection POST was not attempted.`,
        recommendation: "Confirm GraphQL endpoints require intended authentication and disable public playgrounds/introspection where inappropriate.",
        verification: "Review GraphQL server configuration and add authorization tests for representative queries."
      }));
    }
  }
  if (staticHint) {
    findings.push(normalizeFinding({
      id: "web.passive.graphql-static-hint",
      title: "GraphQL static hint found in page content",
      severity: "info",
      confidence: "medium",
      category: "exposure",
      sourceTool: "same-origin-passive-crawler",
      target: context.target.raw,
      endpoint: context.target.url.toString(),
      evidence: "Crawled HTML referenced GraphQL-related paths or tooling. Introspection POST was not attempted.",
      recommendation: "Confirm GraphQL endpoints and developer tooling are intentionally exposed.",
      verification: "Review route configuration and verify public callers cannot access unintended GraphQL operations."
    }));
  }
  return findings;
}

function extractSameOriginLinks(body: string, base: URL): string[] {
  const links = new Set<string>();
  for (const match of body.matchAll(/\b(?:href|src|action)\s*=\s*['"]([^'"]+)['"]/gi)) {
    try {
      const url = new URL(match[1], base);
      if (url.origin !== base.origin || !["http:", "https:"].includes(url.protocol)) continue;
      links.add(normalizePath(`${url.pathname}${url.search}`));
    } catch {
      continue;
    }
  }
  return [...links];
}

function normalizePath(value: string): string {
  if (!value) return "/";
  try {
    const url = new URL(value, "https://bts-sec.local");
    return `${url.pathname}${url.search}`;
  } catch {
    return value.startsWith("/") ? value : `/${value}`;
  }
}

function webFinding(
  context: ScanContext,
  id: string,
  title: string,
  severity: "low" | "medium" | "high",
  confidence: "low" | "medium" | "high",
  page: CrawledPage,
  evidence: string
): Finding {
  return normalizeFinding({
    id,
    title,
    severity,
    confidence,
    category: id.includes("csrf") ? "csrf" : id.includes("redirect") ? "configuration" : "exposure",
    sourceTool: "same-origin-passive-crawler",
    target: context.target.raw,
    endpoint: page.url,
    evidence,
    recommendation: recommendationFor(id),
    verification: verificationFor(id)
  });
}

function header(response: HttpResponseSnapshot, name: string): string | undefined {
  const value = response.headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join(",") : value;
}

function isExternalUrl(value: string, base: URL | undefined): boolean {
  if (!base) return false;
  try {
    return new URL(value, base).origin !== base.origin;
  } catch {
    return false;
  }
}

function recommendationFor(id: string): string {
  if (id.includes("debug-error")) return "Disable detailed error pages in production and return generic client-facing error messages.";
  if (id.includes("version-banner")) return "Reduce unnecessary version banners and framework disclosure headers.";
  if (id.includes("csrf")) return "Add anti-CSRF tokens or a non-cookie auth pattern for state-changing browser flows.";
  if (id.includes("mixed-content")) return "Use HTTPS URLs for all page assets, links, and form actions.";
  return "Validate redirect destinations against a same-origin or explicit allowlist.";
}

function verificationFor(id: string): string {
  if (id.includes("debug-error")) return "Trigger a handled error in a safe local environment and confirm no stack trace or debug page is returned.";
  if (id.includes("version-banner")) return "Repeat a GET/HEAD request and confirm unnecessary version headers or generator tags are absent.";
  if (id.includes("csrf")) return "Inspect forms and handlers and confirm state-changing requests require CSRF protection.";
  if (id.includes("mixed-content")) return "Reload the HTTPS page and confirm all referenced resources use HTTPS.";
  return "Add tests for allowed and rejected redirect destinations.";
}
