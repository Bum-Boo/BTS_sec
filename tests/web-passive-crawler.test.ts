import { describe, expect, it } from "vitest";
import { defaultScanOptions } from "../src/scanner-core/options";
import { HttpResponseSnapshot, SafeHttpClient, SafeRequestInit, ScanContext } from "../src/scanner-core/types";
import { passiveCrawler } from "../src/web-scanner/passive-crawler";

describe("same-origin passive crawler", () => {
  it("uses only safe methods and reports passive web hints", async () => {
    const requests: Array<{ path: string; method: string }> = [];
    const client: SafeHttpClient = {
      async request(pathOrUrl: string, init: SafeRequestInit = {}): Promise<HttpResponseSnapshot> {
        requests.push({ path: pathOrUrl, method: init.method ?? "GET" });
        if (pathOrUrl === "/") {
          return snapshot("https://example.com/", 200, {
            server: "ExampleServer/1.2",
            "x-powered-by": "Express"
          }, `
            <a href="/next">next</a>
            <a href="https://other.example/">offsite</a>
            <form method="post" action="/change"><input name="email"></form>
            <script src="http://cdn.example.test/app.js"></script>
            <a href="/login?next=https://evil.example/">login</a>
            <a href="/graphql">GraphQL</a>
            Traceback (most recent call last)
          `);
        }
        if (pathOrUrl === "/next") {
          return snapshot("https://example.com/next", 302, { location: "https://other.example/redirect" }, "");
        }
        if (pathOrUrl === "/robots.txt" || pathOrUrl === "/.well-known/security.txt") {
          return snapshot(`https://example.com${pathOrUrl}`, 200, {}, "ok");
        }
        if (pathOrUrl === "/graphql") {
          return snapshot("https://example.com/graphql", 200, {}, "");
        }
        return snapshot(`https://example.com${pathOrUrl}`, 404, {}, "");
      }
    };

    const result = await passiveCrawler.scan(contextFor(client));
    const ids = result.findings.map((finding) => finding.id);

    expect(new Set(requests.map((request) => request.method))).toEqual(new Set(["GET", "HEAD"]));
    expect(requests.some((request) => request.path === "https://other.example/")).toBe(false);
    expect(ids).toEqual(expect.arrayContaining([
      "web.passive.debug-error-leakage",
      "web.passive.version-banner-disclosure",
      "web.passive.form-missing-csrf-signal",
      "web.passive.mixed-content-hint",
      "web.passive.unsafe-redirect-hint",
      "web.info.robots-txt",
      "web.info.security-txt",
      "web.passive.graphql-exposure-hint",
      "web.passive.graphql-static-hint"
    ]));
  });

  it("does not treat framework static chunks as reflected debug pages", async () => {
    const client: SafeHttpClient = {
      async request(pathOrUrl: string, init: SafeRequestInit = {}): Promise<HttpResponseSnapshot> {
        if (pathOrUrl === "/") {
          return snapshot("https://example.com/", 200, { "content-type": "text/html" }, `
            <script src="/_next/static/chunks/app.js"></script>
          `);
        }
        if (pathOrUrl === "/_next/static/chunks/app.js") {
          return snapshot("https://example.com/_next/static/chunks/app.js", 200, { "content-type": "application/javascript" }, "class TypeError extends Error {}");
        }
        return snapshot(`https://example.com${pathOrUrl}`, 404, {}, "");
      }
    };

    const result = await passiveCrawler.scan(contextFor(client));

    expect(result.findings.some((finding) => finding.id === "web.passive.debug-error-leakage")).toBe(false);
  });
});

function contextFor(httpClient: SafeHttpClient): ScanContext {
  const url = new URL("https://example.com/");
  return {
    target: {
      kind: "url",
      raw: "https://example.com/",
      url,
      scopeOrigins: [url.origin],
      authorizationConfirmed: true
    },
    options: defaultScanOptions({ maxCrawlDepth: 1, maxCrawlPages: 3 }),
    logger: { info() {}, warn() {}, error() {} },
    httpClient
  };
}

function snapshot(
  url: string,
  status: number,
  headers: Record<string, string>,
  bodySnippet: string
): HttpResponseSnapshot {
  return { url, status, headers, bodySnippet };
}
