import http from "node:http";
import { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { defaultScanOptions, runScan } from "../src";

// Local mock servers only (127.0.0.1); nothing leaves the machine.
const silentLogger = { info() {}, warn() {}, error() {} };
const servers: http.Server[] = [];

async function serve(handler: http.RequestListener): Promise<{ origin: string; requests: string[] }> {
  const requests: string[] = [];
  const server = http.createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    handler(req, res);
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests };
}

async function scanUrl(url: string) {
  const result = await runScan(url, defaultScanOptions({ confirmAuthorization: true, rateLimitRps: 500, timeoutMs: 5000 }), silentLogger);
  return result.findings.filter((finding) => finding.category !== "adapter");
}

const SPA_HTML = '<!doctype html><html lang="en"><head><meta charset="UTF-8" /><title>Fixture</title></head><body><div id="root"></div></body></html>';

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve))));
});

describe("URL scanner against local fixture servers", () => {
  it("reports the planted issues on a vulnerable server", async () => {
    const { origin } = await serve((req, res) => {
      if (req.method === "OPTIONS") {
        res.writeHead(204, { "access-control-allow-origin": String(req.headers.origin), "access-control-allow-credentials": "true" });
        return res.end();
      }
      res.setHeader("set-cookie", ["session=fixture; Path=/secure-area; SameSite=Lax", "theme=httponly-dark; Path=/"]);
      switch (req.url) {
        case "/.env":
          return res.end("APP_SECRET=fixture-value\n");
        case "/.git/HEAD":
          return res.end("ref: refs/heads/main\n");
        case "/backup.zip":
          return res.end(Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]));
        case "/backup.tar.gz":
          return res.end(Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00]));
        default:
          res.writeHead(404);
          return res.end("not found");
      }
    });

    const findings = await scanUrl(`${origin}/`);
    const summary = findings.map((finding) => `${finding.id} ${finding.endpoint?.replace(origin, "")} ${finding.title}`).sort();

    expect(summary).toEqual([
      "web.accidental-exposure /.env .env file may be exposed",
      "web.accidental-exposure /.git/HEAD .git metadata may be exposed",
      "web.accidental-exposure /backup.tar.gz Backup archive may be exposed",
      "web.accidental-exposure /backup.zip Backup archive may be exposed",
      "web.insecure-cookie / Cookie session is missing recommended security flags",
      "web.insecure-cookie / Cookie theme is missing recommended security flags",
      "web.missing-security-header.content-security-policy / Content-Security-Policy header is missing",
      "web.missing-security-header.permissions-policy / Permissions-Policy header is missing",
      "web.missing-security-header.referrer-policy / Referrer-Policy header is missing",
      "web.missing-security-header.x-content-type-options / X-Content-Type-Options header is missing or not nosniff",
      "web.unsafe-cors / CORS allows credentials for a broad origin"
    ]);
    expect(findings.find((finding) => finding.title.includes("Cookie session"))?.evidence).toBe("Cookie session is missing Secure, HttpOnly.");
  });

  it("reports nothing on a hardened single-page app that returns index.html for every path", async () => {
    const { origin, requests } = await serve((req, res) => {
      res.setHeader("content-security-policy", "default-src 'self'");
      res.setHeader("x-content-type-options", "nosniff");
      res.setHeader("referrer-policy", "no-referrer");
      res.setHeader("permissions-policy", "camera=()");
      res.setHeader("set-cookie", "session=fixture; Path=/; Secure; HttpOnly; SameSite=Lax");
      res.setHeader("content-type", "text/html");
      res.end(req.method === "HEAD" ? undefined : SPA_HTML);
    });

    expect(await scanUrl(`${origin}/`)).toEqual([]);
    expect(requests.every((request) => /^(GET|HEAD|OPTIONS) /.test(request))).toBe(true);
  });

  it("does not follow redirects to another origin", async () => {
    const other = await serve((_req, res) => res.end("other origin"));
    const { origin } = await serve((_req, res) => {
      res.writeHead(302, { location: `${other.origin}/collect` });
      res.end();
    });

    await scanUrl(`${origin}/`);
    expect(other.requests).toEqual([]);
  });
});
