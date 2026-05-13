import { remediationFor } from "../knowledge-base/remediation";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";

interface ExposureProbe {
  path: string;
  title: string;
  marker: RegExp;
}

const PROBES: ExposureProbe[] = [
  { path: "/.env", title: ".env file may be exposed", marker: /\b[A-Z0-9_]{2,}\s*=\s*.{3,}/ },
  { path: "/.env.local", title: ".env.local file may be exposed", marker: /\b[A-Z0-9_]{2,}\s*=\s*.{3,}/ },
  { path: "/.git/HEAD", title: ".git metadata may be exposed", marker: /^ref:\s+refs\/heads\//m },
  { path: "/.git/config", title: ".git config may be exposed", marker: /\[core\]|\[remote / },
  { path: "/backup.zip", title: "Backup archive may be exposed", marker: /PK\x03\x04|html|zip/i },
  { path: "/backup.tar.gz", title: "Backup archive may be exposed", marker: /\x1f\x8b|html|gzip/i },
  { path: "/db.sql", title: "Database dump may be exposed", marker: /CREATE TABLE|INSERT INTO|-- MySQL/i },
  { path: "/debug", title: "Debug page may be exposed", marker: /debug|stack trace|environment|traceback/i },
  { path: "/debug/vars", title: "Debug vars endpoint may be exposed", marker: /cmdline|memstats|goroutine|debug/i },
  { path: "/phpinfo.php", title: "phpinfo page may be exposed", marker: /phpinfo\(\)|PHP Version/i },
  { path: "/server-status", title: "Server status page may be exposed", marker: /Apache Server Status|Server uptime/i },
  { path: "/actuator/env", title: "Spring actuator env endpoint may be exposed", marker: /propertySources|activeProfiles|systemEnvironment/i },
  { path: "/actuator/heapdump", title: "Spring actuator heapdump endpoint may be exposed", marker: /JAVA PROFILE|heapdump|application\/octet-stream/i },
  { path: "/", title: "Directory listing may be enabled", marker: /<title>Index of|Index of \//i }
];

export const accidentalExposureChecker: ScannerAdapter = {
  name: "custom-accidental-exposure-checker",
  async scan(context: ScanContext) {
    if (context.target.kind !== "url" || !context.httpClient) {
      return { findings: [] };
    }

    const findings: Finding[] = [];
    const remediation = remediationFor(
      "web.accidental-exposure",
      "Remove exposed files or debug endpoints and deny access to dotfiles, backups, and diagnostics.",
      "Request the path again and confirm it is not accessible."
    );

    for (const probe of PROBES) {
      const response = await context.httpClient.request(probe.path, {
        method: "GET",
        bodySnippetLimit: 768
      });

      if (response.status >= 200 && response.status < 300 && probe.marker.test(response.bodySnippet ?? "")) {
        findings.push(normalizeFinding({
          id: "web.accidental-exposure",
          title: probe.title,
          severity: exposureSeverity(probe.path),
          confidence: "medium",
          category: "exposure",
          sourceTool: "custom-accidental-exposure-checker",
          target: context.target.raw,
          endpoint: response.url,
          evidence: `GET ${probe.path} returned HTTP ${response.status} and matched a known exposure marker. Response content was not stored in the report.`,
          recommendation: remediation.recommendation,
          verification: remediation.verification
        }));
      }
    }

    return { findings };
  }
};

function exposureSeverity(path: string): "medium" | "high" {
  return path.includes(".env") || path.includes(".git") || path.includes("heapdump") || path.endsWith(".sql")
    ? "high"
    : "medium";
}
