import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { generateSbom } from "../src/dependency-scanner";
import { supplyChainScanner } from "../src/dependency-scanner/supply-chain-scanner";
import { aggregateScanResult } from "../src/scanner-core/aggregation";
import { normalizeFinding } from "../src/scanner-core/finding";
import { defaultScanOptions } from "../src/scanner-core/options";
import { ScanContext } from "../src/scanner-core/types";

describe("dependency SBOM and supply-chain checks", () => {
  it("generates lockfile-based transitive SBOM components", async () => {
    const dir = await tempProject();
    await fs.writeFile(path.join(dir, "package.json"), JSON.stringify({
      dependencies: { express: "^4.18.0" }
    }));
    await fs.writeFile(path.join(dir, "package-lock.json"), JSON.stringify({
      packages: {
        "": { dependencies: { express: "^4.18.0" } },
        "node_modules/express": { version: "4.18.2" },
        "node_modules/body-parser": { version: "1.20.1" }
      }
    }));

    const sbom = await generateSbom(dir);

    expect(sbom.components).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "express", version: "4.18.2", relation: "direct" }),
      expect.objectContaining({ name: "body-parser", version: "1.20.1", relation: "transitive" })
    ]));
  });

  it("reports static supply-chain hygiene findings without package install", async () => {
    const dir = await tempProject();
    await fs.writeFile(path.join(dir, "package.json"), JSON.stringify({
      name: "@acme/app",
      packageManager: "pnpm@9.0.0",
      scripts: { postinstall: "node scripts/install.js" },
      dependencies: {
        express: "^4.18.0",
        "@acme/internal-api": "1.0.0",
        "git-helper": "github:owner/repo"
      }
    }, null, 2));

    const findings = (await supplyChainScanner.scan(contextFor(dir))).findings;
    const ids = findings.map((finding) => finding.id);

    expect(ids).toEqual(expect.arrayContaining([
      "supply-chain.lockfile-missing",
      "supply-chain.unpinned-dependency",
      "supply-chain.git-url-dependency",
      "supply-chain.install-script-usage",
      "supply-chain.dependency-confusion-candidate"
    ]));
    expect(findings.map((finding) => finding.redactedEvidence).join("\n")).toContain("no install scripts or package downloads were executed");
  });

  it("does not report caret ranges as unpinned when a JavaScript lockfile is committed", async () => {
    const dir = await tempProject();
    await fs.writeFile(path.join(dir, "package.json"), JSON.stringify({
      dependencies: {
        express: "^4.18.0"
      }
    }, null, 2));
    await fs.writeFile(path.join(dir, "package-lock.json"), JSON.stringify({
      packages: {
        "": { dependencies: { express: "^4.18.0" } },
        "node_modules/express": { version: "4.18.2" }
      }
    }));

    const findings = (await supplyChainScanner.scan(contextFor(dir))).findings;

    expect(findings.some((finding) => finding.id === "supply-chain.unpinned-dependency")).toBe(false);
  });

  it("enriches dependency findings with EPSS and priority score from an opt-in CSV", async () => {
    const dir = await tempProject();
    const epssCsv = path.join(dir, "epss.csv");
    await fs.writeFile(epssCsv, "cve,epss,percentile,date\nCVE-2025-12345,0.91,0.99,2026-01-01\n");
    const finding = normalizeFinding({
      id: "trivy.CVE-2025-12345",
      title: "Dependency vulnerability",
      severity: "high",
      confidence: "high",
      category: "dependency",
      sourceTool: "test",
      target: dir,
      cve: "CVE-2025-12345",
      dependencyName: "express",
      fixAvailable: true,
      evidence: "express vulnerable",
      recommendation: "Upgrade.",
      verification: "Scan again."
    });

    const result = await aggregateScanResult(
      { kind: "directory", raw: dir, path: dir },
      "2026-01-01T00:00:00.000Z",
      [finding],
      {
        scanOptions: {
          epssCsvPath: epssCsv,
          refreshEpss: false,
          timeoutMs: 15000,
          outputDir: dir
        },
        sbom: { components: [{ name: "express", version: "4.18.2", relation: "direct" }] }
      }
    );

    expect(result.findings[0].epssScore).toBe(0.91);
    expect(result.findings[0].epssPercentile).toBe(0.99);
    expect(result.findings[0].dependencyRelation).toBe("direct");
    expect(result.findings[0].priorityScore).toBeGreaterThan(75);
  });
});

async function tempProject(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "bts-deps-"));
}

function contextFor(dir: string): ScanContext {
  return {
    target: { kind: "directory", raw: dir, path: dir },
    options: defaultScanOptions(),
    logger: { info() {}, warn() {}, error() {} }
  };
}
