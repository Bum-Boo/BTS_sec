import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { customCodeScanner } from "../src/code-scanner/custom-rules";
import { defaultScanOptions } from "../src/scanner-core/options";
import { ScanContext } from "../src/scanner-core/types";

describe("custom code scanner rules", () => {
  it("detects the expanded static rule categories with standards metadata", async () => {
    const dir = await tempProject();
    await fs.mkdir(path.join(dir, "src"));
    await fs.writeFile(path.join(dir, "src", "app.ts"), `
      app.post('/admin/users/:id', (req, res) => res.json({ ok: true }));
      const digest = createHash('md5').update(input).digest('hex');
      jwt.verify(token, key, { ignoreExpiration: true });
      fetch(req.query.url);
      fs.readFile(req.query.file, 'utf8');
      res.send(req.query.html);
      res.status(500).send(err.stack);
      app.use(express.json({ limit: '100mb' }));
    `);
    await fs.writeFile(path.join(dir, "src", "app.py"), `
      from django.views.decorators.csrf import csrf_exempt
      import pickle
      @csrf_exempt
      def handler(request):
        return pickle.loads(request.body)
    `);

    const findings = (await customCodeScanner.scan(contextFor(dir))).findings;
    const categories = new Set(findings.map((finding) => finding.category));

    expect([...categories]).toEqual(expect.arrayContaining([
      "missing-authz",
      "weak-crypto",
      "jwt-oauth-misuse",
      "ssrf",
      "path-traversal",
      "xss-template-rendering",
      "exception-leak",
      "resource-consumption",
      "csrf",
      "deserialization"
    ]));
    expect(findings.every((finding) => finding.owaspMapping.length > 0 || finding.cweMapping.length > 0)).toBe(true);
  });

  it("supports false-positive suppression comments and negative fixtures", async () => {
    const dir = await tempProject();
    await fs.writeFile(path.join(dir, "safe.ts"), `
      const pageSize = Math.min(Number(req.query.limit || 20), 100);
      // bts-sec-ignore code.weak-crypto legacy checksum for public cache key
      const checksum = createHash('sha1').update(publicValue).digest('hex');
    `);

    const result = await customCodeScanner.scan(contextFor(dir));

    expect(result.findings.some((finding) => finding.id === "code.weak-crypto")).toBe(false);
    expect(result.findings.some((finding) => finding.id === "code.resource-consumption")).toBe(false);
    expect(result.metadata?.suppressedFindings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: "code.weak-crypto",
        reason: "legacy checksum for public cache key"
      })
    ]));
  });

  it("ignores UI, parser, and visual-randomness patterns that are not security-sensitive", async () => {
    const dir = await tempProject();
    await fs.writeFile(path.join(dir, "portfolio.tsx"), `
      <Slider label="Falloff" value={settings.falloff} onChange={(value) => updateSetting("falloff", value)} />
      const x = width * (0.16 + Math.random() * 0.68);
      while (true) {
        const token = this.peek();
        if (token.type !== "operator") {
          break;
        }
      }
    `);

    const findings = (await customCodeScanner.scan(contextFor(dir))).findings;

    expect(findings.some((finding) => finding.id === "code.raw-sql")).toBe(false);
    expect(findings.some((finding) => finding.id === "code.weak-crypto")).toBe(false);
    expect(findings.some((finding) => finding.id === "code.resource-consumption")).toBe(false);
  });
});

async function tempProject(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "bts-code-rules-"));
}

function contextFor(dir: string): ScanContext {
  return {
    target: { kind: "directory", raw: dir, path: dir },
    options: defaultScanOptions(),
    logger: { info() {}, warn() {}, error() {} }
  };
}
