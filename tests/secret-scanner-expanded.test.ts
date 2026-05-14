import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { internalSecretScanner } from "../src/secret-scanner/internal-secret-scanner";
import { defaultScanOptions } from "../src/scanner-core/options";
import { ScanContext } from "../src/scanner-core/types";

describe("expanded internal secret scanner", () => {
  it("detects provider and entropy-based secrets while reporting only redacted evidence", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "bts-secrets-"));
    const githubToken = ["ghp", "abcdefghijklmnopqrstuvwxyz123456"].join("_");
    const slackToken = ["xoxb", "123456789012", "123456789012", "AbCdEfGhIjKlMnOpQrStUvWx"].join("-");
    const stripeSecret = ["sk", "live", "abcdefghijklmnopqrstuvwxyz123456"].join("_");
    const databaseUrl = ["postgres://user", "pass@db.internal/app"].join(":");
    const sessionToken = ["2xY9zQ8wE7rT6yU5iO4pA3sD", "2fG1hJ0kL9mN8bV7cX6z"].join("");
    await fs.writeFile(path.join(dir, ".env"), [
      `GITHUB_TOKEN=${githubToken}`,
      `SLACK_BOT=${slackToken}`,
      `STRIPE_SECRET=${stripeSecret}`,
      `DATABASE_URL=${databaseUrl}`,
      `SESSION_TOKEN=${sessionToken}`,
      "EXAMPLE_TOKEN=placeholder"
    ].join("\n"));

    const findings = (await internalSecretScanner.scan(contextFor(dir))).findings;
    const ids = findings.map((finding) => finding.id);
    const reportText = findings.map((finding) => finding.redactedEvidence).join("\n");

    expect(ids).toEqual(expect.arrayContaining([
      "secret.github-token",
      "secret.slack-token",
      "secret.stripe-key",
      "secret.database-url",
      "secret.generic-high-entropy"
    ]));
    expect(reportText).toContain("GITHUB_TOKEN=[REDACTED]");
    expect(reportText).toContain("[REDACTED_SLACK_TOKEN]");
    expect(reportText).toContain("STRIPE_SECRET=[REDACTED]");
    expect(reportText).toContain("[REDACTED_DB_URL]");
    expect(reportText).not.toContain("abcdefghijklmnopqrstuvwxyz123456");
    expect(reportText).not.toContain("user:pass");
    expect(reportText).not.toContain("placeholder");
  });

  it("does not treat parser token variables or long identifiers as secrets", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "bts-secrets-"));
    await fs.mkdir(path.join(dir, "src"));
    await fs.writeFile(path.join(dir, "src", "parser.ts"), `
      type Token = { type: string; value: string };
      class Parser {
        constructor(private readonly tokens: Token[]) {}
        parse() {
          const token = this.peek();
          const playingYouTubeMediaId = useState<string | null>(null);
          return token;
        }
      }
    `);

    const findings = (await internalSecretScanner.scan(contextFor(dir))).findings;

    expect(findings.some((finding) => finding.id === "secret.generic-assignment")).toBe(false);
    expect(findings.some((finding) => finding.id === "secret.generic-high-entropy")).toBe(false);
  });
});

function contextFor(dir: string): ScanContext {
  return {
    target: { kind: "directory", raw: dir, path: dir },
    options: defaultScanOptions(),
    logger: { info() {}, warn() {}, error() {} }
  };
}
