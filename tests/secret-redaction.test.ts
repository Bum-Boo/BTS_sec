import { describe, expect, it } from "vitest";
import { redactSecrets } from "../src/secret-scanner";

describe("secret redaction", () => {
  it("redacts common token, key, bearer, and URL credential shapes", () => {
    const redacted = redactSecrets([
      "PASSWORD='correct-horse-battery'",
      "ghp_abcdefghijklmnopqrstuvwxyz123456",
      "Bearer eyJhbGciOiJIUzI1NiJ9.sensitive.signature",
      "https://user:pass@example.com"
    ].join("\n"));

    expect(redacted).toContain("PASSWORD=[REDACTED]");
    expect(redacted).toContain("[REDACTED_GITHUB_TOKEN]");
    expect(redacted).toContain("Bearer [REDACTED]");
    expect(redacted).toContain("https://[REDACTED]:[REDACTED]@example.com");
    expect(redacted).not.toContain("correct-horse-battery");
    expect(redacted).not.toContain("sensitive.signature");
  });

  it("redacts quoted passphrases with spaces and JSON-style quoted keys", () => {
    const redacted = redactSecrets([
      'export const config = { password: "fixture horse battery staple" };',
      '  "client_secret": "fixture-client-secret-3456"',
      "const t = { apiKey: 'it is a fixture value' };"
    ].join("\n"));

    expect(redacted).not.toContain("horse battery");
    expect(redacted).not.toContain("fixture-client-secret-3456");
    expect(redacted).not.toContain("fixture value");
    expect(redacted).toContain('"client_secret"=[REDACTED]');
  });

  it("redacts vendor token shapes that appear without an assignment", () => {
    const stripe = "sk_" + "live_" + "FIXTUREFIXTUREFIXTURE0000";
    const slack = "xox" + "b-0000000000-0000000000-FIXTUREFIXTURE";
    const google = "AI" + "za" + "SyFIXTURE_FIXTURE_FIXTURE_FIXTURE00";
    const redacted = redactSecrets(`require("stripe")("${stripe}"); new WebClient("${slack}"); load({ k: "${google}" });`);

    expect(redacted).not.toContain(stripe);
    expect(redacted).not.toContain(slack);
    expect(redacted).not.toContain(google);
  });
});
