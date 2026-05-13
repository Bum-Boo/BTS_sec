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
});
