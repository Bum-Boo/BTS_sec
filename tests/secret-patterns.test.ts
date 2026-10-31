import { describe, expect, it } from "vitest";
import { hasSecretAssignment, isSecretName } from "../src/secret-scanner/secret-patterns";

describe("secret assignment matching", () => {
  it("recognizes prefixed and camelCase secret names", () => {
    for (const name of ["OPENAI_API_KEY", "DATABASE_PASSWORD", "STRIPE_SECRET_KEY", "stripeSecretKey", "accessToken", "_authToken", "client_secret", "apiKey"]) {
      expect(isSecretName(name), name).toBe(true);
    }
  });

  it("ignores names that only describe a secret", () => {
    for (const name of ["tokenizer", "passwordless", "tokenUrl", "passwordMinLength", "max_tokens", "PORT"]) {
      expect(isSecretName(name), name).toBe(false);
    }
  });

  it("treats bare values as literals only when allowed", () => {
    expect(hasSecretAssignment("OPENAI_API_KEY=fixture-openai-key-value", { allowUnquoted: true })).toBe(true);
    expect(hasSecretAssignment("const apiKey = process.env.API_KEY;", { allowUnquoted: false })).toBe(false);
    expect(hasSecretAssignment("  const password = req.body.password;", { allowUnquoted: false })).toBe(false);
    expect(hasSecretAssignment('  "client_secret": "fixture-client-secret-3456"', { allowUnquoted: false })).toBe(true);
  });

  it("skips placeholders and interpolation", () => {
    for (const line of [
      "DATABASE_PASSWORD=${DATABASE_PASSWORD}",
      "STRIPE_SECRET_KEY=your-stripe-secret-key-here",
      "API_TOKEN=********",
      "TOKEN=$(cat token.txt)"
    ]) {
      expect(hasSecretAssignment(line, { allowUnquoted: true }), line).toBe(false);
    }
    expect(hasSecretAssignment("const header = { token: `Bearer ${token}` };", { allowUnquoted: false })).toBe(false);
  });
});
