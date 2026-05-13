import { describe, expect, it } from "vitest";
import { assertUrlInScope, validateTarget } from "../src/scanner-core/target";

describe("target scope validation", () => {
  it("requires explicit authorization confirmation for URL scanning", () => {
    expect(() => validateTarget("https://example.com", { confirmAuthorization: false }))
      .toThrow(/confirm-authorization/);
  });

  it("blocks URL requests outside the explicit target origin", () => {
    const target = validateTarget("https://example.com/app", { confirmAuthorization: true });
    expect(target.kind).toBe("url");
    if (target.kind === "url") {
      expect(() => assertUrlInScope(target, new URL("https://other.example/app"))).toThrow(/Out-of-scope/);
      expect(() => assertUrlInScope(target, new URL("https://example.com/health"))).not.toThrow();
    }
  });
});
