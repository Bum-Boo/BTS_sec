import { describe, expect, it } from "vitest";
import { assertAllowedNucleiTemplates, isAllowedNucleiTemplate } from "../src/web-scanner";

describe("safe Nuclei allowlist enforcement", () => {
  it("allows only known safe templates", () => {
    expect(isAllowedNucleiTemplate("http/misconfiguration/http-missing-security-headers.yaml")).toBe(true);
    expect(isAllowedNucleiTemplate("../exposures/secrets/aws-keys.yaml")).toBe(false);
    expect(() => assertAllowedNucleiTemplates(["http/exposures/secrets/aws-keys.yaml"]))
      .toThrow(/not allowlisted/);
  });
});
