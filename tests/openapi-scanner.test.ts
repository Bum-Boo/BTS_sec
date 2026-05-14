import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { openApiScanner } from "../src/api-scanner";
import { defaultScanOptions } from "../src/scanner-core/options";
import { ScanContext } from "../src/scanner-core/types";

describe("OpenAPI passive scanner", () => {
  it("detects passive API security risks without sending requests", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "bts-openapi-"));
    const specPath = path.join(dir, "openapi.json");
    await fs.writeFile(specPath, JSON.stringify({
      openapi: "3.1.0",
      paths: {
        "/users/{id}": {
          get: {
            responses: { "200": { description: "ok" } }
          },
          patch: {
            requestBody: {
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      role: { type: "string" },
                      avatarUrl: { type: "string", format: "uri" }
                    }
                  }
                }
              }
            },
            responses: { "200": { description: "ok" } }
          }
        },
        "/admin/reports": {
          get: {
            summary: "Admin reports",
            responses: { "200": { description: "ok" } }
          }
        },
        "/orders": {
          get: {
            summary: "List orders",
            responses: { "200": { description: "ok" } }
          }
        },
        "/legacy/debug": {
          get: {
            deprecated: true,
            responses: { "200": { description: "ok" } }
          }
        }
      }
    }, null, 2));

    const result = await openApiScanner.scan(contextFor(specPath));
    const ids = result.findings.map((finding) => finding.id);

    expect(ids).toEqual(expect.arrayContaining([
      "api.openapi.missing-security",
      "api.openapi.bola-candidate",
      "api.openapi.function-authz-sensitive-path",
      "api.openapi.mass-assignment-risk",
      "api.openapi.user-controlled-url-field",
      "api.openapi.collection-missing-pagination-rate-limit",
      "api.openapi.deprecated-or-undocumented"
    ]));
    expect(result.findings.every((finding) => finding.targetType === "api")).toBe(true);
    expect(result.findings.map((finding) => finding.redactedEvidence).join("\n")).toContain("No exploit payloads or destructive requests were sent");
  });
});

function contextFor(specPath: string): ScanContext {
  return {
    target: { kind: "api-spec", raw: specPath, path: specPath },
    options: defaultScanOptions({ apiSpecPath: specPath }),
    logger: { info() {}, warn() {}, error() {} }
  };
}
