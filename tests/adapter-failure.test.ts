import { describe, expect, it } from "vitest";
import { runAdapterSafely } from "../src/scanner-core/task-runner";
import { defaultScanOptions } from "../src/scanner-core/options";
import { ScannerAdapter } from "../src/scanner-core/types";

describe("adapter failure handling", () => {
  it("turns adapter exceptions into informational findings", async () => {
    const adapter: ScannerAdapter = {
      name: "failing-adapter",
      async scan() {
        throw new Error("boom");
      }
    };

    const result = await runAdapterSafely(adapter, {
      target: { kind: "directory", raw: "fixture", path: process.cwd() },
      options: defaultScanOptions(),
      logger: { info() {}, warn() {}, error() {} }
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].title).toContain("failed safely");
  });
});
