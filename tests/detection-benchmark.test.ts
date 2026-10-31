import { describe, expect, it } from "vitest";
import { formatScores, runDetectionBenchmark } from "./fixtures/benchmark";

describe("detection benchmark on synthetic fixture projects", () => {
  it("reports every expected finding and nothing on clean lines", async () => {
    const result = await runDetectionBenchmark();
    const describe = (items: typeof result.falsePositives) => items.map((item) => `${item.ruleId} ${item.file}:${item.line}`);

    expect(describe(result.falsePositives), formatScores(result)).toEqual([]);
    expect(describe(result.falseNegatives), formatScores(result)).toEqual([]);
  });
});
