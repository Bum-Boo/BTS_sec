import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultScanOptions, runScan } from "../src";
import cases from "./fixtures/heldout-cases.json";

// Single-line cases written independently of the rule implementations (only
// rule ids and descriptions were given). Token prefixes are stored as markers
// so the repository holds no credential-shaped literals.
const MARKERS: Record<string, string> = {
  "{AWS}": "AK" + "IA",
  "{GH}": "gh" + "p_",
  "{STRIPE}": "sk_" + "live_",
  "{SLACK}": "xox" + "b-",
  "{GOOGLE}": "AI" + "za",
  "{PK}": "-----BEGIN " + "PRIVATE KEY-----"
};

describe("independently written single-line cases", () => {
  it("matches the expected rule ids for every case", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-heldout-"));
    try {
      const files: string[] = [];
      for (const [index, testCase] of cases.entries()) {
        const line = Object.entries(MARKERS).reduce((text, [marker, value]) => text.split(marker).join(value), testCase.line);
        const file = path.join(root, `case${index}`, testCase.ext === ".env" ? ".env" : `file${testCase.ext}`);
        await fs.mkdir(path.dirname(file));
        await fs.writeFile(file, `${line}\n`);
        files.push(file);
      }

      const result = await runScan(root, defaultScanOptions(), { info() {}, warn() {}, error() {} });
      const mismatches = cases.flatMap((testCase, index) => {
        const actual = [...new Set(result.findings.filter((finding) => finding.file === files[index]).map((finding) => finding.id))].sort();
        const expected = [...testCase.expect].sort();
        return JSON.stringify(actual) === JSON.stringify(expected) ? [] : [`${testCase.line} => expected ${expected.join(",") || "none"}, got ${actual.join(",") || "none"}`];
      });

      expect(mismatches).toEqual([]);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
