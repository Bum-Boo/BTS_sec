import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultScanOptions, runScan } from "../src";

describe("no destructive scan mode", () => {
  it("does not support destructive mode", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-"));
    await expect(runScan(dir, { ...defaultScanOptions(), noDestructive: false } as unknown as ReturnType<typeof defaultScanOptions>))
      .rejects.toThrow(/Destructive scan mode is not implemented/);
  });
});
