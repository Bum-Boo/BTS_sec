import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { commandExists } from "../src/utils/command";

describe.skipIf(process.platform === "win32")("external command detection", () => {
  it("finds executables on PATH without spawning a shell builtin", async () => {
    expect(await commandExists("node")).toBe(true);
    expect(await commandExists("bts-sec-definitely-missing-tool")).toBe(false);
  });

  it("requires the execute bit", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-path-"));
    try {
      await fs.writeFile(path.join(dir, "fake-tool"), "#!/bin/sh\n", { mode: 0o644 });
      expect(await commandExists("fake-tool", dir)).toBe(false);
      await fs.chmod(path.join(dir, "fake-tool"), 0o755);
      expect(await commandExists("fake-tool", dir)).toBe(true);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
