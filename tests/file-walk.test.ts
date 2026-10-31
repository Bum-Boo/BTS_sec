import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fileTypeKey, walkFiles } from "../src/utils/fs";

describe("file walking", () => {
  let root: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-walk-"));
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it("maps dotfiles to a matchable type key", () => {
    expect(fileTypeKey(".env")).toBe(".env");
    expect(fileTypeKey("/app/.env.local")).toBe(".env");
    expect(fileTypeKey(".env.production")).toBe(".env");
    expect(fileTypeKey(".npmrc")).toBe(".npmrc");
    expect(fileTypeKey("server.TS")).toBe(".ts");
    expect(fileTypeKey("Makefile")).toBe("");
  });

  it("includes .env files when .env is in the extension allowlist", async () => {
    await fs.writeFile(path.join(root, ".env"), "A=1\n");
    await fs.writeFile(path.join(root, ".env.local"), "A=1\n");
    await fs.writeFile(path.join(root, "notes.bin"), "A=1\n");

    const files = (await walkFiles(root, { extensions: new Set([".env"]) })).map((file) => path.basename(file)).sort();
    expect(files).toEqual([".env", ".env.local"]);
  });

  it("does not follow symlinks out of the target directory", async () => {
    const outside = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-outside-"));
    try {
      await fs.writeFile(path.join(outside, "leak.ts"), "export const x = 1;\n");
      await fs.symlink(path.join(outside, "leak.ts"), path.join(root, "linked-file.ts"));
      await fs.symlink(outside, path.join(root, "linked-dir"));
      await fs.writeFile(path.join(root, "inside.ts"), "export const y = 2;\n");

      const files = await walkFiles(root, { extensions: new Set([".ts"]) });
      expect(files).toEqual([path.join(root, "inside.ts")]);
    } finally {
      await fs.rm(outside, { recursive: true, force: true });
    }
  });
});
