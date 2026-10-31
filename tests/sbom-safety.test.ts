import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultScanOptions, runScan } from "../src";
import { generateSbom } from "../src/dependency-scanner";

const silentLogger = { info() {}, warn() {}, error() {} };

describe("SBOM generation safety", () => {
  let root: string;
  let outside: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-sbom-"));
    outside = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-sbom-outside-"));
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(outside, { recursive: true, force: true });
  });

  it("does not read manifests that are symlinks to files outside the target", async () => {
    await fs.writeFile(path.join(outside, "notes.txt"), "OUTSIDE_MARKER_LINE\n");
    await fs.symlink(path.join(outside, "notes.txt"), path.join(root, "requirements.txt"));

    const sbom = await generateSbom(root);
    expect(JSON.stringify(sbom)).not.toContain("OUTSIDE_MARKER_LINE");
    expect(sbom.metadata.properties?.[0].value).toMatch(/requirements\.txt: resolves outside/);
  });

  it("keeps scanning when package.json is malformed", async () => {
    await fs.writeFile(path.join(root, "package.json"), '{ "name": "broken", ');
    await fs.writeFile(path.join(root, "requirements.txt"), "flask==3.0.0\n");

    const result = await runScan(root, defaultScanOptions(), silentLogger);
    const sbom = result.metadata.sbom as Awaited<ReturnType<typeof generateSbom>>;
    expect(sbom.components.map((component) => component.name)).toEqual(["flask"]);
    expect(sbom.metadata.properties?.[0].value).toMatch(/^package\.json: /);
  });

  it("still reads regular manifests", async () => {
    await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ dependencies: { express: "^4.19.0" } }));
    const sbom = await generateSbom(root);
    expect(sbom.components).toEqual([expect.objectContaining({ name: "express", version: "^4.19.0", scope: "required" })]);
    expect(sbom.metadata.properties).toBeUndefined();
  });
});
