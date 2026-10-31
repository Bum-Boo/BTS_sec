import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { semgrepAdapter } from "../src/code-scanner/semgrep-adapter";
import { pipAuditAdapter } from "../src/dependency-scanner/pip-audit-adapter";
import { defaultScanOptions } from "../src/scanner-core/options";

const { calls, state } = vi.hoisted(() => ({
  calls: [] as Array<{ command: string; args: string[] }>,
  state: { nextResult: {} as Partial<import("../src/utils/command").CommandResult> }
}));

vi.mock("../src/utils/command", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/utils/command")>();
  return {
    ...original,
    commandExists: async () => true,
    runCommand: async (command: string, args: string[]) => {
      calls.push({ command, args });
      return { command, args, exitCode: 0, stdout: "{}", stderr: "", timedOut: false, ...state.nextResult };
    }
  };
});

const logger = { info() {}, warn() {}, error() {} };

describe("external adapter safety arguments", () => {
  let root: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-adapter-"));
    calls.length = 0;
    state.nextResult = {};
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  const context = () => ({
    target: { kind: "directory" as const, raw: root, path: root },
    options: defaultScanOptions({ includeExternal: true }),
    logger
  });

  it("runs pip-audit without pip resolution so target setup.py is never executed", async () => {
    await fs.writeFile(path.join(root, "requirements.txt"), "requests==2.19.0\n");
    await pipAuditAdapter.scan(context());

    expect(calls).toHaveLength(1);
    expect(calls[0].args).toEqual(expect.arrayContaining(["--disable-pip", "--no-deps"]));
  });

  it("reports pip-audit errors instead of silently returning no findings", async () => {
    await fs.writeFile(path.join(root, "requirements.txt"), "requests\n");
    state.nextResult = { exitCode: 1, stdout: "", stderr: "requirement requests is not pinned" };

    await expect(pipAuditAdapter.scan(context())).rejects.toThrow(/not pinned/);
  });

  it("disables Semgrep metrics", async () => {
    await fs.writeFile(path.join(root, ".semgrep.yml"), "rules: []\n");
    state.nextResult = { stdout: '{"results": []}' };
    await semgrepAdapter.scan(context());

    expect(calls[0].args).toContain("--metrics=off");
  });
});
