import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { defaultScanOptions, runScan, writeReports } from "../src";

const { commandCalls } = vi.hoisted(() => ({ commandCalls: [] as string[] }));

vi.mock("../src/utils/command", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/utils/command")>();
  return {
    ...original,
    runCommand: async (command: string, args: string[], options?: Parameters<typeof original.runCommand>[2]) => {
      commandCalls.push([command, ...args].join(" "));
      return original.runCommand(command, args, options);
    }
  };
});

describe("default directory scan isolation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    commandCalls.length = 0;
  });

  it("makes no network requests, spawns no processes and runs no target code", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-isolation-"));
    const out = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-isolation-out-"));
    const marker = path.join(root, "TARGET_CODE_RAN");
    try {
      await fs.writeFile(path.join(root, "package.json"), JSON.stringify({
        name: "fixture",
        scripts: { postinstall: `node -e "require('fs').writeFileSync('${marker}', '1')"` },
        dependencies: { express: "4.19.0" }
      }));
      await fs.writeFile(path.join(root, "setup.py"), `open(${JSON.stringify(marker)}, "w").write("1")\n`);
      await fs.writeFile(path.join(root, "requirements.txt"), "./\n");
      await fs.writeFile(path.join(root, "index.js"), 'fetch(req.query.url);\nconst apiKey = "fixture-api-key-value-1234";\n');

      const fetchSpy = vi.spyOn(globalThis, "fetch");
      const result = await runScan(root, defaultScanOptions({ outputDir: out }), { info() {}, warn() {}, error() {} });
      await writeReports(result, out);

      expect(result.findings.some((finding) => finding.id === "code.ssrf-user-controlled-url")).toBe(true);
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(commandCalls).toEqual([]);
      await expect(fs.access(marker)).rejects.toThrow();
      expect(await fs.readFile(path.join(out, "report.json"), "utf8")).not.toContain("fixture-api-key-value-1234");
    } finally {
      await fs.rm(root, { recursive: true, force: true });
      await fs.rm(out, { recursive: true, force: true });
    }
  });
});
