import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { defaultScanOptions, runScan } from "../../src";
import { ExpectedFinding, fixtureProjects, materializeFixture } from "./benchmark-projects";

export interface RuleScore {
  ruleId: string;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
}

export interface BenchmarkResult {
  scores: RuleScore[];
  falsePositives: ExpectedFinding[];
  falseNegatives: ExpectedFinding[];
}

const silentLogger = { info() {}, warn() {}, error() {} };

export async function runDetectionBenchmark(): Promise<BenchmarkResult> {
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "bts-sec-bench-"));
  const expected: ExpectedFinding[] = [];
  const actual: ExpectedFinding[] = [];

  try {
    for (const project of fixtureProjects) {
      const root = path.join(workspace, project.name);
      await fs.mkdir(root, { recursive: true });
      for (const item of await materializeFixture(project, root)) {
        expected.push({ ...item, file: `${project.name}/${item.file}` });
      }

      const result = await runScan(root, defaultScanOptions({ outputDir: path.join(workspace, "reports") }), silentLogger);
      for (const finding of result.findings) {
        if (finding.category === "adapter" || !finding.file || !finding.line) continue;
        const relative = path.relative(root, finding.file).split(path.sep).join("/");
        actual.push({ file: `${project.name}/${relative}`, line: finding.line, ruleId: finding.id });
      }
    }
  } finally {
    await fs.rm(workspace, { recursive: true, force: true });
  }

  const key = (item: ExpectedFinding) => `${item.ruleId}|${item.file}|${item.line}`;
  const expectedKeys = new Set(expected.map(key));
  const actualKeys = new Set(actual.map(key));
  const falsePositives = actual.filter((item) => !expectedKeys.has(key(item)));
  const falseNegatives = expected.filter((item) => !actualKeys.has(key(item)));

  const ruleIds = [...new Set([...expected, ...actual].map((item) => item.ruleId))].sort();
  const scores = ruleIds.map((ruleId) => ({
    ruleId,
    truePositives: expected.filter((item) => item.ruleId === ruleId && actualKeys.has(key(item))).length,
    falsePositives: falsePositives.filter((item) => item.ruleId === ruleId).length,
    falseNegatives: falseNegatives.filter((item) => item.ruleId === ruleId).length
  }));

  return { scores, falsePositives, falseNegatives };
}

export function formatScores(result: BenchmarkResult): string {
  const rows = result.scores.map((score) =>
    `| ${score.ruleId} | ${score.truePositives} | ${score.falsePositives} | ${score.falseNegatives} |`
  );
  return ["| rule | TP | FP | FN |", "| --- | ---: | ---: | ---: |", ...rows].join("\n");
}
