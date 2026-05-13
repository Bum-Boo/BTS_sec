import fs from "node:fs/promises";
import path from "node:path";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { runCommand } from "../utils/command";
import { pathExists, walkFiles } from "../utils/fs";

export const preAgentChecklistScanner: ScannerAdapter = {
  name: "vibe-pre-agent-run-checklist",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }
    return {
      findings: await buildPreAgentChecklist(context.target.path, context.target.raw, context.options.timeoutMs)
    };
  }
};

export async function buildPreAgentChecklist(projectPath: string, target = projectPath, timeoutMs = 5000): Promise<Finding[]> {
  const findings: Finding[] = [];
  findings.push(...await gitFindings(projectPath, target, timeoutMs));
  findings.push(...await projectHygieneFindings(projectPath, target));
  findings.push(...await packageScriptFindings(projectPath, target));
  return findings;
}

async function gitFindings(projectPath: string, target: string, timeoutMs: number): Promise<Finding[]> {
  if (!(await pathExists(path.join(projectPath, ".git")))) {
    return [
      preflightFinding("vibe.preflight.no-git", "No git repository was detected", "medium", target, projectPath, "No .git directory was found.", "Initialize git or create a snapshot before running autonomous coding agents.", "Run git status before agent work.")
    ];
  }

  const findings: Finding[] = [];
  const status = await runCommand("git", ["status", "--porcelain"], { cwd: projectPath, timeoutMs });
  if (status.exitCode === 0 && status.stdout.trim()) {
    findings.push(preflightFinding(
      "vibe.preflight.dirty-working-tree",
      "Git working tree is dirty",
      "medium",
      target,
      projectPath,
      "git status --porcelain reported uncommitted changes.",
      "Commit or stash changes before high-autonomy agent runs so review and rollback stay simple.",
      "Suggested command: git status && git diff"
    ));
  }

  const lastCommit = await runCommand("git", ["log", "-1", "--format=%ct"], { cwd: projectPath, timeoutMs });
  if (lastCommit.exitCode !== 0 || !lastCommit.stdout.trim()) {
    findings.push(preflightFinding(
      "vibe.preflight.no-recent-commit",
      "No recent commit was detected",
      "low",
      target,
      projectPath,
      "No git commit timestamp could be read.",
      "Create a commit before running autonomous coding agents.",
      "Suggested command: git status"
    ));
  }

  return findings;
}

async function projectHygieneFindings(projectPath: string, target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const lockfiles = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.lock", "poetry.lock", "Pipfile.lock"];
  if (!(await anyExists(projectPath, lockfiles))) {
    findings.push(preflightFinding(
      "vibe.preflight.no-lockfile",
      "No dependency lockfile was detected",
      "medium",
      target,
      projectPath,
      "No supported dependency lockfile was found.",
      "Use a lockfile to make AI-introduced dependency changes reviewable and reproducible.",
      "Suggested command: git status; then install with the project's package manager only when intentionally updating dependencies."
    ));
  }

  const testFiles = await walkFiles(projectPath, {
    extensions: new Set([".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".kt"]),
    maxBytes: 512 * 1024
  });
  const hasTests = testFiles.some((file) => /\.(test|spec)\.|__tests__|tests[\\/]/i.test(file));
  if (!hasTests) {
    findings.push(preflightFinding(
      "vibe.preflight.no-tests",
      "No tests were detected",
      "medium",
      target,
      projectPath,
      "No test files were found by filename convention.",
      "Add tests before relying on agent-generated changes for auth, payment, database, or security-sensitive flows.",
      "Suggested commands: npm test / pnpm test / pytest, depending on the project."
    ));
  }

  const hasAuthTests = testFiles.some((file) => /\.(test|spec)\.|__tests__|tests[\\/]/i.test(file) && /auth|session|permission|role|owner|tenant|stripe|webhook/i.test(file));
  if (!hasAuthTests) {
    findings.push(preflightFinding(
      "vibe.preflight.no-auth-tests",
      "No auth/payment/database-focused tests were detected",
      "medium",
      target,
      projectPath,
      "No test filenames referenced auth, session, role, owner, tenant, Stripe, or webhook coverage.",
      "Add negative tests for auth, payment, and database ownership boundaries before high-autonomy agent runs.",
      "Suggested commands: npm test / pnpm test / pytest after adding focused tests."
    ));
  }

  return findings;
}

async function packageScriptFindings(projectPath: string, target: string): Promise<Finding[]> {
  const packagePath = path.join(projectPath, "package.json");
  if (!(await pathExists(packagePath))) {
    return [];
  }
  const pkg = JSON.parse(await fs.readFile(packagePath, "utf8")) as { scripts?: Record<string, string> };
  const findings: Finding[] = [];
  for (const [name, command] of Object.entries(pkg.scripts ?? {})) {
    if (/^(preinstall|postinstall|prepare)$/i.test(name) && /\b(?:curl|wget|bash|sh|powershell|pwsh|node\s+-e)\b/i.test(command)) {
      findings.push(preflightFinding(
        "vibe.preflight.risky-package-script",
        "Package lifecycle script may be risky before agent runs",
        "high",
        target,
        packagePath,
        `package.json script "${name}" invokes shell, network, or inline execution behavior.`,
        "Review lifecycle scripts before installing dependencies or letting agents update package manifests.",
        "Suggested command: git diff -- package.json package-lock.json"
      ));
    }
  }
  return findings;
}

async function anyExists(projectPath: string, files: string[]): Promise<boolean> {
  for (const file of files) {
    if (await pathExists(path.join(projectPath, file))) return true;
  }
  return false;
}

function preflightFinding(
  id: string,
  title: string,
  severity: "low" | "medium" | "high",
  target: string,
  file: string,
  evidence: string,
  recommendation: string,
  verification: string
): Finding {
  return normalizeFinding({
    id,
    title,
    severity,
    confidence: "high",
    category: "configuration",
    vibeRiskCategory: "pre-agent-run-checklist",
    targetType: "config",
    sourceTool: "vibe-pre-agent-run-checklist",
    target,
    file,
    evidence,
    recommendation,
    verification
  });
}
