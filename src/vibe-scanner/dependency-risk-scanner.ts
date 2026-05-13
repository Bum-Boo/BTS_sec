import fs from "node:fs/promises";
import path from "node:path";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext } from "../scanner-core/types";
import { pathExists, readFileLines, walkFiles } from "../utils/fs";

export interface RegistryPackageMetadata {
  createdAt?: string;
  scripts?: Record<string, string>;
}

export interface DependencyRiskOptions {
  registryData?: Record<string, RegistryPackageMetadata>;
  now?: Date;
}

const POPULAR_PACKAGES = [
  "react",
  "next",
  "express",
  "fastapi",
  "django",
  "flask",
  "stripe",
  "openai",
  "@supabase/supabase-js",
  "firebase",
  "mongoose",
  "prisma",
  "axios",
  "lodash",
  "zod",
  "jsonwebtoken",
  "bcrypt",
  "resend",
  "@clerk/nextjs"
];

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".java", ".kt", ".gradle"]);
const NODE_BUILTINS = new Set(["fs", "path", "node:fs", "node:path", "crypto", "http", "https", "url", "os", "child_process"]);
const PYTHON_STDLIB = new Set(["os", "sys", "json", "re", "pathlib", "typing", "datetime", "subprocess", "sqlite3", "logging"]);

export const dependencyRiskScanner: ScannerAdapter = {
  name: "vibe-dependency-risk-scanner",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }
    return {
      findings: await analyzeDependencyRisks(context.target.path, context.target.raw)
    };
  }
};

export async function analyzeDependencyRisks(
  projectPath: string,
  target = projectPath,
  options: DependencyRiskOptions = {}
): Promise<Finding[]> {
  const manifests = await readDependencyManifests(projectPath);
  const imports = await collectImports(projectPath);
  const findings: Finding[] = [];
  const declaredNames = new Set([...manifests.dependencies.keys()].map(normalizePackageName));
  const importedNames = new Set([...imports.keys()].map(normalizePackageName));

  for (const [importName, locations] of imports.entries()) {
    const normalized = normalizePackageName(importName);
    if (isBuiltInImport(normalized) || declaredNames.has(normalized)) {
      continue;
    }
    findings.push(normalizeFinding({
      id: "vibe.dependency.missing-import-manifest",
      title: "Imported package is missing from dependency manifests",
      severity: "medium",
      confidence: "medium",
      category: "dependency",
      vibeRiskCategory: "hallucinated-dependency",
      targetType: "dependency",
      sourceTool: "vibe-dependency-risk-scanner",
      target,
      file: locations[0]?.file,
      line: locations[0]?.line,
      evidence: `Import "${importName}" is used in source code but was not found in supported dependency manifests.`,
      hallucinatedDependencyRisk: true,
      recommendation: "Confirm whether the import is a real dependency. Add the intended package explicitly or remove hallucinated code.",
      verification: "Run the project dependency installer in a controlled environment and confirm the import resolves from an expected package."
    }));
  }

  for (const [declaredName, sourceFile] of manifests.dependencies.entries()) {
    const normalized = normalizePackageName(declaredName);
    if (!importedNames.has(normalized) && !isLikelyToolingDependency(normalized)) {
      findings.push(normalizeFinding({
        id: "vibe.dependency.declared-unused",
        title: "Declared dependency appears unused in source imports",
        severity: "low",
        confidence: "low",
        category: "dependency",
        vibeRiskCategory: "dependency-hygiene",
        targetType: "dependency",
        sourceTool: "vibe-dependency-risk-scanner",
        target,
        file: sourceFile,
        evidence: `Dependency "${declaredName}" is declared but was not observed in static import statements.`,
        recommendation: "Review whether the dependency is still needed. Remove unused dependencies after confirming runtime or framework usage.",
        verification: "Run tests and build after removal, or document why the dependency is intentionally retained."
      }));
    }

    const similar = findPopularPackageLookalike(declaredName);
    if (similar) {
      findings.push(normalizeFinding({
        id: "vibe.dependency.typosquat-like-name",
        title: "Dependency name resembles a popular package",
        severity: "high",
        confidence: "medium",
        category: "dependency",
        vibeRiskCategory: "slopsquatting",
        targetType: "dependency",
        sourceTool: "vibe-dependency-risk-scanner",
        target,
        file: sourceFile,
        evidence: `Declared dependency "${declaredName}" is similar to popular package "${similar}".`,
        hallucinatedDependencyRisk: true,
        recommendation: "Verify the package identity, publisher, repository, and install script behavior before use.",
        verification: "Confirm the dependency is the intended package and pin it to a reviewed version or replace it."
      }));
    }

    const metadata = options.registryData?.[declaredName] ?? options.registryData?.[normalized];
    if (metadata?.createdAt && isSuspiciouslyNew(metadata.createdAt, options.now ?? new Date())) {
      findings.push(normalizeFinding({
        id: "vibe.dependency.suspiciously-new-package",
        title: "Dependency appears suspiciously new",
        severity: "medium",
        confidence: "low",
        category: "dependency",
        vibeRiskCategory: "slopsquatting",
        targetType: "dependency",
        sourceTool: "vibe-dependency-risk-scanner",
        target,
        file: sourceFile,
        evidence: `Package "${declaredName}" appears to have been created recently according to supplied registry metadata.`,
        hallucinatedDependencyRisk: true,
        recommendation: "Manually review the package before trusting it, especially if it was introduced by AI-generated code.",
        verification: "Confirm package age, publisher, source repository, download history, and whether a safer established package exists."
      }));
    }
    if (metadata?.scripts && Object.keys(metadata.scripts).some((script) => /preinstall|postinstall|install|prepare/i.test(script))) {
      findings.push(normalizeFinding({
        id: "vibe.dependency.suspicious-install-script",
        title: "Dependency metadata contains install-time scripts",
        severity: "medium",
        confidence: "medium",
        category: "dependency",
        vibeRiskCategory: "supply-chain-install-script",
        targetType: "dependency",
        sourceTool: "vibe-dependency-risk-scanner",
        target,
        file: sourceFile,
        evidence: `Package "${declaredName}" has install-time scripts in supplied registry metadata.`,
        recommendation: "Review package install scripts before installation and consider using package manager settings that ignore scripts during review.",
        verification: "Confirm the script behavior is expected or replace the dependency."
      }));
    }
  }

  return findings;
}

export function findPopularPackageLookalike(name: string): string | undefined {
  const normalized = normalizePackageName(name);
  for (const popular of POPULAR_PACKAGES) {
    const candidate = normalizePackageName(popular);
    if (normalized === candidate) {
      continue;
    }
    if (levenshtein(normalized, candidate) <= 2 || normalized.replace(/[-_]/g, "") === candidate.replace(/[-_]/g, "")) {
      return popular;
    }
  }
  return undefined;
}

async function readDependencyManifests(projectPath: string): Promise<{ dependencies: Map<string, string> }> {
  const dependencies = new Map<string, string>();
  await readPackageJson(projectPath, dependencies);
  await readRequirementsTxt(projectPath, dependencies);
  await readPyproject(projectPath, dependencies);
  await readPomXml(projectPath, dependencies);
  await readGradle(projectPath, dependencies);
  return { dependencies };
}

async function readPackageJson(projectPath: string, dependencies: Map<string, string>): Promise<void> {
  const file = path.join(projectPath, "package.json");
  if (!(await pathExists(file))) return;
  const pkg = JSON.parse(await fs.readFile(file, "utf8")) as Record<string, Record<string, string> | undefined>;
  for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const name of Object.keys(pkg[section] ?? {})) {
      dependencies.set(name, file);
    }
  }
}

async function readRequirementsTxt(projectPath: string, dependencies: Map<string, string>): Promise<void> {
  const file = path.join(projectPath, "requirements.txt");
  if (!(await pathExists(file))) return;
  const lines = await readFileLines(file);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
    dependencies.set(trimmed.split(/[<>=~!]/)[0].trim(), file);
  }
}

async function readPyproject(projectPath: string, dependencies: Map<string, string>): Promise<void> {
  const file = path.join(projectPath, "pyproject.toml");
  if (!(await pathExists(file))) return;
  const lines = await readFileLines(file);
  for (const line of lines) {
    const match = line.match(/["']([A-Za-z0-9_.-]+)(?:[<>=~!].*)?["']/);
    if (match) dependencies.set(match[1], file);
  }
}

async function readPomXml(projectPath: string, dependencies: Map<string, string>): Promise<void> {
  const file = path.join(projectPath, "pom.xml");
  if (!(await pathExists(file))) return;
  const xml = await fs.readFile(file, "utf8");
  for (const match of xml.matchAll(/<artifactId>([^<]+)<\/artifactId>/g)) {
    dependencies.set(match[1], file);
  }
}

async function readGradle(projectPath: string, dependencies: Map<string, string>): Promise<void> {
  for (const name of ["build.gradle", "build.gradle.kts"]) {
    const file = path.join(projectPath, name);
    if (!(await pathExists(file))) continue;
    const lines = await readFileLines(file);
    for (const line of lines) {
      const match = line.match(/['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):[^'"]+['"]/);
      if (match) dependencies.set(match[2], file);
    }
  }
}

async function collectImports(projectPath: string): Promise<Map<string, Array<{ file: string; line: number }>>> {
  const imports = new Map<string, Array<{ file: string; line: number }>>();
  const files = await walkFiles(projectPath, { extensions: SOURCE_EXTENSIONS, maxBytes: 1024 * 1024 });
  for (const file of files) {
    const lines = await readFileLines(file);
    lines.forEach((line, index) => {
      for (const name of extractImportsFromLine(line)) {
        const existing = imports.get(name) ?? [];
        existing.push({ file, line: index + 1 });
        imports.set(name, existing);
      }
    });
  }
  return imports;
}

function extractImportsFromLine(line: string): string[] {
  const names: string[] = [];
  const patterns = [
    /\bimport\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bfrom\s+([A-Za-z0-9_.]+)\s+import\b/g,
    /^\s*import\s+([A-Za-z0-9_.]+)/g
  ];
  for (const pattern of patterns) {
    for (const match of line.matchAll(pattern)) {
      const normalized = packageRoot(match[1]);
      if (normalized) names.push(normalized);
    }
  }
  return names;
}

function packageRoot(name: string): string | undefined {
  if (name.startsWith(".") || name.startsWith("/")) return undefined;
  if (name.startsWith("@")) return name.split("/").slice(0, 2).join("/");
  return name.split(/[/.]/)[0];
}

function normalizePackageName(name: string): string {
  return name.toLowerCase().replace(/^@types\//, "").replace(/_/g, "-");
}

function isBuiltInImport(name: string): boolean {
  return NODE_BUILTINS.has(name) || PYTHON_STDLIB.has(name);
}

function isLikelyToolingDependency(name: string): boolean {
  return /^(typescript|tsx|vitest|jest|eslint|prettier|webpack|vite|ts-node|nodemon|@types\/)/.test(name);
}

function isSuspiciouslyNew(createdAt: string, now: Date): boolean {
  const created = new Date(createdAt);
  if (Number.isNaN(created.getTime())) return false;
  const days = (now.getTime() - created.getTime()) / (24 * 60 * 60 * 1000);
  return days >= 0 && days <= 30;
}

function levenshtein(a: string, b: string): number {
  const matrix = Array.from({ length: a.length + 1 }, () => Array<number>(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i += 1) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j += 1) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}
