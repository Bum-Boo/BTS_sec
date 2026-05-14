import fs from "node:fs/promises";
import path from "node:path";
import { DependencyRelation } from "../scanner-core/types";
import { pathExists } from "../utils/fs";

export interface SbomComponent {
  type: "library";
  name: string;
  version?: string;
  purl?: string;
  scope?: "required" | "optional" | "excluded";
  packageManager?: string;
  relation: DependencyRelation;
}

export interface SbomDocument {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  version: 1;
  metadata: {
    timestamp: string;
    tools: Array<{ name: string; version: string }>;
  };
  components: SbomComponent[];
}

export async function generateSbom(projectPath: string): Promise<SbomDocument> {
  const components = dedupeComponents([
    ...(await packageJsonComponents(projectPath)),
    ...(await packageLockComponents(projectPath)),
    ...(await pnpmLockComponents(projectPath)),
    ...(await yarnLockComponents(projectPath)),
    ...(await requirementsComponents(projectPath)),
    ...(await pipfileLockComponents(projectPath)),
    ...(await poetryLockComponents(projectPath)),
    ...(await goSumComponents(projectPath)),
    ...(await cargoLockComponents(projectPath)),
    ...(await pomXmlComponents(projectPath)),
    ...(await gradleComponents(projectPath))
  ]);

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: "bts-sec", version: "0.1.0" }]
    },
    components
  };
}

async function packageJsonComponents(projectPath: string): Promise<SbomComponent[]> {
  const packageJsonPath = path.join(projectPath, "package.json");
  if (!(await pathExists(packageJsonPath))) {
    return [];
  }
  const pkg = JSON.parse(await fs.readFile(packageJsonPath, "utf8")) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
  };

  return [
    ...toNpmComponents(pkg.dependencies, "required", "package.json", "direct"),
    ...toNpmComponents(pkg.devDependencies, "optional", "package.json", "direct"),
    ...toNpmComponents(pkg.optionalDependencies, "optional", "package.json", "direct")
  ];
}

async function packageLockComponents(projectPath: string): Promise<SbomComponent[]> {
  const lockPath = path.join(projectPath, "package-lock.json");
  if (!(await pathExists(lockPath))) return [];
  const lock = JSON.parse(await fs.readFile(lockPath, "utf8")) as {
    packages?: Record<string, { version?: string; dev?: boolean; optional?: boolean }>;
    dependencies?: Record<string, { version?: string; dev?: boolean; optional?: boolean }>;
  };
  const root = lock.packages?.[""] as { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string> } | undefined;
  const direct = new Set([
    ...Object.keys(root?.dependencies ?? {}),
    ...Object.keys(root?.devDependencies ?? {}),
    ...Object.keys(root?.optionalDependencies ?? {})
  ]);

  if (lock.packages) {
    return Object.entries(lock.packages)
      .filter(([location]) => location.startsWith("node_modules/"))
      .map(([location, entry]) => {
        const name = location.replace(/^node_modules\//, "");
        return npmComponent(name, entry.version, entry.dev ? "optional" : "required", "package-lock.json", direct.has(name) ? "direct" : "transitive");
      });
  }

  return Object.entries(lock.dependencies ?? {}).map(([name, entry]) =>
    npmComponent(name, entry.version, entry.dev ? "optional" : "required", "package-lock.json", direct.has(name) ? "direct" : "transitive")
  );
}

async function pnpmLockComponents(projectPath: string): Promise<SbomComponent[]> {
  const lockPath = path.join(projectPath, "pnpm-lock.yaml");
  if (!(await pathExists(lockPath))) return [];
  const content = await fs.readFile(lockPath, "utf8");
  const direct = new Set([...content.matchAll(/^\s{6}([@/A-Za-z0-9_.-]+):\s*$/gm)].map((match) => match[1]));
  const components: SbomComponent[] = [];
  for (const match of content.matchAll(/^\s{2}\/?((?:@[^/\s]+\/)?[^@\s:]+)@([^:\s(]+).*:\s*$/gm)) {
    components.push(npmComponent(match[1], match[2], "required", "pnpm-lock.yaml", direct.has(match[1]) ? "direct" : "transitive"));
  }
  return components;
}

async function yarnLockComponents(projectPath: string): Promise<SbomComponent[]> {
  const lockPath = path.join(projectPath, "yarn.lock");
  if (!(await pathExists(lockPath))) return [];
  const content = await fs.readFile(lockPath, "utf8");
  const components: SbomComponent[] = [];
  const blocks = content.split(/\n(?=(?:"?[^"\s][^:]+@[^:]+":?))/g);
  for (const block of blocks) {
    const firstLine = block.split(/\r?\n/)[0] ?? "";
    const version = block.match(/^\s+version\s+"?([^"\s]+)"?/m)?.[1];
    const name = parseYarnName(firstLine);
    if (name && version) {
      components.push(npmComponent(name, version, "required", "yarn.lock", "transitive"));
    }
  }
  return components;
}

async function requirementsComponents(projectPath: string): Promise<SbomComponent[]> {
  const requirementsPath = path.join(projectPath, "requirements.txt");
  if (!(await pathExists(requirementsPath))) {
    return [];
  }
  const content = await fs.readFile(requirementsPath, "utf8");
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith("-"))
    .map((line) => {
      const [name, version] = line.split(/==|>=|<=|~=|>|</, 2).map((part) => part.trim());
      return pypiComponent(name, version, "requirements.txt", "direct");
    });
}

async function pipfileLockComponents(projectPath: string): Promise<SbomComponent[]> {
  const lockPath = path.join(projectPath, "Pipfile.lock");
  if (!(await pathExists(lockPath))) return [];
  const lock = JSON.parse(await fs.readFile(lockPath, "utf8")) as {
    default?: Record<string, { version?: string }>;
    develop?: Record<string, { version?: string }>;
  };
  return [
    ...Object.entries(lock.default ?? {}).map(([name, entry]) => pypiComponent(name, cleanPythonVersion(entry.version), "Pipfile.lock", "direct")),
    ...Object.entries(lock.develop ?? {}).map(([name, entry]) => ({ ...pypiComponent(name, cleanPythonVersion(entry.version), "Pipfile.lock", "direct"), scope: "optional" as const }))
  ];
}

async function poetryLockComponents(projectPath: string): Promise<SbomComponent[]> {
  const lockPath = path.join(projectPath, "poetry.lock");
  if (!(await pathExists(lockPath))) return [];
  const content = await fs.readFile(lockPath, "utf8");
  return [...content.matchAll(/\[\[package\]\][\s\S]*?name\s*=\s*"([^"]+)"[\s\S]*?version\s*=\s*"([^"]+)"/g)]
    .map((match) => pypiComponent(match[1], match[2], "poetry.lock", "transitive"));
}

async function goSumComponents(projectPath: string): Promise<SbomComponent[]> {
  const sumPath = path.join(projectPath, "go.sum");
  if (!(await pathExists(sumPath))) return [];
  const content = await fs.readFile(sumPath, "utf8");
  return content
    .split(/\r?\n/)
    .map((line) => line.trim().split(/\s+/))
    .filter((parts) => parts.length >= 2 && !parts[1].endsWith("/go.mod"))
    .map(([name, version]) => ({
      type: "library" as const,
      name,
      version,
      purl: `pkg:golang/${encodeURIComponent(name)}@${encodeURIComponent(version)}`,
      packageManager: "go.sum",
      relation: "transitive" as const
    }));
}

async function cargoLockComponents(projectPath: string): Promise<SbomComponent[]> {
  const lockPath = path.join(projectPath, "Cargo.lock");
  if (!(await pathExists(lockPath))) return [];
  const content = await fs.readFile(lockPath, "utf8");
  return [...content.matchAll(/\[\[package\]\][\s\S]*?name\s*=\s*"([^"]+)"[\s\S]*?version\s*=\s*"([^"]+)"/g)]
    .map((match) => ({
      type: "library" as const,
      name: match[1],
      version: match[2],
      purl: `pkg:cargo/${encodeURIComponent(match[1])}@${encodeURIComponent(match[2])}`,
      packageManager: "Cargo.lock",
      relation: "transitive" as const
    }));
}

async function pomXmlComponents(projectPath: string): Promise<SbomComponent[]> {
  const pomPath = path.join(projectPath, "pom.xml");
  if (!(await pathExists(pomPath))) return [];
  const content = await fs.readFile(pomPath, "utf8");
  return [...content.matchAll(/<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?(?:<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/g)]
    .map((match) => {
      const name = `${match[1]}:${match[2]}`;
      return {
        type: "library" as const,
        name,
        version: match[3],
        purl: match[3] ? `pkg:maven/${encodeURIComponent(match[1])}/${encodeURIComponent(match[2])}@${encodeURIComponent(match[3])}` : undefined,
        packageManager: "pom.xml",
        relation: "direct" as const
      };
    });
}

async function gradleComponents(projectPath: string): Promise<SbomComponent[]> {
  const files = ["build.gradle", "build.gradle.kts", "gradle.lockfile"];
  const components: SbomComponent[] = [];
  for (const file of files) {
    const filePath = path.join(projectPath, file);
    if (!(await pathExists(filePath))) continue;
    const content = await fs.readFile(filePath, "utf8");
    for (const match of content.matchAll(/['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^'"\s]+)['"]/g)) {
      const name = `${match[1]}:${match[2]}`;
      components.push({
        type: "library",
        name,
        version: match[3],
        purl: `pkg:maven/${encodeURIComponent(match[1])}/${encodeURIComponent(match[2])}@${encodeURIComponent(match[3])}`,
        packageManager: file,
        relation: file === "gradle.lockfile" ? "transitive" : "direct"
      });
    }
  }
  return components;
}

function toNpmComponents(
  deps: Record<string, string> | undefined,
  scope: "required" | "optional",
  packageManager: string,
  relation: DependencyRelation
): SbomComponent[] {
  return Object.entries(deps ?? {}).map(([name, version]) => npmComponent(name, version, scope, packageManager, relation));
}

function npmComponent(
  name: string,
  version: string | undefined,
  scope: "required" | "optional",
  packageManager: string,
  relation: DependencyRelation
): SbomComponent {
  return {
    type: "library",
    name,
    version,
    purl: version ? `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}` : `pkg:npm/${encodeURIComponent(name)}`,
    scope,
    packageManager,
    relation
  };
}

function pypiComponent(name: string, version: string | undefined, packageManager: string, relation: DependencyRelation): SbomComponent {
  return {
    type: "library",
    name,
    version,
    purl: version ? `pkg:pypi/${encodeURIComponent(name)}@${encodeURIComponent(version)}` : `pkg:pypi/${encodeURIComponent(name)}`,
    packageManager,
    relation
  };
}

function cleanPythonVersion(version: string | undefined): string | undefined {
  return version?.replace(/^==/, "");
}

function parseYarnName(firstLine: string): string | undefined {
  const clean = firstLine.replace(/^"|"?:?$/g, "").split(",")[0]?.trim().replace(/^"|"$/g, "");
  if (!clean) return undefined;
  if (clean.startsWith("@")) {
    const parts = clean.split("@");
    return `${parts[0]}@${parts[1]}`.replace(/@$/, "");
  }
  return clean.split("@")[0];
}

function dedupeComponents(components: SbomComponent[]): SbomComponent[] {
  const map = new Map<string, SbomComponent>();
  for (const component of components) {
    if (!component.name) continue;
    const key = `${component.purl ?? component.name}@${component.version ?? ""}`;
    const existing = map.get(key);
    if (!existing || existing.relation !== "direct" && component.relation === "direct") {
      map.set(key, component);
    }
  }
  return [...map.values()];
}
