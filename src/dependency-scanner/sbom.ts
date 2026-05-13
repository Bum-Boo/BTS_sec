import fs from "node:fs/promises";
import path from "node:path";
import { pathExists } from "../utils/fs";

export interface SbomComponent {
  type: "library";
  name: string;
  version?: string;
  purl?: string;
  scope?: "required" | "optional" | "excluded";
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
  const components: SbomComponent[] = [
    ...(await packageJsonComponents(projectPath)),
    ...(await requirementsComponents(projectPath))
  ];

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
    ...toNpmComponents(pkg.dependencies, "required"),
    ...toNpmComponents(pkg.devDependencies, "optional"),
    ...toNpmComponents(pkg.optionalDependencies, "optional")
  ];
}

function toNpmComponents(deps: Record<string, string> | undefined, scope: "required" | "optional"): SbomComponent[] {
  return Object.entries(deps ?? {}).map(([name, version]) => ({
    type: "library",
    name,
    version,
    purl: `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`,
    scope
  }));
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
      return {
        type: "library" as const,
        name,
        version,
        purl: version ? `pkg:pypi/${encodeURIComponent(name)}@${encodeURIComponent(version)}` : `pkg:pypi/${encodeURIComponent(name)}`
      };
    });
}
