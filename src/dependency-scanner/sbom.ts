import fs from "node:fs/promises";
import path from "node:path";

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
    properties?: Array<{ name: string; value: string }>;
  };
  components: SbomComponent[];
}

export async function generateSbom(projectPath: string): Promise<SbomDocument> {
  const skipped: string[] = [];
  const components: SbomComponent[] = [];
  for (const [name, parse] of [
    ["package.json", packageJsonComponents],
    ["requirements.txt", requirementsComponents]
  ] as const) {
    try {
      const content = await readManifest(projectPath, name);
      if (content !== undefined) components.push(...parse(content));
    } catch (error) {
      skipped.push(`${name}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: "bts-sec", version: "0.1.0" }],
      ...(skipped.length > 0 ? { properties: skipped.map((value) => ({ name: "bts-sec:skipped-manifest", value })) } : {})
    },
    components
  };
}

// Reads a manifest only if it resolves inside the target, so a symlinked
// manifest cannot pull files from elsewhere on disk into the report.
async function readManifest(projectPath: string, name: string): Promise<string | undefined> {
  const candidate = path.join(projectPath, name);
  let resolved: string;
  try {
    resolved = await fs.realpath(candidate);
  } catch {
    return undefined;
  }
  const relative = path.relative(await fs.realpath(projectPath), resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("resolves outside the target directory and was not read");
  }
  return fs.readFile(resolved, "utf8");
}

function packageJsonComponents(content: string): SbomComponent[] {
  const pkg = JSON.parse(content) as {
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

function requirementsComponents(content: string): SbomComponent[] {
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
