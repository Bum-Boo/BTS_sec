import fs from "node:fs/promises";
import path from "node:path";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext, Severity } from "../scanner-core/types";
import { pathExists } from "../utils/fs";

interface PackageJson {
  name?: string;
  packageManager?: string;
  private?: boolean;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

const JS_LOCKFILES = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"];
const LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];
const UNPINNED = /^(?:\*|latest|x|\^|~|>=|>|<=|<)/i;
const FLOATING_RANGE = /^(?:\*|latest|x|>=|>|<=|<)/i;
const GIT_OR_URL = /^(?:git\+|git:|https?:|ssh:|github:|gitlab:|bitbucket:)/i;
const INTERNAL_LOOKING_PACKAGE = /(?:^|[-_/])(internal|private|corp|company|enterprise|platform)(?:$|[-_/])/i;

export const supplyChainScanner: ScannerAdapter = {
  name: "supply-chain-static-scanner",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }

    const findings: Finding[] = [];
    findings.push(...await scanNodeSupplyChain(context));
    findings.push(...await scanPythonSupplyChain(context));
    findings.push(...await scanOtherEcosystems(context));
    return { findings };
  }
};

async function scanNodeSupplyChain(context: ScanContext): Promise<Finding[]> {
  const packageJsonPath = path.join(context.target.kind === "directory" ? context.target.path : "", "package.json");
  if (!(await pathExists(packageJsonPath))) return [];

  const pkg = JSON.parse(await fs.readFile(packageJsonPath, "utf8")) as PackageJson;
  const root = context.target.kind === "directory" ? context.target.path : "";
  const findings: Finding[] = [];
  const presentLocks = [];
  for (const lock of JS_LOCKFILES) {
    if (await pathExists(path.join(root, lock))) presentLocks.push(lock);
  }

  if (presentLocks.length === 0) {
    findings.push(finding(context, "supply-chain.lockfile-missing", "JavaScript manifest has no lockfile", "medium", "high", packageJsonPath, "package.json exists but package-lock.json, pnpm-lock.yaml, and yarn.lock are absent."));
  }
  if (presentLocks.length > 1) {
    findings.push(finding(context, "supply-chain.package-manager-mismatch", "Multiple JavaScript package manager lockfiles found", "medium", "high", packageJsonPath, `Found multiple lockfiles: ${presentLocks.join(", ")}.`));
  }
  if (pkg.packageManager) {
    const expected = pkg.packageManager.split("@")[0];
    const mismatch = presentLocks.some((lock) => !lockMatchesPackageManager(lock, expected));
    if (mismatch) {
      findings.push(finding(context, "supply-chain.package-manager-mismatch", "packageManager field does not match lockfile set", "medium", "high", packageJsonPath, `packageManager=${pkg.packageManager}; lockfiles=${presentLocks.join(", ") || "none"}.`));
    }
  }

  for (const [name, spec] of allNodeDependencies(pkg)) {
    if (UNPINNED.test(spec) && (presentLocks.length === 0 || FLOATING_RANGE.test(spec))) {
      findings.push(finding(context, "supply-chain.unpinned-dependency", "Unpinned dependency version", "low", "high", packageJsonPath, `${name} uses range ${spec}.`, name, undefined, false));
    }
    if (GIT_OR_URL.test(spec)) {
      findings.push(finding(context, "supply-chain.git-url-dependency", "Dependency is sourced from git or URL", "medium", "high", packageJsonPath, `${name} uses non-registry source ${spec}.`, name));
    }
    if (dependencyConfusionCandidate(name, pkg, await hasNpmrcForScope(root, name))) {
      findings.push(finding(context, "supply-chain.dependency-confusion-candidate", "Dependency confusion candidate", "medium", "medium", packageJsonPath, `${name} looks internal or scoped without a checked-in registry mapping.`, name));
    }
  }

  for (const scriptName of LIFECYCLE_SCRIPTS) {
    const script = pkg.scripts?.[scriptName];
    if (script) {
      findings.push(finding(context, "supply-chain.install-script-usage", "Package lifecycle install script is present", "medium", "high", packageJsonPath, `script ${scriptName} is defined. Script contents were not executed.`, undefined, undefined, false));
    }
  }

  return findings;
}

async function scanPythonSupplyChain(context: ScanContext): Promise<Finding[]> {
  if (context.target.kind !== "directory") return [];
  const findings: Finding[] = [];
  const requirementsPath = path.join(context.target.path, "requirements.txt");
  if (await pathExists(requirementsPath)) {
    const content = await fs.readFile(requirementsPath, "utf8");
    for (const line of content.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
      if (!/==/.test(trimmed)) {
        const name = trimmed.split(/[<>=~!]/)[0]?.trim();
        findings.push(finding(context, "supply-chain.unpinned-dependency", "Unpinned Python dependency", "low", "high", requirementsPath, `${name || "dependency"} is not pinned with ==.`, name, undefined, false));
      }
      if (/@\s*(?:git\+|https?:|ssh:)/i.test(trimmed)) {
        const name = trimmed.split(/\s*@\s*/)[0]?.trim();
        findings.push(finding(context, "supply-chain.git-url-dependency", "Python dependency is sourced from git or URL", "medium", "high", requirementsPath, `${name || "dependency"} uses a direct URL source.`, name));
      }
    }
  }

  const pyproject = path.join(context.target.path, "pyproject.toml");
  if (await pathExists(pyproject) && !(await pathExists(path.join(context.target.path, "poetry.lock")))) {
    findings.push(finding(context, "supply-chain.lockfile-missing", "Python project has no poetry.lock", "medium", "medium", pyproject, "pyproject.toml exists but poetry.lock was not found."));
  }

  const pipfile = path.join(context.target.path, "Pipfile");
  if (await pathExists(pipfile) && !(await pathExists(path.join(context.target.path, "Pipfile.lock")))) {
    findings.push(finding(context, "supply-chain.lockfile-missing", "Pipfile has no Pipfile.lock", "medium", "medium", pipfile, "Pipfile exists but Pipfile.lock was not found."));
  }

  return findings;
}

async function scanOtherEcosystems(context: ScanContext): Promise<Finding[]> {
  if (context.target.kind !== "directory") return [];
  const root = context.target.path;
  const pairs = [
    ["go.mod", "go.sum", "Go module has no go.sum"],
    ["Cargo.toml", "Cargo.lock", "Cargo manifest has no Cargo.lock"],
    ["build.gradle", "gradle.lockfile", "Gradle build has no gradle.lockfile"],
    ["build.gradle.kts", "gradle.lockfile", "Gradle build has no gradle.lockfile"]
  ];
  const findings: Finding[] = [];
  for (const [manifest, lockfile, title] of pairs) {
    const manifestPath = path.join(root, manifest);
    if (await pathExists(manifestPath) && !(await pathExists(path.join(root, lockfile)))) {
      findings.push(finding(context, "supply-chain.lockfile-missing", title, "medium", "medium", manifestPath, `${manifest} exists but ${lockfile} was not found.`));
    }
  }
  return findings;
}

function allNodeDependencies(pkg: PackageJson): Array<[string, string]> {
  return [
    ...Object.entries(pkg.dependencies ?? {}),
    ...Object.entries(pkg.devDependencies ?? {}),
    ...Object.entries(pkg.optionalDependencies ?? {})
  ];
}

function lockMatchesPackageManager(lockfile: string, packageManager: string): boolean {
  if (packageManager === "npm") return lockfile === "package-lock.json";
  if (packageManager === "pnpm") return lockfile === "pnpm-lock.yaml";
  if (packageManager === "yarn") return lockfile === "yarn.lock";
  return true;
}

async function hasNpmrcForScope(root: string, packageName: string): Promise<boolean> {
  if (!packageName.startsWith("@")) return false;
  const scope = packageName.split("/")[0];
  const npmrc = path.join(root, ".npmrc");
  if (!(await pathExists(npmrc))) return false;
  const content = await fs.readFile(npmrc, "utf8");
  return content.includes(`${scope}:registry=`);
}

function dependencyConfusionCandidate(name: string, pkg: PackageJson, scopeHasRegistry: boolean): boolean {
  if (name.startsWith("@") && !scopeHasRegistry && pkg.name?.startsWith(name.split("/")[0] ?? "")) return true;
  return INTERNAL_LOOKING_PACKAGE.test(name);
}

function finding(
  context: ScanContext,
  id: string,
  title: string,
  severity: Severity,
  confidence: "low" | "medium" | "high",
  file: string,
  evidence: string,
  dependencyName?: string,
  dependencyVersion?: string,
  fixAvailable?: boolean
): Finding {
  return normalizeFinding({
    id,
    title,
    severity,
    confidence,
    category: "supply-chain",
    sourceTool: "supply-chain-static-scanner",
    target: context.target.raw,
    file,
    dependencyName,
    dependencyVersion,
    fixAvailable,
    evidence: `${evidence} OWASP SCVS-style supply-chain hygiene check; no install scripts or package downloads were executed.`,
    recommendation: recommendationFor(id),
    verification: verificationFor(id),
    rawSource: { scvs: true, dependencyName }
  });
}

function recommendationFor(id: string): string {
  if (id.includes("lockfile")) return "Commit the correct lockfile for the package manager and keep CI installs locked or frozen.";
  if (id.includes("mismatch")) return "Use one package manager consistently and remove stale lockfiles.";
  if (id.includes("unpinned")) return "Pin exact versions in application manifests or rely on committed lockfiles with reproducible install settings.";
  if (id.includes("git-url")) return "Prefer registry packages with immutable versions; if a direct URL is required, pin a commit digest and review provenance.";
  if (id.includes("install-script")) return "Review lifecycle scripts, keep them minimal, and disable scripts in CI where not required.";
  return "Configure private registry scopes, reserve internal package names, and verify dependency source provenance.";
}

function verificationFor(id: string): string {
  if (id.includes("lockfile")) return "Run the package manager's frozen/locked install in CI and confirm it succeeds without modifying lockfiles.";
  if (id.includes("mismatch")) return "Confirm only the intended lockfile remains and packageManager matches it.";
  if (id.includes("unpinned")) return "Inspect dependency declarations and confirm exact or lockfile-governed versions are used.";
  if (id.includes("git-url")) return "Confirm direct sources are removed or pinned to immutable commits with reviewed provenance.";
  if (id.includes("install-script")) return "Review script contents manually and confirm CI policies prevent unexpected lifecycle execution.";
  return "Confirm private scopes have checked-in registry mappings and public registries cannot satisfy internal package names.";
}
