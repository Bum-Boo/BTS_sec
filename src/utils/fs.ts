import fs from "node:fs/promises";
import path from "node:path";

const DEFAULT_IGNORE = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  ".nuxt",
  "coverage",
  "reports",
  "vendor",
  ".venv",
  "venv",
  "__pycache__",
  "target"
]);

export async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
}

export async function writeTextFile(filePath: string, content: string): Promise<void> {
  await ensureDir(path.dirname(filePath));
  await fs.writeFile(filePath, content, "utf8");
}

export async function pathExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function walkFiles(root: string, options: { extensions?: Set<string>; maxBytes?: number } = {}): Promise<string[]> {
  const files: string[] = [];
  await walk(root, files, options);
  return files;
}

async function walk(dir: string, files: string[], options: { extensions?: Set<string>; maxBytes?: number }): Promise<void> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (DEFAULT_IGNORE.has(entry.name)) {
      continue;
    }

    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(fullPath, files, options);
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    if (options.extensions && !options.extensions.has(path.extname(entry.name).toLowerCase()) && !options.extensions.has(entry.name.toLowerCase())) {
      continue;
    }
    if (options.maxBytes) {
      const stat = await fs.stat(fullPath);
      if (stat.size > options.maxBytes) {
        continue;
      }
    }
    files.push(fullPath);
  }
}

export async function readFileLines(filePath: string): Promise<string[]> {
  const content = await fs.readFile(filePath, "utf8");
  return content.split(/\r?\n/);
}
