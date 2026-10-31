import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";

export interface CommandResult {
  command: string;
  args: string[];
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export async function runCommand(
  command: string,
  args: string[],
  options: { cwd?: string; timeoutMs: number; input?: string } = { timeoutMs: 15000 }
): Promise<CommandResult> {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      shell: process.platform === "win32",
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, options.timeoutMs);

    child.stdout?.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (error) => {
      clearTimeout(timeout);
      resolve({
        command,
        args,
        exitCode: null,
        stdout,
        stderr: stderr || error.message,
        timedOut
      });
    });
    child.on("close", (exitCode) => {
      clearTimeout(timeout);
      resolve({
        command,
        args,
        exitCode,
        stdout,
        stderr,
        timedOut
      });
    });

    if (options.input) {
      child.stdin?.write(options.input);
    }
    child.stdin?.end();
  });
}

export async function commandExists(command: string, searchPath = process.env.PATH ?? ""): Promise<boolean> {
  if (process.platform === "win32") {
    const result = await runCommand("where", [command], { timeoutMs: 5000 });
    return result.exitCode === 0;
  }
  // `command -v` is a shell builtin, so it cannot be spawned without a shell.
  // Search PATH directly instead.
  for (const dir of searchPath.split(path.delimiter).filter(Boolean)) {
    try {
      await fs.access(path.join(dir, command), fs.constants.X_OK);
      return true;
    } catch {
      // keep searching
    }
  }
  return false;
}

export function summarizeCommandFailure(result: CommandResult): string {
  if (result.timedOut) {
    return `${result.command} timed out.`;
  }
  return `${result.command} exited with ${result.exitCode}: ${result.stderr || result.stdout}`.trim();
}
