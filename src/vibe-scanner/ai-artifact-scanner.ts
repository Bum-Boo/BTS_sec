import fs from "node:fs/promises";
import path from "node:path";
import { normalizeFinding } from "../scanner-core/finding";
import { Finding, ScannerAdapter, ScanContext, Severity } from "../scanner-core/types";
import { pathExists, readFileLines, walkFiles } from "../utils/fs";

interface ArtifactRule {
  id: string;
  title: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  pattern: RegExp;
  why: string;
}

const AGENT_ARTIFACT_FILES = [
  ".cursorrules",
  ".github/copilot-instructions.md",
  "CLAUDE.md",
  "AGENTS.md",
  "GEMINI.md",
  ".windsurfrules",
  ".mcp.json",
  "mcp.json"
];

const AGENT_ARTIFACT_DIRS = [
  ".cursor/rules",
  ".cline",
  ".roo",
  ".github/workflows",
  "docs"
];

const TEXT_EXTENSIONS = new Set(["", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".rules", ".sh"]);

const RULES: ArtifactRule[] = [
  {
    id: "vibe.agent.hidden-instruction-injection",
    title: "AI rule file contains hidden instruction injection language",
    severity: "high",
    confidence: "medium",
    pattern: /\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+instructions\b/i,
    why: "Instruction override language can subvert the user's intended agent constraints when auto-loaded by an AI coding assistant."
  },
  {
    id: "vibe.agent.shell-profile-modification",
    title: "AI artifact instructs modification of shell profile files",
    severity: "high",
    confidence: "medium",
    pattern: /\.(bashrc|zshrc|profile|bash_profile|config\/fish\/config\.fish|powershell_profile)|\$PROFILE/i,
    why: "Shell profile changes can persist commands across terminal sessions and affect later agent or developer runs."
  },
  {
    id: "vibe.agent.curl-pipe-shell",
    title: "AI artifact contains curl or wget piped to a shell",
    severity: "critical",
    confidence: "high",
    pattern: /\b(?:curl|wget)\b[^\n|;&]*(?:\||\s+-O\s+-)[^\n]*(?:sh|bash|zsh|pwsh|powershell)\b/i,
    why: "Network-fetched scripts piped into shells bypass normal review and are unsafe for agent auto-execution."
  },
  {
    id: "vibe.agent.base64-execute",
    title: "AI artifact contains base64 decode and execute pattern",
    severity: "critical",
    confidence: "high",
    pattern: /\bbase64\b[^\n]*(?:-d|--decode|decode)[^\n]*(?:\||;|&&)[^\n]*(?:sh|bash|node|python|pwsh|powershell|iex|invoke-expression)\b/i,
    why: "Encoded command execution hides behavior from reviewers and can bypass simple command allowlists."
  },
  {
    id: "vibe.agent.exfil-like-command",
    title: "AI artifact contains outbound exfiltration-like command",
    severity: "high",
    confidence: "low",
    pattern: /\b(?:curl|wget|nc|netcat|Invoke-WebRequest|iwr)\b[^\n]*(?:\$HOME|~\/|\.env|id_rsa|\.ssh|token|secret|password|cookie)/i,
    why: "Commands that combine local sensitive paths or secret names with outbound network tools may leak developer or project data."
  },
  {
    id: "vibe.agent.auto-approve",
    title: "AI agent configuration appears to enable broad auto-approval",
    severity: "high",
    confidence: "medium",
    pattern: /\b(?:auto[_-]?approve|always[_-]?allow|allowAll|dangerouslyAllow|skipApproval)\b\s*[:=]\s*(?:true|["']?all["']?)/i,
    why: "Broad auto-approval can let an agent run file, shell, browser, or network actions without explicit human review."
  },
  {
    id: "vibe.agent.weaken-validation",
    title: "AI instructions may weaken validation, authentication, logging, or tests",
    severity: "medium",
    confidence: "low",
    pattern: /\b(?:skip|disable|remove|bypass)\b[^\n]*(?:auth|authorization|validation|logging|audit|test|typecheck|lint|csrf|rate limit)/i,
    why: "Generated instructions that reduce guardrails often create hidden security regressions in vibe-coded applications."
  }
];

export const aiArtifactScanner: ScannerAdapter = {
  name: "vibe-ai-artifact-scanner",
  async scan(context: ScanContext) {
    if (context.target.kind !== "directory") {
      return { findings: [] };
    }

    const findings: Finding[] = [];
    const files = await collectAgentArtifactFiles(context.target.path);
    for (const file of files) {
      findings.push(...await scanTextArtifact(context.target.path, file, context.target.raw));
    }
    findings.push(...await scanPackageScripts(context.target.path, context.target.raw));
    findings.push(...await scanMcpConfigs(context.target.path, context.target.raw));

    return { findings };
  }
};

async function collectAgentArtifactFiles(root: string): Promise<string[]> {
  const files = new Set<string>();
  for (const relative of AGENT_ARTIFACT_FILES) {
    const candidate = path.join(root, relative);
    if (await pathExists(candidate)) {
      files.add(candidate);
    }
  }

  for (const relativeDir of AGENT_ARTIFACT_DIRS) {
    const candidate = path.join(root, relativeDir);
    if (await pathExists(candidate)) {
      for (const file of await walkFiles(candidate, { extensions: TEXT_EXTENSIONS, maxBytes: 512 * 1024 })) {
        files.add(file);
      }
    }
  }

  return [...files];
}

async function scanTextArtifact(root: string, file: string, target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const lines = await readFileLines(file);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    for (const rule of RULES) {
      if (!rule.pattern.test(line)) {
        continue;
      }
      findings.push(agentFinding(rule, target, file, root, index + 1, line));
    }
  }
  return findings;
}

async function scanPackageScripts(root: string, target: string): Promise<Finding[]> {
  const packagePath = path.join(root, "package.json");
  if (!(await pathExists(packagePath))) {
    return [];
  }

  const pkg = JSON.parse(await fs.readFile(packagePath, "utf8")) as { scripts?: Record<string, string> };
  const findings: Finding[] = [];
  for (const [scriptName, script] of Object.entries(pkg.scripts ?? {})) {
    if (!/^(preinstall|postinstall|prepare|prepack)$/i.test(scriptName)) {
      continue;
    }
    for (const rule of RULES.filter((candidate) => candidate.severity === "critical" || candidate.id.includes("exfil"))) {
      if (rule.pattern.test(script)) {
        findings.push(agentFinding(rule, target, packagePath, root, undefined, `script ${scriptName}: ${script}`));
      }
    }
  }
  return findings;
}

async function scanMcpConfigs(root: string, target: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const relative of [".mcp.json", "mcp.json"]) {
    const file = path.join(root, relative);
    if (!(await pathExists(file))) {
      continue;
    }
    const raw = await fs.readFile(file, "utf8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      continue;
    }

    const flattened = JSON.stringify(parsed).toLowerCase();
    if (/filesystem|file-system|fs/.test(flattened) && /["']?(\/|c:\\\\|[a-z]:\\\\|\*)/.test(flattened)) {
      findings.push(normalizeFinding({
        id: "vibe.agent.mcp-broad-filesystem",
        title: "MCP configuration may expose broad filesystem access",
        severity: "high",
        confidence: "medium",
        category: "agent-config",
        vibeRiskCategory: "excessive-agent-permissions",
        targetType: "agent-artifact",
        sourceTool: "vibe-ai-artifact-scanner",
        target,
        file,
        evidence: "MCP config references filesystem capabilities with broad-looking root or wildcard access. Raw config values are not stored.",
        agentConfigRisk: true,
        recommendation: "Constrain MCP filesystem servers to the specific project directory and require explicit approval for file writes.",
        verification: "Review the MCP server args and confirm no root, home-directory, wildcard, or unrestricted filesystem access remains."
      }));
    }
    if (/(shell|command|exec|terminal|powershell|bash|cmd\.exe)/.test(flattened)) {
      findings.push(normalizeFinding({
        id: "vibe.agent.mcp-shell-execution",
        title: "MCP configuration exposes shell or command execution capability",
        severity: "high",
        confidence: "medium",
        category: "agent-config",
        vibeRiskCategory: "excessive-agent-permissions",
        targetType: "agent-artifact",
        sourceTool: "vibe-ai-artifact-scanner",
        target,
        file,
        evidence: "MCP config references shell, command, terminal, or exec capabilities. Raw config values are not stored.",
        agentConfigRisk: true,
        recommendation: "Remove arbitrary shell MCP servers or restrict them behind explicit approval and a narrow command allowlist.",
        verification: "Confirm the MCP config no longer exposes unrestricted shell or command execution tools."
      }));
    }
  }
  return findings;
}

function agentFinding(
  rule: ArtifactRule,
  target: string,
  file: string,
  root: string,
  line: number | undefined,
  evidenceLine: string
): Finding {
  return normalizeFinding({
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    confidence: rule.confidence,
    category: "agent-config",
    vibeRiskCategory: "ai-coding-assistant-artifact",
    targetType: "agent-artifact",
    sourceTool: "vibe-ai-artifact-scanner",
    target,
    file,
    line,
    evidence: `${path.relative(root, file)}${line ? `:${line}` : ""}: ${evidenceLine.trim()}. Risk: ${rule.why}`,
    agentConfigRisk: true,
    recommendation: "Review and remove or narrow the risky agent instruction. Keep agent rules explicit, scoped, and human-reviewable.",
    verification: "Re-run the vibe-risk profile and confirm the risky instruction is no longer reported."
  });
}
