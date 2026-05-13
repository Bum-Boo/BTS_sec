const SAFE_NUCLEI_TEMPLATE_ALLOWLIST = new Set([
  "http/misconfiguration/http-missing-security-headers.yaml",
  "http/misconfiguration/cors-misconfig.yaml",
  "http/exposures/configs/git-config.yaml",
  "http/exposures/files/env-file.yaml",
  "http/exposures/files/directory-listing.yaml",
  "http/exposures/files/backup-files.yaml"
]);

export function assertAllowedNucleiTemplates(templates: string[]): void {
  for (const template of templates) {
    if (!isAllowedNucleiTemplate(template)) {
      throw new Error(`Nuclei template is not allowlisted for safe mode: ${template}`);
    }
  }
}

export function isAllowedNucleiTemplate(template: string): boolean {
  const normalized = template.replace(/\\/g, "/").replace(/^\.?\//, "");
  if (normalized.includes("..")) {
    return false;
  }
  return SAFE_NUCLEI_TEMPLATE_ALLOWLIST.has(normalized);
}

export function safeNucleiTemplateAllowlist(): string[] {
  return [...SAFE_NUCLEI_TEMPLATE_ALLOWLIST].sort();
}
