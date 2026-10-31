// Token shapes that are secret regardless of the surrounding assignment.
export const SECRET_TOKEN_PATTERNS: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /\b[rs]k_live_[0-9A-Za-z]{16,}\b/,
  /\bxox[abposr]-[0-9A-Za-z-]{10,}/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/
];

// name, optional closing quote of a JSON key, separator, then a quoted or bare value.
const ASSIGNMENT =
  /([A-Za-z_$][\w$.-]*)(["']?)\s*(?:=|:(?!:))\s*(?:"([^"\n]*)"|'([^'\n]*)'|`([^`\n]*)`|([^\s'"`,;)]+))/g;

const SECRET_WORDS = new Set(["secret", "token", "password", "passwd", "apikey", "privatekey", "clientsecret", "accesskey", "authtoken"]);
const SECRET_PAIRS = new Set(["api key", "private key", "access key"]);
// Names such as tokenUrl or passwordMinLength describe a secret rather than hold one.
const DESCRIPTIVE_SUFFIXES = new Set([
  "url", "uri", "endpoint", "path", "file", "name", "type", "field", "label", "header", "hint",
  "placeholder", "length", "ttl", "min", "max", "policy", "prompt", "message", "regex", "pattern", "seconds"
]);
const PLACEHOLDER =
  /^(?:<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|\$\(?[A-Za-z_][\w]*\)?|%[A-Za-z_]\w*%|(.)\1+|(?:your|my|replace|change|insert|enter)[-_ ].*|.*[-_ ](?:here|placeholder)|changeme|placeholder|example|dummy|redacted|null|undefined|none|true|false)$/i;

export function isSecretName(name: string): boolean {
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  if (words.length === 0 || DESCRIPTIVE_SUFFIXES.has(words[words.length - 1])) {
    return false;
  }
  return words.some((word, index) =>
    SECRET_WORDS.has(word) || SECRET_PAIRS.has(`${word} ${words[index + 1] ?? ""}`)
  );
}

export interface SecretAssignmentOptions {
  // Bare values are literals in .env/.ini/YAML style files, but expressions
  // (process.env.X, req.body.password) in programming languages.
  allowUnquoted: boolean;
  minLength?: number;
}

export function hasSecretAssignment(line: string, options: SecretAssignmentOptions): boolean {
  const minLength = options.minLength ?? 8;
  for (const match of line.matchAll(ASSIGNMENT)) {
    const [, name, , doubleQuoted, singleQuoted, backtick, bare] = match;
    const quoted = doubleQuoted ?? singleQuoted ?? backtick;
    if (quoted === undefined && !options.allowUnquoted) continue;
    const value = (quoted ?? bare ?? "").trim();
    if (value.length < minLength || PLACEHOLDER.test(value)) continue;
    if (backtick !== undefined && value.includes("${")) continue;
    if (isSecretName(name)) return true;
  }
  return false;
}

export function hasSecretToken(line: string): boolean {
  return SECRET_TOKEN_PATTERNS.some((pattern) => pattern.test(line));
}
