const SECRET_ASSIGNMENT =
  /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|JWT)[A-Z0-9_]*)\s*[:=]\s*(['"]?)([^'"\s]{6,})\2/gi;
const AWS_ACCESS_KEY = /\bAKIA[0-9A-Z]{16}\b/g;
const GITHUB_TOKEN = /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g;
const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const BEARER_TOKEN = /\bBearer\s+[A-Za-z0-9._~+/=-]{10,}/gi;
const BASIC_AUTH = /\bBasic\s+[A-Za-z0-9+/=]{10,}/gi;
const URI_CREDENTIALS = /(https?:\/\/)([^:\s/]+):([^@\s/]+)@/gi;

export function redactSecrets(value: unknown): string {
  if (value === undefined || value === null) {
    return "";
  }

  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);

  return text
    .replace(PRIVATE_KEY_BLOCK, "[REDACTED_PRIVATE_KEY]")
    .replace(SECRET_ASSIGNMENT, (_match, key: string) => `${key}=[REDACTED]`)
    .replace(AWS_ACCESS_KEY, "[REDACTED_AWS_ACCESS_KEY]")
    .replace(GITHUB_TOKEN, "[REDACTED_GITHUB_TOKEN]")
    .replace(BEARER_TOKEN, "Bearer [REDACTED]")
    .replace(BASIC_AUTH, "Basic [REDACTED]")
    .replace(URI_CREDENTIALS, "$1[REDACTED]:[REDACTED]@");
}
