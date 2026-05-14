const SECRET_ASSIGNMENT =
  /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|JWT)[A-Z0-9_]*)\s*[:=]\s*(['"]?)([^'"\s]{6,})\2/gi;
const AWS_ACCESS_KEY = /\bAKIA[0-9A-Z]{16}\b/g;
const AWS_SECRET_KEY = /\b[A-Za-z0-9/+=]{40}\b/g;
const GITHUB_TOKEN = /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g;
const GITLAB_TOKEN = /\bglpat-[A-Za-z0-9_-]{20,}\b/g;
const SLACK_TOKEN = /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g;
const STRIPE_KEY = /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g;
const NPM_TOKEN = /\bnpm_[A-Za-z0-9]{20,}\b/g;
const PYPI_TOKEN = /\bpypi-[A-Za-z0-9_-]{20,}\b/g;
const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const BEARER_TOKEN = /\bBearer\s+[A-Za-z0-9._~+/=-]{10,}/gi;
const BASIC_AUTH = /\bBasic\s+[A-Za-z0-9+/=]{10,}/gi;
const URI_CREDENTIALS = /(https?:\/\/)([^:\s/]+):([^@\s/]+)@/gi;
const DB_URL = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s/]+:[^@\s/]+@[^\s'"]+/gi;

export function redactSecrets(value: unknown): string {
  if (value === undefined || value === null) {
    return "";
  }

  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);

  return text
    .replace(PRIVATE_KEY_BLOCK, "[REDACTED_PRIVATE_KEY]")
    .replace(SECRET_ASSIGNMENT, (_match, key: string) => `${key}=[REDACTED]`)
    .replace(DB_URL, "[REDACTED_DB_URL]")
    .replace(AWS_ACCESS_KEY, "[REDACTED_AWS_ACCESS_KEY]")
    .replace(AWS_SECRET_KEY, "[REDACTED_AWS_SECRET_KEY]")
    .replace(GITHUB_TOKEN, "[REDACTED_GITHUB_TOKEN]")
    .replace(GITLAB_TOKEN, "[REDACTED_GITLAB_TOKEN]")
    .replace(SLACK_TOKEN, "[REDACTED_SLACK_TOKEN]")
    .replace(STRIPE_KEY, "[REDACTED_STRIPE_KEY]")
    .replace(NPM_TOKEN, "[REDACTED_NPM_TOKEN]")
    .replace(PYPI_TOKEN, "[REDACTED_PYPI_TOKEN]")
    .replace(JWT, "[REDACTED_JWT]")
    .replace(BEARER_TOKEN, "Bearer [REDACTED]")
    .replace(BASIC_AUTH, "Basic [REDACTED]")
    .replace(URI_CREDENTIALS, "$1[REDACTED]:[REDACTED]@");
}
