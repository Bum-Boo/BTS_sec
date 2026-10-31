// The value alternative accepts any quoted string (including spaces, so
// passphrases are redacted) or an unquoted run of 6+ characters. The optional
// quote after the key covers JSON-style `"client_secret": "..."` keys.
const SECRET_ASSIGNMENT =
  /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|JWT)[A-Z0-9_]*)(['"]?)\s*[:=]\s*(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[^'"`\s,;]{6,})/gi;
const AWS_ACCESS_KEY = /\bAKIA[0-9A-Z]{16}\b/g;
const GITHUB_TOKEN = /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g;
const STRIPE_SECRET_KEY = /\b[rs]k_live_[0-9A-Za-z]{16,}\b/g;
const SLACK_TOKEN = /\bxox[abposr]-[0-9A-Za-z-]{10,}/g;
const GOOGLE_API_KEY = /\bAIza[0-9A-Za-z_-]{35}\b/g;
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
    .replace(SECRET_ASSIGNMENT, (_match, key: string, quote: string) => `${key}${quote}=[REDACTED]`)
    .replace(AWS_ACCESS_KEY, "[REDACTED_AWS_ACCESS_KEY]")
    .replace(GITHUB_TOKEN, "[REDACTED_GITHUB_TOKEN]")
    .replace(STRIPE_SECRET_KEY, "[REDACTED_STRIPE_KEY]")
    .replace(SLACK_TOKEN, "[REDACTED_SLACK_TOKEN]")
    .replace(GOOGLE_API_KEY, "[REDACTED_GOOGLE_API_KEY]")
    .replace(BEARER_TOKEN, "Bearer [REDACTED]")
    .replace(BASIC_AUTH, "Basic [REDACTED]")
    .replace(URI_CREDENTIALS, "$1[REDACTED]:[REDACTED]@");
}
