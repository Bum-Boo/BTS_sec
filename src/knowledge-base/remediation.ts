export const remediationByRule: Record<string, { recommendation: string; verification: string }> = {
  "web.missing-security-header": {
    recommendation: "Set the missing security header at the edge or application layer with the narrowest policy your application can support.",
    verification: "Repeat a HEAD or GET request and confirm the response includes the expected header and value."
  },
  "web.insecure-cookie": {
    recommendation: "Set Secure, HttpOnly, and SameSite on session or sensitive cookies. Use SameSite=Lax or Strict unless cross-site flows require None with Secure.",
    verification: "Authenticate in a test environment and inspect Set-Cookie headers for Secure, HttpOnly, and SameSite."
  },
  "web.unsafe-cors": {
    recommendation: "Avoid wildcard origins with credentials. Use a strict allowlist and validate the Origin header before returning CORS headers.",
    verification: "Send preflight requests from allowed and disallowed origins and confirm only approved origins are accepted."
  },
  "web.accidental-exposure": {
    recommendation: "Remove exposed files or debug endpoints from the deployed web root and block dotfiles, backups, and diagnostic routes at the edge.",
    verification: "Request the previously exposed path and confirm it returns 404, 403, or an intentional non-sensitive response."
  },
  "code.hardcoded-secret": {
    recommendation: "Move secrets to a managed secret store or environment-specific configuration and rotate any exposed values.",
    verification: "Confirm the code no longer contains the value and validate the rotated credential in the intended secret store."
  },
  "code.unsafe-cors": {
    recommendation: "Replace broad CORS settings with explicit trusted origins and avoid credentialed wildcard CORS.",
    verification: "Run unit or integration tests that reject untrusted Origin values."
  },
  "code.shell-execution": {
    recommendation: "Avoid shell invocation with user-controlled input. Prefer safe library APIs or spawn with fixed executable and validated arguments.",
    verification: "Trace all inputs to the shell call and confirm they are fixed or strictly allowlisted."
  },
  "code.eval-usage": {
    recommendation: "Remove dynamic code evaluation. Use safe parsers, expression evaluators, or explicit dispatch tables.",
    verification: "Search for eval, Function constructors, and dynamic execution APIs and confirm they are absent or justified."
  },
  "code.raw-sql": {
    recommendation: "Use parameterized queries or ORM query builders and avoid string interpolation or concatenation in SQL.",
    verification: "Review the query construction and add tests proving user input is bound as parameters."
  },
  "code.unsafe-upload": {
    recommendation: "Validate file type and size, store uploads outside the executable web root, and use generated filenames.",
    verification: "Upload disallowed file types in a test environment and confirm rejection without storing executable content."
  },
  "code.missing-authorization": {
    recommendation: "Apply explicit authorization middleware or policy checks to privileged routes and handlers.",
    verification: "Add negative authorization tests for anonymous and low-privilege users."
  },
  "code.dangerous-logging": {
    recommendation: "Remove secrets, tokens, credentials, and PII from logs. Use structured allowlisted fields.",
    verification: "Run tests or log review checks that confirm sensitive keys are redacted or omitted."
  }
};

export function remediationFor(ruleId: string, fallbackRecommendation: string, fallbackVerification: string) {
  return remediationByRule[ruleId] ?? {
    recommendation: fallbackRecommendation,
    verification: fallbackVerification
  };
}
