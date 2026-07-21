const REQUIRED_VARS = ['DATABASE_URL', 'SESSION_SECRET', 'ENCRYPTION_KEY'] as const;

/**
 * Fail fast on cold start if a required secret is missing. Without this,
 * a misconfigured deployment surfaces as a cryptic per-request HMAC/DB
 * error (and every session cookie silently fails to validate).
 */
export function validateEnv(): void {
  const missing = REQUIRED_VARS.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}
