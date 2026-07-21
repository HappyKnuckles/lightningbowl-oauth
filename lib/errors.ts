/**
 * Thrown when a provider definitively rejects the stored refresh token
 * (revoked by the user, expired through inactivity, or superseded).
 * This is the only refresh failure that requires the user to reauthenticate;
 * every other failure is treated as transient and retried.
 */
export class RefreshTokenInvalidError extends Error {
  constructor(provider: string, detail?: string) {
    super(`Refresh token no longer valid for ${provider}${detail ? ` (${detail})` : ''}`);
    this.name = 'RefreshTokenInvalidError';
  }
}

/**
 * Decide whether a failed token-refresh response means the refresh token
 * itself is dead. All three providers signal this with a 400/401 and an
 * OAuth error code in the body (`invalid_grant` for Google/Microsoft/Dropbox,
 * plus Microsoft's `interaction_required` family). 5xx, 429 and network
 * errors are transient and must NOT match here.
 */
export function isInvalidGrantResponse(status: number, body: string): boolean {
  if (status !== 400 && status !== 401) return false;
  return /invalid_grant|interaction_required|consent_required|login_required/i.test(body);
}
