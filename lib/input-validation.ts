/**
 * Input validation helpers to prevent injection attacks and malformed data.
 */

export interface CallbackParams {
  code: string;
  state: string;
}

/**
 * Validate OAuth callback query parameters.
 * Returns null if validation fails.
 */
export function validateCallbackParams(query: any): CallbackParams | null {
  const { code, state } = query;

  // Type checks
  if (typeof code !== 'string' || typeof state !== 'string') {
    return null;
  }

  // Length checks (prevent DoS via huge params)
  if (code.length === 0 || code.length > 2048) {
    return null;
  }

  // State should be 64 hex characters (32 bytes)
  if (state.length !== 64) {
    return null;
  }

  // State format check (only hex chars)
  if (!/^[a-f0-9]{64}$/i.test(state)) {
    return null;
  }

  return { code, state };
}

/**
 * Validate redirect URL.
 * Ensures only allowed origins are used.
 */
export function validateRedirectUrl(
  url: string | undefined,
  allowedOrigins: string[],
): string | null {
  if (!url || typeof url !== 'string') {
    return null;
  }

  // Length check
  if (url.length > 2048) {
    return null;
  }

  try {
    const parsed = new URL(url);

    // Must be HTTPS in production (or http://localhost for dev)
    if (parsed.protocol !== 'https:' && !url.startsWith('http://localhost')) {
      return null;
    }

    // Must be in allowed list
    if (!allowedOrigins.includes(parsed.origin)) {
      return null;
    }

    return url;
  } catch {
    return null;
  }
}

/**
 * Validate provider name to prevent injection.
 * Provider names should be alphanumeric + hyphens only.
 */
export function validateProviderName(provider: string | undefined): string | null {
  if (!provider || typeof provider !== 'string') {
    return null;
  }

  // Must be lowercase alphanumeric + hyphens, 3-30 chars
  if (!/^[a-z0-9-]{3,30}$/.test(provider)) {
    return null;
  }

  return provider;
}

/**
 * Validate session ID format.
 * Should be a valid UUIDv4.
 */
export function validateSessionId(sessionId: string | undefined): string | null {
  if (!sessionId || typeof sessionId !== 'string') {
    return null;
  }

  // UUID v4 format
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  if (!uuidRegex.test(sessionId)) {
    return null;
  }

  return sessionId;
}
