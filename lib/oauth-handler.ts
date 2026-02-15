import type { VercelRequest, VercelResponse } from '@vercel/node';
import crypto from 'crypto';
import { setCorsHeaders } from './cors';
import { getSessionId, createSession, setSessionCookie } from './session';
import { generateCodeVerifier, generateCodeChallenge } from './pkce';
import { encrypt, decrypt } from './crypto';
import {
  upsertPendingAuth,
  getSession,
  storeTokens,
  updateAccessToken,
  migrateSession,
  deleteSession,
} from './db';
import { validateEnv } from './env-validation';
import { checkRateLimit, RateLimits } from './rate-limit';
import { validateCallbackParams, validateRedirectUrl } from './input-validation';

// Validate environment variables on cold start
// validateEnv();

/* ---------- types ---------- */

export interface ProviderConfig {
  /** URL-safe provider name used in DB + query params (e.g. "google-drive"). */
  name: string;
  /** Whether PKCE is used for this provider. */
  usesPkce: boolean;
  /** Build the authorization URL the user will be redirected to. */
  getAuthUrl(params: { state: string; codeChallenge?: string }): Promise<string>;
  /** Exchange an authorization code for tokens. */
  exchangeCode(params: {
    code: string;
    codeVerifier?: string;
  }): Promise<{ accessToken: string; refreshToken: string; expiresAt: Date }>;
  /** Use a refresh token to get a new access token. */
  refreshAccessToken(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken?: string; expiresAt: Date }>;
  /** Revoke a token at the provider (optional — if absent, only local disconnect). */
  revokeToken?: (token: string) => Promise<void>;
}

/* ---------- helpers ---------- */

function getAllowedOrigins(): string[] {
  const env = process.env.ALLOWED_ORIGINS;
  if (env) return env.split(',').map(o => o.trim());
  return [
    'https://lightningbowl.de',
    'https://test.lightningbowl.de',
    'http://localhost:8100',
  ];
}

function isValidRedirect(url: string): boolean {
  try {
    return getAllowedOrigins().includes(new URL(url).origin);
  } catch {
    return false;
  }
}

/* =================================================================
   /start — initiate OAuth flow
   ================================================================= */

export async function handleStart(
  req: VercelRequest,
  res: VercelResponse,
  provider: ProviderConfig,
): Promise<void> {
  if (setCorsHeaders(req, res)) return;

  try {
    // Rate limit by IP to prevent abuse
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || 'unknown';
    const rateLimit = checkRateLimit(`start:${ip}`, RateLimits.oauthStart);

    if (!rateLimit.success) {
      res.setHeader('Retry-After', Math.ceil((rateLimit.reset.getTime() - Date.now()) / 1000));
      res.status(429).json({
        error: 'Too many requests. Please try again later.',
      });
      return;
    }

    const allowedOrigins = getAllowedOrigins();
    const redirect = validateRedirectUrl(
      req.query.redirect as string,
      allowedOrigins,
    ) || allowedOrigins[0];

    // Re-use existing session or create a new one
    let sessionId = getSessionId(req);
    if (!sessionId) {
      sessionId = createSession(res);
    } else {
      setSessionCookie(res, sessionId); // refresh expiry
    }

    const state = crypto.randomBytes(32).toString('hex');
    let codeVerifier: string | undefined;
    let codeChallenge: string | undefined;

    if (provider.usesPkce) {
      codeVerifier = generateCodeVerifier();
      codeChallenge = generateCodeChallenge(codeVerifier);
    }

    await upsertPendingAuth(sessionId, provider.name, {
      state,
      pkceVerifier: codeVerifier,
      redirectUrl: redirect,
    });

    const authUrl = await provider.getAuthUrl({ state, codeChallenge });
    res.redirect(302, authUrl);
  } catch (err) {
    console.error(`[${provider.name}/start]`, {
      error: err instanceof Error ? err.message : 'Unknown error',
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ error: 'Failed to start authentication' });
  }
}

/* =================================================================
   /callback — handle the provider redirect
   ================================================================= */

export async function handleCallback(
  req: VercelRequest,
  res: VercelResponse,
  provider: ProviderConfig,
): Promise<void> {
  try {
    const {
      code,
      state,
      error: oauthErr,
      error_description: errDesc,
    } = req.query;

    const sessionId = getSessionId(req);
    const session = sessionId
      ? await getSession(sessionId, provider.name)
      : null;
    const fallbackUrl = session?.redirect_url || getAllowedOrigins()[0];

    /* ---- provider returned an error ---- */
    if (oauthErr) {
      const u = new URL(fallbackUrl);
      u.searchParams.set('provider', provider.name);
      u.searchParams.set('status', 'error');
      u.searchParams.set('message', 'Authentication failed');
      res.redirect(302, u.toString());
      return;
    }

    /* ---- validate callback params ---- */
    const params = validateCallbackParams(req.query);
    if (!params) {
      res.status(400).json({ error: 'Invalid callback parameters' });
      return;
    }

    /* ---- validate session ---- */
    if (!sessionId || !session) {
      res.status(401).json({ error: 'No valid session found' });
      return;
    }

    /* ---- CSRF protection: verify state ---- */
    if (session.state !== params.state) {
      console.warn('State mismatch detected', {
        sessionId: sessionId.substring(0, 8) + '...',
        provider: provider.name,
      });
      res.status(403).json({ error: 'Invalid request. Please try again.' });
      return;
    }

    /* ---- exchange code for tokens ---- */
    const tokens = await provider.exchangeCode({
      code: params.code,
      codeVerifier: session.pkce_verifier ?? undefined,
    });

    /* ---- SECURITY: Rotate session after successful auth ---- */
    const newSessionId = crypto.randomUUID();
    await migrateSession(sessionId, newSessionId, provider.name);
    setSessionCookie(res, newSessionId);

    /* ---- SECURITY: Encrypt BOTH refresh AND access tokens ---- */
    await storeTokens(newSessionId, provider.name, {
      encryptedRefreshToken: encrypt(tokens.refreshToken),
      accessToken: encrypt(tokens.accessToken),
      accessTokenExpiresAt: tokens.expiresAt,
    });

    /* ---- redirect user back to frontend ---- */
    const u = new URL(fallbackUrl);
    u.searchParams.set('provider', provider.name);
    u.searchParams.set('status', 'success');
    res.redirect(302, u.toString());
  } catch (err) {
    console.error(`[${provider.name}/callback]`, {
      error: err instanceof Error ? err.message : 'Unknown error',
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ error: 'Authentication failed. Please try again.' });
  }
}

/* =================================================================
   /access-token — return a short-lived access token to frontend
   ================================================================= */

export async function handleAccessToken(
  req: VercelRequest,
  res: VercelResponse,
  provider: ProviderConfig,
): Promise<void> {
  if (setCorsHeaders(req, res)) return;

  try {
    const sessionId = getSessionId(req);
    if (!sessionId) {
      res.status(401).json({ error: 'No session' });
      return;
    }

    /* ---- SECURITY: Rate limit by session ---- */
    const rateLimit = checkRateLimit(
      `access-token:${sessionId}:${provider.name}`,
      RateLimits.accessToken,
    );

    if (!rateLimit.success) {
      res.setHeader('X-RateLimit-Limit', String(rateLimit.limit));
      res.setHeader('X-RateLimit-Remaining', String(rateLimit.remaining));
      res.setHeader('X-RateLimit-Reset', rateLimit.reset.toISOString());
      res.setHeader('Retry-After', Math.ceil((rateLimit.reset.getTime() - Date.now()) / 1000));

      res.status(429).json({
        error: 'Too many requests',
        retry_after: rateLimit.reset.toISOString(),
      });
      return;
    }

    const session = await getSession(sessionId, provider.name);
    if (!session?.encrypted_refresh_token) {
      res.status(404).json({ error: `Not connected to ${provider.name}` });
      return;
    }

    /* ---- return cached token if still valid (5 min buffer) ---- */
    if (session.access_token && session.access_token_expires_at) {
      const exp = new Date(session.access_token_expires_at).getTime();
      if (exp - 5 * 60_000 > Date.now()) {
        res.setHeader('X-RateLimit-Limit', String(rateLimit.limit));
        res.setHeader('X-RateLimit-Remaining', String(rateLimit.remaining));

        res.json({
          access_token: decrypt(session.access_token),
          expires_at: session.access_token_expires_at,
          provider: provider.name,
        });
        return;
      }
    }

    /* ---- refresh ---- */
    const refreshToken = decrypt(session.encrypted_refresh_token);
    const result = await provider.refreshAccessToken(refreshToken);

    const update: Parameters<typeof updateAccessToken>[2] = {
      accessToken: encrypt(result.accessToken),
      accessTokenExpiresAt: result.expiresAt,
    };
    // Some providers rotate refresh tokens
    if (result.refreshToken) {
      update.encryptedRefreshToken = encrypt(result.refreshToken);
    }
    await updateAccessToken(sessionId, provider.name, update);

    res.setHeader('X-RateLimit-Limit', String(rateLimit.limit));
    res.setHeader('X-RateLimit-Remaining', String(rateLimit.remaining));

    res.json({
      access_token: result.accessToken,
      expires_at: result.expiresAt.toISOString(),
      provider: provider.name,
    });
  } catch (err) {
    console.error(`[${provider.name}/access-token]`, {
      error: err instanceof Error ? err.message : 'Unknown error',
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ error: 'Failed to retrieve access token' });
  }
}

/* =================================================================
   /disconnect — revoke stored tokens for a provider
   ================================================================= */

export async function handleDisconnect(
  req: VercelRequest,
  res: VercelResponse,
  provider: ProviderConfig,
): Promise<void> {
  if (setCorsHeaders(req, res)) return;

  try {
    const sessionId = getSessionId(req);
    if (!sessionId) {
      res.status(401).json({ error: 'No session' });
      return;
    }

    // Revoke token at the provider before deleting locally
    if (provider.revokeToken) {
      const session = await getSession(sessionId, provider.name);
      if (session?.encrypted_refresh_token) {
        const refreshToken = decrypt(session.encrypted_refresh_token);
        try {
          await provider.revokeToken(refreshToken);
        } catch (revokeErr) {
          // Log but don't block — still delete the local session
          console.warn(`[${provider.name}/disconnect] Token revocation at provider failed:`, {
            error: revokeErr instanceof Error ? revokeErr.message : 'Unknown error',
            timestamp: new Date().toISOString(),
          });
        }
      }
    }

    await deleteSession(sessionId, provider.name);

    res.json({
      success: true,
      message: `Disconnected from ${provider.name}`,
    });
  } catch (err) {
    console.error(`[${provider.name}/disconnect]`, {
      error: err instanceof Error ? err.message : 'Unknown error',
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ error: 'Failed to disconnect' });
  }
}
