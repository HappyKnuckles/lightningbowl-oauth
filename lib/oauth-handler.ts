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
} from './db';

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
    const redirect =
      (req.query.redirect as string) || getAllowedOrigins()[0];

    if (!isValidRedirect(redirect)) {
      res.status(400).json({ error: 'Invalid redirect URL' });
      return;
    }

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
    console.error(`[${provider.name}/start]`, err);
    res.status(500).json({ error: 'Failed to start OAuth flow' });
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
      u.searchParams.set('error', String(errDesc || oauthErr));
      res.redirect(302, u.toString());
      return;
    }

    /* ---- basic validation ---- */
    if (!code || !state) {
      res.status(400).json({ error: 'Missing code or state parameter' });
      return;
    }
    if (!sessionId || !session) {
      res.status(401).json({ error: 'No valid session found' });
      return;
    }
    if (session.state !== String(state)) {
      res.status(403).json({ error: 'State mismatch — possible CSRF attack' });
      return;
    }

    /* ---- exchange code for tokens ---- */
    const tokens = await provider.exchangeCode({
      code: String(code),
      codeVerifier: session.pkce_verifier ?? undefined,
    });

    /* ---- persist encrypted refresh token ---- */
    await storeTokens(sessionId, provider.name, {
      encryptedRefreshToken: encrypt(tokens.refreshToken),
      accessToken: tokens.accessToken,
      accessTokenExpiresAt: tokens.expiresAt,
    });

    /* ---- redirect user back to frontend ---- */
    const u = new URL(fallbackUrl);
    u.searchParams.set('provider', provider.name);
    u.searchParams.set('status', 'success');
    res.redirect(302, u.toString());
  } catch (err) {
    console.error(`[${provider.name}/callback]`, err);
    res.status(500).json({ error: 'OAuth callback failed' });
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

    const session = await getSession(sessionId, provider.name);
    if (!session?.encrypted_refresh_token) {
      res.status(404).json({ error: `Not connected to ${provider.name}` });
      return;
    }

    /* ---- return cached token if still valid (5 min buffer) ---- */
    if (session.access_token && session.access_token_expires_at) {
      const exp = new Date(session.access_token_expires_at).getTime();
      if (exp - 5 * 60_000 > Date.now()) {
        res.json({
          access_token: session.access_token,
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
      accessToken: result.accessToken,
      accessTokenExpiresAt: result.expiresAt,
    };
    // Some providers rotate refresh tokens
    if (result.refreshToken) {
      update.encryptedRefreshToken = encrypt(result.refreshToken);
    }
    await updateAccessToken(sessionId, provider.name, update);

    res.json({
      access_token: result.accessToken,
      expires_at: result.expiresAt.toISOString(),
      provider: provider.name,
    });
  } catch (err) {
    console.error(`[${provider.name}/access-token]`, err);
    res.status(500).json({ error: 'Failed to retrieve access token' });
  }
}
