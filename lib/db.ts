import { neon } from '@neondatabase/serverless';

let initialized = false;

function sql() {
  return neon(process.env.DATABASE_URL!);
}

/** Lazy table creation — runs once per cold start. */
export async function ensureTable(): Promise<void> {
  if (initialized) return;
  const db = sql();
  await db`
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      session_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      state TEXT,
      pkce_verifier TEXT,
      encrypted_refresh_token TEXT,
      access_token TEXT,
      access_token_expires_at TIMESTAMPTZ,
      redirect_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(session_id, provider)
    )
  `;
  initialized = true;
}

/* ---------- types ---------- */

export interface OAuthSession {
  id: string;
  session_id: string;
  provider: string;
  state: string | null;
  pkce_verifier: string | null;
  encrypted_refresh_token: string | null;
  access_token: string | null;
  access_token_expires_at: string | null;
  redirect_url: string | null;
}

/* ---------- queries ---------- */

/** Insert or update a pending OAuth flow (state, PKCE, redirect). */
export async function upsertPendingAuth(
  sessionId: string,
  provider: string,
  data: { state: string; pkceVerifier?: string; redirectUrl?: string },
): Promise<void> {
  await ensureTable();
  const db = sql();
  await db`
    INSERT INTO oauth_tokens (session_id, provider, state, pkce_verifier, redirect_url)
    VALUES (${sessionId}, ${provider}, ${data.state}, ${data.pkceVerifier ?? null}, ${data.redirectUrl ?? null})
    ON CONFLICT (session_id, provider) DO UPDATE SET
      state = EXCLUDED.state,
      pkce_verifier = EXCLUDED.pkce_verifier,
      redirect_url = EXCLUDED.redirect_url,
      updated_at = NOW()
  `;
}

/** Retrieve a session row for a given session+provider. */
export async function getSession(
  sessionId: string,
  provider: string,
): Promise<OAuthSession | null> {
  await ensureTable();
  const db = sql();
  const rows = await db`
    SELECT * FROM oauth_tokens
    WHERE session_id = ${sessionId} AND provider = ${provider}
  `;
  return (rows[0] as OAuthSession) ?? null;
}

/** Store tokens after a successful OAuth callback. Clears ephemeral state/PKCE. */
export async function storeTokens(
  sessionId: string,
  provider: string,
  data: {
    encryptedRefreshToken: string;
    accessToken: string;
    accessTokenExpiresAt: Date;
  },
): Promise<void> {
  const db = sql();
  await db`
    UPDATE oauth_tokens SET
      encrypted_refresh_token = ${data.encryptedRefreshToken},
      access_token = ${data.accessToken},
      access_token_expires_at = ${data.accessTokenExpiresAt.toISOString()},
      state = NULL,
      pkce_verifier = NULL,
      updated_at = NOW()
    WHERE session_id = ${sessionId} AND provider = ${provider}
  `;
}

/** Update the access token (and optionally a rotated refresh token). */
export async function updateAccessToken(
  sessionId: string,
  provider: string,
  data: {
    accessToken: string;
    accessTokenExpiresAt: Date;
    encryptedRefreshToken?: string;
  },
): Promise<void> {
  const db = sql();
  if (data.encryptedRefreshToken) {
    await db`
      UPDATE oauth_tokens SET
        access_token = ${data.accessToken},
        access_token_expires_at = ${data.accessTokenExpiresAt.toISOString()},
        encrypted_refresh_token = ${data.encryptedRefreshToken},
        updated_at = NOW()
      WHERE session_id = ${sessionId} AND provider = ${provider}
    `;
  } else {
    await db`
      UPDATE oauth_tokens SET
        access_token = ${data.accessToken},
        access_token_expires_at = ${data.accessTokenExpiresAt.toISOString()},
        updated_at = NOW()
      WHERE session_id = ${sessionId} AND provider = ${provider}
    `;
  }
}

/** Delete the stored tokens for a provider (disconnect). */
export async function deleteSession(
  sessionId: string,
  provider: string,
): Promise<void> {
  const db = sql();
  await db`
    DELETE FROM oauth_tokens
    WHERE session_id = ${sessionId} AND provider = ${provider}
  `;
}

/** 
 * Migrate a session to a new session ID (for session rotation after login).
 * This prevents session fixation attacks.
 */
export async function migrateSession(
  oldSessionId: string,
  newSessionId: string,
  provider: string,
): Promise<void> {
  const db = sql();
  await db`
    UPDATE oauth_tokens 
    SET session_id = ${newSessionId}, updated_at = NOW()
    WHERE session_id = ${oldSessionId} AND provider = ${provider}
  `;
}
