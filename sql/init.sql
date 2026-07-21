-- Schema for the OAuth token store. The service also creates this lazily
-- on first use (see lib/db.ts ensureTable), so running this is optional.
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
);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_session_id ON oauth_tokens(session_id);
