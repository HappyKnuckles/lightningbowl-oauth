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

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_session ON oauth_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_created ON oauth_tokens(created_at);
