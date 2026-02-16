import { OAuth2Client, CodeChallengeMethod } from 'google-auth-library';
import type { ProviderConfig } from '../oauth-handler';

const SCOPES = ['https://www.googleapis.com/auth/drive.file'];

function redirectUri(): string {
  const base = process.env.BACKEND_URL || 'https://oauth.lightningbowl.de';
  return `${base}/google-drive/callback`;
}

function client(): OAuth2Client {
  return new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID!,
    process.env.GOOGLE_CLIENT_SECRET!,
    redirectUri(),
  );
}

export const googleProvider: ProviderConfig = {
  name: 'google-drive',
  usesPkce: true,

  async getAuthUrl({ state, codeChallenge }) {
    return client().generateAuthUrl({
      access_type: 'offline',
      scope: SCOPES,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: CodeChallengeMethod.S256,
      prompt: 'consent',
    });
  },

  async exchangeCode({ code, codeVerifier }) {
    const { tokens } = await client().getToken({ code, codeVerifier });
    if (!tokens.access_token || !tokens.refresh_token) {
      throw new Error('Google did not return required tokens');
    }
    return {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: new Date(tokens.expiry_date ?? Date.now() + 3_600_000),
    };
  },

  async refreshAccessToken(refreshToken) {
    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID!,
        client_secret: process.env.GOOGLE_CLIENT_SECRET!,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      }).toString(),
    });

    if (!res.ok) {
      throw new Error(`Google refresh failed: ${await res.text()}`);
    }

    const data: any = await res.json();
    if (!data.access_token) {
      throw new Error('Google refresh returned no access token');
    }

    return {
      accessToken: data.access_token as string,
      expiresAt: new Date(Date.now() + (data.expires_in ?? 3600) * 1000),
    };
  },

  async revokeToken(token) {
    const res = await fetch(
      `https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      },
    );

    if (!res.ok) {
      throw new Error(`Google token revocation failed (${res.status}): ${await res.text()}`);
    }
  },
};
