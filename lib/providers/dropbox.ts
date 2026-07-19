import { DropboxAuth } from 'dropbox';
import type { ProviderConfig } from '../oauth-handler';
import { RefreshTokenInvalidError, isInvalidGrantResponse } from '../errors';

const TOKEN_URL = 'https://api.dropboxapi.com/oauth2/token';

function redirectUri(): string {
  const base = process.env.BACKEND_URL || 'https://oauth.lightningbowl.de';
  return `${base}/dropbox/callback`;
}

function auth(): DropboxAuth {
  return new DropboxAuth({
    clientId: process.env.DROPBOX_CLIENT_ID!,
    clientSecret: process.env.DROPBOX_CLIENT_SECRET!,
  });
}

function basicAuth(): string {
  return Buffer.from(
    `${process.env.DROPBOX_CLIENT_ID}:${process.env.DROPBOX_CLIENT_SECRET}`,
  ).toString('base64');
}

export const dropboxProvider: ProviderConfig = {
  name: 'dropbox',
  usesPkce: false,

  async getAuthUrl({ state }) {
    const dbxAuth = auth();
    const url = await dbxAuth.getAuthenticationUrl(
      redirectUri(),
      state,
      'code',
      'offline',
    );
    return url.toString();
  },

  async exchangeCode({ code }) {
    const dbxAuth = auth();
    const response = await dbxAuth.getAccessTokenFromCode(
      redirectUri(),
      code,
    );
    const result = response.result as Record<string, any>;

    if (!result.access_token || !result.refresh_token) {
      throw new Error('Dropbox did not return required tokens');
    }

    return {
      accessToken: result.access_token as string,
      refreshToken: result.refresh_token as string,
      expiresAt: new Date(Date.now() + (result.expires_in ?? 14400) * 1000),
    };
  },

  async refreshAccessToken(refreshToken) {
    const res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${basicAuth()}`,
      },
      body: new URLSearchParams({
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      }).toString(),
    });

    if (!res.ok) {
      const body = await res.text();
      if (isInvalidGrantResponse(res.status, body)) {
        throw new RefreshTokenInvalidError('dropbox');
      }
      throw new Error(`Dropbox refresh failed (${res.status})`);
    }

    const data: any = await res.json();
    if (!data.access_token) {
      throw new Error('Dropbox refresh returned no access token');
    }

    return {
      accessToken: data.access_token as string,
      expiresAt: new Date(Date.now() + (data.expires_in ?? 14400) * 1000),
    };
  },

  async revokeToken(refreshToken) {
    // /2/auth/token/revoke only accepts an *access* token; revoking it also
    // revokes the paired refresh token. Exchange first, then revoke.
    let accessToken: string;
    try {
      const result = await this.refreshAccessToken(refreshToken);
      accessToken = result.accessToken;
    } catch (err) {
      // Already revoked/expired at Dropbox — nothing left to revoke.
      if (err instanceof RefreshTokenInvalidError) return;
      throw err;
    }

    const res = await fetch('https://api.dropboxapi.com/2/auth/token/revoke', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!res.ok) {
      throw new Error(`Dropbox token revocation failed (${res.status})`);
    }
  },
};
