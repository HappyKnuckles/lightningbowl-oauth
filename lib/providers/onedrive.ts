import { ConfidentialClientApplication } from '@azure/msal-node';
import type { ProviderConfig } from '../oauth-handler';

const SCOPES = ['Files.ReadWrite', 'offline_access'];
const TOKEN_URL =
  'https://login.microsoftonline.com/common/oauth2/v2.0/token';

function redirectUri(): string {
  const base = process.env.BACKEND_URL || 'https://oauth.lightningbowl.de';
  return `${base}/onedrive/callback`;
}

function msalApp(): ConfidentialClientApplication {
  return new ConfidentialClientApplication({
    auth: {
      clientId: process.env.ONEDRIVE_CLIENT_ID!,
      clientSecret: process.env.ONEDRIVE_CLIENT_SECRET!,
      authority: 'https://login.microsoftonline.com/common',
    },
  });
}

export const onedriveProvider: ProviderConfig = {
  name: 'onedrive',
  usesPkce: true,

  async getAuthUrl({ state, codeChallenge }) {
    return msalApp().getAuthCodeUrl({
      scopes: SCOPES,
      redirectUri: redirectUri(),
      state,
      codeChallenge,
      codeChallengeMethod: 'S256',
    });
  },

  async exchangeCode({ code, codeVerifier }) {
    const res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.ONEDRIVE_CLIENT_ID!,
        client_secret: process.env.ONEDRIVE_CLIENT_SECRET!,
        code,
        redirect_uri: redirectUri(),
        grant_type: 'authorization_code',
        code_verifier: codeVerifier!,
      }).toString(),
    });

    if (!res.ok) {
      throw new Error(`OneDrive token exchange failed: ${await res.text()}`);
    }

    const data: any = await res.json();
    if (!data.access_token || !data.refresh_token) {
      throw new Error('OneDrive did not return required tokens');
    }

    return {
      accessToken: data.access_token as string,
      refreshToken: data.refresh_token as string,
      expiresAt: new Date(Date.now() + (data.expires_in ?? 3600) * 1000),
    };
  },

  async refreshAccessToken(refreshToken) {
    const res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.ONEDRIVE_CLIENT_ID!,
        client_secret: process.env.ONEDRIVE_CLIENT_SECRET!,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: SCOPES.join(' '),
      }).toString(),
    });

    if (!res.ok) {
      throw new Error(`OneDrive refresh failed: ${await res.text()}`);
    }

    const data: any = await res.json();
    if (!data.access_token) {
      throw new Error('OneDrive refresh returned no access token');
    }

    return {
      accessToken: data.access_token as string,
      refreshToken: data.refresh_token as string | undefined, // Microsoft may rotate
      expiresAt: new Date(Date.now() + (data.expires_in ?? 3600) * 1000),
    };
  },
};
