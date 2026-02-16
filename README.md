# OAuth Service

Secure OAuth2 proxy service for cloud storage providers (Dropbox, Google Drive, OneDrive).
Used for Lightningbowl automatic file sync.

## Features

- PKCE + state parameter CSRF protection
- Session rotation on successful auth
- Token encryption at rest
- Automatic token refresh

## Setup

1. Install dependencies:
```bash
npm install
```

2. Set environment variables:
```env
DATABASE_URL=postgres://...
ENCRYPTION_KEY=32-byte-hex-key
COOKIE_SECRET=32-byte-hex-key
ALLOWED_ORIGINS=https://yourapp.com

DROPBOX_CLIENT_ID=...
DROPBOX_CLIENT_SECRET=...

GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...

ONEDRIVE_CLIENT_ID=...
ONEDRIVE_CLIENT_SECRET=...
```

3. Initialize database:
```bash
psql $DATABASE_URL -f sql/init.sql
```

4. Run locally:
```bash
vercel dev
```

```bash
npm run dev
```

## Endpoints

- `GET /api/{provider}/start?redirect=https://yourapp.com` - Start OAuth flow
- `GET /api/{provider}/callback` - OAuth callback (automatic)
- `GET /api/{provider}/access-token` - Get current access token
- `POST /api/{provider}/disconnect` - Revoke tokens

Replace `{provider}` with: `dropbox`, `google-drive`, or `onedrive`