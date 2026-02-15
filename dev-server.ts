import dotenv from 'dotenv';
dotenv.config({ path: '.env.development.local' });
dotenv.config(); // fallback to .env

import express from 'express';
import cookieParser from 'cookie-parser';
import type { VercelRequest, VercelResponse } from '@vercel/node';

// Import all handlers
import googleStartHandler from './api/google-drive/start';
import googleCallbackHandler from './api/google-drive/callback';
import googleAccessTokenHandler from './api/google-drive/access-token';
import onedriveStartHandler from './api/onedrive/start';
import onedriveCallbackHandler from './api/onedrive/callback';
import onedriveAccessTokenHandler from './api/onedrive/access-token';
import dropboxStartHandler from './api/dropbox/start';
import dropboxCallbackHandler from './api/dropbox/callback';
import dropboxAccessTokenHandler from './api/dropbox/access-token';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Adapter to convert Express req/res to Vercel-compatible objects
function wrapHandler(handler: (req: VercelRequest, res: VercelResponse) => Promise<void> | void) {
  return async (req: express.Request, res: express.Response) => {
    // Create a Vercel-like request object
    const vercelReq = req as unknown as VercelRequest;
    vercelReq.query = req.query as Record<string, string | string[]>;
    vercelReq.cookies = req.cookies || {};

    // Create a Vercel-like response object
    const vercelRes = res as unknown as VercelResponse;

    try {
      await handler(vercelReq, vercelRes);
    } catch (err) {
      console.error('Handler error:', err);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Internal server error' });
      }
    }
  };
}

// Google Drive
app.all('/google-drive/start', wrapHandler(googleStartHandler));
app.all('/google-drive/callback', wrapHandler(googleCallbackHandler));
app.all('/google-drive/access-token', wrapHandler(googleAccessTokenHandler));
app.all('/google-drive/disconnect', wrapHandler((req, res) => import('./api/google-drive/disconnect').then(mod => mod.default(req, res))));

// OneDrive
app.all('/onedrive/start', wrapHandler(onedriveStartHandler));
app.all('/onedrive/callback', wrapHandler(onedriveCallbackHandler));
app.all('/onedrive/access-token', wrapHandler(onedriveAccessTokenHandler));
app.all('/onedrive/disconnect', wrapHandler((req, res) => import('./api/onedrive/disconnect').then(mod => mod.default(req, res))));

// Dropbox
app.all('/dropbox/start', wrapHandler(dropboxStartHandler));
app.all('/dropbox/callback', wrapHandler(dropboxCallbackHandler));
app.all('/dropbox/access-token', wrapHandler(dropboxAccessTokenHandler));
app.all('/dropbox/disconnect', wrapHandler((req, res) => import('./api/dropbox/disconnect').then(mod => mod.default(req, res))));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Dev server running at http://localhost:${PORT}`);
});
