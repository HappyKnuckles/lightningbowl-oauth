import type { VercelRequest, VercelResponse } from '@vercel/node';
import { handleCallback } from '../../lib/oauth-handler';
import { dropboxProvider } from '../../lib/providers/dropbox';

export default function handler(req: VercelRequest, res: VercelResponse) {
  return handleCallback(req, res, dropboxProvider);
}
