import type { VercelRequest, VercelResponse } from '@vercel/node';
import { handleCallback } from '../../lib/oauth-handler';
import { onedriveProvider } from '../../lib/providers/onedrive';

export default function handler(req: VercelRequest, res: VercelResponse) {
  return handleCallback(req, res, onedriveProvider);
}
