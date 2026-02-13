import type { VercelRequest, VercelResponse } from '@vercel/node';
import { handleCallback } from '../../lib/oauth-handler';
import { googleProvider } from '../../lib/providers/google';

export default function handler(req: VercelRequest, res: VercelResponse) {
  return handleCallback(req, res, googleProvider);
}
