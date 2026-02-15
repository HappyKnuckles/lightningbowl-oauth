import type { VercelRequest, VercelResponse } from '@vercel/node';
import { handleDisconnect } from '../../lib/oauth-handler';
import { googleProvider } from '../../lib/providers/google';

export default function handler(req: VercelRequest, res: VercelResponse) {
  return handleDisconnect(req, res, googleProvider);
}
