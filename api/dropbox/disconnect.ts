import type { VercelRequest, VercelResponse } from '@vercel/node';
import { handleDisconnect } from '../../lib/oauth-handler';
import { dropboxProvider } from '../../lib/providers/dropbox';

export default function handler(req: VercelRequest, res: VercelResponse) {
  return handleDisconnect(req, res, dropboxProvider);
}
