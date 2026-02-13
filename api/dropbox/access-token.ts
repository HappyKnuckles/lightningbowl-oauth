import type { VercelRequest, VercelResponse } from '@vercel/node';
import { handleAccessToken } from '../../lib/oauth-handler';
import { dropboxProvider } from '../../lib/providers/dropbox';

export default function handler(req: VercelRequest, res: VercelResponse) {
  return handleAccessToken(req, res, dropboxProvider);
}
