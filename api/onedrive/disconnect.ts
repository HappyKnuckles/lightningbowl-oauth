import type { VercelRequest, VercelResponse } from '@vercel/node';
import { handleDisconnect } from '../../lib/oauth-handler';
import { onedriveProvider } from '../../lib/providers/onedrive';

export default function handler(req: VercelRequest, res: VercelResponse) {
  return handleDisconnect(req, res, onedriveProvider);
}
