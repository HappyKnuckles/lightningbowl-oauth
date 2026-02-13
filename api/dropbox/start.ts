import type { VercelRequest, VercelResponse } from '@vercel/node';
import { handleStart } from '../../lib/oauth-handler';
import { dropboxProvider } from '../../lib/providers/dropbox';

export default function handler(req: VercelRequest, res: VercelResponse) {
  return handleStart(req, res, dropboxProvider);
}
