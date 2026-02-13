import type { VercelRequest, VercelResponse } from '@vercel/node';
import { handleStart } from '../../lib/oauth-handler';
import { onedriveProvider } from '../../lib/providers/onedrive';

export default function handler(req: VercelRequest, res: VercelResponse) {
  return handleStart(req, res, onedriveProvider);
}
