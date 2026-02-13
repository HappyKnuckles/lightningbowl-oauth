import type { VercelRequest, VercelResponse } from '@vercel/node';
import { setCorsHeaders } from '../lib/cors';
import { ensureTable } from '../lib/db';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (setCorsHeaders(req, res)) return;

  try {
    await ensureTable();
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('[health]', err);
    res.status(500).json({ status: 'error', message: 'Database connection failed' });
  }
}
