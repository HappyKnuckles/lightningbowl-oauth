import type { VercelRequest, VercelResponse } from '@vercel/node';

function getAllowedOrigins(): string[] {
  const env = process.env.ALLOWED_ORIGINS;
  if (env) return env.split(',').map(o => o.trim());
  return [
    'https://lightningbowl.de',
    'https://test.lightningbowl.de',
    'http://localhost:8100',
  ];
}

/**
 * Sets CORS headers and handles OPTIONS preflight.
 * Returns true if the request was a preflight (caller should return early).
 */
export function setCorsHeaders(req: VercelRequest, res: VercelResponse): boolean {
  const origin = req.headers.origin;
  const allowed = getAllowedOrigins();

  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400');
  }

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return true;
  }

  return false;
}
