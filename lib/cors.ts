import type { VercelRequest, VercelResponse } from '@vercel/node';

export function getAllowedOrigins(): string[] {
  const env = process.env.ALLOWED_ORIGINS;
  if (env) return env.split(',').map(o => o.trim()).filter(Boolean);
  return [];
}

let _cachedOriginMatchers: RegExp[] | null = null;

export function getAllowedOriginMatchers(): RegExp[] {
  if (_cachedOriginMatchers !== null) return _cachedOriginMatchers;
  _cachedOriginMatchers = getAllowedOrigins().flatMap(origin => {
    if (origin.startsWith('^')) {
      try {
        return [new RegExp(origin)];
      } catch {
        return [];
      }
    }
    return [new RegExp(`^${origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`)];
  });
  return _cachedOriginMatchers;
}

export function isOriginAllowed(origin: string): boolean {
  return getAllowedOriginMatchers().some(pattern => pattern.test(origin));
}

/**
 * Sets CORS headers and handles OPTIONS preflight.
 * Returns true if the request was a preflight (caller should return early).
 */
export function setCorsHeaders(req: VercelRequest, res: VercelResponse): boolean {
  const origin = req.headers.origin;

  if (origin && isOriginAllowed(origin)) {
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
