import type { VercelRequest, VercelResponse } from '@vercel/node';

export function getAllowedOrigins(): string[] {
  const env = process.env.ALLOWED_ORIGINS;
  if (env) return env.split(',').map(o => o.trim()).filter(Boolean);
  return [];
}

let _cachedPatterns: RegExp[] | null = null;

export function getAllowedOriginPatterns(): RegExp[] {
  if (_cachedPatterns !== null) return _cachedPatterns;
  const env = process.env.ALLOWED_ORIGIN_PATTERNS;
  if (!env) return (_cachedPatterns = []);
  _cachedPatterns = env
    .split(',')
    .map(p => p.trim())
    .filter(Boolean)
    .flatMap(p => {
      try {
        return [new RegExp(p)];
      } catch {
        return [];
      }
    });
  return _cachedPatterns;
}

export function isOriginAllowed(origin: string): boolean {
  if (getAllowedOrigins().includes(origin)) return true;
  return getAllowedOriginPatterns().some(pattern => pattern.test(origin));
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
