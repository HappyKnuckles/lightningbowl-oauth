/**
 * Simple in-memory rate limiter (for demo - use Redis/Upstash in production!)
 * 
 * Production-ready alternative:
 * - Upstash Redis: https://upstash.com/docs/redis/features/ratelimiting
 * - Vercel Edge Config
 * - CloudFlare rate limiting
 */

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

// Cleanup old entries every 5 minutes
const store = new Map<string, RateLimitEntry>();
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of store.entries()) {
    if (entry.resetAt < now) store.delete(key);
  }
}, 5 * 60 * 1000);

export interface RateLimitConfig {
  /** Maximum requests allowed in the window */
  maxRequests: number;
  /** Window duration in milliseconds */
  windowMs: number;
}

export interface RateLimitResult {
  success: boolean;
  limit: number;
  remaining: number;
  reset: Date;
}

/**
 * Check if the given identifier has exceeded the rate limit.
 * 
 * @example
 * const result = checkRateLimit('session-123', { maxRequests: 10, windowMs: 60000 });
 * if (!result.success) {
 *   return res.status(429).json({ error: 'Too many requests' });
 * }
 */
export function checkRateLimit(
  identifier: string,
  config: RateLimitConfig,
): RateLimitResult {
  const now = Date.now();
  const entry = store.get(identifier);

  if (!entry || entry.resetAt < now) {
    // New window
    const resetAt = now + config.windowMs;
    store.set(identifier, { count: 1, resetAt });
    return {
      success: true,
      limit: config.maxRequests,
      remaining: config.maxRequests - 1,
      reset: new Date(resetAt),
    };
  }

  // Existing window
  entry.count++;
  const success = entry.count <= config.maxRequests;

  return {
    success,
    limit: config.maxRequests,
    remaining: Math.max(0, config.maxRequests - entry.count),
    reset: new Date(entry.resetAt),
  };
}

/**
 * Rate limit presets for common use cases.
 */
export const RateLimits = {
  /** 10 requests per minute (for access-token endpoint) */
  accessToken: { maxRequests: 10, windowMs: 60_000 },

  /** 5 OAuth flows per minute (for start endpoint) */
  oauthStart: { maxRequests: 5, windowMs: 60_000 },

  /** 60 requests per minute (for general API) */
  general: { maxRequests: 60, windowMs: 60_000 },
} as const;
