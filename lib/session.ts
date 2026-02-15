import crypto from 'crypto';
import type { VercelRequest, VercelResponse } from '@vercel/node';

const COOKIE_NAME = '__Host-lb_session';
const MAX_AGE = 30 * 24 * 60 * 60; // 30 days

/* ---------- signing helpers ---------- */

function sign(value: string): string {
  const sig = crypto
    .createHmac('sha256', process.env.SESSION_SECRET!)
    .update(value)
    .digest('base64url');
  return `${value}.${sig}`;
}

function verify(signed: string): string | null {
  const idx = signed.lastIndexOf('.');
  if (idx === -1) return null;

  const value = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);
  const expected = crypto
    .createHmac('sha256', process.env.SESSION_SECRET!)
    .update(value)
    .digest('base64url');

  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  return value;
}

/* ---------- public API ---------- */

/** Read and validate session ID from the request cookie. */
export function getSessionId(req: VercelRequest): string | null {
  const header = req.headers.cookie;
  if (!header) return null;

  const match = header
    .split(';')
    .map(c => c.trim())
    .find(c => c.startsWith(`${COOKIE_NAME}=`));
  if (!match) return null;

  const raw = decodeURIComponent(match.slice(COOKIE_NAME.length + 1));
  return verify(raw);
}

/** Write a signed session cookie to the response. */
export function setSessionCookie(res: VercelResponse, sessionId: string): void {
  const value = sign(sessionId);
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${MAX_AGE}`,
  );
}

/** Create a new session (UUID) and set its cookie. Returns the session ID. */
export function createSession(res: VercelResponse): string {
  const id = crypto.randomUUID();
  setSessionCookie(res, id);
  return id;
}
