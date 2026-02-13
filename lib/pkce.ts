import crypto from 'crypto';

/** Generate a random code_verifier for PKCE (RFC 7636). */
export function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/** Derive the S256 code_challenge from a code_verifier. */
export function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}
