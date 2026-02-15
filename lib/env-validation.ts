/** Validate required environment variables at startup. */
export function validateEnv(): void {
  // Critical secrets that MUST be set
  const critical = ['SESSION_SECRET', 'ENCRYPTION_KEY', 'DATABASE_URL'];

  // Provider credentials (at least one provider should be configured)
  const providers = [
    { name: 'Google Drive', id: 'GOOGLE_CLIENT_ID', secret: 'GOOGLE_CLIENT_SECRET' },
    { name: 'OneDrive', id: 'ONEDRIVE_CLIENT_ID', secret: 'ONEDRIVE_CLIENT_SECRET' },
    { name: 'Dropbox', id: 'DROPBOX_CLIENT_ID', secret: 'DROPBOX_CLIENT_SECRET' },
  ];

  const missing: string[] = [];
  const weak: string[] = [];

  // Check critical variables
  for (const key of critical) {
    const value = process.env[key];
    if (!value) {
      missing.push(key);
    } else if ((key === 'SESSION_SECRET' || key === 'ENCRYPTION_KEY') && value.length < 32) {
      weak.push(`${key} (should be at least 32 characters)`);
    }
  }

  if (missing.length > 0) {
    throw new Error(
      `❌ Missing critical environment variables: ${missing.join(', ')}\n` +
      `Please set these in your .env file or deployment environment.`,
    );
  }

  // Check providers (warn if none are configured)
  const configuredProviders = providers.filter(
    (p) => process.env[p.id] && process.env[p.secret],
  );

  if (configuredProviders.length === 0) {
    console.warn(
      '⚠️  No OAuth providers configured. At least one provider should be set up:\n' +
      providers.map((p) => `   - ${p.name}: ${p.id}, ${p.secret}`).join('\n'),
    );
  } else {
    console.log(
      `✅ Configured providers: ${configuredProviders.map((p) => p.name).join(', ')}`,
    );
  }

  if (weak.length > 0) {
    console.warn(`⚠️  Weak secrets detected: ${weak.join(', ')}`);
  }
}
