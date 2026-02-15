# 🔒 OAuth Security Service - GEHÄRTET

## ✅ Behobene Sicherheitsprobleme

Alle kritischen Sicherheitslücken wurden behoben:

### 🔴 Kritisch (BEHOBEN)

- ✅ **Umgebungsvariablen-Validierung** auf Cold Start
- ✅ **Access Tokens verschlüsselt** in Datenbank
- ✅ **Session-Rotation** nach OAuth-Login (verhindert Session Fixation)
- ✅ **Rate Limiting** auf allen Endpoints
- ✅ **Input-Validierung** für alle Parameter

### 🟠 Hoch (BEHOBEN)

- ✅ **Security Headers** (HSTS, X-Frame-Options, etc.)
- ✅ **Cookie-Security** mit `__Host-` Prefix
- ✅ **Disconnect-Endpoint** zum Widerrufen von Tokens
- ✅ **Error-Handling** ohne Information Leakage

---

## 🚀 Deployment

### 1. Umgebungsvariablen setzen

**KRITISCH - MÜSSEN gesetzt sein:**

```bash
SESSION_SECRET=<mindestens 32 Zeichen>  # z.B. openssl rand -hex 32
ENCRYPTION_KEY=<mindestens 32 Zeichen>  # z.B. openssl rand -hex 32
DATABASE_URL=<Neon/Postgres Connection String>
```

**Provider-Credentials (mindestens einer):**

```bash
# Google Drive
GOOGLE_CLIENT_ID=<deine Client ID>
GOOGLE_CLIENT_SECRET=<dein Client Secret>

# OneDrive
ONEDRIVE_CLIENT_ID=<deine Client ID>
ONEDRIVE_CLIENT_SECRET=<dein Client Secret>

# Dropbox
DROPBOX_CLIENT_ID=<deine App ID>
DROPBOX_CLIENT_SECRET=<dein App Secret>
```

**Optional:**

```bash
ALLOWED_ORIGINS=https://lightningbowl.de,https://test.lightningbowl.de
BACKEND_URL=https://oauth.lightningbowl.de
```

### 2. Secrets generieren

```bash
# Linux/macOS:
openssl rand -hex 32

# Windows PowerShell:
[System.Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))

# Node.js:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 3. In Vercel deployen

```bash
# Vercel CLI installieren
npm i -g vercel

# Umgebungsvariablen setzen
vercel env add SESSION_SECRET
vercel env add ENCRYPTION_KEY
vercel env add DATABASE_URL
# ... weitere Secrets

# Deployen
vercel --prod
```

Oder im Vercel Dashboard: **Settings → Environment Variables**

---

## 📡 API-Endpoints

### Für alle Provider (`google-drive`, `onedrive`, `dropbox`):

**1. OAuth-Flow starten:**

```
GET /{provider}/start?redirect=https://yourapp.com
```

**2. OAuth-Callback** (automatisch von Provider aufgerufen):

```
GET /{provider}/callback?code=...&state=...
```

**3. Access Token abrufen:**

```
GET /{provider}/access-token
Cookie: __Host-lb_session=...
```

Response:

```json
{
  "access_token": "ya29.a0...",
  "expires_at": "2026-02-15T12:30:00Z",
  "provider": "google-drive"
}
```

**4. Provider trennen (NEU):**

```
GET /{provider}/disconnect
Cookie: __Host-lb_session=...
```

Response:

```json
{
  "success": true,
  "message": "Disconnected from google-drive"
}
```

**5. Health Check:**

```
GET /health
```

---

## 🔍 Rate Limits

| Endpoint        | Limit                |
| --------------- | -------------------- |
| `/start`        | 5 Requests / Minute  |
| `/access-token` | 10 Requests / Minute |
| `/disconnect`   | Unlimited            |

Bei Überschreitung: HTTP 429 mit `Retry-After` Header

---

## 🛡️ Sicherheits-Features

### 1. Verschlüsselung

- ✅ Refresh Tokens: AES-256-GCM verschlüsselt
- ✅ Access Tokens: AES-256-GCM verschlüsselt (NEU!)
- ✅ Session-Cookies: HMAC-SHA256 signiert

### 2. Session-Sicherheit

- ✅ HttpOnly Cookies (kein JS-Zugriff)
- ✅ Secure Flag (nur HTTPS)
- ✅ SameSite=None (für Cross-Origin)
- ✅ `__Host-` Prefix (verhindert Subdomain-Attacks)
- ✅ Session-Rotation nach Login (verhindert Fixation)

### 3. CSRF-Schutz

- ✅ State-Parameter Validierung
- ✅ Session-gebundene States
- ✅ PKCE für alle OIDC-Provider

### 4. Input-Validierung

- ✅ Parameter-Längenprüfung
- ✅ Format-Validierung (Regex)
- ✅ Type-Safety (TypeScript)

### 5. Security Headers

- ✅ X-Frame-Options: DENY
- ✅ X-Content-Type-Options: nosniff
- ✅ Strict-Transport-Security (HSTS)
- ✅ X-XSS-Protection
- ✅ Referrer-Policy

---

## 🧪 Testing

### Lokaler Test

```bash
# Dependencies installieren
npm install

# Umgebungsvariablen setzen (.env erstellen)
cp .env.example .env
# Dann .env mit deinen Secrets füllen

# Dev-Server starten
npm run dev

# In anderem Terminal:
curl http://localhost:3000/health
```

### Rate Limiting testen

```bash
# 15 Requests in Folge (Limit ist 10/min)
for i in {1..15}; do
  curl -b cookies.txt http://localhost:3000/google-drive/access-token
  echo "Request $i"
done

# Ab Request 11 sollte HTTP 429 kommen
```

### Session-Rotation testen

```bash
# Cookie vor Login
curl -c before.txt http://localhost:3000/google-drive/start

# Nach OAuth-Flow:
curl -c after.txt -b before.txt http://localhost:3000/google-drive/access-token

# Cookie sollte unterschiedlich sein
diff before.txt after.txt
```

---

## 📚 Weitere Dokumentation

- **[SECURITY-FIXES.md](SECURITY-FIXES.md)** - Detaillierte Beschreibung aller 11 Probleme
- **[ATTACK-SCENARIOS.md](ATTACK-SCENARIOS.md)** - Wie könnte man das System hacken?
- **[SECURITY-QUICKSTART.md](SECURITY-QUICKSTART.md)** - Implementierungs-Guide

---

## 🆘 Troubleshooting

### "Missing required environment variables"

→ Setze `SESSION_SECRET`, `ENCRYPTION_KEY` und `DATABASE_URL`

### "No OAuth providers configured"

→ Setze mindestens einen Provider (z.B. `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`)

### HTTP 429 (Too Many Requests)

→ Warte bis `Retry-After` Header-Zeit abgelaufen ist

### "Invalid callback parameters"

→ State-Parameter ist ungültig. Starte OAuth-Flow neu mit `/start`

### "State mismatch"

→ CSRF-Angriff erkannt oder Cookie abgelaufen. Flow neu starten.

---

## 📊 Projekt-Struktur

```
lightningbowl-oauth/
├── api/                        # Vercel Serverless Functions
│   ├── health.ts              # Health-Check Endpoint
│   ├── google-drive/
│   │   ├── start.ts           # OAuth-Flow starten
│   │   ├── callback.ts        # OAuth-Callback
│   │   ├── access-token.ts    # Token abrufen
│   │   └── disconnect.ts      # Verbindung trennen (NEU)
│   ├── onedrive/              # Gleiche Endpoints
│   └── dropbox/               # Gleiche Endpoints
├── lib/
│   ├── oauth-handler.ts       # ✅ GEHÄRTET - Haupt-OAuth-Logik
│   ├── session.ts             # ✅ GEHÄRTET - Session-Management
│   ├── crypto.ts              # AES-256-GCM Verschlüsselung
│   ├── pkce.ts                # PKCE für OAuth
│   ├── db.ts                  # ✅ ERWEITERT - Datenbank-Queries
│   ├── cors.ts                # CORS-Handling
│   ├── env-validation.ts      # ✅ NEU - Env-Validierung
│   ├── rate-limit.ts          # ✅ NEU - Rate Limiting
│   ├── input-validation.ts    # ✅ NEU - Input-Validierung
│   └── providers/
│       ├── google.ts          # Google Drive Provider
│       ├── onedrive.ts        # OneDrive Provider
│       └── dropbox.ts         # Dropbox Provider
├── sql/
│   └── init.sql               # Datenbank-Schema
├── vercel.json                # ✅ GEHÄRTET - Routing + Security Headers
├── tsconfig.json              # ✅ AKTUALISIERT - TypeScript Config
└── package.json
```

---

## 🎯 Nächste Schritte (Optional)

### Production Rate Limiting

Aktuell: In-Memory (verliert Daten bei Neustart)

**Bessere Lösung:**

```bash
npm install @upstash/redis @upstash/ratelimit
```

Dann in `lib/rate-limit.ts`:

```typescript
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

export const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '1 m'),
});
```

### Audit Logging

```typescript
// Bei kritischen Events:
await logAudit({
  event: 'oauth.login.success',
  provider: 'google-drive',
  sessionId: hashSessionId(sessionId),
  ip: req.headers['x-forwarded-for'],
});
```

### Token-Rotation Policy

```typescript
// Refresh Tokens nach 90 Tagen invalidieren
if (tokenAge > 90 * 24 * 60 * 60 * 1000) {
  await deleteSession(sessionId, provider.name);
  throw new Error('Token expired. Please re-authenticate.');
}
```

---

## 📝 Changelog

### v2.0.0 - Security Hardening (2026-02-15)

**Breaking Changes:**

- Cookie-Name geändert zu `__Host-lb_session`
- Session-IDs werden nach Login rotiert
- Access Tokens jetzt verschlüsselt

**Neue Features:**

- ✅ Disconnect-Endpoints
- ✅ Rate Limiting
- ✅ Env-Validierung
- ✅ Input-Validierung

**Security Fixes:**

- ✅ Session Fixation verhindert
- ✅ Access Token Encryption
- ✅ CSRF-Schutz verbessert
- ✅ Security Headers hinzugefügt
- ✅ Error-Handling ohne Leaks

---

**Made with 🔒 by Security-First Development**
