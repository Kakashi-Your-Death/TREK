import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

let _jwtSecret: string = process.env.JWT_SECRET || '';

if (!_jwtSecret) {
  const dataDir = path.resolve(__dirname, '../data');
  const secretFile = path.join(dataDir, '.jwt_secret');

  try {
    _jwtSecret = fs.readFileSync(secretFile, 'utf8').trim();
  } catch {
    _jwtSecret = crypto.randomBytes(32).toString('hex');
    try {
      if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
      fs.writeFileSync(secretFile, _jwtSecret, { mode: 0o600 });
      console.log('Generated and saved JWT secret to', secretFile);
    } catch (writeErr: unknown) {
      console.warn('WARNING: Could not persist JWT secret to disk:', writeErr instanceof Error ? writeErr.message : writeErr);
      console.warn('Sessions will reset on server restart. Set JWT_SECRET env var for persistent sessions.');
    }
  }
}

const JWT_SECRET_IS_GENERATED = !process.env.JWT_SECRET;

// export let so TypeScript's CJS output keeps exports.JWT_SECRET live
// (generates `exports.JWT_SECRET = JWT_SECRET = newVal` inside updateJwtSecret)
export let JWT_SECRET = _jwtSecret;

// Called by the admin rotate-jwt-secret endpoint to update the in-process
// binding that all middleware and route files reference.
export function updateJwtSecret(newSecret: string): void {
  JWT_SECRET = newSecret;
}

// ENCRYPTION_KEY is used to derive at-rest encryption keys for stored secrets
// (API keys, MFA TOTP secrets, SMTP password, OIDC client secret, etc.).
// Keeping it separate from JWT_SECRET means you can rotate session tokens without
// invalidating all stored encrypted data, and vice-versa.
//
// Upgrade note: if you already have encrypted data stored under a previous build
// that used JWT_SECRET for encryption, set ENCRYPTION_KEY to the value of your
// old JWT_SECRET so existing encrypted values continue to decrypt correctly.
// After re-saving all credentials via the admin panel you can switch to a new
// random ENCRYPTION_KEY.
let ENCRYPTION_KEY: string = process.env.ENCRYPTION_KEY || '';

if (!ENCRYPTION_KEY) {
  const dataDir = path.resolve(__dirname, '../data');
  const keyFile = path.join(dataDir, '.encryption_key');

  try {
    ENCRYPTION_KEY = fs.readFileSync(keyFile, 'utf8').trim();
  } catch {
    ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
    try {
      if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
      fs.writeFileSync(keyFile, ENCRYPTION_KEY, { mode: 0o600 });
      console.log('Generated and saved encryption key to', keyFile);
    } catch (writeErr: unknown) {
      console.warn('WARNING: Could not persist encryption key to disk:', writeErr instanceof Error ? writeErr.message : writeErr);
      console.warn('Encrypted secrets will be unreadable after restart. Set ENCRYPTION_KEY env var for persistent encryption.');
    }
  }
}

export { JWT_SECRET_IS_GENERATED, ENCRYPTION_KEY };
