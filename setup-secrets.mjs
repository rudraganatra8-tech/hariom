// Creates the secret keys Hari Om needs and writes them to secrets.json.
// Run once:  node scripts/setup-secrets.mjs
// Then upload them:  npx wrangler secret bulk secrets.json
import { webcrypto as crypto } from 'node:crypto';
import { writeFileSync, existsSync } from 'node:fs';

if (existsSync('secrets.json')) {
  console.log('secrets.json already exists. Not overwriting it, because replacing DATA_KEY would make your saved data unreadable.');
  process.exit(1);
}

const b64 = (u8) => Buffer.from(u8).toString('base64');
const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const setupCode = [...crypto.getRandomValues(new Uint8Array(10))].map((b) => alphabet[b % alphabet.length]).join('');

const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const vapidJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);

const secrets = {
  DATA_KEY: b64(crypto.getRandomValues(new Uint8Array(32))),
  SETUP_CODE: setupCode,
  VAPID_JWK: JSON.stringify(vapidJwk),
  VAPID_SUBJECT: process.argv[2] ? 'mailto:' + process.argv[2] : 'mailto:admin@hariom.app',
};
writeFileSync('secrets.json', JSON.stringify(secrets, null, 2));

console.log('\nDone. secrets.json created.\n');
console.log('YOUR SETUP CODE (needed once, when you create your account in the app):');
console.log('   ' + setupCode + '\n');
console.log('IMPORTANT: secrets.json holds the key that unlocks your data. Keep one copy somewhere safe');
console.log('(a password manager or a private note), never share it, and never put it in a zip or chat.');
console.log('Next:  npx wrangler secret bulk secrets.json\n');
