export const now = () => Math.floor(Date.now() / 1000);
export function fail(status, message) { throw Object.assign(new Error(message), { status }); }
export function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}
const hex = bytes => [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
export async function sha256(value) { return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))); }
export function randomToken() { return hex(crypto.getRandomValues(new Uint8Array(32))); }
// Secrets are compared by digest, so the comparison time says nothing about the secret.
export async function sameSecret(given, expected) {
  if (typeof given !== 'string' || typeof expected !== 'string' || !expected) return false;
  const [a, b] = await Promise.all([sha256('cmp:' + given), sha256('cmp:' + expected)]);
  let difference = 0;
  for (let index = 0; index < a.length; index++) difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return difference === 0;
}
export async function bodyJson(request, limit) {
  const raw = await request.text();
  if (raw.length > limit) fail(413, 'The request is too large.');
  try { const value = JSON.parse(raw); if (value && typeof value === 'object' && !Array.isArray(value)) return value; } catch {}
  fail(400, 'Send a JSON object.');
}
// Case evidence is encrypted at rest with DATA_KEY (AES-256-GCM, a fresh nonce for every value).
async function dataKey(secret) {
  if (typeof secret !== 'string' || secret.length < 32) fail(500, 'Set the DATA_KEY secret (at least 32 characters).');
  return crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret)), 'AES-GCM', false, ['encrypt', 'decrypt']);
}
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = text => Uint8Array.from(atob(text), char => char.charCodeAt(0));
export async function seal(value, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await dataKey(secret), new TextEncoder().encode(JSON.stringify(value)));
  return 'v1.' + b64(iv) + '.' + b64(cipher);
}
export async function unseal(text, secret) {
  const [version, iv, cipher] = String(text).split('.');
  if (version !== 'v1') throw new Error('Unknown sealed value.');
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, await dataKey(secret), unb64(cipher))));
}
export const text = (value, max) => typeof value === 'string' && !/[\x00-\x1f\x7f<>]/.test(value) && value.length <= max ? value : null;
export const whole = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
