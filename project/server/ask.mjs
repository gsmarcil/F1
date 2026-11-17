// Ask the Sentinel service running on this machine one operator question, trusting only its own certificate.
//   node ask.mjs <configuration file> /v1/devices
// Used by the garrett-service command on Windows. Exits 0 when the service answered 200.
import https from 'node:https';
import { readFileSync } from 'node:fs';

const [file, path] = process.argv.slice(2);
if (!file || !/^\/v1\//.test(path || '')) { console.error('Usage: node ask.mjs <configuration file> /v1/...'); process.exit(2); }
const settings = {};
for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) { const found = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim()); if (found) settings[found[1]] = found[2]; }
const request = https.get({ host: '127.0.0.1', port: Number(settings.PORT) || 8443, path, ca: readFileSync(settings.TLS_CERT), checkServerIdentity: () => undefined, timeout: 10000,
  headers: { Authorization: 'Bearer ' + settings.ADMIN_TOKEN } }, response => {
  let body = '';
  response.on('data', chunk => { body += chunk; });
  response.on('end', () => { console.log(body); process.exit(response.statusCode === 200 ? 0 : 1); });
});
request.on('timeout', () => request.destroy(new Error('The service did not answer.')));
request.on('error', error => { console.error(error.message); process.exit(1); });
