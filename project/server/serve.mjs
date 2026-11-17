// Run the Sentinel service on your own machine, for good: a database file that survives restarts, HTTPS with
// your own certificate, and the same housekeeping the Cloudflare deployment runs on a timer.
//
//   node serve.mjs /etc/garrett-service/service.conf
//
// The one-line installers (service.sh, service.ps1) write that file and start this for you. Its lines are NAME=value:
//   ENROLL_KEY, ADMIN_TOKEN, DATA_KEY   required, 32+ characters each (see the README)
//   DATABASE                            path of the database file
//   PORT                                default 8443
//   TLS_CERT and TLS_KEY                PEM files, or TLS_PFX and TLS_PASSPHRASE
//   anything else                       the same settings wrangler.example.jsonc documents (RESPONSE_MODE, FLEET_BLOCK, ...)
// Needs Node.js 22.13 or newer. No packages to install.
import https from 'node:https';
import { readFileSync } from 'node:fs';
import worker from './src/worker.mjs';
import { database } from './sqlite.mjs';

const MAX_BODY = 1024 * 1024;
const file = process.argv[2];
if (!file) { console.error('Usage: node serve.mjs <configuration file>'); process.exit(1); }
const settings = {};
for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) { const found = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim()); if (found) settings[found[1]] = found[2]; }
for (const name of ['ENROLL_KEY', 'ADMIN_TOKEN', 'DATA_KEY']) if (!settings[name] || settings[name].length < 32) { console.error(name + ' must be set in ' + file + ' (at least 32 characters).'); process.exit(1); }
if (!settings.DATABASE) { console.error('DATABASE must be set in ' + file + '.'); process.exit(1); }
const tls = settings.TLS_PFX ? { pfx: readFileSync(settings.TLS_PFX), passphrase: settings.TLS_PASSPHRASE || '' }
  : settings.TLS_CERT && settings.TLS_KEY ? { cert: readFileSync(settings.TLS_CERT), key: readFileSync(settings.TLS_KEY) } : null;
if (!tls) { console.error('Set TLS_CERT and TLS_KEY, or TLS_PFX, in ' + file + '. Agents only talk to a service over HTTPS.'); process.exit(1); }

const { PORT, DATABASE, TLS_CERT, TLS_KEY, TLS_PFX, TLS_PASSPHRASE, ADDRESS, ...rest } = settings;
const env = { AI_PROVIDER: 'none', ...rest, DB: database(DATABASE) };
const background = promise => { Promise.resolve(promise).catch(() => {}); };

const server = https.createServer({ ...tls, minVersion: 'TLSv1.2' }, async (req, res) => {
  try {
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > MAX_BODY) { res.writeHead(413).end(); req.destroy(); return; } chunks.push(chunk); }
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) if (typeof value === 'string') headers.set(name, value);
    const response = await worker.fetch(new Request('https://service' + req.url, { method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks) }), env, { waitUntil: background });
    res.writeHead(response.status, Object.fromEntries(response.headers)); res.end(Buffer.from(await response.arrayBuffer()));
  } catch { if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' }); res.end('{"error":"The request could not be completed."}'); }
});
server.requestTimeout = 30000; server.headersTimeout = 15000;
// The housekeeping Cloudflare runs from a cron trigger: old closed cases out, watched addresses refreshed.
const housekeeping = () => worker.scheduled({}, env, { waitUntil: background }).catch(() => {});
setInterval(housekeeping, 15 * 60 * 1000).unref();
server.listen(Number(PORT) || 8443, () => { console.log('Sentinel service listening on port ' + server.address().port); housekeeping(); });
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => { env.DB.close(); process.exit(0); }));
