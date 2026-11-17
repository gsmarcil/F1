// Measure the service under a fleet of simulated machines.
//   node load.mjs [machines] [concurrency]                          in memory, on this computer: the code's own cost
//   SENTINEL_URL=https://your-service SENTINEL_ENROLL_KEY=... SENTINEL_ADMIN_TOKEN=... node load.mjs [machines] [concurrency]
//                                                                   against a real deployment: enrols machines named load-<n>
// It enrols the machines, sends each a quiet report twice (the second holding the current shared state), asks
// the pulse, reports one stopped attack and times how long the news takes to reach the pulse, then reads the map.
import worker, { PROTOCOL } from './src/service.mjs';

const machines = Number(process.argv[2]) || 2000, concurrency = Number(process.argv[3]) || 50, remote = process.env.SENTINEL_URL;
let call, queries = null;
if (remote) {
  call = async (method, path, body, token) => {
    const response = await fetch(remote.replace(/\/$/, '') + path, { method, headers: { 'Content-Type': 'application/json', 'User-Agent': 'sentinel-load/1', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
    return { status: response.status, body: await response.json().catch(() => ({})) };
  };
} else {
  const { environment } = await import('./test/d1.mjs');
  const env = environment({ TOR_EXITS: 'off', WATCHLIST: 'off', MAX_DEVICES: String(machines + 10) }), ctx = { waitUntil: () => {} };
  queries = { count: 0 }; const prepare = env.DB.prepare; env.DB.prepare = text => { queries.count++; return prepare(text); };
  process.env.SENTINEL_ENROLL_KEY = env.ENROLL_KEY; process.env.SENTINEL_ADMIN_TOKEN = env.ADMIN_TOKEN;
  call = async (method, path, body, token) => {
    const response = await worker.fetch(new Request('https://sentinel.example' + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }), env, ctx);
    return { status: response.status, body: await response.json() };
  };
}
const key = process.env.SENTINEL_ENROLL_KEY, admin = process.env.SENTINEL_ADMIN_TOKEN;
async function run(label, count, job) {
  const times = [], failures = {}; let next = 0; const before = queries?.count, started = performance.now();
  await Promise.all(Array.from({ length: Math.min(concurrency, count) }, async () => {
    while (next < count) {
      const index = next++, at = performance.now();
      try { const answer = await job(index); if (answer.status >= 300) failures[answer.status] = (failures[answer.status] || 0) + 1; } catch { failures.network = (failures.network || 0) + 1; }
      times.push(performance.now() - at);
    }
  }));
  const elapsed = (performance.now() - started) / 1000; times.sort((a, b) => a - b);
  const at = share => times[Math.min(times.length - 1, Math.floor(times.length * share))].toFixed(1);
  console.log(label.padEnd(34) + String(count).padStart(7) + ' requests  ' + (count / elapsed).toFixed(0).padStart(6) + '/s   median ' + at(0.5) + ' ms   95% ' + at(0.95) + ' ms   99% ' + at(0.99) + ' ms'
    + (queries ? '   ' + ((queries.count - before) / count).toFixed(2) + ' queries each' : '') + (Object.keys(failures).length ? '   FAILED ' + JSON.stringify(failures) : ''));
}
const report = (cases, changes) => ({ protocol: PROTOCOL, version: '0.2.0', platform: 'linux', cases, watching: { processes: 180, connections: 40, tracked: 9 },
  mesh: { addresses: ['10.' + (changes.n >> 16 & 255) + '.' + (changes.n >> 8 & 255) + '.' + (changes.n & 255)], peers: [{ address: '10.250.0.' + (changes.n % 250 + 1), port: 5432, direction: 'out' }], coverage: { privileged: true, process_feed: true, host_names: true, web_logs: 0, web_folders: 0, directory_log: false, responds: 'kill' } }, ...(changes.have ? { have: changes.have } : {}) });

console.log((remote ? 'Deployment' : 'In memory') + ': ' + machines + ' machines, ' + concurrency + ' at a time');
const tokens = new Array(machines), have = new Array(machines); let stateKey = '';
await run('enrol', machines, async n => { const answer = await call('POST', '/v1/enroll', { protocol: PROTOCOL, key, platform: 'linux', version: '0.2.0', label: 'load-' + n, mode: 'kill' }); tokens[n] = answer.body.token; stateKey = answer.body.state_key || stateKey; return answer; });
await run('first report (takes the state)', machines, async n => { const answer = await call('POST', '/v1/report', report([], { n }), tokens[n]); have[n] = answer.body.revision; return answer; });
await run('quiet report (has the state)', machines, async n => call('POST', '/v1/report', report([], { n, have: have[n] }), tokens[n]));
await run('pulse', machines, async () => call('GET', '/v1/pulse'));
const before = (await call('GET', '/v1/pulse')).body.revision, stopped = performance.now();
const signal = (id, points) => ({ id, points, category: 'x', evidence: 'Written on the device.' });
await call('POST', '/v1/report', report([{ key: 'f'.repeat(32), name: '.kworkerd', path: '/tmp/.x/.kworkerd', parent: 'systemd', signals: [signal('runs_from_temp', 3), signal('unusual_port', 1), signal('beaconing', 3)],
  remotes: [{ address: '203.0.113.50', port: 56001, names: [], direction: 'out' }], actions: [{ action: 'stopped', programs: 1, reason: 'hostile' }] }], { n: 0 }), tokens[0]);
let seen = null;
for (let tries = 0; tries < 120 && seen === null; tries++) { if ((await call('GET', '/v1/pulse')).body.revision !== before) seen = performance.now() - stopped; else await new Promise(resolve => setTimeout(resolve, 500)); }
console.log('one machine stops an attack: the pulse shows the new state after ' + (seen === null ? 'more than 60 s' : (seen / 1000).toFixed(1) + ' s'));
await run('shared state fetch', Math.min(machines, 2000), async () => call('GET', '/v1/state', null, stateKey));
const mapped = performance.now(), map = (await call('GET', '/v1/coverage', null, admin)).body, pulse = (await call('GET', '/v1/pulse')).body;
console.log('coverage map: ' + map.machines + ' machines read in ' + ((performance.now() - mapped) / 1000).toFixed(1) + ' s, ' + (map.unprotected_neighbours || []).length + ' unwatched neighbours named');
console.log('the service now asks quiet machines to report every ' + pulse.interval + ' s and to check the pulse every ' + pulse.pulse + ' s');
