import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { PROTOCOL, housekeeping } from '../src/service.mjs';
import { SIGNALS } from '../src/signals.mjs';
import { environment } from './d1.mjs';

const ADMIN = 'a'.repeat(40), KEY = 'e'.repeat(40), ATTACKER = '203.0.113.50';
function service(changes) {
  const env = environment({ TOR_EXITS: 'off', WATCHLIST: 'off', ...changes }), ctx = { waitUntil: () => {} }, queries = [];
  const prepare = env.DB.prepare; env.DB.prepare = text => { queries.push(text); return prepare(text); };
  const call = async (method, path, body, token) => {
    const response = await worker.fetch(new Request('https://sentinel.example' + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }), env, ctx);
    return { status: response.status, body: await response.json() };
  };
  const enrol = async label => (await call('POST', '/v1/enroll', { protocol: PROTOCOL, key: KEY, platform: 'linux', version: '0.2.0', label })).body;
  return { env, call, enrol, queries };
}
const signal = id => ({ id, points: SIGNALS[id].weight, category: 'x', evidence: 'Written on the device.' });
const report = (cases, changes) => ({ protocol: PROTOCOL, version: '0.2.0', platform: 'linux', cases, watching: {}, ...changes });
const implant = actions => ({ key: 'a'.repeat(32), name: '.kworkerd', path: '/tmp/.x/.kworkerd', parent: 'systemd', signals: ['runs_from_temp', 'unusual_port', 'beaconing'].map(signal), remotes: [{ address: ATTACKER, port: 56001, names: [], direction: 'out' }], actions });

test('a quiet machine that holds the current shared state costs three queries and is not sent it again', async () => {
  const s = service(), a = await s.enrol('web-01');
  assert.match(a.state_key, /^[a-f0-9]{64}$/);
  const first = (await s.call('POST', '/v1/report', report([]), a.token)).body;
  assert.deepEqual([typeof first.fleet, typeof first.policy, typeof first.watch, first.interval, first.pulse], ['object', 'object', 'object', 300, 60]);
  s.queries.length = 0;
  const quiet = (await s.call('POST', '/v1/report', report([], { have: first.revision }), a.token)).body;
  assert.deepEqual([quiet.accepted, quiet.revision, quiet.fleet, quiet.policy, quiet.watch], [true, first.revision, undefined, undefined, undefined]);
  // The machine's own row, the one write, and its own trusted and pending cases. Nothing fleet-wide.
  assert.equal(s.queries.length, 3);
  // An agent from before revisions sends no "have" and still gets everything.
  assert.equal(typeof (await s.call('POST', '/v1/report', report([]), a.token)).body.fleet, 'object');
});

test('the pulse is answered from memory, and the shared state opens only with the fleet read key', async () => {
  const s = service(), a = await s.enrol('web-01'), b = await s.enrol('db-01');
  const before = (await s.call('GET', '/v1/pulse')).body;
  assert.deepEqual(Object.keys(before).sort(), ['interval', 'pulse', 'revision']);
  s.queries.length = 0;
  for (let index = 0; index < 50; index++) await s.call('GET', '/v1/pulse');
  assert.equal(s.queries.length, 0);
  for (const token of [undefined, a.token, ADMIN]) assert.equal((await s.call('GET', '/v1/state', null, token)).status, 401);
  // One machine stops an attack: the revision moves at once, and every machine can fetch what changed.
  await s.call('POST', '/v1/report', report([implant([{ action: 'stopped', programs: 1, reason: 'hostile' }])]), a.token);
  const after = (await s.call('GET', '/v1/pulse')).body;
  assert.notEqual(after.revision, before.revision);
  const state = (await s.call('GET', '/v1/state', null, b.state_key)).body;
  assert.deepEqual([state.revision, Object.keys(state.fleet.indicators)], [after.revision, [ATTACKER]]);
});

test('the reporting interval and the pulse stretch with the size of the fleet, and enrolling does not scan the device table', async () => {
  const s = service({ HEARTBEAT_WRITES_PER_SECOND: '0.002', PULSE_REQUESTS_PER_SECOND: '0.01', MAX_DEVICES: '3' });
  const a = await s.enrol('n1'); await s.enrol('n2');
  await s.call('POST', '/v1/report', report([implant([{ action: 'stopped', programs: 1, reason: 'hostile' }])]), a.token);  // refreshes the shared state
  const pulse = (await s.call('GET', '/v1/pulse')).body;
  assert.deepEqual([pulse.interval, pulse.pulse], [1000, 200]);  // 2 machines at 0.002 writes and 0.01 pulses a second
  s.queries.length = 0;
  await s.enrol('n3');
  assert.equal(s.queries.filter(text => /COUNT\(\*\)/.test(text)).length, 0);
  const big = service({ HEARTBEAT_WRITES_PER_SECOND: '0.00001' });
  await big.enrol('n1'); await big.call('POST', '/v1/report', report([implant([{ action: 'stopped', programs: 1, reason: 'hostile' }])]), (await big.enrol('n2')).token);
  assert.equal((await big.call('GET', '/v1/pulse')).body.interval, 3600);  // never slower than hourly
  // A machine is "watching" for two and a half intervals, not a fixed fifteen minutes.
  await big.env.DB.prepare('UPDATE devices SET last_seen_at=?').bind(Math.floor(Date.now() / 1000) - 5000).run();
  assert.equal((await big.call('GET', '/v1/devices', null, ADMIN)).body.watching, 2);
});

test('housekeeping removes closed cases past their keep time and nothing else', async () => {
  const s = service({ RESPONSE_MODE: 'report' }), a = await s.enrol('web-01');
  await s.call('POST', '/v1/report', report([implant()]), a.token);
  const found = (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases[0];
  await s.call('POST', '/v1/cases/' + found.id + '/action', { action: 'resolve' }, ADMIN);
  assert.deepEqual(await housekeeping(s.env), { cases_removed: 0 });
  await s.env.DB.prepare('UPDATE cases SET last_seen_at=?').bind(Math.floor(Date.now() / 1000) - 40 * 86400).run();
  assert.deepEqual(await housekeeping(s.env), { cases_removed: 1 });
  assert.equal(typeof worker.scheduled, 'function');
});

test('an operator can add an indicator of their own, and it reaches every machine like a learned one', async () => {
  const s = service({ FLEET_BLOCK: 'on' }), a = await s.enrol('web-01');
  for (const body of [{ address: '10.0.0.5' }, { address: 'evil.example' }, { address: ATTACKER, reason: '<b>' }]) assert.equal((await s.call('POST', '/v1/fleet/add', body, ADMIN)).status, 400);
  assert.equal((await s.call('POST', '/v1/fleet/add', { address: ATTACKER, reason: 'seen attacking our other region' }, a.token)).status, 401);
  assert.equal((await s.call('POST', '/v1/fleet/add', { address: ATTACKER, reason: 'seen attacking our other region' }, ADMIN)).status, 201);
  const fleet = (await s.call('POST', '/v1/report', report([]), a.token)).body.fleet;
  assert.deepEqual([fleet.indicators, fleet.block], [{ [ATTACKER]: 'seen attacking our other region' }, [ATTACKER]]);
});
