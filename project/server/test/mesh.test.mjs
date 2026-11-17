import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { PROTOCOL } from '../src/service.mjs';
import { SIGNALS } from '../src/signals.mjs';
import { environment } from './d1.mjs';

const ADMIN = 'a'.repeat(40), KEY = 'e'.repeat(40), ATTACKER = '203.0.113.50';
function service(changes) {
  const env = environment({ TOR_EXITS: 'off', WATCHLIST: 'off', ...changes }), ctx = { waitUntil: () => {} };
  const call = async (method, path, body, token) => {
    const response = await worker.fetch(new Request('https://sentinel.example' + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }), env, ctx);
    return { status: response.status, body: await response.json() };
  };
  const enrol = async (label, platform = 'linux', mode) => (await call('POST', '/v1/enroll', { protocol: PROTOCOL, key: KEY, platform, version: '0.1.0', label, ...(mode ? { mode } : {}) })).body;
  return { env, call, enrol };
}
const signal = id => ({ id, points: SIGNALS[id].weight, category: 'x', evidence: 'Written on the device.' });
const report = (platform, cases, mesh) => ({ protocol: PROTOCOL, version: '0.1.0', platform, cases, watching: {}, mesh });
const sees = (changes = {}) => ({ privileged: true, process_feed: true, host_names: true, web_logs: 0, web_folders: 0, directory_log: true, responds: 'kill', ...changes });
const implant = (letter, actions) => ({ key: letter.repeat(32), name: '.kworkerd', path: '/tmp/.x/.kworkerd', parent: 'systemd', signals: ['runs_from_temp', 'unusual_port', 'beaconing'].map(signal),
  remotes: [{ address: ATTACKER, port: 56001, names: [], direction: 'out' }, { address: '10.0.0.9', port: 445, names: [], direction: 'out' }], ...(actions ? { actions } : {}) });

test('an attack stopped on one machine arms every other machine against the same address', async () => {
  const s = service(), web = await s.enrol('web-01'), db = await s.enrol('db-01');
  assert.deepEqual((await s.call('POST', '/v1/report', report('linux', [], { addresses: ['10.0.0.6'], peers: [], coverage: sees() }), db.token)).body.fleet, { indicators: {}, suspects: [] });
  // web-01 ends an implant in kill mode. Its internet destination is shared; the address on our own network is not.
  await s.call('POST', '/v1/report', report('linux', [implant('a', [{ action: 'stopped', programs: 1, reason: 'hostile' }])], { addresses: ['10.0.0.5'], peers: [], coverage: sees() }), web.token);
  const fleet = (await s.call('POST', '/v1/report', report('linux', []), db.token)).body.fleet;
  assert.deepEqual(fleet.indicators, { [ATTACKER]: 'a program stopped on web-01 called out to it' });
  // What web-01 says about its own addresses names nobody by itself: a machine an intruder controls could claim any.
  assert.deepEqual(fleet.suspects, []);
  // Once an operator confirms the attack, db-01 is told to treat connections from web-01 as an intruder spreading.
  const hit = (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases[0];
  await s.call('POST', '/v1/cases/' + hit.id + '/action', { action: 'confirm' }, ADMIN);
  assert.deepEqual((await s.call('POST', '/v1/report', report('linux', []), db.token)).body.fleet.suspects, ['10.0.0.5']);
  // web-01 itself is not told to suspect itself.
  assert.deepEqual((await s.call('POST', '/v1/report', report('linux', [], { addresses: ['10.0.0.5'], peers: [], coverage: sees() }), web.token)).body.fleet.suspects, []);
  // db-01 reports the two fleet signals; the service accepts and titles them.
  const spread = { key: 'b'.repeat(32), name: 'sshd', path: '/usr/sbin/sshd', parent: '', signals: [signal('inbound_from_suspect_peer'), signal('remote_access_burst')], remotes: [] };
  const beacon = { key: 'c'.repeat(32), name: 'job', path: '/tmp/job', parent: 'cron', signals: [signal('fleet_indicator'), signal('runs_from_temp')], remotes: [{ address: ATTACKER, port: 56001, names: [], direction: 'out' }] };
  assert.equal((await s.call('POST', '/v1/report', report('linux', [spread, beacon]), db.token)).body.saved, 2);
  // An operator can read the shared list and withdraw an address.
  assert.equal((await s.call('GET', '/v1/fleet', null, ADMIN)).body.indicators[0].address, ATTACKER);
  assert.equal((await s.call('POST', '/v1/fleet/remove', { address: 'not an address' }, ADMIN)).status, 400);
  await s.call('POST', '/v1/fleet/remove', { address: ATTACKER }, ADMIN);
  assert.deepEqual((await s.call('POST', '/v1/report', report('linux', []), db.token)).body.fleet.indicators, {});
});

test('a confirmed or model-stopped attack is shared too; a dismissed one never is', async () => {
  const s = service({ RESPONSE_MODE: 'report' }), web = await s.enrol('web-01'), db = await s.enrol('db-01');
  await s.call('POST', '/v1/report', report('linux', [implant('a')]), web.token);
  const found = (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases[0];
  assert.deepEqual((await s.call('POST', '/v1/report', report('linux', []), db.token)).body.fleet.indicators, {});  // reported, not yet judged
  await s.call('POST', '/v1/cases/' + found.id + '/action', { action: 'confirm' }, ADMIN);
  assert.deepEqual((await s.call('POST', '/v1/report', report('linux', []), db.token)).body.fleet.indicators, { [ATTACKER]: 'an attack confirmed on another of your machines called out to it' });
  const t = service({ RESPONSE_MODE: 'report' }), a = await t.enrol('web-01'), b = await t.enrol('db-01');
  await t.call('POST', '/v1/report', report('linux', [implant('a')]), a.token);
  await t.call('POST', '/v1/cases/' + (await t.call('GET', '/v1/cases', null, ADMIN)).body.cases[0].id + '/action', { action: 'trust' }, ADMIN);
  assert.deepEqual((await t.call('POST', '/v1/report', report('linux', []), b.token)).body.fleet.indicators, {});
});

test('the coverage map shows what each machine can see and which neighbours nobody is watching', async () => {
  const s = service(), web = await s.enrol('web-01'), pc = await s.enrol('desk-07', 'windows', 'report');
  await s.call('POST', '/v1/report', report('linux', [], { addresses: ['10.0.0.5'], coverage: sees({ process_feed: false, web_folders: 1 }),
    peers: [{ address: '10.0.0.6', port: 5432, direction: 'out' }, { address: '10.0.0.9', port: 445, direction: 'out' }, { address: '10.0.0.40', port: 3389, direction: 'out' }, { address: 'junk', port: 1, direction: 'out' }] }), web.token);
  await s.call('POST', '/v1/report', report('windows', [], { addresses: ['10.0.0.6'], coverage: sees({ privileged: false, directory_log: false, host_names: false, responds: 'report', oversized: 'x'.repeat(40) }),
    peers: [{ address: '10.0.0.9', port: 445, direction: 'out' }, { address: '10.0.0.5', port: 443, direction: 'out' }, { address: '8.8.8.8', port: 443, direction: 'out' }] }), pc.token);
  assert.equal((await s.call('GET', '/v1/coverage')).status, 401);
  const map = (await s.call('GET', '/v1/coverage', null, ADMIN)).body;
  assert.deepEqual({ machines: map.machines, with_gaps: map.with_gaps }, { machines: 2, with_gaps: 2 });
  const byLabel = Object.fromEntries(map.devices.map(device => [device.label, device]));
  assert.deepEqual(byLabel['web-01'].gaps.map(gap => gap.split(':')[0]), ['no kernel process feed', 'a web folder exists but no access log is readable']);
  assert.deepEqual(byLabel['desk-07'].gaps.map(gap => gap.split(':')[0]), ["runs without administrator or root rights", 'cannot name the hosts programs connect to', 'cannot read the Security log', 'reports only']);
  assert.equal(byLabel['desk-07'].sees.oversized, undefined);
  // 10.0.0.9 is used by both machines and watched by neither; 10.0.0.6 and 10.0.0.5 are enrolled; 8.8.8.8 is not ours.
  assert.deepEqual(map.unprotected_neighbours, [{ address: '10.0.0.9', ports: [445], seen_by: ['desk-07', 'web-01'] }, { address: '10.0.0.40', ports: [3389], seen_by: ['web-01'] }]);
  assert.match(map.note, /never installs itself/);
});

test('what one machine may add to the shared addresses by itself is limited; an operator\'s verdict is not', async () => {
  const s = service(), web = await s.enrol('web-01');
  const many = (letter, base) => ({ ...implant(letter, [{ action: 'stopped', programs: 1, reason: 'hostile' }]), remotes: Array.from({ length: 8 }, (_, n) => ({ address: '198.51.100.' + (base + n), port: 443, names: [], direction: 'out' })) });
  for (const [letter, base] of [['a', 1], ['b', 20], ['c', 40]]) await s.call('POST', '/v1/report', report('linux', [many(letter, base)]), web.token);
  const shared = async () => (await s.call('GET', '/v1/fleet', null, ADMIN)).body.indicators.length;
  assert.equal(await shared(), 8);
  const third = (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases.find(item => item.title.includes('stopped'));
  await s.call('POST', '/v1/cases/' + third.id + '/action', { action: 'confirm' }, ADMIN);
  assert.ok(await shared() >= 8);
});
