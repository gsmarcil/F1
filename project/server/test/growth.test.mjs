import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { PROTOCOL } from '../src/service.mjs';
import { SIGNALS } from '../src/signals.mjs';
import { learnShapes } from '../src/learning.mjs';
import { environment } from './d1.mjs';

const ADMIN = 'a'.repeat(40), KEY = 'e'.repeat(40), ATTACKER = '203.0.113.50';
function service(changes) {
  const env = environment({ TOR_EXITS: 'off', WATCHLIST: 'off', ...changes }), ctx = { waitUntil: () => {} };
  const call = async (method, path, body, token) => {
    const response = await worker.fetch(new Request('https://sentinel.example' + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }), env, ctx);
    return { status: response.status, body: await response.json() };
  };
  const enrol = async (label, mode) => (await call('POST', '/v1/enroll', { protocol: PROTOCOL, key: KEY, platform: 'linux', version: '0.1.0', label, ...(mode ? { mode } : {}) })).body;
  return { env, call, enrol };
}
const signal = id => ({ id, points: SIGNALS[id].weight, category: 'x', evidence: 'Written on the device.' });
const report = (cases, results) => ({ protocol: PROTOCOL, version: '0.1.0', platform: 'linux', cases, watching: {}, ...(results ? { results } : {}) });
const found = (letter, ids, actions) => ({ key: letter.repeat(32), name: 'job', path: '/tmp/job', parent: 'cron', signals: ids.map(signal), remotes: [{ address: ATTACKER, port: 56001, names: [], direction: 'out' }], ...(actions ? { actions } : {}) });
const judge = async (s, token, letter, ids, action) => {
  await s.call('POST', '/v1/report', report([found(letter, ids)]), token);
  const item = (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases.find(entry => entry.state === 'open');
  return s.call('POST', '/v1/cases/' + item.id + '/action', { action }, ADMIN);
};

test('a pair of signals two confirmed attacks share becomes a signal on every machine, until a case marked ours has it', async () => {
  const s = service({ RESPONSE_MODE: 'report' }), a = await s.enrol('web-01'), b = await s.enrol('db-01');
  await judge(s, a.token, 'a', ['runs_from_temp', 'unusual_port', 'beaconing'], 'confirm');
  assert.deepEqual((await s.call('POST', '/v1/report', report([]), b.token)).body.shapes, []);  // one attack is not a pattern
  await judge(s, a.token, 'b', ['runs_from_temp', 'unusual_port', 'fresh_file'], 'confirm');
  // Only the pair both attacks had.
  assert.deepEqual((await s.call('POST', '/v1/report', report([]), b.token)).body.shapes, [['runs_from_temp', 'unusual_port']]);
  assert.deepEqual((await s.call('GET', '/v1/learning', null, ADMIN)).body.shapes, [['runs_from_temp', 'unusual_port']]);
  // A machine that applies it reports the learned signal; the service accepts it and it never enters a remembered shape.
  const learned = found('c', ['runs_from_temp', 'unusual_port', 'learned_attack_shape']);
  assert.equal((await s.call('POST', '/v1/report', report([learned]), b.token)).body.saved, 1);
  // The operators mark a program with that pair as theirs: the pair is withdrawn everywhere.
  await s.call('POST', '/v1/cases/' + (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases.find(entry => entry.state === 'open').id + '/action', { action: 'trust' }, ADMIN);
  assert.deepEqual((await s.call('POST', '/v1/report', report([]), b.token)).body.shapes, []);
});

test('the decision model teaches shapes only when the deployment says so, and never weights', async () => {
  const model = { fetch: async () => new Response(JSON.stringify({ summary: 'A new program in a temporary folder calls home.', technique: 'implant', recommendation: 'stop', confidence: 'high' })) };
  const run = async changes => {
    const s = service({ AI_PROVIDER: 'custom', ANALYST: model, ...changes }), a = await s.enrol('web-01');
    for (const letter of ['a', 'b', 'c']) {
      const first = await s.call('POST', '/v1/report', report([found(letter, ['runs_from_temp', 'unusual_port', 'beaconing'], [{ action: 'paused', programs: 1, reason: 'hostile' }])]), a.token);
      assert.deepEqual(first.body.commands.map(command => command.action), ['stop']);
      await s.call('POST', '/v1/report', report([], [{ key: letter.repeat(32), action: 'stopped', programs: 1, gone: 0 }]), a.token);
    }
    return (await s.call('GET', '/v1/learning', null, ADMIN)).body;
  };
  const off = await run({});
  assert.deepEqual({ shapes: off.shapes, verdicts: off.verdicts }, { shapes: [], verdicts: 0 });
  const on = await run({ LEARN_FROM: 'operators-and-model' });
  assert.deepEqual({ by_model: on.confirmed_by_model, policy: on.policy, pairs: on.shapes.length }, { by_model: 3, policy: {}, pairs: 3 });
  // Two model stops are not enough; three are.
  assert.deepEqual(learnShapes([1, 2].map(() => ({ shape: ['beaconing', 'unusual_port'], verdict: 'confirmed', source: 'model' }))), []);
});

test('fleet blocking is off unless the deployment turns it on', async () => {
  const stopped = [found('a', ['runs_from_temp', 'unusual_port', 'beaconing'], [{ action: 'stopped', programs: 1, reason: 'hostile' }])];
  const off = service(), a = await off.enrol('web-01');
  await off.call('POST', '/v1/report', report(stopped), a.token);
  assert.equal((await off.call('POST', '/v1/report', report([]), a.token)).body.fleet.block, undefined);
  const on = service({ FLEET_BLOCK: 'on' }), b = await on.enrol('web-01'), c = await on.enrol('db-01');
  await on.call('POST', '/v1/report', report(stopped), b.token);
  assert.deepEqual((await on.call('POST', '/v1/report', report([]), c.token)).body.fleet.block, [ATTACKER]);
  await on.call('POST', '/v1/fleet/remove', { address: ATTACKER }, ADMIN);
  assert.deepEqual((await on.call('POST', '/v1/report', report([]), c.token)).body.fleet.block, []);
});
