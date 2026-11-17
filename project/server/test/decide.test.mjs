import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { PROTOCOL, refreshWatch, validateCase } from '../src/service.mjs';
import { SIGNALS, REFERENCE_ATTACKS, WATCH_HOSTS, reported } from '../src/signals.mjs';
import { scoreShape } from '../src/learning.mjs';
import { environment } from './d1.mjs';

const ADMIN = 'a'.repeat(40), KEY = 'e'.repeat(40);
function service(changes) {
  const env = environment(changes), waiting = [], ctx = { waitUntil: promise => waiting.push(promise) };
  const call = async (method, path, body, token) => {
    const response = await worker.fetch(new Request('https://sentinel.example' + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }), env, ctx);
    return { status: response.status, body: await response.json() };
  };
  return { env, call, settle: () => Promise.all(waiting.splice(0)) };
}
const model = (recommendation, confidence = 'high') => ({ AI_PROVIDER: 'workers-ai', AI_MODEL: '@cf/example/model', AI: { run: async () => ({ response: JSON.stringify({ summary: 'A judgement.', technique: 'web shell', recommendation, confidence }) }) } });
const signal = id => ({ id, points: SIGNALS[id].weight, category: 'x', evidence: 'Written on the device.' });
const frozen = (letter, ids = ['shell_from_web_server', 'risky_command_line']) => ({ key: letter.repeat(32), name: 'dash', path: '/usr/bin/dash', parent: 'php-fpm', signals: ids.map(signal), remotes: [], actions: [{ action: 'paused', programs: 1, reason: 'a web server started a shell' }] });
const report = (cases, changes = {}) => ({ protocol: PROTOCOL, version: '0.1.0', platform: 'linux', cases, watching: { processes: 1, connections: 1, tracked: 1 }, ...changes });
const enrolled = async (s, mode) => (await s.call('POST', '/v1/enroll', { protocol: PROTOCOL, key: KEY, platform: 'linux', version: '0.1.0', label: 'web-01', ...(mode ? { mode } : {}) })).body;
const first = async s => (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases[0];

test('with a model configured the default is decide: freeze first, and the model stops a real attack in the same exchange', async () => {
  const s = service(model('stop')), device = await enrolled(s);
  assert.deepEqual({ mode: device.mode, fallback: device.fallback, decide_after: device.decide_after }, { mode: 'decide', fallback: 'kill', decide_after: 20 });
  const answer = (await s.call('POST', '/v1/report', report([frozen('a')]), device.token)).body;
  assert.deepEqual(answer.commands, [{ key: 'a'.repeat(32), action: 'stop' }]);
  let found = await first(s);
  assert.deepEqual({ paused: found.paused, pending: found.pending, decided: found.analysis.decided, provider: found.analysis.provider }, { paused: true, pending: 'stop', decided: 'stop', provider: 'workers-ai' });
  await s.call('POST', '/v1/report', report([], { results: [{ key: 'a'.repeat(32), action: 'stopped', programs: 1, gone: 0 }] }), device.token);
  found = (await s.call('GET', '/v1/cases/' + found.id, null, ADMIN)).body;
  assert.deepEqual({ state: found.state, by: found.detail.outcome.by }, { state: 'resolved', by: 'decision model' });
  // The model's decision teaches nothing: learning comes only from operators.
  assert.equal((await s.call('GET', '/v1/learning', null, ADMIN)).body.verdicts, 0);
  // Explicit modes still win over the default.
  assert.equal((await enrolled(service({ ...model('stop'), RESPONSE_MODE: 'kill' }))).mode, 'kill');
  assert.equal((await enrolled(s, 'pause')).mode, 'pause');
});

test('a false alarm is released or held, never killed, and a model may release only when the deployment allows it', async () => {
  // Not allowed to release: an unsure model, or a confident "release", both leave it frozen for an operator.
  for (const answer of [model('release', 'high'), model('investigate', 'medium'), model('stop', 'low'), model('stop', 'medium')]) {
    const s = service(answer), device = await enrolled(s);
    assert.deepEqual((await s.call('POST', '/v1/report', report([frozen('a')]), device.token)).body.commands, [{ key: 'a'.repeat(32), action: 'hold' }]);
    const found = await first(s);
    assert.deepEqual({ paused: found.paused, pending: found.pending }, { paused: true, pending: 'hold' });
    // The operator still decides, and that decision replaces the hold.
    assert.equal((await s.call('POST', '/v1/cases/' + found.id + '/action', { action: 'release' }, ADMIN)).body.pending, 'release');
  }
  // Allowed to release at high confidence.
  const s = service({ ...model('release', 'high'), DECISION_RELEASE: 'high-confidence' }), device = await enrolled(s);
  assert.deepEqual((await s.call('POST', '/v1/report', report([frozen('a')]), device.token)).body.commands, [{ key: 'a'.repeat(32), action: 'release' }]);
  await s.call('POST', '/v1/report', report([], { results: [{ key: 'a'.repeat(32), action: 'released', programs: 1 }] }), device.token);
  const done = await first(s);
  assert.equal(done.state, 'resolved');  // closed, but not marked as ours: only an operator does that
  assert.deepEqual((await s.call('POST', '/v1/report', report([]), device.token)).body.trusted, []);
  // Never when a locked signal is involved, however confident the model sounds.
  const locked = service({ ...model('release', 'high'), DECISION_RELEASE: 'high-confidence' }), other = await enrolled(locked);
  assert.deepEqual((await locked.call('POST', '/v1/report', report([frozen('b', ['advisory_indicator', 'runs_from_temp'])]), other.token)).body.commands, [{ key: 'b'.repeat(32), action: 'hold' }]);
});

test('when the model fails the fallback decides, and an agent that heard nothing reports its own stop', async () => {
  const broken = { AI_PROVIDER: 'workers-ai', AI_MODEL: 'm', AI: { run: async () => { throw new Error('model down'); } } };
  const s = service(broken), device = await enrolled(s);
  assert.deepEqual((await s.call('POST', '/v1/report', report([frozen('a')]), device.token)).body.commands, [{ key: 'a'.repeat(32), action: 'stop' }]);
  assert.equal((await first(s)).analysis.reason, 'no decision model answered in time');
  const held = service({ ...broken, DECISION_FALLBACK: 'hold' }), other = await enrolled(held);
  assert.equal(other.fallback, 'hold');
  assert.deepEqual((await held.call('POST', '/v1/report', report([frozen('a')]), other.token)).body.commands, [{ key: 'a'.repeat(32), action: 'hold' }]);
  // The service was unreachable when the agent froze the program; it ended it after its own wait and says so.
  const late = service({ ...model('stop'), RESPONSE_MODE: 'decide' }), third = await enrolled(late);
  await late.env.DB.prepare("INSERT INTO cases(id,device_id,case_key,level,severity,title,detail,first_seen_at,last_seen_at) VALUES('11111111-1111-4111-8111-111111111111',?,?,'SUSPECT','high','dash was paused',?,1,1)")
    .bind(third.device_id, 'c'.repeat(32), await (await import('../src/util.mjs')).seal(validateCase(frozen('c')), late.env.DATA_KEY)).run();
  await late.call('POST', '/v1/report', report([], { results: [{ key: 'c'.repeat(32), action: 'stopped', programs: 1, gone: 0, fallback: true }] }), third.token);
  const done = (await late.call('GET', '/v1/cases/11111111-1111-4111-8111-111111111111', null, ADMIN)).body;
  assert.deepEqual({ state: done.state, by: done.detail.outcome.by }, { state: 'resolved', by: 'agent, after no decision arrived in time' });
  // A pause-mode agent cannot claim a stop nobody asked for.
  const pause = service({ RESPONSE_MODE: 'pause' }), fourth = await enrolled(pause);
  await pause.call('POST', '/v1/report', report([frozen('d')]), fourth.token);
  await pause.call('POST', '/v1/report', report([], { results: [{ key: 'd'.repeat(32), action: 'stopped', programs: 1 }] }), fourth.token);
  assert.equal((await first(pause)).paused, true);
});

test('web attacks, new scripts in web folders and Tor are accepted, titled and kept reportable', async () => {
  const s = service(), device = await enrolled(s);
  const web = { key: 'a'.repeat(32), name: 'Web client 45.33.32.7', path: '', parent: '', signals: ['web_fuzzing', 'web_injection_attempt', 'web_injection_answered'].map(signal), remotes: [{ address: '45.33.32.7', port: 0, names: [], direction: 'in' }] };
  const planted = { key: 'b'.repeat(32), name: 'shell.jsp', path: '/var/www/app/shell.jsp', parent: '', signals: [signal('web_shell_file')], remotes: [] };
  const tor = { key: 'c'.repeat(32), name: 'svc', path: '/tmp/svc', parent: 'bash', signals: ['runs_from_temp', 'tor_routing'].map(signal), remotes: [] };
  assert.equal((await s.call('POST', '/v1/report', report([web, planted, tor]), device.token)).body.saved, 3);
  const titles = (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases.map(found => found.title).sort();
  assert.deepEqual(titles, ['New script in a web folder: shell.jsp', 'Web attack: Web client 45.33.32.7', 'svc looks suspicious']);
  for (const shape of REFERENCE_ATTACKS) assert.ok(reported(scoreShape(shape).level), shape.join('+'));
});

test('the service looks up the watched hosts itself and hands agents the addresses', async () => {
  const asked = [], real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    asked.push(url); assert.equal(init.headers.accept, 'application/dns-json');
    const host = new URL(url).searchParams.get('name');
    return new Response(JSON.stringify(host === 'webhook.site' ? { Answer: [{ type: 5, data: 'alias.example.' }, { type: 1, data: '93.184.216.34' }] } : host === 'xcai.pro' ? { Answer: [{ type: 1, data: '203.0.113.9' }, { type: 1, data: 'not-an-address' }] } : {}));
  };
  try {
    const s = service(), device = await enrolled(s);
    assert.deepEqual(await refreshWatch(s.env), { '93.184.216.34': 'webhook.site', '203.0.113.9': 'xcai.pro' });
    assert.equal(asked.length, WATCH_HOSTS.length);
    assert.deepEqual((await s.call('POST', '/v1/report', report([]), device.token)).body.watch, { '93.184.216.34': 'webhook.site', '203.0.113.9': 'xcai.pro' });
    const off = service({ WATCHLIST: 'off' }), quiet = await enrolled(off);
    assert.deepEqual((await off.call('POST', '/v1/report', report([]), quiet.token)).body.watch, {});
  } finally { globalThis.fetch = real; }
});

test('a machine cannot have one case judged again and again, flood alerts with one case, or ask the model without limit', async () => {
  let asked = 0; const alerts = [], realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => { if (String(url) === 'https://hooks.example/alert') { alerts.push(JSON.parse(init.body)); return new Response('{}'); } return realFetch(url, init); };
  try {
    const s = service({ AI_PROVIDER: 'workers-ai', AI_MODEL: '@cf/example/model', ALERT_WEBHOOK_URL: 'https://hooks.example/alert', AI: { run: async () => { asked++; return { response: JSON.stringify({ summary: 'A judgement.', technique: 'web shell', recommendation: 'stop', confidence: 'high' }) }; } } });
    const device = await enrolled(s), send = (cases, changes) => s.call('POST', '/v1/report', report(cases, changes), device.token);
    assert.deepEqual((await send([frozen('a')])).body.commands, [{ key: 'a'.repeat(32), action: 'stop' }]);
    for (let round = 0; round < 4; round++) {
      // The machine says it carried the stop out, which closes the case, then reports the same program frozen again.
      await send([], { results: [{ key: 'a'.repeat(32), action: 'stopped', programs: 1, gone: 0 }] });
      assert.deepEqual((await send([frozen('a')])).body.commands, [{ key: 'a'.repeat(32), action: 'hold' }]);
    }
    await s.settle();
    assert.equal(asked, 1);
    // New cases go to the model only up to the day's limit; the rest are held for an operator.
    for (const letter of 'bcdef0123456789') await send([frozen(letter)]);
    await s.settle();
    assert.equal(asked, 12);
    // One case flipping between suspicious and hostile alerts on the first report and on the first escalation only.
    const quiet = service({ ALERT_WEBHOOK_URL: 'https://hooks.example/alert', RESPONSE_MODE: 'report' }), watcher = await enrolled(quiet); alerts.length = 0;
    const mild = { key: '9'.repeat(32), name: 'job', path: '/tmp/job', parent: 'cron', signals: ['runs_from_temp', 'unusual_port', 'fan_out'].map(signal), remotes: [] };
    const serious = { ...mild, signals: ['runs_from_temp', 'unusual_port', 'beaconing', 'risky_command_line'].map(signal) };
    for (let round = 0; round < 5; round++) { await quiet.call('POST', '/v1/report', report([mild]), watcher.token); await quiet.call('POST', '/v1/report', report([serious]), watcher.token); }
    await quiet.settle();
    assert.equal(alerts.length, 2);
  } finally { globalThis.fetch = realFetch; }
});

test('what an agent cleaned up after a stop is kept with the case, and a malformed cleanup list is refused', async () => {
  const s = service(model('stop')), device = await enrolled(s);
  await s.call('POST', '/v1/report', report([frozen('a')]), device.token);
  const steps = [{ action: 'quarantined', kind: 'program file', where: '/tmp/updater' }, { action: 'disabled', kind: 'scheduled job', where: '/etc/crontab' }, { action: 'review', kind: 'sign-in keys', where: '/root/.ssh/authorized_keys' }];
  const done = await s.call('POST', '/v1/report', report([], { results: [{ key: 'a'.repeat(32), action: 'stopped', programs: 1, gone: 0, cleanup: steps }] }), device.token);
  assert.equal(done.status, 200);
  const found = (await s.call('GET', '/v1/cases/' + (await first(s)).id, null, ADMIN)).body;
  assert.deepEqual(found.detail.outcome.cleanup, steps);
  // kill mode: the cleanup arrives with the case itself.
  const killed = { ...frozen('b'), actions: [{ action: 'stopped', programs: 2, reason: 'a web server started a shell' }], cleanup: steps.slice(0, 1) };
  assert.equal((await s.call('POST', '/v1/report', report([killed]), device.token)).status, 200);
  const all = await Promise.all((await s.call('GET', '/v1/cases', null, ADMIN)).body.cases.map(async row => (await s.call('GET', '/v1/cases/' + row.id, null, ADMIN)).body));
  assert.deepEqual(all.map(row => row.detail.cleanup).filter(Boolean), [steps.slice(0, 1)]);
  for (const bad of [[{ action: 'deleted', kind: 'program file', where: '/tmp/x' }], [{ action: 'quarantined', kind: '', where: '/tmp/x' }], [{ action: 'quarantined', kind: 'program file', where: '<script>' }], 'everything', Array(13).fill(steps[0])])
    assert.equal((await s.call('POST', '/v1/report', report([{ ...frozen('c'), cleanup: bad }]), device.token)).status, 400);
});

test('the same attack again is the same case, and the case counts how many times', async () => {
  const s = service(), device = await enrolled(s);
  await s.call('POST', '/v1/report', report([frozen('a')]), device.token);
  let found = (await s.call('GET', '/v1/cases/' + (await first(s)).id, null, ADMIN)).body;
  assert.equal(found.detail.times, 1);
  await s.call('POST', '/v1/report', report([{ ...frozen('a'), repeats: 3 }]), device.token);
  await s.call('POST', '/v1/report', report([frozen('a')]), device.token);  // said again with no repeat: the count stays
  found = (await s.call('GET', '/v1/cases/' + found.id, null, ADMIN)).body;
  assert.deepEqual({ times: found.detail.times, repeats: found.detail.repeats, cases: (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases.length }, { times: 4, repeats: undefined, cases: 1 });
  assert.equal((await s.call('POST', '/v1/report', report([{ ...frozen('b'), repeats: -1 }]), device.token)).status, 400);
});
