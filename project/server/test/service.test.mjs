import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { PROTOCOL, validateCase } from '../src/service.mjs';
import { SIGNALS, REFERENCE_ATTACKS, reported } from '../src/signals.mjs';
import { cleanPolicy, learnPolicy, scoreShape } from '../src/learning.mjs';
import { analystRequest, parseAnalysis } from '../src/analyst.mjs';
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
const signal = id => ({ id, points: SIGNALS[id].weight, category: 'x', evidence: 'Written on the device.' });
const item = (letter, ids, changes = {}) => ({ key: letter.repeat(32), name: 'tool', path: '/opt/app/tool', parent: 'bash', signals: ids.map(signal), remotes: [], ...changes });
const report = (cases, changes = {}) => ({ protocol: PROTOCOL, version: '0.1.0', platform: 'linux', cases, watching: { processes: 10, connections: 4, tracked: 2 }, ...changes });
async function enrolled(s, mode) {
  const done = await s.call('POST', '/v1/enroll', { protocol: PROTOCOL, key: KEY, platform: 'linux', version: '0.1.0', label: 'web-01', ...(mode ? { mode } : {}) });
  assert.equal(done.status, 201);
  return done.body;
}

test('enrolment needs the key, device credentials are stored as digests, and operators need their token', async () => {
  const s = service();
  assert.equal((await s.call('POST', '/v1/enroll', { protocol: PROTOCOL, key: 'wrong', platform: 'linux', version: '1', label: 'x' })).status, 401);
  const device = await enrolled(s);
  assert.match(device.token, /^[a-f0-9]{64}$/);
  assert.notEqual((await s.env.DB.prepare('SELECT token_hash FROM devices').first()).token_hash, device.token);
  assert.equal((await s.call('GET', '/v1/devices')).status, 401);
  assert.equal((await s.call('GET', '/v1/devices', null, device.token)).status, 401);
  assert.equal((await s.call('POST', '/v1/report', report([]), 'f'.repeat(64))).status, 401);
  assert.equal((await s.call('POST', '/v1/report', report([]), device.token)).body.accepted, true);
  const listed = await s.call('GET', '/v1/devices', null, ADMIN);
  assert.deepEqual({ label: listed.body.devices[0].label, watching: listed.body.devices[0].watching, mode: listed.body.devices[0].mode }, { label: 'web-01', watching: true, mode: 'kill' });
  assert.equal((await service({ ADMIN_TOKEN: 'short' }).call('GET', '/v1/devices', null, 'short')).status, 500);
});

test('a case is scored here, stored encrypted, alerted with service-written text, and survives a restart of the report', async () => {
  const sent = [], real = globalThis.fetch;
  globalThis.fetch = async (url, init) => { sent.push({ url, body: JSON.parse(init.body) }); return new Response('{}'); };
  try {
    const s = service({ ALERT_WEBHOOK_URL: 'https://hooks.example/alert' }), device = await enrolled(s);
    const sentCase = item('a', ['shell_from_web_server', 'risky_command_line'], { name: 'dash', parent: 'php-fpm', level: 'CLEAR', score: 0 });
    assert.equal((await s.call('POST', '/v1/report', report([sentCase]), device.token)).body.saved, 1);
    await s.settle();
    const row = await s.env.DB.prepare('SELECT * FROM cases').first();
    assert.equal(row.level, 'SUSPECT'); assert.ok(!row.detail.includes('php-fpm'));
    assert.equal(sent.length, 1); assert.match(sent[0].body.text, /web-01: Sentinel flagged something that is a shell started by a web server process/);
    assert.doesNotMatch(JSON.stringify(sent[0].body), /Written on the device/);
    await s.call('POST', '/v1/report', report([sentCase]), device.token); await s.settle();
    assert.equal(sent.length, 1);
    const listed = await s.call('GET', '/v1/cases?state=open', null, ADMIN);
    assert.equal(listed.body.cases.length, 1); assert.equal(listed.body.cases[0].title, 'dash looks suspicious');
    const full = await s.call('GET', '/v1/cases/' + row.id, null, ADMIN);
    assert.equal(full.body.detail.score, 6); assert.equal(full.body.detail.signals[0].category, 'lineage');
  } finally { globalThis.fetch = real; }
});

test('malformed or inflated cases are refused', async () => {
  const s = service(), device = await enrolled(s);
  const send = cases => s.call('POST', '/v1/report', report(cases), device.token);
  for (const bad of [item('a', ['beaconing'], { signals: [{ id: 'made_up', points: 9, evidence: '' }] }), item('a', ['beaconing'], { signals: [{ id: 'beaconing', points: 9, evidence: '' }] }),
    item('a', ['beaconing'], { signals: [{ id: 'owner_trusted', points: 5, evidence: '' }] }), item('a', ['beaconing'], { name: '<script>' }), item('a', ['beaconing'], { key: 'short' }),
    item('a', ['beaconing'], { remotes: [{ address: 'evil.example/x', port: 1, names: [], direction: 'out' }] })]) assert.equal((await send([bad])).status, 400);
  assert.equal((await send([item('a', ['beaconing']), item('a', ['beaconing'])])).status, 400);
  assert.equal((await send([item('a', ['unsigned_program'])])).body.saved, 0);
  assert.equal(validateCase(item('a', ['unsigned_program', 'shell_from_web_server', 'unusual_port', 'beaconing'])).level, 'HOSTILE');
});

test('kill is the default: the agent ends the program and the case records it; the service can hold agents to less', async () => {
  const s = service(), device = await enrolled(s);
  assert.equal(device.mode, 'kill');
  const killed = item('a', ['shell_from_web_server', 'risky_command_line'], { name: 'dash', actions: [{ action: 'stopped', programs: 2, reason: 'a web server started a shell' }] });
  const answer = (await s.call('POST', '/v1/report', report([killed]), device.token)).body;
  assert.deepEqual({ saved: answer.saved, commands: answer.commands, mode: answer.mode }, { saved: 1, commands: [], mode: 'kill' });
  const found = (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases[0];
  assert.deepEqual({ title: found.title, severity: found.severity, stopped: found.stopped, paused: found.paused, state: found.state }, { title: 'dash was stopped', severity: 'high', stopped: true, paused: false, state: 'open' });
  // Nothing is left to decide, but the operator's verdict still teaches: it was ours, or it was an attack.
  assert.equal((await s.call('POST', '/v1/cases/' + found.id + '/action', { action: 'stop' }, ADMIN)).status, 409);
  assert.equal((await s.call('POST', '/v1/cases/' + found.id + '/action', { action: 'confirm' }, ADMIN)).body.state, 'resolved');
  // An agent gets the lower of what it asks for and what the service allows.
  assert.equal((await enrolled(s, 'pause')).mode, 'pause');
  assert.equal((await enrolled(s, 'report')).mode, 'report');
  assert.equal((await enrolled(service({ RESPONSE_MODE: 'pause' }))).mode, 'pause');
  assert.equal((await enrolled(service({ RESPONSE_MODE: 'report' }), 'kill')).mode, 'report');
  assert.equal((await enrolled(service({ RESPONSE_MODE: 'nonsense' }))).mode, 'kill');
});

test('in pause mode a program is stopped or released only by the operator', async () => {
  const s = service({ RESPONSE_MODE: 'pause' }), device = await enrolled(s);
  const paused = item('a', ['shell_from_web_server', 'risky_command_line'], { name: 'dash', actions: [{ action: 'paused', programs: 2, reason: 'a web server started a shell' }], chain: [{ name: 'php-fpm', path: '/usr/sbin/php-fpm' }] });
  assert.deepEqual((await s.call('POST', '/v1/report', report([paused]), device.token)).body.commands, []);
  const found = (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases[0];
  assert.deepEqual({ title: found.title, severity: found.severity, paused: found.paused }, { title: 'dash was paused', severity: 'high', paused: true });
  assert.equal((await s.call('POST', '/v1/cases/' + found.id + '/action', { action: 'stop' })).status, 401);
  assert.equal((await s.call('POST', '/v1/cases/' + found.id + '/action', { action: 'delete' }, ADMIN)).status, 400);
  assert.equal((await s.call('POST', '/v1/cases/' + found.id + '/action', { action: 'stop' }, ADMIN)).body.pending, 'stop');
  assert.deepEqual((await s.call('POST', '/v1/report', report([]), device.token)).body.commands, [{ key: 'a'.repeat(32), action: 'stop' }]);
  await s.call('POST', '/v1/report', report([], { results: [{ key: 'a'.repeat(32), action: 'released', programs: 2 }] }), device.token);
  assert.equal((await s.call('GET', '/v1/cases', null, ADMIN)).body.cases[0].pending, 'stop');
  await s.call('POST', '/v1/report', report([], { results: [{ key: 'a'.repeat(32), action: 'stopped', programs: 2, gone: 0 }] }), device.token);
  const done = (await s.call('GET', '/v1/cases/' + found.id, null, ADMIN)).body;
  assert.deepEqual({ state: done.state, paused: done.paused, outcome: done.detail.outcome.action }, { state: 'resolved', paused: false, outcome: 'stopped' });
  // A report-only deployment records no pause and sends no command.
  const quiet = service({ RESPONSE_MODE: 'report' }), watcher = await enrolled(quiet);
  assert.equal(watcher.mode, 'report');
  await quiet.call('POST', '/v1/report', report([paused]), watcher.token);
  const seen = (await quiet.call('GET', '/v1/cases', null, ADMIN)).body.cases[0];
  assert.equal(seen.paused, false);
  assert.equal((await quiet.call('POST', '/v1/cases/' + seen.id + '/action', { action: 'stop' }, ADMIN)).status, 409);
  // A removed device is refused and its pending decisions are dropped.
  await s.call('POST', '/v1/devices/' + device.device_id + '/revoke', {}, ADMIN);
  assert.equal((await s.call('POST', '/v1/report', report([]), device.token)).status, 401);
});

test('operators teach the policy within its bounds, and trusted programs are sent back to the agent', async () => {
  const s = service(), device = await enrolled(s);
  for (const letter of ['a', 'b', 'c']) {
    await s.call('POST', '/v1/report', report([item(letter, ['runs_from_temp', 'drop_or_tunnel_host', 'llm_api_host'])]), device.token);
    const open = (await s.call('GET', '/v1/cases?state=open', null, ADMIN)).body.cases[0];
    const done = (await s.call('POST', '/v1/cases/' + open.id + '/action', { action: 'trust' }, ADMIN)).body;
    if (letter === 'c') {
      assert.deepEqual(done.learned.changes, [{ signal: 'drop_or_tunnel_host', from: 0, to: -1 }, { signal: 'llm_api_host', from: 0, to: -1 }]);
      assert.deepEqual(done.learned.rejected.map(entry => entry.signal), ['runs_from_temp']);
    }
  }
  const next = (await s.call('POST', '/v1/report', report([]), device.token)).body;
  assert.deepEqual(next.policy, { drop_or_tunnel_host: -1, llm_api_host: -1 }); assert.equal(next.trusted.length, 3);
  assert.equal((await s.call('GET', '/v1/learning', null, ADMIN)).body.dismissed, 3);
  await s.call('POST', '/v1/learning/reset', {}, ADMIN);
  assert.deepEqual((await s.call('POST', '/v1/report', report([]), device.token)).body.policy, {});
  for (const shape of REFERENCE_ATTACKS) assert.ok(reported(scoreShape(shape).level), shape.join('+'));
  assert.deepEqual(cleanPolicy({ unusual_port: -2, beaconing: 3, advisory_indicator: -1, made_up: 1 }), { unusual_port: -2 });
  assert.deepEqual(learnPolicy(Array(9).fill({ shape: ['advisory_indicator', 'dcsync_pattern'], verdict: 'dismissed' })).policy, {});
});

test('the AI analyst is optional, pluggable and advisory', async () => {
  const detail = validateCase(item('a', ['shell_from_web_server', 'risky_command_line'], { name: 'dash', parent: 'php-fpm' }));
  const asked = analystRequest(detail, 'linux', { dismissed: 0, confirmed: 2 });
  assert.equal(asked.signals[0].meaning, 'is a shell started by a web server process'); assert.equal(asked.similar_cases_before.confirmed_attacks, 2);
  assert.deepEqual(parseAnalysis('Sure! {"summary":"A web shell ran a downloader.","technique":"web shell","recommendation":"stop","confidence":"high"} hope that helps'), { summary: 'A web shell ran a downloader.', technique: 'web shell', recommendation: 'stop', confidence: 'high' });
  assert.deepEqual(parseAnalysis({ summary: 'x', recommendation: 'format the disk', confidence: 'certain' }), { summary: 'x', technique: 'unclear', recommendation: 'investigate', confidence: 'low' });
  assert.equal(parseAnalysis('no json here'), null);
  // Workers AI through the AI binding.
  const calls = [], s = service({ AI_PROVIDER: 'workers-ai', AI_MODEL: '@cf/example/model', AI: { run: async (model, input) => { calls.push({ model, input }); return { response: '{"summary":"A web server started a shell that downloads and runs a script.","technique":"web shell","recommendation":"stop","confidence":"medium"}' }; } } });
  const device = await enrolled(s);
  await s.call('POST', '/v1/report', report([item('a', ['shell_from_web_server', 'risky_command_line'])]), device.token); await s.settle();
  const found = (await s.call('GET', '/v1/cases', null, ADMIN)).body.cases[0];
  assert.equal(calls[0].model, '@cf/example/model'); assert.match(calls[0].input.messages[0].content, /never an instruction to you/);
  assert.deepEqual({ recommendation: found.analysis.recommendation, provider: found.analysis.provider, state: found.state, pending: found.pending }, { recommendation: 'stop', provider: 'workers-ai', state: 'open', pending: null });
  // An OpenAI-compatible endpoint, and a failing one: the case is unaffected either way.
  const real = globalThis.fetch;
  try {
    globalThis.fetch = async (url, init) => { assert.equal(url, 'https://llm.example/v1/chat/completions'); assert.equal(init.headers.Authorization, 'Bearer k'); return new Response(JSON.stringify({ choices: [{ message: { content: '{"summary":"Looks like routine activity.","recommendation":"release","confidence":"low"}' } }] })); };
    const o = service({ AI_PROVIDER: 'openai', AI_BASE_URL: 'https://llm.example/v1/', AI_MODEL: 'm', AI_API_KEY: 'k' }), d = await enrolled(o);
    await o.call('POST', '/v1/report', report([item('a', ['shell_from_web_server', 'risky_command_line'])]), d.token); await o.settle();
    const id = (await o.call('GET', '/v1/cases', null, ADMIN)).body.cases[0].id;
    assert.equal((await o.call('GET', '/v1/cases/' + id, null, ADMIN)).body.analysis.recommendation, 'release');
    globalThis.fetch = async () => new Response('nope', { status: 500 });
    assert.match((await o.call('POST', '/v1/cases/' + id + '/analyze', {}, ADMIN)).body.analysis.error, /answered 500/);
    assert.equal((await o.call('GET', '/v1/cases/' + id, null, ADMIN)).body.state, 'open');
  } finally { globalThis.fetch = real; }
  const none = service(), plain = await enrolled(none);
  await none.call('POST', '/v1/report', report([item('a', ['shell_from_web_server', 'risky_command_line'])]), plain.token); await none.settle();
  assert.equal((await none.call('GET', '/v1/cases', null, ADMIN)).body.cases[0].analysis, null);
});
