import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/service.mjs';
import { judge, markOf, markOfText, rowsOf } from '../src/edge.mjs';
import tail, { recordsOf } from '../edge/tail.mjs';
import { refused } from '../edge/guard.mjs';
import { environment } from './d1.mjs';

const ADMIN = 'a'.repeat(40), INGEST = 'i'.repeat(40), VISITOR = '93.184.216.34';
function service(changes) {
  const env = environment({ INGEST_TOKEN: INGEST, TOR_EXITS: 'off', WATCHLIST: 'off', ...changes }), waiting = [], ctx = { waitUntil: promise => waiting.push(promise) };
  const call = async (method, path, body, token) => {
    const response = await worker.fetch(new Request('https://sentinel.example' + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }), env, ctx);
    return { status: response.status, body: await response.json() };
  };
  return { env, call, settle: () => Promise.all(waiting.splice(0)) };
}
const record = (method, target, status, client = VISITOR) => ({ client, ...markOf(method, target, status) });

test('one request is marked where it is seen, and its own text is not in the marks', () => {
  assert.equal(markOf('GET', '/pricing', 200), null);
  assert.deepEqual(markOf('GET', '/admin/backup.zip', 404), { missing: markOfText('/admin/backup.zip') });
  assert.deepEqual(markOf('GET', "/search?q=1'%20OR%20'1'='1", 200).injection, 'SQL injection');
  assert.equal(markOf('GET', '/files?name=..%252f..%252f..%252fetc%252fpasswd', 500).injection, 'path traversal'); // encoded twice, as attackers do
  assert.equal(markOf('GET', '/files?name=..%2f..%2fetc%2fpasswd', 500).answered, true);
  assert.equal(markOf('GET', '/files?name=..%2f..%2fetc%2fpasswd', 403).answered, undefined);
  assert.deepEqual(markOf('POST', '/account/login', 401), { login: true });
  assert.deepEqual(markOf('POST', '/api/import', 502), { error: true });
  assert.equal(markOf('GET', '/uploads/img.php?cmd=id', 200).shell, true);
  assert.equal(markOf('GET', '/uploads/img.php?cmd=id', 404).shell, undefined);
  const first = markOf('GET', '/invoices/1041', 200), second = markOf('GET', '/invoices/1042', 200);
  assert.equal(first.shape, second.shape);     // the same address pattern
  assert.notEqual(first.number, second.number); // a different record
  const sent = JSON.stringify(markOf('GET', '/customers/1041/export?token=s3cr3t-value', 200));
  assert.ok(!sent.includes('customers') && !sent.includes('s3cr3t') && !sent.includes('1041'), sent);
});

test('a record that is not in the agreed form is refused whole', () => {
  assert.deepEqual(rowsOf({ client: VISITOR, login: true }), [['login', '', '']]);
  assert.deepEqual(rowsOf({ client: VISITOR }), []);
  for (const bad of [null, {}, { client: 'not an address', login: true }, { client: VISITOR, missing: '/etc/passwd' }, { client: VISITOR, injection: 'DROP TABLE users' },
    { client: VISITOR, shape: markOfText('a') }, { client: VISITOR, shape: 'x', number: 'y' }]) assert.equal(rowsOf(bad), null, JSON.stringify(bad));
});

test('one visitor is judged on the last minutes, by the thresholds the agent uses', () => {
  const rows = (kind, count, at, value = index => String(index), extra = () => '') => Array.from({ length: count }, (_, index) => ({ kind, value: value(index), extra: extra(index), at }));
  const ids = found => found.map(item => item.id);
  assert.deepEqual(ids(judge(rows('missing', 59, 1000), 1010)), []);
  assert.deepEqual(ids(judge(rows('missing', 60, 1000), 1010)), ['web_fuzzing']);
  assert.deepEqual(ids(judge(rows('missing', 60, 1000, () => 'same'), 1010)), [], 'sixty different pages, not one page sixty times');
  assert.deepEqual(ids(judge(rows('missing', 60, 1000), 1070)), [], 'a minute later it is over');
  const injected = judge([...rows('injection', 2, 1000, () => 'SQL injection'), ...rows('injection', 1, 1000, () => 'path traversal', () => '1')], 1100);
  assert.deepEqual(ids(injected), ['web_injection_attempt', 'web_injection_answered']);
  assert.equal(injected[0].evidence, 'This web client sent 3 requests shaped like SQL injection and path traversal.');
  assert.deepEqual(ids(judge(rows('number', 40, 1000, () => 'shape', index => 'n' + index), 1010)), ['web_enumeration']);
  assert.deepEqual(ids(judge(rows('number', 40, 1000, index => 'shape' + index, () => 'n'), 1010)), [], 'forty patterns once each is ordinary browsing');
  assert.deepEqual(ids(judge(rows('login', 30, 1000), 1010)), ['web_login_burst']);
  assert.deepEqual(ids(judge(rows('shell', 1, 1000), 1200)), ['web_shell_request']);
  assert.deepEqual(ids(judge(rows('error', 20, 1000), 1010)), ['web_error_burst']);
});

test('marks forwarded by an edge system become a case for that visitor, kept without any request text', async () => {
  const { env, call, settle } = service();
  assert.equal((await call('POST', '/v1/edge-events', { name: 'shop-api', records: [] })).status, 401);
  assert.equal((await call('POST', '/v1/edge-events', { name: 'shop api!', records: [] }, INGEST)).status, 400);
  assert.equal((await call('POST', '/v1/edge-events', { name: 'shop-api', records: [{ client: VISITOR, missing: '/etc/passwd' }] }, INGEST)).status, 400);
  // An ordinary visitor: a few pages, one failed sign-in.
  const ordinary = [record('GET', '/', 200), record('GET', '/missing.png', 404), record('POST', '/login', 401), record('GET', '/orders/7', 200)].filter(item => Object.keys(item).length > 1);
  assert.deepEqual((await call('POST', '/v1/edge-events', { name: 'shop-api', records: ordinary }, INGEST)).body, { accepted: true, records: 3, saved: 0 });
  // A scanner, in three batches as an edge system sends them: nothing on the first two, a case on the third.
  const probe = index => record('GET', '/files?id=' + index + "'%20UNION%20SELECT%20password%20FROM%20users--", index === 2 ? 500 : 403, '45.33.32.156');
  assert.equal((await call('POST', '/v1/edge-events', { name: 'shop-api', records: [probe(0)] }, INGEST)).body.saved, 0);
  assert.equal((await call('POST', '/v1/edge-events', { name: 'shop-api', records: [probe(1)] }, INGEST)).body.saved, 0);
  assert.equal((await call('POST', '/v1/edge-events', { name: 'shop-api', records: [probe(2)] }, INGEST)).body.saved, 1);
  await settle();
  const cases = (await call('GET', '/v1/cases?state=open', null, ADMIN)).body.cases;
  assert.equal(cases.length, 1);
  assert.equal(cases[0].device, 'Edge (shop-api)');
  assert.equal(cases[0].platform, 'edge');
  const one = (await call('GET', '/v1/cases/' + cases[0].id, null, ADMIN)).body, detail = one.detail || one.case?.detail;
  assert.deepEqual(detail.signals.map(signal => signal.id), ['web_injection_attempt', 'web_injection_answered']);
  assert.deepEqual(detail.remotes, [{ address: '45.33.32.156', port: 0, names: [], direction: 'in' }]);
  const stored = JSON.stringify((await env.DB.prepare('SELECT * FROM edge_marks').all()).results);
  assert.ok(!/UNION|password|files\?id/i.test(stored), 'no request text is stored');
  // Nobody is refused until a person confirms; then that visitor is, and only that visitor.
  assert.deepEqual((await call('GET', '/v1/edge/refused', null, INGEST)).body, { addresses: [] });
  assert.equal((await call('POST', '/v1/cases/' + cases[0].id + '/action', { action: 'confirm' }, ADMIN)).status, 200);
  assert.deepEqual((await call('GET', '/v1/edge/refused', null, INGEST)).body, { addresses: ['45.33.32.156'] });
  assert.equal((await call('GET', '/v1/edge/refused', null, 'wrong'.repeat(8))).status, 401);
  // The visitor comes back and is turned away; that request is forwarded too and opens the case again. They stay
  // refused, until the operator takes the verdict back.
  assert.equal((await call('POST', '/v1/edge-events', { name: 'shop-api', records: [record('GET', '/', 403, '45.33.32.156')] }, INGEST)).body.saved, 1);
  assert.equal((await call('GET', '/v1/cases?state=open', null, ADMIN)).body.cases.length, 1);
  assert.deepEqual((await call('GET', '/v1/edge/refused', null, INGEST)).body, { addresses: ['45.33.32.156'] });
  assert.equal((await call('POST', '/v1/cases/' + cases[0].id + '/action', { action: 'reopen' }, ADMIN)).status, 200);
  assert.deepEqual((await call('GET', '/v1/edge/refused', null, INGEST)).body, { addresses: [] });
  // A directory scan alone is below the bar, as it is for the agent: it is kept, and counts with anything else.
  const again = service();
  const scan = Array.from({ length: 60 }, (_, index) => record('GET', '/wp-content/' + index + '.bak', 404));
  assert.equal((await again.call('POST', '/v1/edge-events', { name: 'shop-api', records: scan }, INGEST)).body.saved, 0);
  // A visitor marked as ours is never reported again.
  const three = [0, 1, 2].map(index => record('GET', '/files?id=' + index + '%27%20UNION%20SELECT%20password%20FROM%20users--', 200));
  assert.equal((await again.call('POST', '/v1/edge-events', { name: 'shop-api', records: three }, INGEST)).body.saved, 1);
  const found = (await again.call('GET', '/v1/cases?state=open', null, ADMIN)).body.cases[0];
  assert.match(found.level, /HOSTILE|SUSPECT/);
  await again.call('POST', '/v1/cases/' + found.id + '/action', { action: 'trust' }, ADMIN);
  assert.equal((await again.call('POST', '/v1/edge-events', { name: 'shop-api', records: three }, INGEST)).body.saved, 0);
});

test('the Workers forwarder sends marks only, and the guard refuses only whom the service names', async () => {
  const event = (url, status, method = 'GET', client = VISITOR) => ({ scriptName: 'shop-api', eventTimestamp: 1794780000123, outcome: 'ok', logs: [], exceptions: [],
    event: { request: { url: 'https://shop.example/REDACTED', method, headers: { 'cf-connecting-ip': client, cookie: 'REDACTED' }, getUnredacted: () => ({ url, method, headers: { 'cf-connecting-ip': client, cookie: 'session=abc' } }) }, response: { status } } });
  const records = recordsOf([event('https://shop.example/pricing', 200), event('https://shop.example/files?name=../../etc/passwd', 500), { scriptName: 'cron', event: null }, event('https://shop.example/x.php?cmd=id', 200, 'GET', 'not-an-address')]);
  assert.equal(records.length, 2);
  assert.deepEqual(records[0], { client: VISITOR, at: 1794780000, injection: 'path traversal', answered: true });
  const sent = [];
  const before = globalThis.fetch;
  globalThis.fetch = async (url, init) => { sent.push({ url, init }); return new Response('{}'); };
  try {
    const waiting = [];
    await tail.tail([event('https://shop.example/files?name=../../etc/passwd&session=abc', 500)], { SENTINEL_URL: 'https://sentinel.example/', SENTINEL_TOKEN: INGEST }, { waitUntil: promise => waiting.push(promise) });
    await Promise.all(waiting);
    await tail.tail([event('https://shop.example/pricing', 200)], { SENTINEL_URL: 'https://sentinel.example/', SENTINEL_TOKEN: INGEST }, { waitUntil: promise => waiting.push(promise) });
  } finally { globalThis.fetch = before; }
  assert.equal(sent.length, 1, 'an ordinary request sends nothing at all');
  assert.equal(sent[0].url, 'https://sentinel.example/v1/edge-events');
  assert.ok(!/passwd|session|cookie|shop\.example/.test(sent[0].init.body), sent[0].init.body);
  assert.equal(JSON.parse(sent[0].init.body).name, 'shop-api');
  // The forwarder's records are exactly what the service takes.
  const { call } = service();
  assert.equal((await call('POST', '/v1/edge-events', JSON.parse(sent[0].init.body), INGEST)).status, 200);

  const env = { SENTINEL_URL: 'https://sentinel.example', SENTINEL_TOKEN: INGEST }, asked = [];
  const fetcher = async url => { asked.push(url); return new Response(JSON.stringify({ addresses: ['45.33.32.156'] })); };
  const visit = client => new Request('https://shop.example/', { headers: { 'cf-connecting-ip': client } });
  assert.equal((await refused(visit('45.33.32.156'), env, {}, fetcher)).status, 403);
  assert.equal(await refused(visit(VISITOR), env, {}, fetcher), null);
  assert.equal(asked.length, 1, 'the list is asked for once a minute, not once a request');
  assert.equal(await refused(visit('45.33.32.156'), {}, {}, fetcher), null, 'with no service configured nobody is refused');
});

test('a script served from an uploads folder, a smuggled object and an overflow probe are marked', () => {
  assert.deepEqual(markOf('GET', '/wp-content/uploads/a.php', 200), { uploaded: true });
  assert.equal(markOf('GET', '/wp-content/uploads/photo.jpg', 200), null);
  assert.equal(markOf('GET', '/index.php', 200), null);
  assert.equal(markOf('GET', '/uploads/a.php', 404).uploaded, undefined);
  assert.equal(markOf('GET', '/uploads/a.php?cmd=id', 200).uploaded, undefined, 'a command parameter is the older mark');
  assert.equal(markOf('GET', '/CFIDE/x.cfm?cmd=id', 200).shell, true);
  assert.equal(markOf('GET', '/api?data=O:8:%22Requests%22:1:%7B%7D', 500).injection, 'object injection');
  assert.equal(markOf('GET', '/r/' + '+'.repeat(60), 400).injection, 'a memory corruption probe');
  assert.equal(markOf('GET', '/search?q=' + 'a+'.repeat(60), 200), null);
  // An object sent in a cookie, as base64, alone or after a name and a colon. The cookie itself is not in the marks.
  const object = btoa('O:8:"Requests":1:{s:3:"url";s:1:"x";}');
  assert.deepEqual(markOf('GET', '/', 200, 'theme=dark; state=' + object), { injection: 'object injection', answered: true });
  assert.equal(markOf('GET', '/', 403, 'warm=Warmer:' + object).injection, 'object injection');
  assert.equal(markOf('GET', '/', 200, 'theme=dark; session=' + btoa('an ordinary session value 123456')), null);
  assert.ok(!JSON.stringify(markOf('GET', '/', 200, 'state=' + object)).includes(object));
  assert.deepEqual(rowsOf({ client: VISITOR, uploaded: true }), [['uploaded', '', '']]);
  const row = (kind, at) => ({ kind, value: '', extra: '', at });
  assert.deepEqual(judge([row('uploaded', 100)], 110), [{ id: 'web_shell_request', evidence: 'This web client was served a server-side script from an uploads folder 1 time(s).' }]);
  assert.match(judge([row('uploaded', 100), row('shell', 101)], 110)[0].evidence, /with a command parameter 1 time/);
});

test('the service says which signals it knows and takes the later ones', async () => {
  const { validateCase } = await import('../src/service.mjs');
  const { SIGNAL_SET, SIGNALS } = await import('../src/signals.mjs');
  assert.equal(SIGNAL_SET, 5);
  for (const [id, points] of [['helper_with_child', 5], ['privilege_jump', 6]]) {
    assert.ok(SIGNALS[id]);
    const taken = validateCase({ key: 'a'.repeat(32), name: 'sh', path: '/usr/bin/dash', parent: 'bash', signals: [{ id, points, category: 'x', evidence: 'e' }], remotes: [], categories: [], level: 'SUSPECT', score: points, observed_at: 1794832407, first_seen: 1794832407 });
    assert.equal(taken.signals[0].id, id);
  }
});
