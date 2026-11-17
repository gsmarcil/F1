import { analyze } from './analyst.mjs';
import { CLOUD_EVIDENCE, CLOUD_SOURCES, evaluateCloud } from './cloud.mjs';
import { judge, rowsOf } from './edge.mjs';
import { currentPolicy, learningView, recallSimilar, rememberVerdict, resetLearning } from './learning.mjs';
import { LOCKED, SIGNALS, SIGNAL_SET, TRUST, WATCH_HOSTS, levelFor, reported } from './signals.mjs';
import { bodyJson, fail, json, now, randomToken, sameSecret, seal, sha256, text, unseal, whole } from './util.mjs';

// Sentinel service: one Cloudflare Worker and one D1 database for one organisation.
//
//   Agents   POST /v1/enroll   (enrolment key)       -> a per-device credential
//            POST /v1/report   (device credential)   -> cases in, decisions and learned weights out
//            GET  /v1/pulse    (no credential)       -> the revision of the shared state, from memory
//            GET  /v1/state    (the fleet read key)  -> the shared state: weights, pairs, watched and shared addresses
//   Operators (ADMIN_TOKEN)
//            GET  /v1/devices            POST /v1/devices/:id/revoke
//            GET  /v1/cases[?state=open] GET  /v1/cases/:id
//            POST /v1/cases/:id/action   {"action": "trust" | "confirm" | "resolve" | "reopen" | "stop" | "release"}
//            POST /v1/cases/:id/analyze  GET /v1/learning   POST /v1/learning/reset
//            GET  /v1/coverage  GET /v1/fleet  POST /v1/fleet/add {"address","reason"}  POST /v1/fleet/remove {"address"}
//   Cloud audit records (INGEST_TOKEN or ADMIN_TOKEN)
//            POST /v1/cloud-events  {"source": "entra-audit" | "entra-signin" | "aws-cloudtrail" | "azure-activity", "records": [...]}
//   Edge systems and devices with no agent (INGEST_TOKEN or ADMIN_TOKEN)
//            POST /v1/edge-events   {"name": "<the system>", "records": [...]}   marks of its requests, see edge.mjs
//            GET  /v1/edge/refused  the visitors an operator confirmed as attackers, for the edge system to refuse
//
// The only command this service ever sends an agent is the operator's own decision on a program that agent
// paused. It cannot name a process or run anything on a device.
export const PROTOCOL = 'sentinel-v1';
const PLATFORMS = ['windows', 'macos', 'linux'], MAX_CASES = 8, MAX_CASES_PER_DEVICE = 60;
// What one machine can set off by itself in a day, whatever it reports: addresses added to the shared list, and
// questions put to the decision model. A machine an intruder controls holds a valid credential, so neither may
// be unlimited. An operator's own verdict is not limited this way.
const DEVICE_SHARES_A_DAY = 8, DECISIONS_A_DAY = 12, FLEET_MAX = 300;
// What an agent may do about a hostile program. kill: end it at once (the default). pause: freeze it and wait
// for an operator. decide: freeze it and let the decision model say stop, release or hold. report: nothing.
// An agent gets the lower of what it asked for and what RESPONSE_MODE allows. With no RESPONSE_MODE set, a
// deployment that has a model configured decides with it, and one without ends hostile programs outright.
export const MODES = ['report', 'pause', 'decide', 'kill'];
const hasModel = env => (env.AI_PROVIDER || 'none') !== 'none';
const allowedMode = env => MODES.includes(env.RESPONSE_MODE) ? env.RESPONSE_MODE : hasModel(env) ? 'decide' : 'kill';
const fallbackFor = env => env.DECISION_FALLBACK === 'hold' ? 'hold' : 'kill';

// What an agent did after stopping a program: files quarantined, startup entries switched off, things left for a person.
const cleanupSteps = value => {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 12) fail(400, 'Invalid cleanup.');
  return value.map(item => { if (!item || !['quarantined', 'disabled', 'ended', 'review', 'left'].includes(item.action) || !text(item.kind, 40) || !text(item.where, 200)) fail(400, 'Invalid cleanup.'); return { action: item.action, kind: item.kind, where: item.where }; });
};

export function validateCase(input) {
  if (!input || typeof input !== 'object' || !/^[a-f0-9]{32}$/.test(input.key || '') || !text(input.name, 80) || text(input.path ?? '', 300) === null || text(input.parent ?? '', 80) === null) fail(400, 'Invalid case.');
  if (!Array.isArray(input.signals) || !input.signals.length || input.signals.length > 14 || !Array.isArray(input.remotes) || input.remotes.length > 8) fail(400, 'Invalid case.');
  const signals = input.signals.map(signal => {
    const id = signal?.id, trust = TRUST.has(id), known = SIGNALS[id];
    if (!trust && !known || !whole(signal.points, -9, 9) || signal.points === 0 || trust !== (signal.points < 0) || text(signal.evidence, 200) === null) fail(400, 'Invalid signal.');
    // A learned policy may move a signal two points from its base weight (one more for a stronger variant), never further.
    if (!trust && Math.abs(signal.points - known.weight) > 2) fail(400, 'Invalid signal.');
    return { id, points: signal.points, category: trust ? 'trust' : known.category, evidence: signal.evidence };
  });
  if (new Set(signals.map(signal => signal.id)).size !== signals.length) fail(400, 'Invalid signal.');
  const remotes = input.remotes.map(remote => {
    if (!remote || !text(remote.address, 60) || !/^[0-9a-fA-F:.]+$/.test(remote.address) || !whole(remote.port, 0, 65535) || !['in', 'out'].includes(remote.direction) || !Array.isArray(remote.names) || remote.names.length > 2 || remote.names.some(name => !text(name, 120))) fail(400, 'Invalid connection.');
    return { address: remote.address, port: remote.port, names: remote.names, direction: remote.direction };
  });
  const list = (value, max, check) => { if (value === undefined) return []; if (!Array.isArray(value) || value.length > max) fail(400, 'Invalid case.'); return value.map(check); };
  const chain = list(input.chain, 6, item => { if (!item || !text(item.name, 80) || text(item.path ?? '', 300) === null) fail(400, 'Invalid chain.'); return { name: item.name, path: item.path ?? '' }; });
  const actions = list(input.actions, 2, item => { if (!item || !['paused', 'pause_failed', 'stopped', 'stop_failed'].includes(item.action) || !whole(item.programs, 0, 64) || text(item.reason ?? '', 160) === null) fail(400, 'Invalid action.'); return { action: item.action, programs: item.programs, reason: item.reason ?? '' }; });
  const persistence = list(input.persistence, 6, item => { if (!item || !text(item.kind, 40) || !text(item.where, 200)) fail(400, 'Invalid persistence.'); return { kind: item.kind, where: item.where }; });
  const cleanup = cleanupSteps(input.cleanup);
  if (input.repeats !== undefined && !whole(input.repeats, 0, 9999)) fail(400, 'Invalid case.');
  // The level is decided here from the signals, never taken from the device.
  const score = signals.reduce((sum, signal) => sum + signal.points, 0), categories = [...new Set(signals.filter(signal => signal.points > 0).map(signal => signal.category))].sort();
  return { key: input.key, name: input.name, path: input.path ?? '', parent: input.parent ?? '', signals, remotes, chain, actions, persistence, ...(cleanup.length ? { cleanup } : {}), ...(input.repeats ? { repeats: input.repeats } : {}), score, categories, level: levelFor(score, categories.length), observed_at: now() };
}
const isPaused = detail => !!detail?.actions?.some(action => action.action === 'paused') && !detail.outcome;
const why = detail => detail.signals.filter(signal => signal.points > 0).sort((a, b) => b.points - a.points).slice(0, 2).map(signal => SIGNALS[signal.id].phrase).join(' and ');
function titleFor(detail, paused, stopped) {
  const positive = detail.signals.filter(signal => signal.points > 0);
  if (positive.every(signal => signal.category === 'cloud')) return 'Cloud: ' + detail.name;
  if (positive.some(signal => signal.id === 'web_shell_file')) return 'New script in a web folder: ' + detail.name;
  if (positive.some(signal => signal.category === 'web') && positive.every(signal => ['web', 'inbound'].includes(signal.category))) return 'Web attack: ' + detail.name;
  if (positive.some(signal => signal.id === 'antivirus_detection')) return 'Windows Defender detected a threat';
  if (positive.every(signal => signal.category === 'inbound')) return 'Connection attempts against ' + detail.name;
  if (!detail.path && positive.every(signal => signal.category === 'directory')) return 'Directory attack pattern: ' + detail.name;
  return detail.name + (stopped ? ' was stopped' : paused ? ' was paused' : detail.level === 'HOSTILE' ? ' looks hostile' : ' looks suspicious');
}
// ---- the fleet mesh: what one machine learns protects the others
const IP = /^[0-9a-fA-F:.]{3,45}$/;
const privateAddress = address => /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.|::1$|::$|f[cd][0-9a-f]{2}:|fe80:)/i.test(address);
function meshOf(input) {
  const mesh = input && typeof input === 'object' ? input : {};
  const addresses = (Array.isArray(mesh.addresses) ? mesh.addresses : []).filter(address => typeof address === 'string' && IP.test(address)).slice(0, 8);
  const peers = (Array.isArray(mesh.peers) ? mesh.peers : []).filter(peer => peer && typeof peer.address === 'string' && IP.test(peer.address) && whole(peer.port, 0, 65535) && ['in', 'out'].includes(peer.direction)).slice(0, 60).map(peer => ({ address: peer.address, port: peer.port, direction: peer.direction }));
  const coverage = {};
  for (const [key, value] of Object.entries(mesh.coverage && typeof mesh.coverage === 'object' ? mesh.coverage : {}).slice(0, 12))
    if (/^[a-z_]{3,24}$/.test(key) && (typeof value === 'boolean' || whole(value, 0, 1e6) || text(value, 16))) coverage[key] = value;
  return { addresses, peers, coverage };
}
// An address a stopped or confirmed attack called out to is shared with every machine for a week. Addresses on
// your own network and addresses the watchlist knows many sites share are left out.
// deviceId is given when the machine itself reported the stop: those additions are limited per machine per day.
async function promote(env, caseId, detail, why, deviceId = null) {
  let room = deviceId ? DEVICE_SHARES_A_DAY - (await env.DB.prepare('SELECT COUNT(*) AS n FROM fleet_indicators f JOIN cases c ON c.id=f.case_id WHERE c.device_id=? AND f.added_at>?').bind(deviceId, now() - 86400).first()).n : Infinity;
  for (const remote of detail?.remotes || []) {
    if (remote.direction !== 'out' || !IP.test(remote.address) || privateAddress(remote.address) || Object.hasOwn(watchCache.map, remote.address)) continue;
    if (room <= 0 || deviceId && (await env.DB.prepare('SELECT COUNT(*) AS n FROM fleet_indicators WHERE expires_at>?').bind(now()).first()).n >= FLEET_MAX) break;
    room--;
    await env.DB.prepare('INSERT INTO fleet_indicators(address,reason,case_id,added_at,expires_at) VALUES(?,?,?,?,?) ON CONFLICT(address) DO UPDATE SET reason=excluded.reason,case_id=excluded.case_id,expires_at=excluded.expires_at')
      .bind(remote.address, why, caseId, now(), now() + 7 * 86400).run();
  }
  invalidate(env);
}
// What each machine can see, where its sight is partial, and which neighbours no agent is watching.
async function coverage(env) {
  // Read in pages, up to 20,000 machines. Past 1,000 only machines with a gap are listed; the counts cover them all.
  const rows = { results: [] }, quiet = Math.max(900, 2.5 * (await fleetState(env)).interval);
  for (let page = 0; page < 20; page++) {
    const next = await env.DB.prepare('SELECT id,label,platform,addresses,peers,coverage,last_seen_at,revoked_at FROM devices WHERE revoked_at IS NULL ORDER BY label,id LIMIT 1000 OFFSET ?').bind(page * 1000).all();
    rows.results.push(...next.results);
    if (next.results.length < 1000) break;
  }
  const read = (value, fallback) => { try { return JSON.parse(value); } catch { return fallback; } };
  const known = new Set(), neighbours = new Map(), devices = [];
  for (const row of rows.results) for (const address of read(row.addresses, [])) known.add(address);
  for (const row of rows.results) {
    const seen = read(row.coverage, {}), gaps = [], watching = row.last_seen_at > now() - quiet;
    if (row.platform !== 'cloud') {
      if (!watching) gaps.push('not reporting: no agent has answered from this machine in the last fifteen minutes');
      if (seen.privileged === false) gaps.push("runs without administrator or root rights: it sees only its own user's programs");
      if (row.platform === 'linux' && seen.process_feed === false) gaps.push('no kernel process feed: a command that lives for a fraction of a second can be missed');
      if (seen.host_names === false) gaps.push('cannot name the hosts programs connect to: host-based signals depend on the service watchlist');
      if (seen.web_folders > 0 && !seen.web_logs) gaps.push('a web folder exists but no access log is readable: web-request attacks are not seen');
      if (row.platform === 'windows' && seen.directory_log === false) gaps.push('cannot read the Security log: directory attacks are seen only by their commands');
      if (seen.responds === 'report') gaps.push('reports only: nothing on this machine is paused or stopped');
      if (seen.block_failed === true) gaps.push('fleet blocking is on but this machine could not change its firewall');
    }
    devices.push({ id: row.id, label: row.label, platform: row.platform, watching, addresses: read(row.addresses, []), sees: seen, gaps });
    for (const peer of read(row.peers, [])) {
      if (known.has(peer.address) || !privateAddress(peer.address) || /^(127\.|169\.254\.|::1$)/.test(peer.address)) continue;
      const entry = neighbours.get(peer.address) || { address: peer.address, ports: new Set(), seen_by: new Set() };
      entry.ports.add(peer.port); entry.seen_by.add(row.label); neighbours.set(peer.address, entry);
    }
  }
  const unprotected = [...neighbours.values()].map(entry => ({ address: entry.address, ports: [...entry.ports].sort((a, b) => a - b).slice(0, 12), seen_by: [...entry.seen_by].slice(0, 8) })).sort((a, b) => b.seen_by.length - a.seen_by.length).slice(0, 100);
  const large = devices.length > 1000;
  return { machines: devices.length, with_gaps: devices.filter(device => device.gaps.length).length, devices: large ? devices.filter(device => device.gaps.length).slice(0, 1000) : devices, ...(large ? { listed: 'machines with a gap only' } : {}), unprotected_neighbours: unprotected,
    note: 'Unprotected neighbours are addresses on your own network that watched machines talk to and that no agent reports from. Sentinel never installs itself anywhere: put an agent on them with your own tooling.' };
}

// ---- large fleets
// What every machine needs to know is the same for all of them: the learned weights and pairs, the watched
// addresses, the shared attacker addresses and the machines under attack. It is worked out once, kept in memory
// for a few seconds, and given a revision. A quiet machine's report then costs three small queries and one
// write, and a machine that already has the current revision is not sent it again.
//
// Two numbers stretch with the size of the fleet so the database sees a steady load whatever the size:
//   interval  how often a quiet machine reports (the one write)       five minutes, growing to an hour
//   pulse     how often a machine asks "has anything changed?"        one minute, growing to ten
// The pulse is answered from memory with no database work, so news still reaches a very large fleet in minutes.
// A case is always reported at once, whatever the interval.
const STATE_SECONDS = 20, shared = new WeakMap();
const clamp = (value, low, high) => Math.max(low, Math.min(high, value));
const positive = (value, fallback) => Number(value) > 0 ? Number(value) : fallback;
export function invalidate(env) { const held = shared.get(env.DB); if (held) held.at = 0; }
export async function fleetState(env, ctx) {
  const held = shared.get(env.DB);
  if (held && now() - held.at < STATE_SECONDS) return held.value;
  // A database too busy to answer must not take the pulse down with it: keep serving what we last knew.
  try { return await readState(env, ctx); } catch (error) { if (held) { held.at = now() - STATE_SECONDS + 5; return held.value; } throw error; }
}
async function readState(env, ctx) {
  const stamp = now(), learned = await currentPolicy(env);
  const rows = await env.DB.prepare('SELECT address,reason FROM fleet_indicators WHERE expires_at>? ORDER BY added_at DESC LIMIT 300').bind(stamp).all();
  // Machines an operator confirmed an attack on in the last day: a connection from one of them to another machine
  // is how an intruder spreads. A machine's own report names nobody: its addresses are what it says they are, so a
  // machine an intruder controls could otherwise point the whole fleet at any address.
  const hot = await env.DB.prepare("SELECT DISTINCT d.id,d.addresses FROM audit a JOIN cases c ON c.id=a.detail JOIN devices d ON d.id=c.device_id WHERE a.actor='operator' AND a.action IN ('case_confirm','case_stop') AND a.at>? AND d.revoked_at IS NULL LIMIT 300").bind(stamp - 86400).all();
  const suspects = [...new Set(hot.results.flatMap(row => { try { return JSON.parse(row.addresses); } catch { return []; } }))].slice(0, 300);
  const devices = (await env.DB.prepare('SELECT COUNT(*) AS n FROM devices WHERE revoked_at IS NULL').first()).n;
  const fleet = { indicators: Object.fromEntries(rows.results.map(row => [row.address, row.reason])), suspects,
    // FLEET_BLOCK=on: machines that may end programs also refuse traffic to and from the shared addresses.
    ...(env.FLEET_BLOCK === 'on' ? { block: rows.results.map(row => row.address).slice(0, 200) } : {}) };
  const body = { policy: learned.policy, policy_revision: learned.revision, shapes: learned.shapes, watch: watchMap(env, ctx), fleet, signals: SIGNAL_SET };
  const value = { ...body, revision: (await sha256(JSON.stringify(body))).slice(0, 16), devices,
    interval: clamp(Math.ceil(devices / positive(env.HEARTBEAT_WRITES_PER_SECOND, 25)), 300, 3600),
    pulse: clamp(Math.ceil(devices / positive(env.PULSE_REQUESTS_PER_SECOND, 500)), 60, 600) };
  shared.set(env.DB, { at: stamp, value });
  return value;
}
// Every enrolled machine holds the same read key for the shared state. It opens nothing else.
const stateKey = env => sha256('state:' + env.DATA_KEY);
const sharedParts = state => ({ policy: state.policy, policy_revision: state.policy_revision, shapes: state.shapes, watch: state.watch, fleet: state.fleet, signals: state.signals });
// Housekeeping, run on a timer (see the cron trigger in wrangler.example.jsonc): closed cases, expired shared
// addresses and old audit lines are removed so the database stays small however long the service runs.
export async function housekeeping(env, ctx) {
  const stamp = now(), keep = positive(env.CASE_RETENTION_DAYS, 30) * 86400;
  const cases = await env.DB.prepare("DELETE FROM cases WHERE state='resolved' AND response IS NULL AND last_seen_at<?").bind(stamp - keep).run();
  await env.DB.prepare('DELETE FROM fleet_indicators WHERE expires_at<?').bind(stamp).run();
  await env.DB.prepare('DELETE FROM audit WHERE at<?').bind(stamp - 90 * 86400).run();
  if (env.WATCHLIST !== 'off') await refreshWatch(env);
  if (env.TOR_EXITS !== 'off') await refreshExits(env);
  invalidate(env);
  return { cases_removed: cases.meta?.changes ?? 0 };
}

async function audit(env, actor, action, detail = '') { await env.DB.prepare('INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)').bind(now(), actor, action, String(detail).slice(0, 300)).run(); }
async function alert(env, payload) {
  if (!env.ALERT_WEBHOOK_URL) return;
  try { await fetch(env.ALERT_WEBHOOK_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }); } catch {}
}
async function analyzeCase(env, id) {
  const row = await env.DB.prepare('SELECT c.detail,d.platform FROM cases c JOIN devices d ON d.id=c.device_id WHERE c.id=?').bind(id).first();
  if (!row) return null;
  const detail = await unseal(row.detail, env.DATA_KEY);
  let analysis;
  try { analysis = await analyze(env, detail, row.platform, await recallSimilar(env, row.platform, detail)); } catch (error) { analysis = { error: String(error.message || error).slice(0, 200) }; }
  if (analysis) await env.DB.prepare('UPDATE cases SET analysis=? WHERE id=?').bind(await seal({ ...analysis, at: now() }, env.DATA_KEY), id).run();
  return analysis;
}

// The decision on a program an agent froze. A model may stop it when it is highly confident; it may release it only when the deployment
// allows that, it is highly confident, and no locked signal is involved. Anything else is held for an operator.
// With no model, or none that answers in time, DECISION_FALLBACK decides: "kill" (default) or "hold".
export async function decideCase(env, id, detail, platform) {
  let analysis = null, action = fallbackFor(env) === 'kill' ? 'stop' : 'hold', reason = 'no decision model answered in time';
  if (hasModel(env)) {
    try { analysis = await Promise.race([analyze(env, detail, platform, await recallSimilar(env, platform, detail), true), new Promise(resolve => setTimeout(() => resolve(null), 8000))]); } catch { analysis = null; }
    if (analysis) {
      const locked = detail.signals.some(signal => LOCKED.has(signal.id));
      if (analysis.recommendation === 'stop' && analysis.confidence === 'high') { action = 'stop'; reason = 'the decision model recommended stopping it'; }
      else if (analysis.recommendation === 'release' && analysis.confidence === 'high' && env.DECISION_RELEASE === 'high-confidence' && !locked) { action = 'release'; reason = 'the decision model judged it ordinary activity with high confidence'; }
      else { action = 'hold'; reason = 'the decision model was not sure enough; an operator decides'; }
    }
  }
  await env.DB.prepare('UPDATE cases SET response=?,analysis=? WHERE id=?').bind(action, await seal({ ...(analysis || {}), decided: action, reason, at: now() }, env.DATA_KEY), id).run();
  await audit(env, analysis ? 'decision-model' : 'fallback', 'case_' + action, id);
  return action;
}
// Addresses that currently answer for the watched hosts, looked up from here over DNS-over-HTTPS.
let watchCache = { at: 0, map: {} };
export async function refreshWatch(env) {
  const resolver = env.WATCH_RESOLVER || 'https://cloudflare-dns.com/dns-query', map = {};
  await Promise.all(WATCH_HOSTS.map(async host => {
    try {
      const response = await fetch(resolver + '?name=' + encodeURIComponent(host) + '&type=A', { headers: { accept: 'application/dns-json' } });
      if (!response.ok) return;
      for (const answer of (await response.json()).Answer || []) if (answer.type === 1 && /^\d{1,3}(\.\d{1,3}){3}$/.test(answer.data) && Object.keys(map).length < 400) map[answer.data] = host;
    } catch {}
  }));
  if (Object.keys(map).length) { watchCache = { at: now(), map }; invalidate(env); }
  return watchCache.map;
}
// The Tor Project's published list of exit nodes, fetched from here and handed to an agent only when it changed.
let exitCache = { at: 0, revision: '', addresses: [] };
export async function refreshExits(env) {
  try {
    const response = await fetch(env.TOR_EXIT_LIST || 'https://check.torproject.org/torbulkexitlist');
    if (!response.ok) return exitCache;
    const addresses = [...new Set((await response.text()).split(/\s+/).filter(line => /^\d{1,3}(\.\d{1,3}){3}$/.test(line)))].sort().slice(0, 6000);
    if (addresses.length) exitCache = { at: now(), revision: (await sha256(addresses.join(','))).slice(0, 16), addresses };
  } catch {}
  return exitCache;
}
function exitsFor(env, ctx, have) {
  if (env.TOR_EXITS === 'off') return {};
  if (now() - exitCache.at > 3600) { exitCache = { ...exitCache, at: now() }; ctx?.waitUntil(refreshExits(env)); }
  return exitCache.revision && exitCache.revision !== have ? { exits: { revision: exitCache.revision, addresses: exitCache.addresses } } : {};
}
// Cloud audit records forwarded by the organisation. Each identity whose records add up to a reportable case
// gets one, under a stand-in device named after the source.
async function cloudEvents(request, env, ctx) {
  const input = await bodyJson(request, 2 * 1024 * 1024);
  if (!CLOUD_SOURCES.includes(input.source) || !Array.isArray(input.records) || input.records.length > 1000) fail(400, 'Send {"source", "records"} with a known source and at most 1000 records.');
  const label = 'Cloud audit (' + input.source + ')', stamp = now();
  let device = await env.DB.prepare("SELECT id FROM devices WHERE platform='cloud' AND label=?").bind(label).first();
  if (!device) { device = { id: crypto.randomUUID() }; await env.DB.prepare("INSERT INTO devices(id,label,platform,created_at) VALUES(?,?,'cloud',?)").bind(device.id, label, stamp).run(); }
  await env.DB.prepare('UPDATE devices SET last_seen_at=?,summary=? WHERE id=?').bind(stamp, JSON.stringify({ records: input.records.length }), device.id).run();
  let saved = 0;
  for (const found of evaluateCloud(input.source, input.records)) {
    const signals = Object.entries(found.signals).map(([id, count]) => ({ id, points: SIGNALS[id].weight, category: 'cloud', evidence: CLOUD_EVIDENCE[id](count) }));
    const score = signals.reduce((sum, signal) => sum + signal.points, 0), level = levelFor(score, 1);
    if (!reported(level)) continue;
    const key = (await sha256('cloud:' + input.source + ':' + found.actor.toLowerCase())).slice(0, 32);
    const old = await env.DB.prepare('SELECT id,state,severity FROM cases WHERE device_id=? AND case_key=?').bind(device.id, key).first();
    if (old?.state === 'trusted') continue;
    const detail = { key, name: found.actor, path: '', parent: '', signals, remotes: found.address ? [{ address: found.address, port: 0, names: [], direction: 'in' }] : [], chain: [], actions: [], persistence: [], score, categories: ['cloud'], level, observed_at: stamp };
    const id = old?.id || crypto.randomUUID(), severity = score >= 7 ? 'high' : 'medium', title = titleFor(detail, false, false);
    await env.DB.prepare("INSERT INTO cases(id,device_id,case_key,level,severity,title,detail,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id,case_key) DO UPDATE SET state='open',level=excluded.level,severity=CASE WHEN cases.state='open' AND cases.severity='high' THEN 'high' ELSE excluded.severity END,title=excluded.title,detail=excluded.detail,last_seen_at=excluded.last_seen_at WHERE cases.state!='trusted'")
      .bind(id, device.id, key, level, severity, title, await seal(detail, env.DATA_KEY), stamp, stamp).run();
    saved++;
    if (!old || old.state !== 'open' || (old.severity !== 'high' && severity === 'high')) {
      ctx?.waitUntil(alert(env, { text: label + ': a cloud identity ' + why(detail) + '. Nothing was changed by Sentinel; review the case.', title, level, severity, device: label, case_id: id, paused: false, stopped: false, signals: signals.map(signal => signal.id) }));
      if (hasModel(env)) ctx?.waitUntil(analyzeCase(env, id));
    }
  }
  return json({ accepted: true, records: input.records.length, saved });
}
// Marks of requests an edge system saw (see edge.mjs): the request text itself is never sent. Each visitor whose
// marks of the last minutes add up to a reportable case gets one, under a stand-in device named after the system.
const EDGE_NAME = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$/;
async function edgeEvents(request, env, ctx) {
  const input = await bodyJson(request, 512 * 1024);
  if (typeof input.name !== 'string' || !EDGE_NAME.test(input.name) || !Array.isArray(input.records) || input.records.length > 1000) fail(400, 'Send {"name", "records"} with at most 1000 records.');
  const label = 'Edge (' + input.name + ')', stamp = now(), rows = [], clients = new Set();
  for (const record of input.records) {
    const kept = rowsOf(record);
    if (!kept) fail(400, 'Invalid record.');
    // The sender's clock is taken only when it is close to this one.
    const at = whole(record.at, stamp - 300, stamp + 60) ? record.at : stamp;
    for (const [kind, value, extra] of kept) rows.push([label, record.client, kind, value, extra, at]);
    if (kept.length) clients.add(record.client);
  }
  let device = await env.DB.prepare("SELECT id FROM devices WHERE platform='edge' AND label=?").bind(label).first();
  if (!device) {
    if ((await env.DB.prepare("SELECT COUNT(*) AS n FROM devices WHERE platform='edge'").first()).n >= 50) fail(409, 'This service already has 50 edge systems.');
    device = { id: crypto.randomUUID() };
    await env.DB.prepare("INSERT INTO devices(id,label,platform,created_at) VALUES(?,?,'edge',?)").bind(device.id, label, stamp).run();
  }
  await env.DB.prepare('UPDATE devices SET last_seen_at=?,summary=? WHERE id=?').bind(stamp, JSON.stringify({ records: input.records.length }), device.id).run();
  await env.DB.prepare('DELETE FROM edge_marks WHERE at<?').bind(stamp - 900).run();
  const insert = env.DB.prepare('INSERT INTO edge_marks(system,client,kind,value,extra,at) VALUES(?,?,?,?,?,?)');
  for (let start = 0; start < rows.length; start += 50) await env.DB.batch(rows.slice(start, start + 50).map(row => insert.bind(...row)));
  let saved = 0;
  for (const client of [...clients].slice(0, 40)) {
    const seen = await env.DB.prepare('SELECT kind,value,extra,at FROM edge_marks WHERE system=? AND client=? AND at>? ORDER BY at DESC LIMIT 4000').bind(label, client, stamp - 300).all();
    const signals = judge(seen.results, stamp).map(found => ({ id: found.id, points: SIGNALS[found.id].weight, category: 'web', evidence: found.evidence }));
    if (!signals.length) continue;
    const score = signals.reduce((sum, signal) => sum + signal.points, 0), level = levelFor(score, 1);
    if (!reported(level)) continue;
    const key = (await sha256('edge:' + label + ':' + client)).slice(0, 32);
    const old = await env.DB.prepare('SELECT id,state,severity,level FROM cases WHERE device_id=? AND case_key=?').bind(device.id, key).first();
    if (old?.state === 'trusted') continue;
    const detail = { key, name: 'Web client ' + client, path: '', parent: '', signals, remotes: [{ address: client, port: 0, names: [], direction: 'in' }], chain: [], actions: [], persistence: [], score, categories: ['web'], level, observed_at: stamp };
    const id = old?.id || crypto.randomUUID(), severity = score >= 7 ? 'high' : 'medium', title = titleFor(detail, false, false);
    await env.DB.prepare("INSERT INTO cases(id,device_id,case_key,level,severity,title,detail,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id,case_key) DO UPDATE SET state='open',level=excluded.level,severity=CASE WHEN cases.state='open' AND cases.severity='high' THEN 'high' ELSE excluded.severity END,title=excluded.title,detail=excluded.detail,last_seen_at=excluded.last_seen_at WHERE cases.state!='trusted'")
      .bind(id, device.id, key, level, severity, title, await seal(detail, env.DATA_KEY), stamp, stamp).run();
    saved++;
    if (!old || old.state !== 'open' || (old.severity !== 'high' && severity === 'high')) {
      ctx?.waitUntil(alert(env, { text: label + ': a visitor ' + why(detail) + '. Nothing was refused by Sentinel; review the case.', title, level, severity, device: label, case_id: id, paused: false, stopped: false, signals: signals.map(signal => signal.id) }));
      if (hasModel(env)) ctx?.waitUntil(analyzeCase(env, id));
    }
  }
  return json({ accepted: true, records: input.records.length, saved });
}
// The visitors an operator confirmed as attackers on an edge system in the last week. Nothing is refused on a
// score alone: an edge system that reads this list refuses only whom a person has judged. The visitor stays on
// the list when they come back and the case opens again; an operator takes them off with "trust" or "reopen".
async function edgeRefused(env) {
  const rows = await env.DB.prepare("SELECT c.detail FROM audit a JOIN cases c ON c.id=a.detail JOIN devices d ON d.id=c.device_id WHERE a.actor='operator' AND a.action='case_confirm' AND a.at>? AND d.platform='edge' AND NOT EXISTS (SELECT 1 FROM audit b WHERE b.detail=a.detail AND b.actor='operator' AND b.action IN ('case_trust','case_reopen') AND b.id>a.id) ORDER BY a.at DESC LIMIT 200").bind(now() - 7 * 86400).all();
  const addresses = new Set();
  for (const row of rows.results) {
    try { const address = (await unseal(row.detail, env.DATA_KEY)).remotes?.[0]?.address; if (typeof address === 'string' && IP.test(address) && !privateAddress(address)) addresses.add(address); } catch {}
  }
  return json({ addresses: [...addresses].sort() });
}
function watchMap(env, ctx) {
  if (env.WATCHLIST === 'off') return {};
  if (now() - watchCache.at > 900) { watchCache = { at: now(), map: watchCache.map }; ctx?.waitUntil(refreshWatch(env)); }
  return watchCache.map;
}

async function enroll(request, env) {
  const input = await bodyJson(request, 4096);
  if (!await sameSecret(input.key, env.ENROLL_KEY)) fail(401, 'The enrolment key is not valid.');
  if (input.protocol !== PROTOCOL || !PLATFORMS.includes(input.platform) || !text(input.label, 80) || !text(input.version, 40)) fail(400, 'Use a current Sentinel agent.');
  // The count comes from the shared state, so enrolling a large fleet does not scan the device table each time.
  const limit = Number(env.MAX_DEVICES) > 0 ? Number(env.MAX_DEVICES) : 10000, state = await fleetState(env);
  if (state.devices >= limit) fail(409, 'This service has reached its device limit. Raise MAX_DEVICES to enrol more machines.');
  const asked = MODES.includes(input.mode) ? input.mode : 'kill', mode = MODES[Math.min(MODES.indexOf(asked), MODES.indexOf(allowedMode(env)))];
  const token = randomToken(), id = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO devices(id,label,platform,token_hash,respond,created_at) VALUES(?,?,?,?,?,?)').bind(id, input.label, input.platform, await sha256(token), MODES.indexOf(mode), now()).run();
  await audit(env, 'device:' + id, 'enrolled', input.platform + ' ' + mode + ' ' + input.label);
  return json({ protocol: PROTOCOL, device_id: id, token, mode, fallback: fallbackFor(env), decide_after: 20, state_key: await stateKey(env), interval: state.interval, pulse: state.pulse }, 201);
}

async function report(request, env, ctx) {
  const token = /^Bearer ([a-f0-9]{64})$/.exec(request.headers.get('Authorization') || '')?.[1];
  if (!token) fail(401, 'A device credential is required.');
  const device = await env.DB.prepare('SELECT * FROM devices WHERE token_hash=? AND revoked_at IS NULL').bind(await sha256(token)).first();
  if (!device) fail(401, 'This device was removed.');
  const input = await bodyJson(request, 96 * 1024);
  if (input.protocol !== PROTOCOL || input.platform !== device.platform || !text(input.version, 40) || !Array.isArray(input.cases) || input.cases.length > MAX_CASES) fail(400, 'Invalid report.');
  const cases = input.cases.map(validateCase);
  if (new Set(cases.map(item => item.key)).size !== cases.length) fail(400, 'The report repeats a case.');
  if (input.results !== undefined && (!Array.isArray(input.results) || input.results.length > 16)) fail(400, 'Invalid result.');
  const results = (input.results || []).map(item => { if (!item || !/^[a-f0-9]{32}$/.test(item.key || '') || !['stopped', 'released'].includes(item.action) || !whole(item.programs, 0, 64) || !whole(item.gone ?? 0, 0, 64)) fail(400, 'Invalid result.'); return { ...item, cleanup: cleanupSteps(item.cleanup) }; });
  const stamp = now(), respond = device.respond >= 1, watching = {};
  for (const key of ['processes', 'connections', 'tracked']) watching[key] = whole(input.watching?.[key], 0, 1e6) ? input.watching[key] : 0;
  const mesh = meshOf(input.mesh);
  const seen = env.DB.prepare('UPDATE devices SET last_seen_at=?,summary=?,addresses=?,peers=?,coverage=? WHERE id=?').bind(stamp, JSON.stringify(watching), JSON.stringify(mesh.addresses), JSON.stringify(mesh.peers), JSON.stringify(mesh.coverage), device.id);
  const ownCases = env.DB.prepare("SELECT case_key,state,response FROM cases WHERE device_id=? AND (state='trusted' OR response IS NOT NULL) LIMIT 320").bind(device.id);
  // A quiet report (nothing to save, nothing carried out) is the common one: its write and its read go to the database together.
  const quiet = !cases.length && !results.length && typeof env.DB.batch === 'function';
  let own = quiet ? (await env.DB.batch([seen, ownCases]))[1] : null;
  if (!quiet) await seen.run();
  // The device carried out the operator's decision on a program it had paused.
  for (const result of respond ? results : []) {
    const row = await env.DB.prepare('SELECT id,detail,response,analysis FROM cases WHERE device_id=? AND case_key=?').bind(device.id, result.key).first();
    // In decide mode an agent that heard nothing in time ends the program by itself and says so.
    const unanswered = row && !row.response && result.action === 'stopped' && MODES[device.respond] === 'decide';
    if (!row || !(unanswered || row.response === 'stop' && result.action === 'stopped' || row.response === 'release' && result.action === 'released')) continue;
    const detail = await unseal(row.detail, env.DATA_KEY);
    let by = 'operator';
    if (unanswered) by = 'agent, after no decision arrived in time';
    else { try { if (row.analysis && (await unseal(row.analysis, env.DATA_KEY)).decided) by = 'decision model'; } catch {} }
    detail.outcome = { action: result.action, programs: result.programs, gone: result.gone ?? 0, at: stamp, by, ...(result.cleanup.length ? { cleanup: result.cleanup } : {}) };
    // Only an operator's release marks a program as ours for good; a model's release just closes the case.
    await env.DB.prepare('UPDATE cases SET response=NULL,state=?,detail=?,last_seen_at=? WHERE id=?').bind(result.action === 'released' && by === 'operator' ? 'trusted' : 'resolved', await seal(detail, env.DATA_KEY), stamp, row.id).run();
    if (result.action === 'stopped') await promote(env, row.id, detail, 'a program stopped on ' + device.label + ' called out to it', device.id);
    // Set and forget: with LEARN_FROM=operators-and-model, a stop the decision model ordered teaches shapes (never weights).
    if (result.action === 'stopped' && by === 'decision model' && env.LEARN_FROM === 'operators-and-model') { await rememberVerdict(env, device.platform, detail, 'confirmed', 'model'); invalidate(env); }
    await audit(env, 'device:' + device.id, result.action, row.id);
  }
  let saved = 0;
  if (results.length) invalidate(env);
  for (const item of cases) {
    if (!reported(item.level)) continue;
    if (!respond) item.actions = [];
    const old = await env.DB.prepare('SELECT id,state,severity,detail,analysis FROM cases WHERE device_id=? AND case_key=?').bind(device.id, item.key).first();
    if (old?.state === 'trusted') continue;
    if (!old && (await env.DB.prepare('SELECT COUNT(*) AS n FROM cases WHERE device_id=?').bind(device.id).first()).n >= MAX_CASES_PER_DEVICE) continue;
    // A later report of a program that is still paused keeps the record that it was paused.
    const freshPause = item.actions.some(action => action.action === 'paused');
    if (!item.actions.some(action => action.action === 'paused') && old?.state === 'open') { try { const before = await unseal(old.detail, env.DATA_KEY); if (isPaused(before)) item.actions = before.actions; } catch {} }
    const paused = item.actions.some(action => action.action === 'paused'), stopped = item.actions.some(action => action.action === 'stopped');
    const severity = item.level === 'HOSTILE' || paused || stopped ? 'high' : 'medium', title = titleFor(item, paused, stopped);
    // The same program under the same parent is one case however often it happens: the case says how many times.
    let times = 1;
    if (old) { try { times = ((await unseal(old.detail, env.DATA_KEY)).times || 1) + (item.repeats || 0); } catch { times = 1 + (item.repeats || 0); } }
    item.times = Math.min(times, 99999);
    delete item.repeats;
    const id = old?.id || crypto.randomUUID(), sealed = await seal(item, env.DATA_KEY);
    await env.DB.prepare("INSERT INTO cases(id,device_id,case_key,level,severity,title,detail,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id,case_key) DO UPDATE SET state='open',level=excluded.level,severity=CASE WHEN cases.state='open' AND cases.severity='high' THEN 'high' ELSE excluded.severity END,title=excluded.title,detail=excluded.detail,last_seen_at=excluded.last_seen_at WHERE cases.state!='trusted'")
      .bind(id, device.id, item.key, item.level, severity, title, sealed, stamp, stamp).run();
    saved++;
    invalidate(env);
    if (stopped) await promote(env, id, item, 'a program stopped on ' + device.label + ' called out to it', device.id);
    // decide mode: the program is frozen on the machine; the model (or the fallback) says what happens to it.
    if (freshPause && MODES[device.respond] === 'decide') {
      // The model is asked once about a case. One it judged in the last day that comes back is held for an operator,
      // and so are a machine's new cases past the day's limit, so a machine cannot have the model asked without end.
      let judged = false;
      try { const before = old?.analysis ? await unseal(old.analysis, env.DATA_KEY) : null; judged = !!before?.decided && stamp - (before.at || 0) < 86400; } catch {}
      const today = (await env.DB.prepare('SELECT COUNT(*) AS n FROM cases WHERE device_id=? AND first_seen_at>?').bind(device.id, stamp - 86400).first()).n;
      if (judged) { if (old.state !== 'open') await env.DB.prepare("UPDATE cases SET response='hold' WHERE id=?").bind(id).run(); }
      else if (today > DECISIONS_A_DAY) await env.DB.prepare("UPDATE cases SET response='hold' WHERE id=?").bind(id).run();
      else await decideCase(env, id, item, device.platform);
    }
    if (!old || old.state !== 'open' || (old.severity !== 'high' && severity === 'high')) {
      ctx?.waitUntil(alert(env, { text: device.label + ': Sentinel ' + (stopped ? 'stopped' : paused ? 'paused' : 'flagged') + ' something that ' + why(item) + '. ' + (stopped ? 'The program was ended on the machine. Review the case, and mark it as yours if it was.' : paused ? 'It is paused, not removed: decide whether to stop it or let it continue.' : 'Nothing was stopped.'), title, level: item.level, severity, device: device.label, case_id: id, paused, stopped, signals: item.signals.filter(signal => signal.points > 0).map(signal => signal.id) }));
      if (hasModel(env) && !(freshPause && MODES[device.respond] === 'decide')) ctx?.waitUntil(analyzeCase(env, id));
    }
  }
  own = own || await ownCases.all();
  const state = await fleetState(env, ctx), mine = new Set(mesh.addresses);
  // A machine that already holds the current shared state is not sent it again.
  const parts = input.have === state.revision ? {} : { ...sharedParts(state), fleet: { ...state.fleet, suspects: state.fleet.suspects.filter(address => !mine.has(address)) } };
  return json({ protocol: PROTOCOL, accepted: true, saved, trusted: own.results.filter(row => row.state === 'trusted').map(row => row.case_key), commands: respond ? own.results.filter(row => row.response).slice(0, 16).map(row => ({ key: row.case_key, action: row.response })) : [],
    mode: MODES[device.respond] || 'report', revision: state.revision, interval: state.interval, pulse: state.pulse, state_key: await stateKey(env), ...parts, ...exitsFor(env, ctx, input.exits_have) });
}

async function caseView(env, row, full) {
  let detail = null, analysis = null;
  try { detail = await unseal(row.detail, env.DATA_KEY); } catch {}
  try { analysis = row.analysis ? await unseal(row.analysis, env.DATA_KEY) : null; } catch {}
  const view = { id: row.id, device_id: row.device_id, device: row.label, platform: row.platform, title: row.title, level: row.level, severity: row.severity, state: row.state, paused: isPaused(detail), stopped: !!detail?.actions?.some(action => action.action === 'stopped'), pending: row.response || null, first_seen_at: row.first_seen_at, last_seen_at: row.last_seen_at, analysis };
  if (full && detail) { view.detail = detail; view.similar = await recallSimilar(env, row.platform, detail); }
  return view;
}
// trust: the program is ours; the agent stops reporting it and releases it if paused.
// confirm: it was an attack. stop / release: the decision on a paused program, carried out by the agent.
// resolve: handled, no verdict. reopen: watch it again.
async function caseAction(env, id, input) {
  const action = input.action;
  if (!['trust', 'confirm', 'resolve', 'reopen', 'stop', 'release'].includes(action) || Object.keys(input).some(key => key !== 'action')) fail(400, 'Choose a case action.');
  const row = await env.DB.prepare('SELECT c.*,d.platform,d.respond,d.revoked_at FROM cases c JOIN devices d ON d.id=c.device_id WHERE c.id=?').bind(id).first();
  if (!row) fail(404, 'Case not found.');
  const detail = await unseal(row.detail, env.DATA_KEY), held = isPaused(detail) && row.respond >= 1 && !row.revoked_at;
  if (['stop', 'release'].includes(action) && !held) fail(409, 'This program is not paused by Sentinel.');
  const response = action === 'stop' ? 'stop' : action === 'release' || action === 'trust' && held ? 'release' : null;
  const state = action === 'trust' ? 'trusted' : response ? 'open' : { confirm: 'resolved', resolve: 'resolved', reopen: 'open' }[action];
  await env.DB.prepare('UPDATE cases SET state=?,response=? WHERE id=?').bind(state, response, id).run();
  invalidate(env);
  if (action === 'confirm' || action === 'stop') await promote(env, id, detail, 'an attack confirmed on another of your machines called out to it');
  const verdict = { trust: 'dismissed', release: 'dismissed', confirm: 'confirmed', stop: 'confirmed' }[action];
  const learned = verdict ? await rememberVerdict(env, row.platform, detail, verdict) : null;
  invalidate(env);
  await audit(env, 'operator', 'case_' + action, id);
  return json({ state, pending: response, learned: learned && { changes: learned.changes, rejected: learned.rejected, revision: learned.revision } });
}

async function route(request, env, ctx) {
  const url = new URL(request.url), path = url.pathname, method = request.method;
  if (method === 'GET' && path === '/health') return json({ ok: true, protocol: PROTOCOL });
  for (const name of ['DATA_KEY', 'ENROLL_KEY', 'ADMIN_TOKEN']) if (typeof env[name] !== 'string' || env[name].length < 32) fail(500, 'Set the ' + name + ' secret (at least 32 characters).');
  if (method === 'POST' && path === '/v1/enroll') return enroll(request, env);
  if (method === 'POST' && path === '/v1/report') return report(request, env, ctx);
  if (method === 'GET' && path === '/v1/pulse') {
    // Kept in the edge cache for a few seconds as well, so a fresh copy of the Worker answers without the database.
    const edge = globalThis.caches?.default, cacheKey = new Request(url.origin + '/v1/pulse');
    const cached = edge && await edge.match(cacheKey);
    if (cached) return cached;
    const state = await fleetState(env, ctx), answer = new Response(JSON.stringify({ revision: state.revision, interval: state.interval, pulse: state.pulse }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=10' } });
    if (edge) ctx?.waitUntil(edge.put(cacheKey, answer.clone()));
    return answer;
  }
  const bearer = /^Bearer (.+)$/.exec(request.headers.get('Authorization') || '')?.[1];
  if (method === 'GET' && path === '/v1/state') {
    if (!await sameSecret(bearer, await stateKey(env))) fail(401, 'The fleet read key is required.');
    const state = await fleetState(env, ctx);
    return json({ revision: state.revision, interval: state.interval, pulse: state.pulse, ...sharedParts(state) });
  }
  if (method === 'POST' && path === '/v1/cloud-events') {
    if (!(await sameSecret(bearer, env.INGEST_TOKEN) || await sameSecret(bearer, env.ADMIN_TOKEN))) fail(401, 'An ingest token is required.');
    return cloudEvents(request, env, ctx);
  }
  if (path === '/v1/edge-events' && method === 'POST' || path === '/v1/edge/refused' && method === 'GET') {
    if (!(await sameSecret(bearer, env.INGEST_TOKEN) || await sameSecret(bearer, env.ADMIN_TOKEN))) fail(401, 'An ingest token is required.');
    return method === 'POST' ? edgeEvents(request, env, ctx) : edgeRefused(env);
  }
  if (!await sameSecret(/^Bearer (.+)$/.exec(request.headers.get('Authorization') || '')?.[1], env.ADMIN_TOKEN)) fail(401, 'An operator token is required.');
  if (method === 'GET' && path === '/v1/devices') {
    // ?after=<created_at of the last one you have> pages through a large fleet, newest first.
    const after = Number(url.searchParams.get('after')) > 0 ? Number(url.searchParams.get('after')) : 1e12, quiet = Math.max(900, 2.5 * (await fleetState(env, ctx)).interval);
    const rows = await env.DB.prepare('SELECT id,label,platform,respond,summary,created_at,last_seen_at,revoked_at FROM devices WHERE created_at<? ORDER BY created_at DESC LIMIT 1000').bind(after).all();
    const totals = await env.DB.prepare('SELECT COUNT(*) AS enrolled,SUM(last_seen_at>?) AS watching FROM devices WHERE revoked_at IS NULL').bind(now() - quiet).first();
    return json({ enrolled: totals.enrolled, watching: totals.watching || 0, devices: rows.results.map(row => ({ ...row, respond: undefined, mode: MODES[row.respond] || 'report', summary: JSON.parse(row.summary || '{}'), watching: !row.revoked_at && row.last_seen_at > now() - quiet })) });
  }
  const device = /^\/v1\/devices\/([0-9a-f-]{36})\/revoke$/.exec(path);
  if (device && method === 'POST') {
    await env.DB.prepare('UPDATE devices SET revoked_at=?,token_hash=NULL WHERE id=? AND revoked_at IS NULL').bind(now(), device[1]).run();
    await env.DB.prepare('UPDATE cases SET response=NULL WHERE device_id=?').bind(device[1]).run();
    await audit(env, 'operator', 'device_revoked', device[1]);
    invalidate(env);
    return json({ revoked: true });
  }
  if (method === 'GET' && path === '/v1/cases') {
    const state = url.searchParams.get('state');
    const rows = await env.DB.prepare('SELECT c.*,d.label,d.platform FROM cases c JOIN devices d ON d.id=c.device_id WHERE (? IS NULL OR c.state=?) ORDER BY c.last_seen_at DESC LIMIT 200').bind(state, state).all();
    return json({ cases: await Promise.all(rows.results.map(row => caseView(env, row, false))) });
  }
  const one = /^\/v1\/cases\/([0-9a-f-]{36})(?:\/(action|analyze))?$/.exec(path);
  if (one) {
    if (method === 'GET' && !one[2]) {
      const row = await env.DB.prepare('SELECT c.*,d.label,d.platform FROM cases c JOIN devices d ON d.id=c.device_id WHERE c.id=?').bind(one[1]).first();
      return row ? json(await caseView(env, row, true)) : fail(404, 'Case not found.');
    }
    if (method === 'POST' && one[2] === 'action') return caseAction(env, one[1], await bodyJson(request, 1024));
    if (method === 'POST' && one[2] === 'analyze') { const analysis = await analyzeCase(env, one[1]); return json({ analysis: analysis || null, provider: env.AI_PROVIDER || 'none' }); }
  }
  if (method === 'GET' && path === '/v1/coverage') return json(await coverage(env));
  if (method === 'GET' && path === '/v1/fleet') { const rows = await env.DB.prepare('SELECT address,reason,case_id,added_at,expires_at FROM fleet_indicators WHERE expires_at>? ORDER BY added_at DESC LIMIT 300').bind(now()).all(); return json({ indicators: rows.results }); }
  // An operator's own indicator, or one carried over from another Sentinel service: shared exactly like a learned one.
  if (method === 'POST' && path === '/v1/fleet/add') {
    const input = await bodyJson(request, 1024);
    if (typeof input.address !== 'string' || !IP.test(input.address) || privateAddress(input.address) || text(input.reason ?? '', 120) === null) fail(400, 'Give a public address and an optional reason.');
    await env.DB.prepare('INSERT INTO fleet_indicators(address,reason,case_id,added_at,expires_at) VALUES(?,?,NULL,?,?) ON CONFLICT(address) DO UPDATE SET reason=excluded.reason,expires_at=excluded.expires_at').bind(input.address, input.reason || 'added by an operator', now(), now() + 7 * 86400).run();
    invalidate(env); await audit(env, 'operator', 'fleet_indicator_added', input.address);
    return json({ added: true }, 201);
  }
  if (method === 'POST' && path === '/v1/fleet/remove') { const input = await bodyJson(request, 512); if (typeof input.address !== 'string' || !IP.test(input.address)) fail(400, 'Give the address to remove.'); await env.DB.prepare('DELETE FROM fleet_indicators WHERE address=?').bind(input.address).run(); invalidate(env); await audit(env, 'operator', 'fleet_indicator_removed', input.address); return json({ removed: true }); }
  if (method === 'GET' && path === '/v1/learning') return json(await learningView(env));
  if (method === 'POST' && path === '/v1/learning/reset') { await resetLearning(env); invalidate(env); await audit(env, 'operator', 'learning_reset'); return json({ reset: true }); }
  fail(404, 'Not found.');
}

export default {
  async fetch(request, env, ctx) {
    try { return await route(request, env, ctx); }
    catch (error) { return json({ error: error.status ? error.message : 'The request could not be completed.' }, error.status || 500); }
  },
  async scheduled(event, env, ctx) { await housekeeping(env, ctx); }
};
