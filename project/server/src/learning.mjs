import { LOCKED, REFERENCE_ATTACKS, SIGNALS, levelFor, reported } from './signals.mjs';
import { now, seal, unseal } from './util.mjs';

// What this deployment's Sentinel learns, and only from its own operators' verdicts.
//
// Memory: every case an operator judged is remembered as its SHAPE (the signal ids, the platform, the verdict),
// never a program name, path, address or command line.
//
// Policy: a signal the operators keep dismissing is worth less on their machines; one they keep confirming is
// worth more. No model writes, judges or ranks any of this. A change is one point per step and two points in
// total, never touches a LOCKED signal, and is adopted only if every confirmed past case and every reference
// attack would still be reported under it. A rejected change is dropped. Operators can reset everything learned.
//
// Shapes: a pair of signals that confirmed attacks share and that no case marked "ours" ever had becomes a
// signal of its own on every machine (learned_attack_shape, two points). It needs two operator confirmations.
// With LEARN_FROM set to "operators-and-model", a program the decision model had stopped also counts, and then
// three confirmations are needed. One case marked "ours" that contains the pair withdraws it. Weights never move
// on a model's word.
export const POLICY_LIMIT = 2, HISTORY_MAX = 500, SHAPES_MAX = 20;

export function shapeOf(detail) {
  return [...new Set((detail?.signals || []).filter(signal => signal.points > 0 && SIGNALS[signal.id] && signal.id !== 'learned_attack_shape').map(signal => signal.id))].sort();
}
export function learnShapes(history) {
  const pairs = new Map();
  for (const item of history) for (let i = 0; i < item.shape.length; i++) for (let j = i + 1; j < item.shape.length; j++) {
    const key = item.shape[i] + '+' + item.shape[j], entry = pairs.get(key) || { pair: [item.shape[i], item.shape[j]], operator: 0, model: 0, dismissed: 0 };
    entry[item.verdict === 'dismissed' ? 'dismissed' : item.source === 'model' ? 'model' : 'operator']++;
    pairs.set(key, entry);
  }
  return [...pairs.values()].filter(entry => entry.dismissed === 0 && (entry.operator >= 2 || entry.model > 0 && entry.operator + entry.model >= 3))
    .sort((a, b) => b.operator + b.model - a.operator - a.model || (a.pair.join() < b.pair.join() ? -1 : 1)).slice(0, SHAPES_MAX).map(entry => entry.pair);
}
export function scoreShape(shape, policy = {}) {
  let score = 0; const categories = new Set();
  for (const id of shape) {
    const points = Math.max(0, Math.min(9, SIGNALS[id].weight + (policy[id] || 0)));
    if (points > 0) { score += points; categories.add(SIGNALS[id].category); }
  }
  return { score, level: levelFor(score, categories.size) };
}
export function cleanPolicy(value) {
  const policy = {};
  for (const [id, delta] of Object.entries(value && typeof value === 'object' ? value : {}))
    if (SIGNALS[id] && !LOCKED.has(id) && Number.isInteger(delta) && delta !== 0 && Math.abs(delta) <= POLICY_LIMIT) policy[id] = delta;
  return policy;
}
// One step from the verdict history. Returns { policy, changes, rejected }.
export function learnPolicy(history, current = {}) {
  const dismissed = {}, confirmed = {};
  for (const item of history) for (const id of item.shape) {
    const bucket = item.verdict === 'dismissed' ? dismissed : confirmed;
    bucket[id] = (bucket[id] || 0) + 1;
  }
  const changes = [], rejected = []; let policy = cleanPolicy(current);
  const mustStay = [...history.filter(item => item.verdict === 'confirmed').map(item => item.shape), ...REFERENCE_ATTACKS];
  for (const id of Object.keys(SIGNALS)) {
    if (LOCKED.has(id)) continue;
    const d = dismissed[id] || 0, c = confirmed[id] || 0, have = policy[id] || 0;
    // Three dismissals and no confirmation move a signal down a point; six move it two. Confirmations mirror it.
    const want = c === 0 && d >= 6 ? -2 : c === 0 && d >= 3 ? -1 : d === 0 && c >= 4 ? 2 : d === 0 && c >= 2 ? 1 : 0;
    if (want === have) continue;
    const next = have + Math.sign(want - have), candidate = { ...policy };
    if (next === 0) delete candidate[id]; else candidate[id] = next;
    const lost = mustStay.find(shape => reported(scoreShape(shape, policy).level) && !reported(scoreShape(shape, candidate).level));
    if (lost) { rejected.push({ signal: id, to: next, because: lost.join('+') }); continue; }
    policy = candidate; changes.push({ signal: id, from: have, to: next });
  }
  return { policy, changes, rejected };
}
async function load(env) {
  const row = await env.DB.prepare('SELECT * FROM learning WHERE id=1').first();
  let history = [];
  try { history = row?.history && row.history !== '[]' ? await unseal(row.history, env.DATA_KEY) : []; } catch {}
  return { history: Array.isArray(history) ? history : [], policy: cleanPolicy(JSON.parse(row?.policy || '{}')), revision: row?.revision || 0 };
}
export async function currentPolicy(env) { const state = await load(env); return { policy: state.policy, revision: state.revision, shapes: learnShapes(state.history) }; }
// An operator judged a case: 'dismissed' (this program is ours) or 'confirmed' (this was an attack).
export async function rememberVerdict(env, platform, detail, verdict, source = 'operator') {
  const shape = shapeOf(detail);
  if (!shape.length || !['dismissed', 'confirmed'].includes(verdict)) return null;
  const state = await load(env), history = [...state.history, { shape, platform, verdict, at: now(), ...(source === 'model' ? { source } : {}) }].slice(-HISTORY_MAX);
  const learned = learnPolicy(history.filter(item => item.source !== 'model'), state.policy), changed = JSON.stringify(learned.policy) !== JSON.stringify(state.policy);
  const revision = state.revision + (changed ? 1 : 0);
  await env.DB.prepare('INSERT INTO learning(id,history,policy,revision,updated_at) VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET history=excluded.history,policy=excluded.policy,revision=excluded.revision,updated_at=excluded.updated_at')
    .bind(await seal(history, env.DATA_KEY), JSON.stringify(learned.policy), revision, now()).run();
  // Optional semantic memory: see README "Plugging in a memory engine".
  if (env.SENTINEL_MEMORY?.remember) { try { await env.SENTINEL_MEMORY.remember(verdict + ' case on ' + platform + ' with ' + shape.join(' ')); } catch {} }
  return { changes: learned.changes, rejected: learned.rejected, policy: learned.policy, revision, shapes: learnShapes(history) };
}
// What the operators decided before about cases like this one.
export async function recallSimilar(env, platform, detail) {
  const shape = shapeOf(detail);
  if (!shape.length) return null;
  const state = await load(env);
  const overlap = item => item.shape.filter(id => shape.includes(id)).length / new Set([...item.shape, ...shape]).size;
  const near = state.history.filter(item => overlap(item) >= 0.5);
  let recalled = [];
  if (env.SENTINEL_MEMORY?.recall) { try { recalled = (await env.SENTINEL_MEMORY.recall('case on ' + platform + ' with ' + shape.join(' '), 3)).map(String).slice(0, 3); } catch {} }
  return { dismissed: near.filter(item => item.verdict === 'dismissed').length, confirmed: near.filter(item => item.verdict === 'confirmed').length, recalled };
}
export async function learningView(env) {
  const state = await load(env);
  return { verdicts: state.history.length, dismissed: state.history.filter(item => item.verdict === 'dismissed').length, confirmed: state.history.filter(item => item.verdict === 'confirmed').length, confirmed_by_model: state.history.filter(item => item.source === 'model').length, policy: state.policy, shapes: learnShapes(state.history), revision: state.revision, limit: POLICY_LIMIT };
}
export async function resetLearning(env) { await env.DB.prepare('DELETE FROM learning WHERE id=1').run(); }
