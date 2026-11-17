// Cloudflare D1's interface over Node's built-in SQLite, so the same service code runs on your own machine.
// With no path the database lives in memory (tests, evaluation); with a path it is a file that survives restarts.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';

export function database(path = ':memory:') {
  const sql = new DatabaseSync(path);
  if (path !== ':memory:') sql.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;');
  sql.exec(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));
  const statement = (text, values = []) => ({
    bind: (...next) => statement(text, next),
    async first() { return sql.prepare(text).get(...values) ?? null; },
    async all() { return { results: sql.prepare(text).all(...values) }; },
    async run() { const done = sql.prepare(text).run(...values); return { meta: { changes: Number(done.changes) } }; },
    async answer() { return /^\s*SELECT/i.test(text) ? this.all() : this.run(); }
  });
  // D1's batch: the statements run in order in one round trip; each answer carries its rows.
  const batch = async list => { const answers = []; for (const item of list) answers.push(await item.answer()); return answers; };
  return { prepare: text => statement(text), batch, close: () => sql.close() };
}
