// The database the tests and local runs use: Node's built-in SQLite behind Cloudflare D1's interface.
import { database } from '../sqlite.mjs';

export { database };
export function environment(changes = {}) {
  return { DB: database(), DATA_KEY: 'd'.repeat(40), ENROLL_KEY: 'e'.repeat(40), ADMIN_TOKEN: 'a'.repeat(40), ...changes };
}
