// Edge systems and other devices that cannot run the agent: a Worker at the network edge, a serverless
// function, an appliance that only keeps a request log. There is no process to watch there. What there is, is
// the requests, and the same rules the agent applies to a web server's log apply to them.
//
// Two halves, kept apart on purpose:
//
//   markOf()     runs where the request is seen (in the forwarder, at the edge). It looks at one request and says
//                what it is a sign of, as labels and short marks. The request's own text never leaves that place:
//                no address path, no query, no body.
//   judge()      runs here, in the service. It adds up one visitor's marks over the last minutes and says which
//                of the known signals they amount to.
//
// The thresholds and wording are the agent's (rust/src/web.rs), so a visitor is judged the same way wherever the
// request was seen.
const INJECTION = [
  [/\bunion\b.{0,40}\bselect\b|'\s*or\s*'?\d+'?\s*=\s*'?\d|\bsleep\(\d+\)|\bwaitfor\s+delay\b|information_schema|;\s*drop\s+table/i, 'SQL injection'],
  [/\.\.\/\.\.\/|\.\.\\\.\.\\|\/etc\/passwd|win\.ini|boot\.ini/i, 'path traversal'],
  [/[;|`]\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh)\b|\$\((id|whoami|cat)\b/i, 'command injection'],
  [/\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|<%=\s*\d+\s*\*/i, 'template injection'],
  [/169\.254\.169\.254|metadata\.google\.internal|=(gopher|file|dict):\/\/|=https?:\/\/(127\.0\.0\.1|localhost)\b/i, 'server-side request forgery'],
  [/\bO:\d{1,3}:"[a-z_\\][a-z0-9_\\]{0,80}":\d{1,3}:\{/i, 'object injection'],
  [/ {50,}/, 'a memory corruption probe']
];
export const INJECTION_LABELS = INJECTION.map(([, label]) => label);
const SHELL_PARAMETER = /[?&](cmd|exec|command|shell|execute|run)=/i;
const LOGIN_PATH = /\/(wp-login\.php|login|signin|sign-in|logon|auth|authenticate|session|token|oauth\/token)(\/|\.|$)/i;
const UPLOADS = /\/(uploads?|uploaded|user_?files)\//;
const SCRIPT_EXTENSIONS = ['.php', '.phtml', '.phar', '.jsp', '.jspx', '.aspx', '.ashx', '.asp', '.cfm'];
const NUMBER = /\d{1,12}/g;
export const EDGE_KINDS = ['missing', 'injection', 'login', 'error', 'shell', 'uploaded', 'number'];
const ADDRESS = /^[0-9a-fA-F:.]{3,45}$/;

// "%2e%2e" and "+" as the server will read them. Text that is not valid is left as it is.
function unquotePlus(text) {
  const spaced = text.replace(/\+/g, ' ');
  try { return decodeURIComponent(spaced); } catch { return spaced.replace(/%([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))); }
}
// A short mark of a piece of text: enough to tell two apart, not enough to read either back.
export function markOfText(text) {
  let a = 0x811c9dc5, b = 0x01000193;
  for (let index = 0; index < text.length; index++) {
    const unit = text.charCodeAt(index);
    a = Math.imul(a ^ unit, 0x01000193) >>> 0;
    b = Math.imul(b + unit, 0x85ebca6b) >>> 0;
  }
  return a.toString(16).padStart(8, '0') + b.toString(16).padStart(8, '0');
}
// A cookie's value as the application will read it, when it was sent as base64: an object smuggled to the
// application usually is. Anything else is returned as it came.
function unwrapped(value) {
  if (!/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(value)) return value;
  try { return atob(value.replace(/-/g, '+').replace(/_/g, '/')).slice(0, 400); } catch { return value; }
}
// What one request is a sign of. `target` is the path and query as requested; `cookie` is its Cookie header where
// the edge system has it. Returns the marks to forward, or null for a request that is a sign of nothing.
export function markOf(method, target, status, cookie = '') {
  if (typeof target !== 'string' || !Number.isInteger(status)) return null;
  const decoded = unquotePlus(unquotePlus(target)).slice(0, 2000), stem = decoded.split('?')[0], marks = {};
  if (status === 403 || status === 404) marks.missing = markOfText(stem.slice(0, 200));
  // Only an object is looked for in a cookie: every other pattern is about the address.
  const smuggled = typeof cookie === 'string' && cookie.slice(0, 4000).split(';').some(pair => { const value = pair.slice(pair.indexOf('=') + 1).trim(), last = value.slice(value.lastIndexOf(':') + 1); let plain = value; try { plain = decodeURIComponent(value); } catch {} return [plain, unwrapped(plain), unwrapped(last)].some(text => INJECTION[5][0].test(text)); });
  const found = INJECTION.find(([pattern]) => pattern.test(decoded)) || (smuggled ? INJECTION[5] : undefined);
  if (found) { marks.injection = found[1]; if (status === 200 || status >= 500) marks.answered = true; }
  if (method === 'POST' && LOGIN_PATH.test(stem)) marks.login = true;
  if (['POST', 'PUT', 'PATCH'].includes(method) && status >= 500) marks.error = true;
  if (status < 400) {
    const numbers = decoded.match(NUMBER);
    if (numbers) { marks.shape = markOfText(decoded.replace(NUMBER, '#').slice(0, 200)); marks.number = markOfText(numbers[numbers.length - 1]); }
  }
  const lowered = stem.toLowerCase();
  if (SCRIPT_EXTENSIONS.some(extension => lowered.endsWith(extension)) && status === 200) { if (SHELL_PARAMETER.test(decoded)) marks.shell = true; else if (UPLOADS.test(lowered)) marks.uploaded = true; }
  return Object.keys(marks).length ? marks : null;
}
const mark = value => typeof value === 'string' && /^[0-9a-f]{16}$/.test(value);
// One forwarded record, checked: { client, at?, missing?, injection?, answered?, login?, error?, shell?, uploaded?, shape?, number? }.
// Returns the rows to keep, [kind, value, extra], or null when the record is not in that form.
export function rowsOf(record) {
  if (!record || typeof record !== 'object' || typeof record.client !== 'string' || !ADDRESS.test(record.client)) return null;
  const rows = [];
  if (record.missing !== undefined) { if (!mark(record.missing)) return null; rows.push(['missing', record.missing, '']); }
  if (record.injection !== undefined) { if (!INJECTION_LABELS.includes(record.injection)) return null; rows.push(['injection', record.injection, record.answered === true ? '1' : '']); }
  if (record.login === true) rows.push(['login', '', '']);
  if (record.error === true) rows.push(['error', '', '']);
  if (record.shell === true) rows.push(['shell', '', '']);
  if (record.uploaded === true) rows.push(['uploaded', '', '']);
  if (record.shape !== undefined || record.number !== undefined) { if (!mark(record.shape) || !mark(record.number)) return null; rows.push(['number', record.shape, record.number]); }
  return rows;
}
// One visitor's rows from the last five minutes, each { kind, value, extra, at }: which signals do they amount to?
// Returns [{ id, evidence }], in the agent's order and the agent's words.
export function judge(rows, stamp) {
  const within = (kind, seconds) => rows.filter(row => row.kind === kind && stamp - row.at <= seconds);
  const found = [], say = (id, text) => found.push({ id, evidence: ('This web client ' + text + '.').slice(0, 200) });
  const missing = new Set(within('missing', 60).map(row => row.value)).size;
  if (missing >= 60) say('web_fuzzing', 'asked for ' + missing + ' different pages that do not exist in one minute, the way a directory scanner works');
  const injection = within('injection', 300);
  if (injection.length >= 3) {
    const labels = [...new Set(injection.map(row => row.value))].sort().slice(0, 3);
    say('web_injection_attempt', 'sent ' + injection.length + ' requests shaped like ' + labels.join(' and '));
    const answered = injection.filter(row => row.extra === '1').length;
    if (answered > 0) say('web_injection_answered', 'got a normal or error answer to ' + answered + ' of those requests, so the application processed them');
  }
  const shapes = new Map();
  for (const row of within('number', 60)) { if (!shapes.has(row.value)) shapes.set(row.value, new Set()); shapes.get(row.value).add(row.extra); }
  const walked = Math.max(0, ...[...shapes.values()].map(values => values.size));
  if (walked >= 40) say('web_enumeration', 'walked through ' + walked + ' record numbers on one address pattern in one minute');
  const logins = within('login', 60).length;
  if (logins >= 30) say('web_login_burst', 'made ' + logins + ' sign-in attempts in one minute');
  const shell = within('shell', 300).length, uploaded = within('uploaded', 300).length;
  if (shell > 0) say('web_shell_request', 'called a server-side script with a command parameter ' + shell + ' time(s) and was answered');
  else if (uploaded > 0) say('web_shell_request', 'was served a server-side script from an uploads folder ' + uploaded + ' time(s)');
  const errors = within('error', 60).length;
  if (errors >= 20) say('web_error_burst', 'made the application fail ' + errors + ' times in one minute with requests that carry a body');
  return found;
}
