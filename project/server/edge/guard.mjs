// The other half for a Worker: refusing the visitors you confirmed as attackers. Nobody is refused on a score.
// Sentinel reports a visitor; a person presses "confirm" on the case; from then on, for a week, this turns that
// visitor away at the edge, before your Worker does any work.
//
//   import { refused } from './guard.mjs';
//   export default {
//     async fetch(request, env, ctx) {
//       const no = await refused(request, env, ctx);
//       if (no) return no;
//       ... your Worker ...
//     }
//   };
//
// Settings: SENTINEL_URL and SENTINEL_TOKEN, as for the tail Worker. The list is asked for at most once a minute
// in each place your Worker runs; if the service cannot be reached, nobody is refused.
//
// If your service is itself a Worker on the same account's workers.dev address, give the Worker that uses this the
// compatibility flag "global_fetch_strictly_public". Without it Cloudflare answers the request for the list with
// error 1042, and nobody is refused.
let held = { at: 0, addresses: new Set() };

export async function refusedAddresses(env, ctx, fetcher = fetch) {
  const stamp = Date.now();
  if (stamp - held.at < 60_000) return held.addresses;
  held = { at: stamp, addresses: held.addresses };
  const refresh = (async () => {
    try {
      const response = await fetcher(String(env.SENTINEL_URL).replace(/\/$/, '') + '/v1/edge/refused', { headers: { Authorization: 'Bearer ' + env.SENTINEL_TOKEN } });
      if (!response.ok) return;
      const body = await response.json();
      if (Array.isArray(body.addresses)) held = { at: stamp, addresses: new Set(body.addresses.filter(address => typeof address === 'string').slice(0, 2000)) };
    } catch {}
  })();
  // The first request in a place waits for the list; later ones are answered from what is held while it refreshes.
  if (held.addresses.size === 0) await refresh; else ctx?.waitUntil?.(refresh);
  return held.addresses;
}

export async function refused(request, env, ctx, fetcher = fetch) {
  if (!env.SENTINEL_URL || !env.SENTINEL_TOKEN) return null;
  const client = request.headers.get('cf-connecting-ip');
  if (!client) return null;
  return (await refusedAddresses(env, ctx, fetcher)).has(client) ? new Response('Refused.', { status: 403 }) : null;
}
