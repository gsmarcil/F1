import { timingSafeEqual } from 'node:crypto';

const MAX_BYTES = 48 * 1024;
const RECOMMENDATIONS = new Set(['investigate', 'stop', 'release', 'hold']);
const CONFIDENCES = new Set(['low', 'medium', 'high']);

function isAuthorized(header, secret) {
  if (!secret || typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const supplied = Buffer.from(header.slice(7));
  const expected = Buffer.from(secret);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  if (!isAuthorized(req.headers.authorization, process.env.SENTINELS_LAB_AI_KEY)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  const gatewayKey = process.env.AI_GATEWAY_API_KEY;
  const model = process.env.AI_GATEWAY_MODEL;
  if (!gatewayKey || !model) return res.status(503).json({ error: 'gateway_not_configured' });
  if (Number(req.headers['content-length'] || 0) > MAX_BYTES) return res.status(413).json({ error: 'payload_too_large' });

  let input = req.body;
  if (typeof input === 'string') {
    try { input = JSON.parse(input); } catch { return res.status(400).json({ error: 'invalid_json' }); }
  }
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      typeof input.instructions !== 'string' || input.instructions.length > 8000 ||
      !input.case || typeof input.case !== 'object' || Array.isArray(input.case) ||
      typeof input.deciding !== 'boolean') {
    return res.status(400).json({ error: 'invalid_request' });
  }
  if (Buffer.byteLength(JSON.stringify(input)) > MAX_BYTES) return res.status(413).json({ error: 'payload_too_large' });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch('https://ai-gateway.vercel.sh/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + gatewayKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model, temperature: 0, max_tokens: 400,
        messages: [
          { role: 'system', content: input.instructions },
          { role: 'user', content: JSON.stringify(input.case) }
        ]
      }),
      signal: controller.signal
    });
    if (!response.ok) {
      return res.status(response.status === 429 ? 429 : 502).json({
        error: 'model_unavailable', upstream_status: response.status
      });
    }
    const data = await response.json();
    let raw = data?.choices?.[0]?.message?.content;
    if (Array.isArray(raw)) raw = raw.map(item => item?.text || '').join('');
    if (typeof raw !== 'string') return res.status(502).json({ error: 'invalid_model_output' });
    const match = raw.match(/\{[\s\S]*\}/);
    let parsed;
    try { parsed = JSON.parse(match ? match[0] : raw); }
    catch { return res.status(502).json({ error: 'invalid_model_json' }); }
    if (!parsed || typeof parsed.summary !== 'string' || !parsed.summary.trim() ||
        !RECOMMENDATIONS.has(parsed.recommendation) || !CONFIDENCES.has(parsed.confidence)) {
      return res.status(502).json({ error: 'invalid_model_schema' });
    }
    return res.status(200).json({
      summary: parsed.summary.slice(0, 600),
      technique: typeof parsed.technique === 'string' ? parsed.technique.slice(0, 120) : 'unclear',
      recommendation: parsed.recommendation,
      confidence: parsed.confidence
    });
  } catch (error) {
    return res.status(502).json({ error: error?.name === 'AbortError' ? 'model_timeout' : 'gateway_request_failed' });
  } finally {
    clearTimeout(timer);
  }
}
