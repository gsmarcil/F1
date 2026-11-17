import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';

const MAX_BYTES = 48 * 1024;
const DEFAULT_MODEL = 'openai/gpt-4.1-mini';
const RECOMMENDATIONS = new Set(['investigate', 'stop', 'release', 'hold']);
const CONFIDENCES = new Set(['low', 'medium', 'high']);

function isAuthorized(header, secret) {
  if (!secret || typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const supplied = Buffer.from(header.slice(7));
  const expected = Buffer.from(secret);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export default async function handler(req, res) {
  const adapterRequestId = randomUUID();
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Lab-Request-Id', adapterRequestId);
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'method_not_allowed', request_id: adapterRequestId });
  }
  if (!isAuthorized(req.headers.authorization, process.env.SENTINELS_LAB_AI_KEY)) {
    return res.status(401).json({ error: 'unauthorized', request_id: adapterRequestId });
  }
  const gatewayKey = process.env.AI_GATEWAY_API_KEY;
  const model = process.env.AI_GATEWAY_MODEL || DEFAULT_MODEL;
  if (!gatewayKey) return res.status(503).json({ error: 'gateway_not_configured', request_id: adapterRequestId });
  if (Number(req.headers['content-length'] || 0) > MAX_BYTES) {
    return res.status(413).json({ error: 'payload_too_large', request_id: adapterRequestId });
  }

  let input = req.body;
  if (typeof input === 'string') {
    try { input = JSON.parse(input); } catch { return res.status(400).json({ error: 'invalid_json', request_id: adapterRequestId }); }
  }
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      typeof input.instructions !== 'string' || input.instructions.length > 8000 ||
      !input.case || typeof input.case !== 'object' || Array.isArray(input.case) ||
      typeof input.deciding !== 'boolean') {
    return res.status(400).json({ error: 'invalid_request', request_id: adapterRequestId });
  }
  if (Buffer.byteLength(JSON.stringify(input)) > MAX_BYTES) {
    return res.status(413).json({ error: 'payload_too_large', request_id: adapterRequestId });
  }

  const upstreamRequestBody = JSON.stringify({
    model,
    temperature: 0,
    max_tokens: 400,
    messages: [
      { role: 'system', content: input.instructions },
      { role: 'user', content: JSON.stringify(input.case) }
    ]
  });
  const sentAtUtc = new Date().toISOString();
  const sentAtMonotonicMs = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);

  try {
    const response = await fetch('https://ai-gateway.vercel.sh/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + gatewayKey, 'Content-Type': 'application/json' },
      body: upstreamRequestBody,
      signal: controller.signal
    });
    const receivedAtUtc = new Date().toISOString();
    const receivedAtMonotonicMs = performance.now();
    const rawResponseBody = await response.text();
    const upstreamRequestId = response.headers.get('x-request-id') || response.headers.get('x-vercel-id');
    const evidence = {
      adapter_request_id: adapterRequestId,
      provider: 'vercel-ai-gateway',
      model,
      sent_at_utc: sentAtUtc,
      response_received_at_utc: receivedAtUtc,
      upstream_latency_ms: Math.round((receivedAtMonotonicMs - sentAtMonotonicMs) * 1000) / 1000,
      upstream_http_status: response.status,
      upstream_request_id: upstreamRequestId,
      raw_request: upstreamRequestBody,
      raw_request_sha256: sha256(upstreamRequestBody),
      raw_response: rawResponseBody,
      raw_response_sha256: sha256(rawResponseBody)
    };

    if (!response.ok) {
      return res.status(response.status === 429 ? 429 : 502).json({
        error: 'model_unavailable',
        upstream_status: response.status,
        request_id: adapterRequestId,
        evidence
      });
    }

    let data;
    try { data = JSON.parse(rawResponseBody); }
    catch { return res.status(502).json({ error: 'invalid_upstream_json', request_id: adapterRequestId, evidence }); }

    let raw = data?.choices?.[0]?.message?.content;
    if (Array.isArray(raw)) raw = raw.map(item => item?.text || '').join('');
    if (typeof raw !== 'string') {
      return res.status(502).json({ error: 'invalid_model_output', request_id: adapterRequestId, evidence });
    }
    const match = raw.match(/\{[\s\S]*\}/);
    let parsed;
    try { parsed = JSON.parse(match ? match[0] : raw); }
    catch { return res.status(502).json({ error: 'invalid_model_json', request_id: adapterRequestId, evidence }); }
    if (!parsed || typeof parsed.summary !== 'string' || !parsed.summary.trim() ||
        !RECOMMENDATIONS.has(parsed.recommendation) || !CONFIDENCES.has(parsed.confidence)) {
      return res.status(502).json({ error: 'invalid_model_schema', request_id: adapterRequestId, evidence });
    }

    return res.status(200).json({
      summary: parsed.summary.slice(0, 600),
      technique: typeof parsed.technique === 'string' ? parsed.technique.slice(0, 120) : 'unclear',
      recommendation: parsed.recommendation,
      confidence: parsed.confidence,
      evidence
    });
  } catch (error) {
    return res.status(502).json({
      error: error?.name === 'AbortError' ? 'model_timeout' : 'gateway_request_failed',
      request_id: adapterRequestId
    });
  } finally {
    clearTimeout(timer);
  }
}
