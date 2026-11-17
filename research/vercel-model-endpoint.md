# Vercel model adapter

The endpoint `POST /api/analyze` accepts the existing Sentinels `AI_PROVIDER=custom` JSON payload: `{"instructions":"...","case":{...},"deciding":true}`. Its top-level response retains the fields expected by Sentinels: `{"summary":"...","technique":"...","recommendation":"stop|release|hold","confidence":"low|medium|high"}`.

Successful responses also contain an `evidence` object with the exact upstream request and response bodies, their SHA-256 hashes, UTC send/receive timestamps, measured upstream latency, model ID, generation ID, HTTP status, adapter request ID and upstream request ID when supplied. This evidence is returned only through the authenticated endpoint and must be saved verbatim by the test runner before the Sentinels service makes its decision. Authorization headers and gateway credentials are never included.

## Independent gateway-log correlation

The response evidence is only the adapter's claim, not independent proof by itself. Each upstream call therefore sends these reporting identifiers to Vercel AI Gateway:

- user: `sentinels-independent-ab`
- tags: `sentinels-independent-ab` and `sentinels-adapter:<adapter_request_id>`

After the run, allow about 90 seconds for ingestion, open the team's or project's **AI Gateway → Logs**, locate the generation ID and/or reporting tag, and export the matching row as JSON or CSV. Compare the independent export against the run record: generation/request ID, model, provider, start time, HTTP outcome, token usage and routing attempts. Preserve the original export and its SHA-256 separately from the adapter response.

The gateway log independently establishes that a request was routed and records its model, provider, timing and usage. Vercel's request/trace logs do not necessarily retain prompt or completion content. If the exported record lacks the completion text, it cannot independently bind the returned recommendation to that provider response; the result must state that limitation. Stronger content binding requires a provider-side retrievable response or an independent content-preserving witness, not another log emitted by this adapter.

Production environment variables:
- `SENTINELS_LAB_AI_KEY` — sensitive shared bearer secret for lab requests.
- `AI_GATEWAY_API_KEY` — sensitive Vercel AI Gateway credential.
- `AI_GATEWAY_MODEL` — optional provider/model ID from AI Gateway's live catalog; defaults to `openai/gpt-4.1-mini` and is recorded in every evidence object.

The original `project/server/src/analyst.mjs` reads `AI_BASE_URL`, **not** `SENTINEL_AI_BASE_URL`. Configure the lab with:

```text
AI_PROVIDER=custom
AI_BASE_URL=https://sentinels-research-lab-20261116.vercel.app/api/analyze
AI_API_KEY=<same private value as SENTINELS_LAB_AI_KEY>
```

Never commit or send secrets in chat. The adapter limits request size, enforces bearer authentication and a timeout, and does not host the long-running Sentinels agent. The response remains model-supplied advice; test against a controlled lab only. A complete result still requires the independent gateway export, downstream service decision, agent execution and OS-level process-state transition for the same case and PID.
