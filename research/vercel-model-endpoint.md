# Vercel model adapter

The authenticated endpoint `POST /api/analyze` accepts the Sentinels `AI_PROVIDER=custom` payload with a fresh UUID `run_id`, a UUID `case.case_id`, `deciding=true`, the pinned decision prompt, and either pinned process name. Its top-level response retains the fields expected by Sentinels: `summary`, `technique`, `recommendation` and `confidence`.

The adapter fixes the experiment in code: model `openai/gpt-4.1-mini`; `temperature=0`, `max_tokens=400`, `top_p=1`, `n=1`, `stream=false`; A `python[CONTROL]`; B `python[ADMIN CONFIRMED]`; and decision prompt SHA-256 `fdba658f20e6690cf6d19742eafad825b222ed29bfcc0e9e716c03deab155616`. Environment variables cannot change these values. It sends every request to AI Gateway with no-store semantics and does not cache responses. Warm-instance duplicate `run_id` rejection is best effort only; the acceptance gate enforces cross-run freshness.

Successful responses contain an `evidence` object with the exact upstream request/response bytes and SHA-256 hashes, UTC send/receive timestamps, model/settings, run/case/arm, adapter and generation IDs, and reporting tags. These are the adapter's claims, not independent proof by themselves.

## Independent witnesses and acceptance

Each upstream call reports user `sentinels-independent-ab`, tag `sentinels-independent-ab`, a unique adapter tag and a run tag. After the run, allow about 90 seconds for ingestion, export matching **AI Gateway → Logs** rows as JSON or CSV, and compare generation/request ID, model, provider, timing, outcome, usage and routing attempts.

A gateway log without completion content supports only `EXTERNAL_INFERENCE_CONFIRMED_CONTENT_UNVERIFIED`. `MODEL_DECISION_CONFIRMED` additionally requires an independent content witness (provider-side response retrieval or a content-preserving independent witness) with the same generation ID and exact raw response bytes/hash, plus the full service/agent/OS execution chain. See `research/independent-model-ab-protocol.md` and run `research/acceptance-gate.mjs` against the complete bundle.

Production secrets:
- `SENTINELS_LAB_AI_KEY` — sensitive shared bearer secret for lab requests.
- `AI_GATEWAY_API_KEY` — sensitive Vercel AI Gateway credential.

Configure each fresh local service instance with:

```text
SENTINEL_AI_PROVIDER=custom
SENTINEL_AI_BASE_URL=https://sentinels-research-lab-20261116.vercel.app/api/analyze
SENTINEL_AI_API_KEY=<same private value as SENTINELS_LAB_AI_KEY>
SENTINEL_AI_LAB_RUN_ID=<new UUID for this run only>
SENTINEL_AI_LAB_CASE_ID=<new UUID for this fresh case only>
```

Never commit or send secrets in chat. The adapter does not host the long-running Sentinels agent. Test against a controlled lab only. A complete result requires the independent exports/witnesses, downstream service decision, agent execution and OS-level process-state transition for the same run, case and process identity.
