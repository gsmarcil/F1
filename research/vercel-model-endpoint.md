# Vercel model adapter

The endpoint `POST /api/analyze` accepts the existing Sentinels `AI_PROVIDER=custom` JSON payload: `{"instructions":"...","case":{...},"deciding":true}`. It returns `{"summary":"...","technique":"...","recommendation":"stop|release|hold","confidence":"low|medium|high"}`.

Production environment variables:
- `SENTINELS_LAB_AI_KEY` — sensitive shared bearer secret for lab requests.
- `AI_GATEWAY_API_KEY` — sensitive Vercel AI Gateway credential.
- `AI_GATEWAY_MODEL` — a valid provider/model ID from AI Gateway's live catalog.

The original `project/server/src/analyst.mjs` reads `AI_BASE_URL`, **not** `SENTINEL_AI_BASE_URL`. Configure the lab with:

```text
AI_PROVIDER=custom
AI_BASE_URL=https://sentinels-research-lab-20261116.vercel.app/api/analyze
AI_API_KEY=<same private value as SENTINELS_LAB_AI_KEY>
```

Never commit or send secrets in chat. The adapter limits request size, enforces bearer authentication and a timeout, and does not expose raw model messages in responses. It does not host the long-running Sentinels agent. The response remains model-supplied advice; test against a controlled lab only.
