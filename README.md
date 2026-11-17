# F1 — Sentinels security research

This public repository separates the pinned upstream source from security research.

- [`project/`](project/) — `gary23w/sentinels` at `665ab86a61667bb9fba7c24896cc9d66279505dc`, retaining upstream license.
- [`research/`](research/) — carefully scoped findings and reproduction criteria; raw case records, tokens and model payload logs are intentionally withheld.

**Evidence limit:** a controlled local model responder demonstrated a process-name-to-model-to-release execution path. It does not establish that an independent model follows the injection, that the backdoor is intentional, or that admin authentication is bypassed.

Do not publish secrets or test third-party installations without authorization.
