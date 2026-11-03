# Runbook

How to deploy and operate the verification service. Commands assume the repository root.

## Deploy

```bash
docker build -t atproof:1.0.0 .
python -m atproof.ops keygen            # one API key per examiner, viewer and monitor
docker run -d --name atproof -p 8104:8104 -v atproof-data:/data \
  -e ATPROOF_KEYS_FILE=/run/secrets/atproof-keys.json \
  atproof:1.0.0
curl -fsS http://127.0.0.1:8104/readyz
```

The image runs in production mode as a non-root user with its log in SQLite under `/data`. It
refuses to start, and logs why, without hashed API keys or a database URL. It needs no outbound
network access.

## Use

Capture on the examiner's machine (this is the only step that touches the network), then verify:

```bash
atproof capture --uri at://did:plc:.../app.bsky.feed.post/<rkey> --out case9-live
python - <<'EOF' > body.json
import base64, json
print(json.dumps({"car": base64.b64encode(open("case9-live/proof.car", "rb").read()).decode(),
                  "identity": json.load(open("case9-live/identity.json")),
                  "uri": "at://did:plc:.../app.bsky.feed.post/<rkey>", "label": "case 9 exhibit 1"}))
EOF
curl -fsS -H "x-api-key: $KEY" -H "content-type: application/json" -d @body.json http://127.0.0.1:8104/v1/verify
```

`POST /v1/deleted` takes `inclusion`, `absence`, `identity` and `uri` the same way.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `ATPROOF_ENV` | — | `development` (default) or `production` |
| `ATPROOF_API_KEYS` / `ATPROOF_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `examiner` (verify, read), `viewer`, `monitor`, `admin` |
| `ATPROOF_DATABASE_URL` | yes | the verification log: `sqlite:////data/atproof.db` or `postgresql://...` |
| `ATPROOF_HOST`, `ATPROOF_PORT` | — | default `127.0.0.1:8104`; any other address needs API keys |
| `ATPROOF_RATE_LIMIT`, `ATPROOF_MAX_BODY_BYTES` | — | default 120/min per client, 70,000,000 bytes |
| `ATPROOF_CORS_ORIGINS` | — | comma-separated origins allowed to call the API from a browser |

## Watch

- `GET /healthz`; `GET /readyz` (database); `GET /metrics` (role `monitor`): requests, latency,
  errors, `atproof_decisions_total{decision="present|absent|failed|proven|not_proven"}`.
- A rise in `failed` means malformed or tampered submissions; look at the entries' `failures`.

## Rotate keys

Add the new API key hash, restart, hand over the key, remove the old hash, restart.

## Back up and restore

Back up the log like any SQLite or Postgres database (`python -m atproof migrate` creates the
schema on a fresh one). Keep the evidence packages themselves with the case files.

## Incidents

1. **Leaked API key.** Remove its hash and restart; list that user's entries.
2. **A verdict is challenged.** Find the entry, compare its input hashes with the package's
   manifest, and re-run `atproof check-package` on the package with the same version.
