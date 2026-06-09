# PAN Copilot — License Server

Lightweight FastAPI auth + quota service deployed to **Render** (`render.yaml`).
Handles user accounts, session tokens, query counting against tier limits, and
delivery of the (encrypted) shared Anthropic key to authenticated clients.

> Firewall configs, PAN-OS output, and chat content **never** pass through here —
> only email + session token. That privacy boundary is intentional.

## Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | yes | — | Shared key delivered (encrypted) to paid clients. |
| `SECRET_PEPPER` | yes | `change-me-in-production` | Pepper for legacy SHA-256 hashes; set a real value. |
| `LS_WEBHOOK_SECRET` | yes | — | HMAC secret for the Lemon Squeezy webhook. If unset, the webhook rejects everything. |
| `ADMIN_TOKEN` | recommended | — | Bearer token for `/admin/*`. If unset, admin endpoints are disabled. |
| `DB_PATH` | **prod** | `data/license_server.db` | SQLite path. **Must not be under `/tmp`** in production (data is wiped on restart). Point at a mounted persistent disk. |
| `TRUSTED_PROXY_HOPS` | no | `1` | Reverse-proxy hops in front of the app. The client IP used for rate limiting is taken this many entries from the right of `X-Forwarded-For` — never the spoofable leftmost. Render = `1`. |
| `KEY_DELIVERY_IP_THRESHOLD` | no | `5` | If one account pulls the API key from more distinct IPs than this per month, a `CRITICAL` anomaly is logged. |
| `ANTHROPIC_KEY_VERSION` | no | `1` | Reported by `/health`; bump it whenever you rotate the key. |
| `ALLOW_EPHEMERAL_DB` | no | — | Set to `1` to allow a `/tmp` DB on Render (throwaway envs only). |

## Persisting the database (Render)

By default the SQLite file is ephemeral and lost on every restart/redeploy. To
keep accounts, mount a disk and point `DB_PATH` at it: in `render.yaml`, uncomment
the `disk:` block (requires a paid plan) and set `DB_PATH=/var/data/license_server.db`.
On Render free tier there is no persistent disk — treat the DB as disposable.

## Rotating the shared Anthropic key

The key is shared across paid clients and is extractable by any client that holds
its own session token, so rotation + monitoring (not encryption) is the real
control:

1. Issue a new Anthropic key; revoke the old once traffic has cut over.
2. Update `ANTHROPIC_API_KEY` and bump `ANTHROPIC_KEY_VERSION`.
3. Watch logs for `Key-delivery anomaly` lines (driven by `KEY_DELIVERY_IP_THRESHOLD`)
   to spot one account fanning the key out across many IPs. The per-user quota
   counter remains the hard spend cap.

## Tier management

`/admin/*` authenticates with an `Authorization: Bearer <ADMIN_TOKEN>` header:

```bash
curl -X POST https://pan-copilot.onrender.com/admin/set-tier \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tier":"pro","seats_allowed":1}'
```

Tiers: `free` | `local` | `pro` | `max` | `owner`. For multi-seat accounts set
`seats_allowed` accordingly.

## Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/auth/register` | Create account → session token + encrypted key |
| POST | `/auth/login` | Login → session token + encrypted key |
| POST | `/auth/validate` | Validate token, return tier + query count |
| POST | `/query/check` | Atomic check-and-count before each query |
| POST | `/admin/set-tier` | Upgrade/downgrade a user's tier (admin) |
| GET | `/admin/users` | List all users (admin) |
| POST | `/webhook/lemonsqueezy` | Subscription lifecycle → tier changes (HMAC-verified) |
| GET | `/health` | Health check (reports `key_version`) |

## Local development

```bash
cd license_server
pip install -r requirements.txt
DB_PATH=./dev.db SECRET_PEPPER=dev LS_WEBHOOK_SECRET=dev uvicorn app:app --reload --port 8001
```

## Tests

```bash
cd license_server && pytest
```
