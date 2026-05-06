# PAN Copilot — License Server

Lightweight Railway service that handles user accounts, session tokens, and
weekly query counting for the free tier.

## Environment variables (set in Railway dashboard)

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | ADK Cyber's Anthropic key — returned to authenticated users |
| `SECRET_PEPPER` | Random secret used when hashing passwords (generate once, never change) |
| `ADMIN_TOKEN` | Secret token for the `/admin/*` endpoints |
| `DB_PATH` | Path to SQLite file (default: `/data/license_server.db`) — use Railway volume |

## Deploy steps

1. Push this directory to a GitHub repo (or a subfolder with Railway monorepo)
2. Create a new Railway project → Deploy from GitHub
3. Add a Railway Volume mounted at `/data`
4. Set the four environment variables above
5. Railway auto-detects `Procfile` and starts the server

## Tier management

After a user pays (via Lemon Squeezy webhook or manually), upgrade their tier:

```bash
curl -X POST https://your-license-server.railway.app/admin/set-tier \
  -H "Content-Type: application/json" \
  -d '{"admin_token":"YOUR_ADMIN_TOKEN","email":"user@example.com","tier":"pro","seats_allowed":1}'
```

Tiers: `free` | `pro` | `team`

For team accounts, set `seats_allowed` to the number of seats purchased (e.g. 5).

## Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/auth/register` | Create account → returns session token + Anthropic key |
| POST | `/auth/login` | Login → returns session token + Anthropic key |
| POST | `/auth/validate` | Validate session token, returns current tier + query count |
| POST | `/query/check` | Check weekly limit (free) or validate (paid) before each query |
| POST | `/admin/set-tier` | Upgrade/downgrade a user's tier |
| GET | `/admin/users` | List all users (admin only) |
| GET | `/health` | Health check |

## Lemon Squeezy webhook (future)

When a subscription is created/renewed, Lemon Squeezy can POST to a webhook
endpoint you add here. That endpoint calls `set-tier` automatically.
For now, tier upgrades are done manually via `/admin/set-tier` after confirming payment.
