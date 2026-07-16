# ADK Cyber AI — Zero Data Retention (ZDR) and Data Retention Runbook

**Product:** ADK Cyber AI (PAN Copilot)  
**Audience:** Operators, security, and anyone answering customer questions about where prompts and configs go  
**Last updated:** 2026-07-15  
**Status:** Operational guidance (enterprise ZDR is contract-enabled, not a self-serve app toggle)

---

## 1. Purpose

This runbook explains how to achieve and **prove** zero (or near-zero) retention of chat content when ADK Cyber AI traffic goes through:

- **Claude** (Anthropic API via ADK Cloudflare proxy / AI Gateway BYOK)
- **Grok** (xAI API via the same Worker with org `XAI_API_KEY`)
- **Local** (on-device LM Studio / Ollama; no cloud inference)

It covers provider contracts, Cloudflare Gateway/Worker policy, the license server, and on-device history. Use it when a customer asks for ZDR, when enabling enterprise keys, or during a privacy audit.

---

## 2. Executive summary

| Goal | How |
|------|-----|
| Claude provider ZDR | Anthropic **enterprise ZDR** on the org that owns the AI Gateway BYOK key |
| Grok provider ZDR | xAI **enterprise ZDR** on the team that owns Worker secret `XAI_API_KEY` |
| ADK relay does not store chat | Already the design: metadata-only Worker logs; Gateway payload logging **off** |
| License server never sees chat | Already true by architecture |
| No history on the PC | **Not** automatic; history lives in `%USERPROFILE%\.pan_copilot\conversations_v3\` unless the user deletes it |
| One Settings toggle that turns on ZDR for both clouds | **Does not exist** and cannot replace provider contracts |

**Bottom line:** Dual-provider ZDR is two independent enterprise enablements on the keys ADK holds, plus continued ADK no-content-log policy. The desktop app already redacts secrets on device and does not ship provider keys to clients.

---

## 3. Data flow (what touches what)

```
User machine (ADK Cyber AI desktop)
  │  ConfigSanitizer redacts secrets in message/config text
  │  Optional: Local LLM (never leaves machine for inference)
  │
  ├─ Auth / quota only ──> pan-copilot.onrender.com (license server)
  │                         NO chat, NO firewall configs
  │
  └─ Cloud chat ─────────> adk-cyber-ai-proxy.adkcyber.workers.dev
                              │  Bearer = ADK session token (not provider key)
                              │  Quota check against license server
                              │  Metadata logs only (no message body)
                              │
                              ├─ POST /v1/messages
                              │     → Cloudflare AI Gateway (BYOK Anthropic)
                              │     → Anthropic Messages API
                              │
                              └─ POST /v1/chat/completions
                                    → xAI api.x.ai (Bearer XAI_API_KEY on Worker)
                                    → Grok models
```

**Local paths that retain data by design (user-controlled):**

| Path | Contents |
|------|----------|
| `%USERPROFILE%\.pan_copilot\settings_v3.json` | Settings; DPAPI-wrapped session token and firewall API key material |
| `%USERPROFILE%\.pan_copilot\conversations_v3\` | Per-conversation JSON history (user + assistant text after redaction) |
| `%LOCALAPPDATA%\ADK Cyber AI\WebView2\` | WebView2 profile (UI state, not the primary chat store) |

---

## 4. Layer model (do not confuse these)

| Layer | Default retention | ZDR / control |
|-------|-------------------|---------------|
| **1. Model provider (Anthropic)** | Commercial API retention for abuse/policy (see Anthropic commercial policy) | Org-level **ZDR arrangement** via Anthropic sales |
| **2. Model provider (xAI)** | API request/response data retained ~**30 days** for abuse audit | Team-level **ZDR** via `sales@x.ai`; no app code change once enabled |
| **3. Cloudflare AI Gateway** | Can log request/response **payloads** if enabled | Keep **payload logging off** on gateway `adk-cyber-ai` |
| **4. Cloudflare Worker** | Structured logs | `logging.ts`: metadata only; **never** message/config content |
| **5. D1 / KV on proxy** | Users, session **token hashes**, usage counters | No chat bodies |
| **6. License server (Render)** | Accounts, hashed sessions, query counts, tiers | Explicitly excludes chat and configs |
| **7. Desktop** | Local conversation store | User deletes history; Local provider avoids cloud entirely |

Provider ZDR does **not** erase layers 3–7. Customer claims must name which layers are covered.

---

## 5. What is already true in production (ADK stack)

Confirm these still hold after every deploy that touches logging or Gateway settings.

### 5.1 Cloudflare Worker (`adk-cyber-ai-proxy`)

- Live base URL: `https://adk-cyber-ai-proxy.adkcyber.workers.dev`
- Claude: `POST /v1/messages`
- Grok: `POST /v1/chat/completions`
- Anthropic key: AI Gateway BYOK (not on client; not returned by license server)
- xAI key: Worker secret `XAI_API_KEY` only
- Logging (`src/lib/logging.ts`): one JSON line per event with fields such as `event`, `requestId`, `userId`/`tier`, `model`, `weight`, `status`, `latencyMs`, `reason`. Comment in code: **never log message content or config data**.
- Grok forwarder streams OpenAI-compatible SSE; design: **do not log message content**.

### 5.2 AI Gateway

Documented production posture (from proxy README):

- Gateway name: `adk-cyber-ai`
- Authenticated gateway
- **Payload logging off**
- Anthropic key in BYOK

### 5.3 License server

- Host: `https://pan-copilot.onrender.com`
- Responsibilities: register/login, session hashes, query quota, tiers, billing webhooks
- **Never** receives: firewall configs, CLI output, chat message content
- Cloud inference keys are **not** delivered to clients

### 5.4 Desktop

- `ConfigSanitizer` runs on outbound user text and config attachments before cloud relay
- Screenshots / images are a different path: treat as higher residual risk; do not claim full redaction for pixels
- Free tier: Claude Haiku only (no Grok)
- Grok: Pro / Max / Owner only
- Local tier: proxy returns 403 for cloud inference routes

---

## 6. Enable Anthropic ZDR (Claude path)

### 6.1 Prerequisites

- Commercial Anthropic organization (API under commercial terms), not a consumer Claude Free/Pro/Max chat account
- The **same org** that owns the API key stored in AI Gateway BYOK for ADK
- Eligible product surface: **Claude Messages API** (and other features marked ZDR-eligible). Console/Workbench and consumer UIs are **not** ZDR-covered.

### 6.2 Steps

1. Contact [Anthropic sales](https://claude.com/contact-sales) and request **Zero Data Retention** for the organization that holds the production BYOK key.
2. Confirm in writing:
   - Org id / name covered
   - Effective date
   - That `/v1/messages` traffic under this key is in scope
   - Any feature exclusions (batches, files API, code execution, managed agents, etc.)
3. After enablement, record in the ops vault (not in git):
   - Anthropic org name / id
   - Account owner email
   - Contract / order reference
   - Date enabled
   - Workspace notes (ZDR is per org; new orgs need separate enablement)
4. Ensure production inference stays on the **Messages** path only (ADK already uses `/v1/messages`). Do not enable non-ZDR-eligible features in the Worker if you market ZDR.
5. Re-check AI Gateway still points BYOK at a key belonging to the ZDR org (no leftover personal/consumer keys).

### 6.3 What Anthropic ZDR does (plain language)

Under a ZDR arrangement, Anthropic does **not** store customer prompts or responses **at rest after the API response is returned**, for eligible API usage. Flagged abuse content and legal holds can still cause retention under Anthropic policy. Covered models that require 30-day retention are not available under ZDR.

Official reference: [API and data retention (Claude Platform)](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention)

### 6.4 Verification (Anthropic)

There is no universal response header equivalent to xAI’s ZDR flag. Verification is:

| Check | How |
|-------|-----|
| Contract | Sales confirmation / DPA addendum on file |
| Console | Confirm with Anthropic account team that org shows ZDR |
| Key ownership | BYOK key is from that org only |
| Product path | Production only hits Messages (and other ZDR-eligible features) |
| No payload logs middle hop | Gateway payload logging off (section 8) |

---

## 7. Enable xAI ZDR (Grok path)

### 7.1 Prerequisites

- xAI **enterprise** account / team (ZDR is enterprise-only)
- Team that owns the API key stored as Worker secret `XAI_API_KEY`
- Grok traffic from the desktop goes to the Worker, then to `https://api.x.ai/v1/chat/completions` (or `XAI_CHAT_COMPLETIONS_URL` override)

### 7.2 Steps

1. Email [sales@x.ai](mailto:sales@x.ai) requesting **Zero Data Retention** for the production team.
2. After enablement:
   - Open [xAI Console](https://console.x.ai/) team picker
   - Confirm a **Zero Data Retention** label under the team name
3. Record in the ops vault:
   - Team name / id
   - Date enabled
   - Sales contact / ticket id
4. No desktop or Worker code change is required for enablement. Keys on a ZDR team inherit ZDR automatically.
5. Optional (recommended): after enablement, verify response header `x-zero-data-retention: true` on a real Grok call (section 9.2).

### 7.3 What xAI ZDR does (plain language)

When ZDR is enabled for the team, prompts, completions, and associated metadata are processed in real time and **not persisted** for the default 30-day audit retention. Safety/moderation can still run in real time without storing results. Server-side conversation features that depend on stored state are unavailable under ZDR (ADK manages context client-side, so this matches the product).

Official reference: [xAI FAQ — Security / ZDR](https://docs.x.ai/developers/faq/security)

### 7.4 Secret hygiene (xAI)

```powershell
# From the adk-cyber-ai-proxy project directory (production)
npx wrangler secret put XAI_API_KEY
# Secret *name* must be exactly XAI_API_KEY (not the key value as the name)
```

After rotating keys for a ZDR team, put the new key and confirm Grok still returns `x-zero-data-retention: true`.

---

## 8. Cloudflare AI Gateway and Worker checklist

Run this whenever someone changes Gateway settings, observability, or logging.

### 8.1 AI Gateway (`adk-cyber-ai`)

| Control | Required state | How to verify |
|---------|----------------|---------------|
| Gateway name | `adk-cyber-ai` | Cloudflare dashboard → AI → AI Gateway |
| Authentication | On | Authenticated gateway + Worker uses `AIG_TOKEN` |
| **Payload / request body logging** | **Off** | Gateway settings: payload logging disabled |
| BYOK Anthropic | Present; production key only | Provider keys → Anthropic |
| Spend limits | Set on Anthropic key + gateway if available | Anthropic console + CF |
| Collect logs (metadata) | Allowed for ops metrics | Prefer metadata that cannot reconstruct prompts |

If payload logging is turned on for debugging, treat it as a **privacy incident** until it is turned off and any retained payloads are purged per Cloudflare retention.

### 8.2 Worker logs

| Control | Required state |
|---------|----------------|
| `src/lib/logging.ts` | Metadata only |
| Code review | No `console.log` of `body`, `messages`, `content`, or raw request text |
| Tail sample | `wrangler tail` shows events without prompt text |

Sample safe log shape:

```json
{
  "ts": "2026-07-15T12:00:00.000Z",
  "level": "info",
  "event": "request_ok",
  "requestId": "…",
  "tier": "pro",
  "model": "…",
  "weight": 1,
  "status": 200,
  "latencyMs": 842,
  "provider": "xai"
}
```

### 8.3 D1 / KV

| Store | Allowed data | Forbidden |
|-------|--------------|-----------|
| D1 users / sessions / usage | user id, email, plan, token **hash**, counters | prompt text, completions, configs |
| KV `SESSION_CACHE` | short-lived session metadata | chat bodies |

Periodic check: no new tables or “debug transcript” stores without a privacy review.

### 8.4 Deploy regression

After proxy deploys:

1. `GET https://adk-cyber-ai-proxy.adkcyber.workers.dev/health`
2. One authenticated Claude message (Pro session)
3. One authenticated Grok message (Pro+ session)
4. Spot-check Workers logs: no content fields
5. Confirm Gateway payload logging still off

---

## 9. Verification procedures

### 9.1 End-to-end inventory (quarterly)

Fill this table and keep a dated copy offline (ops vault), not in the public repo.

| Layer | Owner | ZDR / no-content? | Evidence | Date checked |
|-------|--------|-------------------|----------|--------------|
| Anthropic org | | Yes / No | Sales email / console | |
| xAI team | | Yes / No | Console label + header | |
| AI Gateway payload log | | Off | Screenshot / setting export | |
| Worker content logs | | None | Code + wrangler tail | |
| License server | | No chat path | Architecture review | |
| Desktop history | | User-local | Path exists by design | |

### 9.2 Prove xAI ZDR on a live Grok call

Requires a valid ADK session token for Pro/Max/Owner and ZDR-enabled `XAI_API_KEY`.

**Option A — via Worker (production path):**

1. Call `POST /v1/chat/completions` with Bearer session token and a tiny non-sensitive prompt, `"stream": true` (Worker forces stream).
2. Capture **upstream** response headers if the Worker forwards them, or temporarily log **only** the header name/value of `x-zero-data-retention` in a staging deploy (never log bodies).
3. Expect: `x-zero-data-retention: true` when team ZDR is active.

**Option B — direct to xAI (ops only, same key, never from customer machines):**

```powershell
# Ops machine with secret in env only; do not commit; use a throwaway prompt
$headers = @{
  Authorization = "Bearer $env:XAI_API_KEY"
  "Content-Type" = "application/json"
}
$body = @{
  model = "grok-3"   # use an id your account allows
  messages = @(@{ role = "user"; content = "ping" })
  stream = $false
} | ConvertTo-Json -Depth 5

$r = Invoke-WebRequest -Uri "https://api.x.ai/v1/chat/completions" -Method POST -Headers $headers -Body $body
$r.Headers["x-zero-data-retention"]
```

Interpret:

| Header value | Meaning |
|--------------|---------|
| `true` | ZDR active for this key/team |
| `false` or missing | Treat as **not** ZDR; default ~30-day retention may apply |

**Recommended product hardening (optional engineering):** proxy reads upstream `x-zero-data-retention` and exposes `X-ADK-Xai-Zdr: true|false` on Grok responses for support diagnostics (metadata only).

### 9.3 Prove Anthropic path does not use a non-ZDR product surface

1. Confirm desktop and Worker only call Messages (`/v1/messages`), not Console, Workbench, or consumer apps for production inference.
2. Confirm BYOK key org matches the ZDR contract org.
3. Confirm no Worker feature flags enable batch/files/code-execution APIs under the production ZDR claim.

### 9.4 Prove ADK middle hops

| Check | Pass criteria |
|-------|----------------|
| Gateway payload logging | Off |
| `wrangler tail` during a chat | No prompt/completion text in log lines |
| D1 sample query | No columns holding message content |
| License server access logs / DB | Auth and quota only |
| Client redaction unit tests | `ConfigSanitizer` tests still green |

### 9.5 Local provider (strongest isolation)

1. In app, set provider to **Local** with a working LM Studio / Ollama endpoint.
2. Confirm no calls to `adk-cyber-ai-proxy` for inference (proxy returns 403 for local tier on cloud routes; Local path uses local base URL).
3. Chat text may still be written under `conversations_v3` on disk.

---

## 10. Desktop and customer-side retention

### 10.1 What customers should know

- **Cloud ZDR** (if enabled on ADK’s Anthropic/xAI accounts) means the **model provider** does not retain prompts/responses under that arrangement.
- ADK’s relay is designed **not to store** chat content; it may log metadata for reliability and abuse resistance.
- **Conversation history remains on the user’s machine** until deleted.
- **Local mode** keeps inference on-device; history can still be local.
- Screenshots and pasted raw secrets that redaction misses can still leave the device on cloud turns.

### 10.2 Where to delete local history

1. Close ADK Cyber AI.
2. Delete or empty:  
   `%USERPROFILE%\.pan_copilot\conversations_v3\`
3. Optional: review `settings_v3.json` (does not store full chat transcripts).
4. Restart the app.

### 10.3 Future product options (not shipped; backlog candidates)

- Settings: “Do not save conversation history”
- Settings: “Clear all conversations”
- Support export of privacy posture for enterprise buyers

Do not document these as available until implemented.

---

## 11. Customer / sales language (approved shape)

Use accurate, layered wording. Avoid “we never see your data” without qualifiers.

**Acceptable (when contracts + Gateway policy are true):**

> Cloud chat is relayed through ADK Cyber’s authenticated gateway. Provider API keys stay on ADK infrastructure, not in the desktop app. Message content is not written to ADK application logs. On-device redaction strips common credential patterns before send. Enterprise Zero Data Retention is available when enabled with Anthropic and/or xAI on the accounts ADK uses for inference. Conversation history, if saved, remains on your device. Local model mode keeps inference on your machine.

**Avoid:**

- “Zero data retention everywhere by default” (false without enterprise enablement and without addressing local history)
- “HIPAA compliant” unless a signed BAA and product scope explicitly cover the deployment
- “We never process your data” (the proxy and providers process it in transit for inference)

---

## 12. Incident playbooks (retention-related)

### 12.1 Gateway payload logging found enabled

1. Disable payload logging immediately.
2. Determine retention window of Gateway logs; request purge/export deletion if available.
3. Note time range and whether customer traffic was included.
4. Notify security owner; update quarterly checklist date.
5. Root-cause: who changed the setting and why.

### 12.2 Worker or support tooling logged full bodies

1. Stop the offending code path / hotfix deploy.
2. Purge log streams if retained (Cloudflare logpush destinations, external sinks).
3. Rotate provider keys if logs could have included secrets that bypassed redaction.
4. Post-incident: add a CI grep for forbidden log fields if useful.

### 12.3 Wrong API key / non-ZDR org used in production

1. Restore BYOK / `XAI_API_KEY` to the ZDR-enabled org/team keys.
2. Treat prior traffic as under default retention of the wrong account.
3. Document window; inform impacted enterprise customers if required by contract.

### 12.4 Suspected key extraction from an old desktop build

1. Rotate Anthropic BYOK key and xAI Worker secret.
2. Revoke old keys in provider consoles.
3. Confirm new keys are on ZDR orgs/teams if ZDR is claimed.
4. Force client upgrade path if any build still expected an embedded key (legacy only).

---

## 13. Operator quick reference

| Item | Value / action |
|------|----------------|
| Proxy health | `GET https://adk-cyber-ai-proxy.adkcyber.workers.dev/health` |
| Claude route | `POST …/v1/messages` |
| Grok route | `POST …/v1/chat/completions` |
| License (no chat) | `https://pan-copilot.onrender.com` |
| Gateway id | `adk-cyber-ai` |
| Worker secrets | `AIG_TOKEN`, `XAI_API_KEY` (and BYOK Anthropic in Gateway, not as client secret) |
| Anthropic ZDR request | https://claude.com/contact-sales |
| xAI ZDR request | sales@x.ai |
| xAI ZDR verify | Console label + `x-zero-data-retention` header |
| Local history | `%USERPROFILE%\.pan_copilot\conversations_v3\` |
| Proxy repo (ops) | `adk-cyber-ai-proxy` (Cloudflare Worker project) |
| Desktop repo | `PAN-Copilot` |

---

## 14. Quarterly audit checklist (copy per audit)

- [ ] Anthropic org still under ZDR (sales/console confirmation)
- [ ] xAI team still shows ZDR label
- [ ] Live Grok response: `x-zero-data-retention: true`
- [ ] AI Gateway payload logging **off**
- [ ] Worker deploy has no content logging regressions
- [ ] BYOK Anthropic key is the ZDR org key; spend caps set
- [ ] `XAI_API_KEY` is the ZDR team key; old keys revoked
- [ ] License server still has no chat storage
- [ ] Privacy page / sales deck language matches this runbook
- [ ] Sample `wrangler tail` during Claude + Grok: metadata only
- [ ] Document date, auditor name, exceptions

**Audit date:** _______________  
**Auditor:** _______________  
**Exceptions:** _______________

---

## 15. Related documents

| Doc | Location |
|-----|----------|
| Multi-cloud LLM design | `docs/superpowers/specs/2026-07-09-multi-cloud-llm-provider-design.md` |
| Proxy README (security model, Gateway) | `adk-cyber-ai-proxy/README.md` |
| Proxy setup runbook | `adk-cyber-ai-proxy/SETUP-RUNBOOK.md` |
| License server responsibilities | `license_server/app.py` header comment |
| Anthropic ZDR | https://platform.claude.com/docs/en/manage-claude/api-and-data-retention |
| xAI ZDR | https://docs.x.ai/developers/faq/security |
| xAI enterprise terms (ZDR language) | https://x.ai/legal/terms-of-service-enterprise |
| Product privacy (public) | https://www.adkcyber.com (privacy / ADK Cyber AI pages as published) |

---

## 16. Change log

| Date | Change |
|------|--------|
| 2026-07-15 | Initial runbook: dual-provider ZDR enablement, ADK layer model, verification, incident steps |

---

*Internal operations document for Adirondack CyberSecurity / ADK Cyber AI. Update when contracts, Gateway settings, or logging code change.*
