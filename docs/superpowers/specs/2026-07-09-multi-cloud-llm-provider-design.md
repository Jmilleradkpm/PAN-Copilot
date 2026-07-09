# Multi-cloud LLM provider (Anthropic + Grok + Local)

**Date:** 2026-07-09  
**Status:** Draft for review  
**Repos:** `C:\Users\jmill\PAN-Copilot` (desktop) + `adk-cyber-ai-proxy` (Cloudflare Worker)  
**Author:** Design session with product owner

---

## 1. Problem

PAN Copilot cloud chat is **Claude-only** today, via the ADK Cloudflare proxy and a session token. Users want to choose:

- **Grok 4.5** or **Grok 4.3** (ADK-hosted, same subscription quota)
- **Anthropic products** (existing Auto / Haiku / Sonnet / Opus)
- **Local LLM** (existing OpenAI-compatible endpoint)

UI requirement: **provider first, then model** (two controls, not one mega-dropdown).

---

## 2. Goals

1. Pro / Max / Owner can pick **Anthropic**, **Grok**, or **Local**.
2. Free remains **Anthropic Haiku only** (no Grok).
3. Local tier remains **local only** (no cloud relay).
4. Grok is **ADK-hosted**: session token → ADK proxy → xAI with org `XAI_API_KEY`. Counts against the same query quota as Claude.
5. Persist **last used** provider + model in `settings_v3.json`.
6. On-device config redaction unchanged for all cloud paths.
7. Ship desktop (.NET) and proxy changes together so Grok is not a dead UI control.

## 3. Non-goals (v1)

- User-supplied xAI API keys
- Separate Grok vs Claude quota buckets
- Free-tier Grok
- Python `local/app.py` / legacy backend parity
- Grok tool-calling / Live Search product features
- Changing Lemon Squeezy tier pricing

---

## 4. Current architecture (baseline)

```
UI chat_provider: cloud | local
  cloud → AnthropicClient POST adk-cyber-ai-proxy.../v1/messages
           Bearer session_token → quota → AI Gateway BYOK Anthropic
  local → LocalLlmService → localhost OpenAI-compat SSE
```

**Important proxy behavior today:** `modelForTier()` **overwrites** the client model (free→Haiku; paid→Sonnet/Opus by size). Client model pills are not fully authoritative on the server. This design **fixes paid-tier model honor** within an allowlist so Grok and explicit Claude models work.

Proxy source (not in PAN-Copilot repo):

`C:\Users\jmill\OneDrive\Documents\Claude\Projects\CyberSecurity Analysis\adk-cyber-ai-proxy`

---

## 5. Product UX

### 5.1 Controls

**Provider** (dropdown or radio group — match existing settings visual language):

| Value | Label | Available tiers |
|-------|-------|-----------------|
| `anthropic` | Anthropic (Claude) | free, pro, max, owner |
| `grok` | Grok (xAI) | pro, max, owner |
| `local` | Local LLM | local, pro, max, owner |

**Model** (dropdown; contents depend on provider):

| Provider | Models (UI label → API id) |
|----------|----------------------------|
| Anthropic | Auto → `auto`; Haiku 4.5 → `claude-haiku-4-5-20251001`; Sonnet 4.6 → `claude-sonnet-4-6`; Opus 4.8 → `claude-opus-4-8` |
| Grok | Grok 4.5 → `grok-4.5`; Grok 4.3 → `grok-4.3` |
| Local | Keep existing free-text model field + List / Test (no fixed cloud list) |

### 5.2 Defaults and persistence

- **First install / empty settings:** `chat_provider=anthropic`, cloud model=`auto` (free still resolves to Haiku).
- **Thereafter:** last saved provider + model win (`settings_v3.json`).
- Migration: existing `chat_provider=cloud` → `anthropic` on load/normalize.
- Mode pill / header text updates: e.g. `Cloud · Claude Sonnet`, `Cloud · Grok 4.5`, `Local · qwen…`.

### 5.3 Privacy / quota copy

- Anthropic: existing gateway + Anthropic language (update if still says “direct”).
- Grok: “Credentials redacted on device · relayed through ADK Cyber's gateway (not stored) to xAI”.
- Local: unchanged.
- Quota meter: same query counters for Anthropic and Grok cloud calls.

---

## 6. Settings schema

### 6.1 `SettingsStore` fields

```csharp
// chat_provider: "anthropic" | "grok" | "local"
// (legacy "cloud" accepted on load and rewritten to "anthropic")
public string chat_provider { get; set; } = "anthropic";

// Preferred cloud model when provider is anthropic or grok.
// Local continues to use local_model.
public string cloud_model { get; set; } = "auto";

// existing local_* and fw_* and session_* unchanged
```

**Normalize rules:**

- Map `cloud` → `anthropic`.
- If provider not in allowed set for tier, coerce: local tier → `local`; free + grok → `anthropic`; invalid → `anthropic` (or `local` if only local available).
- `cloud_model` must be in the allowlist for the active provider family; else default `auto` (anthropic) or `grok-4.5` (grok).

### 6.2 Public API (`GET/POST /api/settings`)

Add:

```json
{
  "chat_provider": "grok",
  "cloud_model": "grok-4.5",
  "effective_provider": "grok",
  "providers_available": {
    "anthropic": true,
    "grok": true,
    "local": true
  },
  "models_available": {
    "anthropic": ["auto", "claude-haiku-4-5-20251001", "claude-sonnet-4-6", "claude-opus-4-8"],
    "grok": ["grok-4.5", "grok-4.3"],
    "local": []
  }
}
```

POST rejects:

- `grok` when tier is free or local → **403** with clear message  
- `anthropic` when tier is local → **403** (existing behavior)  
- unknown provider → **400**

Chat stream body continues to send `model` for the turn; server also respects saved `cloud_model` when body omits/invalidates.

---

## 7. Desktop runtime design

### 7.1 Effective provider

```text
if tier == "local" → local
else if pref == "local" and local allowed → local
else if pref == "grok" and tier in {pro,max,owner} → grok
else if pref == "anthropic" and tier != "local" → anthropic
else → anthropic (or local if no cloud)
```

### 7.2 Dispatch in `ChatService`

| Effective provider | Client | Endpoint |
|--------------------|--------|----------|
| `anthropic` | `AnthropicClient` (existing) | `POST …/v1/messages` |
| `grok` | `CloudOpenAiClient` (new) | `POST …/v1/chat/completions` |
| `local` | `LocalLlmService` (existing) | user `local_base_url` |

**`CloudOpenAiClient` responsibilities:**

- URL default: `https://adk-cyber-ai-proxy.adkcyber.workers.dev/v1/chat/completions`  
  Override: `ADK_PROXY_CHAT_COMPLETIONS_URL`
- Auth: `Authorization: Bearer <session_token>`
- Body: OpenAI chat-completions shape (`model`, `messages`, `stream: true`, `max_tokens` / `max_completion_tokens`)
- Parse SSE like `LocalLlmService` (delta content + optional `reasoning_content` → thinking events)
- Surface `X-ADK-Used|Limit|Remaining|Model` headers into session/done event

**Message build for Grok:**

- Convert Anthropic-shaped history (string or content blocks) to OpenAI messages.
- System prompt → first `role: system` message (string; join multi-block system if needed).
- Images: map to OpenAI image_url parts when present; if unsupported by model, fail with clear error.

**Model resolution:**

- Anthropic free: always Haiku (client + proxy).
- Anthropic paid `auto`: keep existing `SelectModel` heuristics + conversation pin.
- Anthropic paid explicit model: use it (proxy must honor).
- Grok: only `grok-4.5` | `grok-4.3`; default `grok-4.5` if missing.
- Conversation pin: pin only when provider family matches (do not pin Claude model onto a Grok turn).

### 7.3 Frontend (`dotnet/Frontend/index.html`)

Replace binary Cloud/Local radios with:

1. Provider control (`anthropic` / `grok` / `local`)  
2. Model control (dynamic options)  
3. Local settings panel only when provider is `local`

Wire:

- `onProviderChange` → POST settings + refresh model list  
- model change → persist `cloud_model` (and chat `selectedModel`)  
- `providers_available` disables/hides unavailable options  
- Privacy blurb switches by provider  
- Mode pill shows current provider + model label  

---

## 8. Proxy design (`adk-cyber-ai-proxy`)

### 8.1 Routes

| Route | Purpose |
|-------|---------|
| `POST /v1/messages` | Anthropic Messages (existing; model resolution updated) |
| `POST /v1/chat/completions` | **New** OpenAI-compatible path for Grok |
| `GET /v1/usage`, `GET /health` | Unchanged |

Both inference routes: authenticate session → reject local tier → size guard → validate body → quota check-and-count → forward → stream + `X-ADK-*` headers.

### 8.2 Model resolution (server-authoritative allowlist)

```text
FREE:
  /v1/messages → always claude-haiku-4-5-20251001
  /v1/chat/completions → 403 model_not_allowed (Grok not on free)

PRO / MAX / OWNER:
  /v1/messages:
    requested in {auto, haiku, sonnet, opus ids} → honor explicit;
    auto or missing → existing size heuristic (Sonnet vs Opus)
  /v1/chat/completions:
    requested in {grok-4.5, grok-4.3} → honor;
    missing/invalid → grok-4.5
    anything else → 400

LOCAL tier:
  both inference routes → 403 local_tier
```

This **restores** client ability to pick Claude models on paid tiers (within allowlist), while free remains locked.

### 8.3 xAI upstream

- Endpoint: `https://api.x.ai/v1/chat/completions` (or CF AI Gateway xAI path if configured).
- Auth: Worker secret `XAI_API_KEY` as `Authorization: Bearer …` (never on client).
- Prefer Gateway BYOK for xAI when available; fallback direct to `api.x.ai` with secret (document in proxy README).
- Stream passthrough of OpenAI SSE; do not log message content.

### 8.4 Env / secrets additions

| Name | Type | Purpose |
|------|------|---------|
| `XAI_API_KEY` | secret | Org xAI key for Grok |
| Optional Gateway xAI path vars | var | If using AI Gateway for xAI |

No license-server schema change required for v1 (same query meter).

---

## 9. Error handling

| Condition | Client UX |
|-----------|-----------|
| Free user selects Grok | Control hidden/disabled; POST → 403 |
| Local tier cloud | Existing upgrade message |
| Proxy 429 | Existing quota exceeded UI |
| xAI upstream error | “Cloud model unavailable — try again or switch provider” |
| Invalid model | Coerce to default; log once |

---

## 10. Testing plan

### Desktop (.NET)

- Settings migrate `cloud` → `anthropic`
- Normalize rejects/coerces invalid provider per tier
- `EffectiveProvider` matrix (free/local/pro × prefs)
- `ChatService` routes anthropic/grok/local (mock HTTP handlers)
- `CloudOpenAiClient` SSE parse + header extraction
- Allowlist for Grok models

### Proxy (Worker)

- Free cannot call chat/completions for Grok
- Paid allowlist honor for Grok and Claude
- Free messages still Haiku
- Quota headers present on both routes
- Auth failure paths unchanged

### Manual smoke

1. Pro login → Anthropic Auto chat works  
2. Switch to Grok 4.5 → stream works; quota decrements  
3. Switch to Grok 4.3 → works  
4. Free account → no Grok option; Haiku only  
5. Local tier → local only  
6. Restart app → last provider/model restored  

---

## 11. Rollout order

1. Deploy proxy with Grok route + paid Claude model honor + `XAI_API_KEY` secret.  
2. Verify with curl (session token) against staging/production Worker.  
3. Ship desktop app that exposes provider/model UI.  
4. Update privacy copy and CLAUDE.md architecture notes (proxy + multi-vendor).

Do **not** ship desktop Grok UI before the Worker accepts Grok (or gate behind a remote flag — not planned for v1; coordinate deploy).

---

## 12. File touch list (expected)

### PAN-Copilot

- `dotnet/PanCopilot.Core/Services/SettingsStore.cs`
- `dotnet/PanCopilot.Core/Services/ChatService.cs`
- `dotnet/PanCopilot.Core/Services/ApiRouter.cs`
- `dotnet/PanCopilot.Core/Services/AnthropicClient.cs` (minor if needed)
- `dotnet/PanCopilot.Core/Services/CloudOpenAiClient.cs` (**new**)
- `dotnet/Frontend/index.html`
- Tests under `dotnet/PanCopilot.Tests/`
- Docs: this file + short CLAUDE.md architecture note

### adk-cyber-ai-proxy

- `src/index.ts` — register `/v1/chat/completions`
- `src/handlers/chatCompletions.ts` (**new**)
- `src/lib/xai.ts` or `openaiUpstream.ts` (**new**)
- `src/lib/plans.ts` — allowlist resolution
- `src/lib/validate.ts` — chat completions body validation
- `src/types.ts` — env secrets
- `README.md` / `SETUP-RUNBOOK.md`

---

## 13. Open implementation notes

- Exact CF AI Gateway support for xAI BYOK should be checked at implement time; direct `api.x.ai` with Worker secret is an acceptable v1.
- Model ids `grok-4.5` and `grok-4.3` match current xAI public catalog (2026-07); confirm against console if deploy fails with model_not_found.
- Opus 4.7 remains in legacy allowlist if already present; UI can continue to offer Opus 4.8 only unless product asks otherwise.

---

## 14. Acceptance criteria

1. Pro user can select Anthropic or Grok from provider control and complete a streamed chat on each.  
2. Free user cannot use Grok.  
3. Local tier cannot use Anthropic or Grok.  
4. Last provider + model persist across restart.  
5. Cloud queries (Claude or Grok) decrement the same quota.  
6. Config redaction still runs before any cloud relay.  
7. Automated tests cover migration, tier gates, and routing.
