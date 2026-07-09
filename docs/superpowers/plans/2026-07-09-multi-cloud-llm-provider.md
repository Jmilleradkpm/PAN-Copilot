# Multi-cloud LLM Provider Implementation Plan

> **For agentic workers:** Execute task-by-task. Spec: `docs/superpowers/specs/2026-07-09-multi-cloud-llm-provider-design.md`

**Goal:** Let Pro/Max/Owner choose Anthropic (Claude), Grok 4.5/4.3, or Local LLM via provider-then-model UI; free stays Haiku; Grok is ADK-hosted via proxy.

**Architecture:** `chat_provider` becomes `anthropic|grok|local`. Anthropic uses existing `/v1/messages`. Grok uses new proxy `/v1/chat/completions` + desktop `CloudOpenAiClient`. Settings persist last used.

**Tech Stack:** .NET 8, Cloudflare Workers (TS), xAI OpenAI-compatible API

## Global Constraints

- Grok: pro/max/owner only; ADK session token + org XAI_API_KEY
- Free: Anthropic Haiku only
- Local tier: local only
- Migrate legacy `cloud` → `anthropic`
- Same query quota for Claude and Grok
- On-device redaction unchanged

---

### Task 1: Settings + provider resolution
### Task 2: CloudOpenAiClient + ChatService dispatch
### Task 3: ApiRouter settings API
### Task 4: Frontend provider-then-model UI
### Task 5: Proxy Grok route + model allowlist
### Task 6: Unit tests + build verify
