# Local Tier ($5/mo) — Setup Checklist

The code for the Local-LLM tier is shipped and working as of `05c6545` + the
license-server change in this PR. This doc lists the things only you can do —
Stripe configuration, GitHub Secrets, marketing site copy — to actually
launch the tier to paying customers.

---

## 1. Generate the prompt-encryption key

The CI build expects a 32-byte AES key in a GitHub Secret. Run locally once:

```powershell
python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Copy the output (ends in `=`) and add as a new repo secret:

- Settings → Secrets and variables → Actions → New repository secret
- Name: `PAN_COPILOT_PROMPT_AES_KEY`
- Value: the base64 string from above

**Once you set this, every future build will encrypt the prompts.** Builds
made before this secret is set will fail at the "Encrypt prompts" step
(intentionally — fails loud rather than shipping plaintext).

---

## 2. Local-variant system prompt

The build pipeline reads a second GitHub Secret:

- Name: `PAN_COPILOT_SYSTEM_PROMPT_LOCAL`
- Value: the full text of `PAN_Copilot_Master_System_Prompt_Local.md`

The current draft is a ~5 KB compression of the cloud prompt — review/edit
the file in this repo, then paste the final content into the secret.

If you leave the secret empty, CI falls back to using the cloud prompt for
the local variant too (with a warning in the build log) — useful while you
finalize the local content.

---

## 3. Lemon Squeezy product

> NOTE: Billing is **Lemon Squeezy**, not Stripe. The webhook in
> `license_server/app.py` (`/webhook/lemonsqueezy`) assigns the tier by
> matching the word `local`/`pro`/`max` in the variant or product name,
> falling back to the `LS_VARIANT_TIER` variant-id map.

Create a new product/variant in the Lemon Squeezy dashboard:

- Product name: **PAN Copilot — Local Tier** (the word "local" in the
  product or variant name is what the webhook keys off — keep it there)
- Price: **$5.00 USD / month**
- Description: "Run PAN Copilot against your own local LLM (Ollama,
  LM Studio, etc.). Queries and configs stay on your machine. No cloud
  AI included — best for security-conscious environments."

For belt-and-suspenders, also add the new variant's UUID to
`LS_VARIANT_TIER` in `license_server/app.py` mapped to `"local"`, so the
tier resolves correctly even if the product name is ever edited.

---

## 4. Lemon Squeezy webhook  ✅ DONE (code)

The `/webhook/lemonsqueezy` handler now recognizes the local tier — a
`local` branch was added alongside `pro`/`max`:

```python
elif "local" in variant_name or "local" in product_name:
    tier = "local"
```

The DB schema already accepts `local` as a valid tier (`VALID_TIERS`).
No migration needed. Remaining work here is only the dashboard product
(section 3) and deploying the updated license server to Render.

---

## 5. Marketing site (adkcyber-site)

`pan-copilot.html` pricing section — add a new tier card between Free and Pro:

```
LOCAL  — $5/mo
  • Bring your own LLM (Ollama, LM Studio, etc.)
  • All chat stays on your machine
  • No cloud AI quota
  • Built for security-conscious environments
  • Best-effort responses (cloud is the supported experience)
```

ToS update — add a clause:

> Local-tier subscribers receive a copy of the PAN Copilot system prompt
> for use with their local LLM. Redistribution, public posting, or
> commercial reuse of the system prompt is prohibited.

---

## 6. Smoke test before launch

1. Manually flip a test user to `tier='local'` via the admin endpoint:

   ```bash
   curl -X POST https://pan-copilot.onrender.com/admin/set-tier \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"email":"you@adkcyber.com","tier":"local"}'
   ```

2. Log in to the app with that user. Verify:
   - Tier badge shows "⚙ Local · runs on your machine"
   - Chat Provider sidebar panel: cloud radio is greyed out with the
     upgrade-to-Pro lock banner
   - Mode pill near the model picker reads "LOCAL · qwen2.5:14b" (or
     whatever model you set)
   - A chat round-trip works against your local Ollama (run
     `ollama serve` first)

3. Flip the user back to `pro` and confirm cloud mode is selectable again.

---

## Architecture references (for future you)

| Concern | File | Key symbols |
|---|---|---|
| Encryption at rest | `local/app.py` | `_load_prompt_aes_key`, `_decrypt_prompt_file`, `load_system_prompt(variant)` |
| Provider dispatch  | `local/app.py` | `_effective_provider`, `_stream_anthropic`, `_stream_openai_compat` |
| Settings storage   | `local/app.py` | `SETTINGS_FILE`, `load_settings`, `save_settings` |
| Endpoints          | `local/app.py` | `/api/settings`, `/api/local_llm/test` |
| Hard-lock          | `local/app.py` | `update_settings` 403 + `_effective_provider` |
| License tier       | `license_server/app.py` | `VALID_TIERS`, `TIER_LIMITS`, `usage_response`, `/query/check` |
| Frontend UI        | `local/pan_copilot_desktop.html` | `#provider-section`, `loadProviderSettings`, `renderProviderUI` |
| CI encryption      | `.github/workflows/build-release.yml` | "Encrypt prompts" step |

---

## Honest threat-model note (paste into ToS or FAQ)

The system prompt is AES-256-GCM encrypted in the exe so casual extraction
(`7z x PAN_Copilot.exe`, `strings PAN_Copilot.exe`) won't reveal it. A
motivated reverse-engineer with Ghidra + the binary can still recover the
AES key. In Local mode, the prompt is transmitted in plaintext to the
user's own local LLM endpoint — that's an unavoidable architectural
property of how LLMs work. Protection in that case is contractual (ToS),
not technical.

If you ever decide the in-flight exposure is unacceptable, the path forward
is to deliver the AES key from the license server at login time instead of
shipping it in the binary, at the cost of breaking the "totally local
after activation" narrative (one network call required to start chatting).
