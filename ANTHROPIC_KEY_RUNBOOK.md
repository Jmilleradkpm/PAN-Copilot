# Anthropic API Key — Spend Cap, Alerts & Rotation Runbook

**Owner action required.** Every step here happens in the **Anthropic Console**
(<https://console.anthropic.com>) and the **Render dashboard**
(<https://dashboard.render.com>). Both need your login — they can't be automated
from this repo.

> UI labels below are approximate and may have moved since this was written.
> Look for the described *function* (e.g. "spend limit") rather than an exact
> menu name.

---

## Why this exists (the risk it controls)

The license server (`license_server/app.py`, deployed on Render) holds ADK's
single Anthropic key and **hands a copy to every signed-in client**, which then
calls `api.anthropic.com` directly. That copy is recoverable by the client, so a
determined user can extract the key and call Anthropic **outside** the license
server's per-user quota (`/query/check`).

We are **not** trying to make the key un-extractable (that would require proxying
chat through Render and giving up the "your config never touches our servers"
promise). Instead we **bound the damage** at the Anthropic billing layer — a
control the extracted key *cannot* bypass:

| Control | What it buys you |
|---|---|
| Hard spend cap | A leaked key can't run the bill past a fixed ceiling. |
| Budget alerts | You hear about abuse early, not on the invoice. |
| Key rotation | Rotating + revoking instantly kills every extracted copy. |
| Usage monitoring | Lets you spot abuse and decide when to rotate. |

**Residual risk you are accepting:** a single abuser can still burn the whole
monthly cap and deny service to paying users until you rotate. Keep the cap sane,
watch usage, rotate on suspicion.

---

## 1. One-time setup

### 1a. Set a hard monthly spend cap

1. Anthropic Console → **Settings / Organization → Billing → Usage limits**
   (a.k.a. "Spend limit" / "Monthly budget").
2. Set a **hard monthly limit**. Sizing guide — don't guess, estimate:

   ```
   expected_monthly = (paying_users × their_monthly_query_allotment × avg_$_per_query)
                    +  (free_users  × 10 queries/week × ~4.3 weeks × avg_$_per_query)
   cap = expected_monthly × 1.5 to 2     # headroom for legit spikes, but still
                                         # well below "runaway" territory
   ```
   - Pull `avg_$_per_query` from the last month's Console **Usage/Cost** view
     (total cost ÷ total requests).
   - Tiers for the math: Free = 10/week, Pro = 1,000/month, Max = 2,500/month
     (see `CLAUDE.md`).
   - When in doubt, start **low** — you can always raise it; you can't un-spend.
3. Save.

### 1b. Turn on budget alerts

1. Same Billing area → **Alerts / Notifications**.
2. Add threshold alerts at e.g. **50%, 80%, 100%** of the cap, emailed to
   `jmiller@adkcyber.com`.
3. (Optional) A low daily-spend alert catches a key being hammered before it
   eats the whole month.

---

## 2. Routine: rotate the Anthropic key

Do this on a **cadence** (see §4) and **immediately** on any suspected leak.

> **Timing:** rotate during a low-usage window. Clients currently signed in
> cache the old key for the life of their session; after you revoke it they get
> Anthropic auth errors until they **restart the app / sign in again**, at which
> point the license server hands them the new key automatically.

1. **Create** the replacement key
   Anthropic Console → **API Keys → Create Key**. Name it with the date, e.g.
   `pan-copilot-2026-05`. Copy the value once.
2. **Update Render** (this is the only place the key is configured)
   Render → service **pan-copilot** → **Environment** → edit `ANTHROPIC_API_KEY`
   → paste the new value → **Save** (Render redeploys automatically).
   - Verify the deploy goes green and `GET https://pan-copilot.onrender.com/health`
     returns `{"status":"ok",...}`.
   - Smoke-test: sign in from the desktop app and send one chat.
3. **Revoke** the old key
   Back in Anthropic Console → API Keys → **delete/disable the previous key**.
   This is the step that actually kills every extracted copy — don't skip it.
4. Note the rotation date below.

> Same Render-env pattern applies to the other server secrets if you ever rotate
> them: `SECRET_PEPPER`, `LS_WEBHOOK_SECRET`, `ADMIN_TOKEN`.

---

## 3. Monitoring — what to watch

- **Anthropic Console → Usage/Cost**, ~weekly. Red flags:
  - Spend climbing toward the cap mid-month.
  - Request volume that doesn't match your active-user count × their quota
    (the gap is roughly the extracted-key traffic).
- Reconcile against the license server's own counters if you add usage
  reporting later. A large, persistent gap between "Anthropic requests" and
  "license-server `/query/check` calls" is the signal that a key is in the wild.

---

## 4. Cadence

- **Spend cap + alerts:** set once (§1), review the cap each quarter as user
  counts change.
- **Rotation:** quarterly as routine, **and** immediately if an alert fires or
  usage looks abnormal.

---

## 5. Incident: suspected key abuse

1. **Lower the spend cap** right now (§1a) to stop the bleeding.
2. **Rotate + revoke** the key (§2) — this invalidates the leaked copy.
3. Review Console usage to gauge how much was abused.
4. If abuse recurs after rotation, the leaked-key model has been
   weaponized repeatedly — that's the trigger to revisit **Option B** (proxy
   chat through the Render license server so the key is never handed out). See
   the security review notes / the `security-medium-fixes` work for context.

---

## Rotation log

| Date | Rotated by | Reason |
|---|---|---|
| _(fill in at first rotation)_ | | |
