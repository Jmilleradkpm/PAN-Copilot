# PAN Copilot Prompt Updater

A scheduled loop that keeps the PAN Copilot master system prompt current with new
Palo Alto Networks information, and with PAN information judged useful to an end
user of the application.

## How the loop works

Each run executes these stages:

1. **Fetch** items from the sources in `sources.json` (PAN PSIRT advisory RSS by
   default, plus anything you add).
2. **Dedup** against a seen list so each item is processed once.
3. **Judge** each new item with Claude. The judge returns a structured verdict:
   include or not, a 1 to 5 usefulness score, a category, and a distilled entry.
4. **Store** accepted items as structured entries in `knowledge_store.json`. This
   store is the single source of truth.
5. **Age and budget**. Non evergreen entries (CVEs, version notes) expire after
   `ADVISORY_TTL_DAYS`. The rendered block is capped at `MAX_KNOWLEDGE_CHARS`,
   evicting lowest priority entries first.
6. **Render and write** a single AUTO-MANAGED block back into the prompt.

The managed block is always a deterministic render of the store, so the prompt
and the store never drift apart.

## Safety model

* **Markers protect your prompt.** The loop only edits text between
  `BEGIN ADKCYBER AUTO-MANAGED PAN KNOWLEDGE` and the matching END marker. Your
  hand authored persona and core instructions are never touched.
* **Fetched content is untrusted.** Because the output feeds a system prompt, a
  prompt injection planted in an advisory or blog post could otherwise propagate
  into PAN Copilot. The judge prompt treats fetched text as data only, the stored
  entries are constrained to short factual statements, and a sanitizer strips role
  markers and instruction like lines before anything is written.
* **Review by default.** `--mode review` stages proposed changes in `pending/`
  for you to approve. Switch to `--mode autonomous` only once you trust the feed
  set and the judge behavior.
* **Versioned backups.** Every applied change snapshots the prior prompt into
  `backups/` with a timestamp.

## Setup (Windows)

```powershell
cd C:\path\to\pan-copilot-updater
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
notepad .env   # set ANTHROPIC_API_KEY and PROMPT_FILE
```

Point `PROMPT_FILE` at your real PAN Copilot prompt. If it does not yet contain
the managed markers, insert them once:

```powershell
python pan_copilot_prompt_updater.py --bootstrap
```

This appends an empty managed block at the end of the file. Move the two marker
lines to wherever you want managed content to live, then run normally.

## Usage

```powershell
# Default: stage changes for review, nothing applied to the live prompt
python pan_copilot_prompt_updater.py --mode review

# See what it would do without writing anything to pending or the prompt
python pan_copilot_prompt_updater.py --dry-run

# Apply directly (use only after you trust the pipeline)
python pan_copilot_prompt_updater.py --mode autonomous
```

In review mode, inspect the file in `pending/`, then copy it over your prompt to
apply. The `knowledge_store.json` is updated either way so items are not
re-judged.

## Scheduling

Run weekly with Task Scheduler using the included PowerShell runner:

```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument '-ExecutionPolicy Bypass -File "C:\path\to\pan-copilot-updater\Run-PromptUpdater.ps1" -Mode review' `
  -WorkingDirectory 'C:\path\to\pan-copilot-updater'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
Register-ScheduledTask -TaskName 'PAN Copilot Prompt Updater' `
  -Action $action -Trigger $trigger -Description 'Refresh PAN Copilot prompt from PAN sources'
```

## Adding sources

Edit `sources.json`. Each entry needs a `name`, `type` (`rss` for now), `url`,
and a `category_hint`. Confirm every feed URL against the vendor before trusting
it. Good candidates to add: PAN-OS release notes, Prisma Access release notes,
Cortex XSIAM release notes, and Unit 42 threat research.

## Files

| File | Purpose |
|------|---------|
| `pan_copilot_prompt_updater.py` | The loop |
| `sources.json` | Feed definitions |
| `knowledge_store.json` | Source of truth (created on first run) |
| `pan_copilot_system_prompt.md` | Sample prompt with markers (replace with yours) |
| `Run-PromptUpdater.ps1` | Task Scheduler runner |
| `backups/`, `pending/` | Snapshots and staged proposals |

## Environment variables

See `.env.example`. Key knobs: `UPDATE_MODE`, `USEFULNESS_THRESHOLD`,
`ADVISORY_TTL_DAYS`, `MAX_KNOWLEDGE_CHARS`, `JUDGE_MODEL`, `SYNTH_MODEL`.

---

## Web and x.com discovery (added)

The loop now runs a discovery sweep each run, on top of the RSS sources, using the
Anthropic `web_search` server tool:

* **Web sweep:** critical or important recent PAN items (actively exploited CVEs,
  urgent advisories, new release versions with security fixes) from vendor docs,
  NVD, CISA KEV, and security press.
* **x.com sweep:** the same search restricted to `x.com` / `twitter.com` via the
  tool's `allowed_domains`, biased toward vendor and known researcher accounts.

Discovered items flow through the same judge, sanitizer, dedup, and budget pipeline
as RSS items, so the injection hardening still applies (this matters because x.com
and blog content is untrusted and the output feeds a system prompt). Items the scout
marks `critical` or `high` bypass the usefulness floor and render into a
**Critical alerts (act first)** section at the top of the managed block.

Toggle with `ENABLE_DISCOVERY` in `.env` or `--no-discovery` per run. Tune with
`DISCOVERY_DAYS`, `DISCOVERY_MAX_SEARCHES`, and `X_ALLOWED_DOMAINS`.

If you have a paid X API bearer token and want native X v2 recent-search instead of
web-scoped search, that is a clean drop-in to add to `WebDiscovery`.

## Why release-notes bugs are NOT in the system prompt

You asked for retroactive release-notes bugs to be available so PAN Copilot can ask
a user's version and check for a known bug. That corpus is thousands of "Addressed
Issues" rows across every PAN-OS train. It cannot live in a system prompt (size), and
it should not (you want indexed lookup, not a wall of text).

So this is two tiers:

* **`known_issues.db` (SQLite):** the retroactive bug corpus. PAN Copilot queries it
  at runtime by version and symptom.
* **The system prompt** holds only the **procedure** for using it (rendered into the
  managed block as "Operating procedure: known-issue and version lookup"): ask the
  user's version, call the lookup, report the fix or offer a report.

### Lookup logic

A defect fixed in version F of a train is assumed present in all earlier
maintenance/hotfix releases of that same train. So a user on 11.1.2 matches a bug
fixed in 11.1.4, but a user already on 11.1.5 does not. Cross-train inference is not
made, because PAN tracks fixes per train.

Query it directly:

```powershell
python known_issues_db.py --version 11.1.2 --query "globalprotect tunnel drops"
python known_issues_db.py --stats
```

Wire `known_issues_db.KnownIssuesDB.search(version, query)` as a tool in PAN Copilot's
backend so the model can call it during a conversation.

## Building the retroactive bug corpus

1. Put the release-notes "Addressed Issues" URLs you care about into
   `release_notes_sources.json` (one entry per maintenance release). Confirm each URL
   on docs.paloaltonetworks.com.
2. Backfill:

   ```powershell
   python release_notes_ingest.py --backfill --llm-assist
   ```

   `--llm-assist` uses Claude to parse pages the table heuristic cannot. Run it once
   for history; after that the weekly loop only needs new releases (drop `--backfill`).

PAN docs HTML changes over time, so expect to tune `extract_rows_heuristic` or lean on
`--llm-assist` for older pages.

## Notifying Palo Alto Networks (honest version)

Two cases, handled differently:

* **Known bug match:** there is nothing to report. The fix exists. PAN Copilot tells
  the user the issue ID and the version that fixes it, and recommends upgrading.
* **No match, looks like a real defect:** `suspected_bug_report.py` drafts a structured,
  secret-redacted report and stages it in `pending/reports/` for your review.

There is no open PAN API to auto-file defects. Reports go through a TAC case in the
Customer Support Portal, which needs a support entitlement. So submission is a gated,
review-first hook (`PanCaseNotifier`), **disabled by default** (`ENABLE_PAN_CASE_SUBMISSION=false`),
and dry-run even when enabled. Wire your own CSP/TAC case API there with per-case
approval before turning it on. ⚠️ Never auto-file to a vendor without a human in the loop.

```powershell
python suspected_bug_report.py --version 11.1.6 --issue "GP tunnel drops after failover" --check "ruled out MTU"
```

## New files

| File | Purpose |
|------|---------|
| `known_issues_db.py` | SQLite bug corpus + version-aware lookup (runtime tool) |
| `release_notes_ingest.py` | Retroactive + incremental Addressed-Issues ingester |
| `release_notes_sources.json` | Release-notes URLs to ingest |
| `suspected_bug_report.py` | Report draft generator + gated PAN submission stub |

---

## What is pre-built for you (June 2026)

I did the two setup steps so the new pieces work immediately:

* **`release_notes_sources.json`** is populated with verified Addressed-Issues URLs for
  all four live PAN-OS trains: 12.1 (through 12.1.7), 11.2 (through 11.2.11), 11.1
  (through 11.1.13), and 10.2 (through 10.2.18). 53 base maintenance releases. Note
  that 12.1 lives under a different path (`/ngfw/release-notes/12-1/`); that is handled.
* **`known_issues.db`** is pre-seeded with 32 real addressed issues pulled from the
  11.1.13, 11.2.11, and 10.2.16 release notes (descriptions condensed into ADKCyber
  wording, issue IDs and source URLs preserved). The version lookup works out of the box:

  ```powershell
  python known_issues_db.py --version 11.1.12 --query "dataplane reboot after commit"
  python known_issues_db.py --version 11.2.5  --query "globalprotect portal FIPS"
  ```

This is a representative seed, not the full history. Run the full backfill on your box,
which reaches docs.paloaltonetworks.com and uses your API key:

```powershell
python release_notes_ingest.py --backfill --crawl --llm-assist
```

`--crawl` expands each release into its base and every `-hN` hotfix Addressed-Issues
subpage automatically, so you do not hand-list hotfixes. `--llm-assist` falls back to
Claude on any page the table heuristic cannot parse. After the one-time backfill, the
weekly job only needs new releases (drop `--backfill`).

## Known-issues HTTP API (FastAPI)

`api_known_issues.py` exposes the lookup so PAN Copilot can call it over HTTP during a
conversation.

```powershell
uvicorn api_known_issues:app --host 0.0.0.0 --port 8088
```

Endpoints:

* `POST /lookup` body `{ "version": "11.1.2", "query": "tunnel drops", "limit": 15 }`
* `GET /health`, `GET /stats`
* `GET /tool-schema` returns the Anthropic tool definition, ready to drop into PAN
  Copilot's `tools` array. The model fills `version` and `query`, your backend posts to
  `/lookup`, and the result goes back as the tool result.

## Native X (Twitter) API search

The x.com sweep defaults to web-scoped search (no token needed). If you have X API v2
access, set these in `.env` to use native recent search instead:

```
X_API_MODE=native
X_BEARER_TOKEN=your_v2_bearer_token
```

Tune the query with `X_SEARCH_QUERY` and the result count with `X_MAX_TWEETS`. If the
native call returns nothing or fails, the loop falls back to the web-scoped X sweep
automatically, so discovery never goes dark.

## New files (this round)

| File | Purpose |
|------|---------|
| `known_issues.db` | Pre-seeded bug corpus (32 real issues across 3 trains) |
| `seed_known_issues.py` | Loads the real seed rows into the DB |
| `api_known_issues.py` | FastAPI lookup service + Anthropic tool schema |
| `release_notes_sources.json` | Verified Addressed-Issues URLs for all four live trains |
