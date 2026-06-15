<#
.SYNOPSIS
    One-shot or scheduled runner for the PAN known-issues release-notes ingest (ADKCyber).
.DESCRIPTION
    Activates the local virtual environment and runs release_notes_ingest.py to load
    PAN-OS Addressed Issues into known_issues.db. Logs a timestamped line with the exit
    code for Task Scheduler history.

    Default run is incremental (new releases only) using the base Addressed-Issues
    pages and the table parser only. No crawl, no LLM, no API key required. Crawl and
    LLM assist are opt-in. Use -Full for the one-time retroactive backfill of all history.
.PARAMETER Full
    Ingest every release in release_notes_sources.json (adds --backfill). Use once.
.PARAMETER Force
    Re-ingest releases already recorded in ingest_state.json (adds --force).
.PARAMETER Crawl
    Also expand each release into its -hN hotfix subpages (adds --crawl).
.PARAMETER LlmAssist
    Fall back to Claude for pages the heuristic cannot parse (adds --llm-assist).
    Requires a valid ANTHROPIC_API_KEY in .env.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Run-IssueIngest.ps1 -Full
    # One-time full base backfill across all trains (parser only, no key needed).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Run-IssueIngest.ps1
    # Weekly incremental base catch-up of new releases.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Run-IssueIngest.ps1 -Full -Crawl -LlmAssist
    # Deepest backfill: base pages + hotfix subpages, with Claude fallback (needs API key).
#>
param(
    [switch]$Full,
    [switch]$Force,
    [switch]$Crawl,
    [switch]$LlmAssist
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    $python = 'python'  # fall back to PATH if no venv
}

$argList = @('release_notes_ingest.py')
if ($Full)      { $argList += '--backfill' }
if ($Crawl)     { $argList += '--crawl' }
if ($LlmAssist) { $argList += '--llm-assist' }
if ($Force)     { $argList += '--force' }

$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Output "[$stamp] Starting PAN known-issues ingest (full=$($Full.IsPresent), crawl=$($Crawl.IsPresent), llmAssist=$($LlmAssist.IsPresent))"

& $python @argList
$code = $LASTEXITCODE

$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Output "[$stamp] Ingest finished with exit code $code"
exit $code
