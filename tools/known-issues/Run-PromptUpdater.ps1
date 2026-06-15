<#
.SYNOPSIS
    Scheduled runner for the PAN Copilot system prompt updater (ADKCyber).
.DESCRIPTION
    Activates the local virtual environment, runs the updater, and writes a
    timestamped log line with the exit code for Task Scheduler history.
.PARAMETER Mode
    'review' (default) stages changes for approval. 'autonomous' applies directly.
.PARAMETER DryRun
    Compute and stage changes without applying, regardless of mode.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Run-PromptUpdater.ps1 -Mode review
#>
param(
    [ValidateSet('review','autonomous')]
    [string]$Mode = 'review',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    $python = 'python'  # fall back to PATH if no venv
}

$argList = @('pan_copilot_prompt_updater.py', '--mode', $Mode)
if ($DryRun) { $argList += '--dry-run' }

$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Output "[$stamp] Starting PAN Copilot updater (mode=$Mode, dryRun=$($DryRun.IsPresent))"

& $python @argList
$code = $LASTEXITCODE

$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Output "[$stamp] Updater finished with exit code $code"
exit $code
