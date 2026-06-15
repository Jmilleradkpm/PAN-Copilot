<#
.SYNOPSIS
    Registers (or removes) the weekly ADKCyber PAN Copilot scheduled tasks.
.DESCRIPTION
    Creates two weekly Task Scheduler jobs under the \ADKCyber\ folder:

      1. "ADKCyber - PAN Issue Ingest"
         Runs Run-IssueIngest.ps1 (incremental, base Addressed-Issues pages, parser
         only, no API key). Keeps known_issues.db current as new maintenance releases
         ship. Add -IngestCrawl to also sweep -hN hotfix subpages each week.

      2. "ADKCyber - PAN Copilot Prompt Updater"
         Runs Run-PromptUpdater.ps1 -Mode review. Pulls new PAN advisories/discovery
         and STAGES proposed managed-block changes into pending/ for your approval.

    Both jobs are non-destructive. The ingest writes only the local DB. The prompt
    updater in review mode never edits the live prompt, it only stages to pending/.
    Neither touches firewall or Panorama configuration.

    Run once to install. Re-running updates the existing tasks. Use -Remove to delete.
    If registration is denied, re-run from an elevated PowerShell.
.PARAMETER IngestDay
    Day of week for the ingest job. Default Sunday.
.PARAMETER IngestTime
    Time of day (HH:mm) for the ingest job. Default 02:00.
.PARAMETER PromptDay
    Day of week for the prompt updater job. Default Sunday.
.PARAMETER PromptTime
    Time of day (HH:mm) for the prompt updater job. Default 03:00.
.PARAMETER IngestCrawl
    Add -Crawl to the weekly ingest so hotfix (-hN) subpages are included.
.PARAMETER Remove
    Unregister both tasks instead of creating them.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Register-PanCopilotTasks.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Register-PanCopilotTasks.ps1 -IngestCrawl -IngestTime 01:30
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Register-PanCopilotTasks.ps1 -Remove
#>
param(
    [ValidateSet('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')]
    [string]$IngestDay = 'Sunday',
    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$IngestTime = '02:00',

    [ValidateSet('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')]
    [string]$PromptDay = 'Sunday',
    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$PromptTime = '03:00',

    [switch]$IngestCrawl,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$TaskPath      = '\ADKCyber\'
$IngestName    = 'ADKCyber - PAN Issue Ingest'
$PromptName    = 'ADKCyber - PAN Copilot Prompt Updater'
$IngestRunner  = Join-Path $ProjectRoot 'Run-IssueIngest.ps1'
$PromptRunner  = Join-Path $ProjectRoot 'Run-PromptUpdater.ps1'

# ----- removal path ---------------------------------------------------------
if ($Remove) {
    foreach ($name in @($IngestName, $PromptName)) {
        if (Get-ScheduledTask -TaskName $name -TaskPath $TaskPath -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $name -TaskPath $TaskPath -Confirm:$false
            Write-Output "Removed: $name"
        } else {
            Write-Output "Not found (skipped): $name"
        }
    }
    return
}

# ----- sanity checks --------------------------------------------------------
foreach ($runner in @($IngestRunner, $PromptRunner)) {
    if (-not (Test-Path $runner)) {
        throw "Runner not found: $runner. Run this script from the project folder."
    }
}

# Run as the current user, whether logged on or not, without storing a password.
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType S4U -RunLevel Limited

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -DontStopOnIdleEnd `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

function Register-PanTask {
    param(
        [string]$Name,
        [string]$Runner,
        [string[]]$RunnerArgs,
        [string]$Day,
        [string]$TimeOfDay
    )
    # powershell.exe -ExecutionPolicy Bypass -NoProfile -File <runner> [args]
    $argLine = "-ExecutionPolicy Bypass -NoProfile -File `"$Runner`""
    if ($RunnerArgs) { $argLine += ' ' + ($RunnerArgs -join ' ') }

    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument $argLine -WorkingDirectory $ProjectRoot
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Day -At (Get-Date $TimeOfDay)

    Register-ScheduledTask -TaskName $Name -TaskPath $TaskPath `
        -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'ADKCyber PAN Copilot automation. Non-destructive.' -Force | Out-Null

    $info = Get-ScheduledTaskInfo -TaskName $Name -TaskPath $TaskPath
    Write-Output ("Registered: {0}  (next run: {1})" -f $Name, $info.NextRunTime)
}

# Weekly incremental ingest (base parser only; optional -Crawl for hotfix subpages).
$ingestArgs = @()
if ($IngestCrawl) { $ingestArgs += '-Crawl' }
Register-PanTask -Name $IngestName -Runner $IngestRunner -RunnerArgs $ingestArgs `
    -Day $IngestDay -TimeOfDay $IngestTime

# Weekly prompt updater in review mode (stages to pending/, never edits live prompt).
Register-PanTask -Name $PromptName -Runner $PromptRunner -RunnerArgs @('-Mode','review') `
    -Day $PromptDay -TimeOfDay $PromptTime

Write-Output ''
Write-Output 'Done. Inspect or run on demand:'
Write-Output ('  Get-ScheduledTask -TaskPath ''{0}''' -f $TaskPath)
Write-Output ('  Start-ScheduledTask -TaskName ''{0}'' -TaskPath ''{1}''' -f $IngestName, $TaskPath)
Write-Output 'Remove both with: .\Register-PanCopilotTasks.ps1 -Remove'
