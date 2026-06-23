param(
    [string]$PublishDir = (Join-Path $PSScriptRoot '..\publish'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\ADK_Cyber_AI_Store.msix')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$publishDir = (Resolve-Path $PublishDir).Path
$exe = Join-Path $publishDir 'PAN Copilot.exe'
if (-not (Test-Path $exe)) { throw "Publish output missing: $exe. Run dotnet publish first." }

& (Join-Path $PSScriptRoot 'Sync-ManifestIdentity.ps1')

$staging = Join-Path $env:TEMP ("adk_msix_staging_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $staging | Out-Null
try {
    Write-Host "Staging MSIX payload from $publishDir"
    robocopy $publishDir $staging /E /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }

    Copy-Item (Join-Path $PSScriptRoot 'Package.appxmanifest') (Join-Path $staging 'AppxManifest.xml') -Force
    Copy-Item (Join-Path $PSScriptRoot 'Images') (Join-Path $staging 'Images') -Recurse -Force

    $makeAppx = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter makeappx.exe -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $makeAppx) { throw "makeappx.exe not found. Install Windows 10/11 SDK." }

    if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }
    & $makeAppx.FullName pack /d $staging /p $OutputPath /o /l
    if ($LASTEXITCODE -ne 0) { throw "makeappx pack failed with exit code $LASTEXITCODE" }

    $sizeMb = (Get-Item $OutputPath).Length / 1MB
    Write-Host "Built $OutputPath ($([math]::Round($sizeMb, 1)) MB)"
}
finally {
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue }
}