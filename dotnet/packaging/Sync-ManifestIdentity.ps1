# Sync Package.appxmanifest Identity from PartnerCenter.Identity.props and PanCopilot.csproj Version.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$manifest = Join-Path $here 'Package.appxmanifest'
$props = Join-Path $here 'PartnerCenter.Identity.props'
$csproj = Join-Path $here '..\PanCopilot.csproj'

if (-not (Test-Path $manifest)) { throw "Missing $manifest" }
if (-not (Test-Path $props)) { throw "Missing $props" }
if (-not (Test-Path $csproj)) { throw "Missing $csproj" }

[xml]$propsXml = Get-Content $props
$name = $propsXml.Project.PropertyGroup.PackageIdentityName
$publisher = $propsXml.Project.PropertyGroup.PackageIdentityPublisher
if (-not $name -or -not $publisher) { throw 'PartnerCenter.Identity.props must define PackageIdentityName and PackageIdentityPublisher' }

$versionLine = (Select-String -Path $csproj -Pattern '<Version>([^<]+)</Version>').Matches[0].Groups[1].Value
if ($versionLine -notmatch '^(\d+)\.(\d+)\.(\d+)$') { throw "Unexpected Version in csproj: $versionLine" }
$appxVersion = "$versionLine.0"

$content = Get-Content $manifest -Raw
$content = $content -replace 'Name="[^"]+"', "Name=`"$name`""
$content = $content -replace 'Publisher="[^"]+"', "Publisher=`"$publisher`""
$content = $content -replace 'Version="[^"]+"', "Version=`"$appxVersion`""
Set-Content -Path $manifest -Value $content -Encoding UTF8
Write-Host "Synced manifest identity: $name @ $appxVersion"