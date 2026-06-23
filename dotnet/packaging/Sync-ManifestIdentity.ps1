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

[xml]$doc = Get-Content $manifest
$ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
$ns.AddNamespace('m', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
$identity = $doc.SelectSingleNode('//m:Identity', $ns)
if (-not $identity) { throw 'Identity element not found in Package.appxmanifest' }

$identity.SetAttribute('Name', $name)
$identity.SetAttribute('Publisher', $publisher)
$identity.SetAttribute('Version', $appxVersion)

$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$settings = New-Object System.Xml.XmlWriterSettings
$settings.Encoding = $utf8NoBom
$settings.Indent = $true
$settings.OmitXmlDeclaration = $false
$writer = [System.Xml.XmlWriter]::Create($manifest, $settings)
$doc.Save($writer)
$writer.Close()

Write-Host "Synced manifest identity: $name @ $appxVersion"