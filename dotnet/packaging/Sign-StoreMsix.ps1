param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $PackagePath)) { throw "Package not found: $PackagePath" }

$props = Join-Path $PSScriptRoot 'PartnerCenter.Identity.props'
if (-not (Test-Path $props)) { throw "Missing $props" }
[xml]$propsXml = Get-Content $props
$publisher = $propsXml.Project.PropertyGroup.PackageIdentityPublisher
if (-not $publisher) { throw 'PartnerCenter.Identity.props must define PackageIdentityPublisher' }

$signtool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $signtool) { throw 'signtool.exe not found. Install Windows 10/11 SDK.' }

$certDir = Join-Path $env:TEMP 'adk_store_sign'
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
$pfxPath = Join-Path $certDir 'store-upload.pfx'
$pwd = 'AdkStoreMsixSign!'
$securePwd = ConvertTo-SecureString -String $pwd -Force -AsPlainText

$existing = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $publisher } |
    Select-Object -First 1

if ($existing) {
    $cert = $existing
}
else {
    $cert = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $publisher `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
}

if (Test-Path $pfxPath) { Remove-Item $pfxPath -Force }
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePwd | Out-Null

& $signtool.FullName sign /fd SHA256 /f $pfxPath /p $pwd $PackagePath
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed with exit code $LASTEXITCODE" }

Write-Host "Signed $PackagePath with publisher $publisher"