param(
    [string]$PublishDir = (Join-Path $PSScriptRoot '..\publish'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\ADK_Cyber_AI_Store.msix'),
    [switch]$SkipSign
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$publishDir = (Resolve-Path $PublishDir).Path
$srcExe = Join-Path $publishDir 'PAN Copilot.exe'
if (-not (Test-Path $srcExe)) { throw "Publish output missing: $srcExe. Run dotnet publish first." }

& (Join-Path $PSScriptRoot 'Sync-ManifestIdentity.ps1')

$staging = Join-Path $env:TEMP ("adk_msix_staging_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $staging | Out-Null
try {
    Write-Host "Staging MSIX payload from $publishDir"
    robocopy $publishDir $staging /E /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }

    Get-ChildItem $staging -Filter '*.pdb' -Recurse -File | Remove-Item -Force
    Get-ChildItem $staging -Filter '*.pdb' -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        throw "Failed to remove debug symbol: $($_.FullName)"
    }

    $storeExe = Join-Path $staging 'ADKCyberAI.exe'
    Copy-Item $srcExe $storeExe -Force
    Remove-Item (Join-Path $staging 'PAN Copilot.exe') -Force -ErrorAction SilentlyContinue

    Copy-Item (Join-Path $PSScriptRoot 'Package.appxmanifest') (Join-Path $staging 'AppxManifest.xml') -Force
    Copy-Item (Join-Path $PSScriptRoot 'Images') (Join-Path $staging 'Images') -Recurse -Force

    if (-not (Test-Path $storeExe)) { throw "Store entrypoint missing after rename: $storeExe" }

    $sdkBin = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $makeAppx = Get-ChildItem -Path $sdkBin -Recurse -Filter makeappx.exe -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $makeAppx) { throw "makeappx.exe not found. Install Windows 10/11 SDK." }

    $makePri = Get-ChildItem -Path $sdkBin -Recurse -Filter makepri.exe -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $makePri) { throw "makepri.exe not found. Install Windows 10/11 SDK." }

    $manifestPath = Join-Path $staging 'AppxManifest.xml'
    $priConfig = Join-Path $staging 'priconfig.xml'
    $priOut = Join-Path $staging 'resources.pri'
    if (Test-Path $priOut) { Remove-Item $priOut -Force }

    & $makePri.FullName createconfig /cf $priConfig /dq en-US /o
    if ($LASTEXITCODE -ne 0) { throw "makepri createconfig failed with exit code $LASTEXITCODE" }

    & $makePri.FullName new /pr $staging /cf $priConfig /mn $manifestPath /of $priOut /o
    if ($LASTEXITCODE -ne 0) { throw "makepri new failed with exit code $LASTEXITCODE" }

    if (-not (Test-Path $priOut)) { throw "makepri did not produce resources.pri" }
    Remove-Item $priConfig -Force -ErrorAction SilentlyContinue
    Write-Host "Generated resources.pri ($((Get-Item $priOut).Length) bytes)"

    if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }
    & $makeAppx.FullName pack /d $staging /p $OutputPath /o
    if ($LASTEXITCODE -ne 0) { throw "makeappx pack failed with exit code $LASTEXITCODE" }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $pkg = [System.IO.Compression.ZipFile]::OpenRead($OutputPath)
    try {
        if (-not $pkg.GetEntry('resources.pri')) {
            throw "Packed MSIX is missing resources.pri — Partner Center will reject this package"
        }
    }
    finally {
        $pkg.Dispose()
    }

    if (-not $SkipSign) {
        & (Join-Path $PSScriptRoot 'Sign-StoreMsix.ps1') -PackagePath $OutputPath
    }

    $uploadPath = [System.IO.Path]::ChangeExtension($OutputPath, '.msixupload')
    if (Test-Path $uploadPath) { Remove-Item $uploadPath -Force }
    $uploadStaging = Join-Path $env:TEMP ("adk_msixupload_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $uploadStaging | Out-Null
    try {
        Copy-Item $OutputPath (Join-Path $uploadStaging (Split-Path $OutputPath -Leaf)) -Force
        $zipPath = "$uploadPath.zip"
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Compress-Archive -Path (Join-Path $uploadStaging '*') -DestinationPath $zipPath -CompressionLevel Optimal
        Move-Item $zipPath $uploadPath -Force
    }
    finally {
        if (Test-Path $uploadStaging) { Remove-Item $uploadStaging -Recurse -Force -ErrorAction SilentlyContinue }
    }

    $sizeMb = (Get-Item $OutputPath).Length / 1MB
    $uploadMb = (Get-Item $uploadPath).Length / 1MB
    Write-Host "Built $OutputPath ($([math]::Round($sizeMb, 1)) MB)"
    Write-Host "Built $uploadPath ($([math]::Round($uploadMb, 1)) MB) for Partner Center upload"
}
finally {
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue }
}