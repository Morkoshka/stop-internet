<#
.SYNOPSIS
Builds the installer: target\installer\stop-internet-<version>-setup.exe.

.DESCRIPTION
Builds the release programs with cargo, writes the icon of Setup to
target\icon\stop-internet.ico, then compiles installer\stop-internet.iss with
Inno Setup 6.4 or later. The version comes from Cargo.toml.

It writes only into target\ and changes nothing on the system. ISCC.exe is
taken from PATH, from $env:ISCC or from the usual install folders of
Inno Setup 6 (winget installs it for the user or for the machine).

.PARAMETER SkipBuild
Use the programs already in target\release, for example in CI after
`cargo build --release`.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build-installer.ps1

Windows blocks scripts by default; Bypass lifts that for this run only.
#>
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Find-Iscc {
    if ($env:ISCC) {
        if (Test-Path -LiteralPath $env:ISCC) { return $env:ISCC }
        throw "ISCC is set to '$env:ISCC', but there is no such file."
    }
    $onPath = Get-Command 'ISCC.exe' -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw 'Inno Setup 6 not found. Install it (winget install --id JRSoftware.InnoSetup -e) or set $env:ISCC to ISCC.exe.'
}

Push-Location $root
try {
    if (-not $SkipBuild) {
        cargo build --workspace --release
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
    }
    $metadata = cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed.' }
    $version = ($metadata.packages | Where-Object { $_.name -eq 'stopinet-cli' }).version
    if (-not $version) { throw 'No version of stopinet-cli in cargo metadata.' }

    # The icon of Setup, where installer\stop-internet.iss expects it.
    New-Item -ItemType Directory -Force -Path 'target\icon' | Out-Null
    cargo run --quiet --release -p stopinet-icon --example ico -- 'target\icon\stop-internet.ico'
    if ($LASTEXITCODE -ne 0) { throw 'Writing the icon failed.' }

    $iscc = Find-Iscc
    & $iscc /Q "/DAppVersion=$version" 'installer\stop-internet.iss'
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE." }
    Write-Host "Built target\installer\stop-internet-$version-setup.exe"
}
finally {
    Pop-Location
}
