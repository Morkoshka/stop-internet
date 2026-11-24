<#
.SYNOPSIS
Prints the text of a GitHub release, made from the changelogs.

.DESCRIPTION
Takes the section of the version from CHANGELOG.md and CHANGELOG.ru.md and
puts both into the template .github/release-notes.md. Stops with an error
if a changelog has no section "## <version>" or it is empty. Reads files
only; -Out writes the text to a file (UTF-8) instead of printing it.

The Release workflow runs it before it builds anything, so a missing
section stops the release early.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-notes.ps1 -Version 0.1.0
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,
    [string]$Out
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$utf8 = New-Object System.Text.UTF8Encoding($false)

# The lines after "## <version>" up to the next "## ", trimmed.
function Get-Section([string]$File) {
    $lines = [IO.File]::ReadAllLines((Join-Path $root $File), $utf8)
    $heading = '^## ' + [regex]::Escape($Version) + '(\s|$)'
    $start = -1
    $end = $lines.Count
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($start -lt 0) {
            if ($lines[$i] -match $heading) { $start = $i + 1 }
        }
        elseif ($lines[$i] -match '^## ') {
            $end = $i
            break
        }
    }
    if ($start -lt 0) { throw "$File has no section ""## $Version""." }
    $text = if ($end -gt $start) { ($lines[$start..($end - 1)] -join "`n").Trim() } else { '' }
    if (-not $text) { throw "The section ""## $Version"" of $File is empty." }
    $text
}

$template = [IO.File]::ReadAllText((Join-Path $root '.github\release-notes.md'), $utf8)
$notes = $template.Replace("`r`n", "`n")
$notes = $notes.Replace('{{changes}}', (Get-Section 'CHANGELOG.md'))
$notes = $notes.Replace('{{changes.ru}}', (Get-Section 'CHANGELOG.ru.md'))
$notes = $notes.Replace('{{version}}', $Version)

if ($Out) {
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Out)
    [IO.File]::WriteAllText($path, $notes, $utf8)
} else {
    $notes
}
