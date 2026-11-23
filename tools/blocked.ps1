<#
.SYNOPSIS
    Shows which programs had connections blocked, and by which filter,
    anonymized.

.DESCRIPTION
    Turns on auditing of blocked connections (event 5157, audit subcategory
    "Filtering Platform Connection") for a while. Repeat the action that
    fails during that time, for example a subscription update in the VPN
    client. Then the script turns auditing back to what it was and prints
    the blocked connections grouped by program, direction, protocol, remote
    address, port and the WFP filter that blocked them. Filters of
    stop-internet are named "stop-internet: ..."; everything else comes from
    Windows Firewall, Windows service hardening or other software.

    What changes: the audit setting of that one subcategory, only while the
    script runs. Its previous value is read first and set back at the end,
    also after Ctrl+C. Meanwhile blocked connections are written to the
    Security event log.

    Anonymization as in diag.ps1: public addresses become PUB-01, PUB-02, ...,
    the user name and the computer name become <user> and <pc>. Private,
    loopback and link-local addresses are kept.

    Run from an elevated PowerShell.

.PARAMETER Seconds
    How long to record, 10 to 600 seconds.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\blocked.ps1 -Seconds 60
#>
param(
    [ValidateRange(10, 600)]
    [int]$Seconds = 60
)

$ErrorActionPreference = 'Stop'

# "Filtering Platform Connection". The GUID works with any display language.
$subcategory = '{0CCE9226-69AE-11D9-BED3-505054503030}'
$provider = '{ee4512c1-ffd5-4cd3-bc99-c224a27d5988}'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Run this from an elevated PowerShell.'
    exit 1
}

$userRx = [regex]::Escape($env:USERNAME)
$pcRx = [regex]::Escape($env:COMPUTERNAME)
$publicLabels = @{}

function Hide-Text([string]$Text) {
    if (-not $Text) { return $Text }
    $Text -replace $userRx, '<user>' -replace $pcRx, '<pc>'
}

function Get-IpClass([string]$Ip) {
    $Ip = $Ip -replace '%\d+$', ''
    if (-not $Ip) { return '' }
    switch -Regex ($Ip) {
        '^(127\.|::1$)'                                { return 'loopback' }
        '^(0\.0\.0\.0|::)$'                            { return 'any' }
        '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' { return 'private' }
        '^(169\.254\.|fe80:)'                          { return 'link-local' }
        '^(f[cd]|fec0:)'                               { return 'local-v6' }
        '^(22[4-9]\.|23\d\.|255\.|ff)'                 { return 'multicast' }
        '^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.'     { return 'cgnat' }
    }
    'public'
}

function Get-IpLabel([string]$Ip) {
    $Ip = $Ip -replace '%\d+$', ''
    if ((Get-IpClass $Ip) -ne 'public') { return $Ip }
    if (-not $publicLabels.ContainsKey($Ip)) {
        $publicLabels[$Ip] = 'PUB-{0:D2}' -f ($publicLabels.Count + 1)
    }
    $publicLabels[$Ip]
}

function Format-Program([string]$Path) {
    if (-not $Path -or $Path -eq '-') { return '(kernel)' }
    # \device\harddiskvolume3\program files\... -> \program files\...
    Hide-Text ($Path -replace '^\\device\\harddiskvolume\d+', '')
}

function Format-Protocol([string]$Number) {
    switch ($Number) {
        '1'  { 'ICMP' }
        '2'  { 'IGMP' }
        '6'  { 'TCP' }
        '17' { 'UDP' }
        '58' { 'ICMPv6' }
        default { $Number }
    }
}

function Format-Port([string]$Port) {
    if ([int]$Port -lt 10000) { $Port } else { 'high' }
}

# auditpol /backup writes headers in the display language, but the GUID and
# the last column, the numeric setting (0 none, 1 success, 2 failure,
# 3 both), are the same everywhere. "auditpol /restore" of such a file can
# fail, so only this one subcategory is read and set back.
function Get-AuditValue {
    $file = Join-Path $env:TEMP ('stopinet-audit-{0}.csv' -f [guid]::NewGuid())
    auditpol /backup "/file:$file" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol /backup failed' }
    try {
        $line = Get-Content $file | Where-Object { $_ -like "*$subcategory*" } | Select-Object -First 1
    }
    finally {
        Remove-Item $file -ErrorAction SilentlyContinue
    }
    if (-not $line) { throw "audit subcategory $subcategory not found" }
    [int](($line -split ',')[-1])
}

function Set-AuditValue([int]$Value) {
    $success = if ($Value -band 1) { 'enable' } else { 'disable' }
    $failure = if ($Value -band 2) { 'enable' } else { 'disable' }
    auditpol /set "/subcategory:$subcategory" "/success:$success" "/failure:$failure" | Out-Null
    $LASTEXITCODE -eq 0
}

# Names of all WFP filters by id. Filters of stop-internet keep their own
# names; the others are marked as such.
function Get-FilterNames {
    $file = Join-Path $env:TEMP ('stopinet-filters-{0}.xml' -f [guid]::NewGuid())
    $names = @{}
    try {
        netsh wfp show filters "file=$file" | Out-Null
        if (-not (Test-Path $file)) { return $names }
        $xml = New-Object xml
        $xml.Load($file)
        foreach ($item in $xml.SelectNodes('//item[filterId]')) {
            $name = Hide-Text $item.displayData.name
            if ($item.providerKey -ne $provider) {
                if ($name.Length -gt 50) { $name = $name.Substring(0, 50) + '...' }
                $name = "other: $name"
            }
            $names[[string]$item.filterId] = $name
        }
    }
    finally {
        Remove-Item $file -ErrorAction SilentlyContinue
    }
    $names
}

# --- record ------------------------------------------------------------------

$previous = Get-AuditValue
# Session filters are rebuilt when the tunnel changes, so collect the
# names before and after recording.
$filters = Get-FilterNames

try {
    if (-not (Set-AuditValue ($previous -bor 2))) { throw 'auditpol /set failed' }
    $start = Get-Date
    Write-Host "Recording blocked connections for $Seconds s. Repeat the action that fails now."
    for ($left = $Seconds; $left -gt 0; $left--) {
        Write-Progress -Activity 'Recording blocked connections' -SecondsRemaining $left
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity 'Recording blocked connections' -Completed
}
finally {
    if (Set-AuditValue $previous) {
        Write-Host 'Audit setting restored.'
    } else {
        Write-Host "Could not restore the audit setting. It was $previous (0 none, 1 success, 2 failure, 3 both)."
    }
}

$after = Get-FilterNames
foreach ($id in $after.Keys) { $filters[$id] = $after[$id] }

# --- report ------------------------------------------------------------------

$filter = @{ LogName = 'Security'; Id = 5157; StartTime = $start }
$events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)

# Source is the local end and Destination the remote end, in both directions.
$rows = foreach ($event in $events) {
    $data = @{}
    foreach ($field in ([xml]$event.ToXml()).Event.EventData.Data) {
        $data[$field.Name] = $field.'#text'
    }
    $filterName = $filters[[string]$data.FilterRTID]
    if (-not $filterName) { $filterName = "(gone, id $($data.FilterRTID))" }
    [pscustomobject]@{
        Program   = Format-Program $data.Application
        Direction = if ($data.Direction -eq '%%14592') { 'in' } else { 'out' }
        Protocol  = Format-Protocol $data.Protocol
        Remote    = Get-IpLabel $data.DestAddress
        Port      = Format-Port $data.DestPort
        Filter    = $filterName
    }
}

''
"Blocked connections, $($events.Count) events in $Seconds s:"
if (-not $rows) {
    '(none)'
    exit 0
}
$rows |
    Group-Object Program, Direction, Protocol, Remote, Port, Filter |
    Sort-Object Count -Descending |
    ForEach-Object {
        $first = $_.Group[0]
        [pscustomobject]@{
            Count     = $_.Count
            Direction = $first.Direction
            Protocol  = $first.Protocol
            Remote    = $first.Remote
            Port      = $first.Port
            Filter    = $first.Filter
            Program   = $first.Program
        }
    } |
    Format-Table -AutoSize -Wrap |
    Out-String -Width 400
