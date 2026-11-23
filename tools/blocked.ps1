<#
.SYNOPSIS
    Shows which programs had connections blocked, anonymized.

.DESCRIPTION
    Turns on auditing of blocked connections (event 5157, audit subcategory
    "Filtering Platform Connection") for a while. Repeat the action that
    fails during that time, for example a subscription update in the VPN
    client. Then the script restores the previous audit policy and prints
    the blocked connections grouped by program, direction, protocol, remote
    address and port.

    What changes: the audit policy, only while the script runs. It is saved
    with "auditpol /backup" first and restored with "auditpol /restore" at the
    end, also after Ctrl+C. Meanwhile blocked connections are written to the
    Security event log.

    Anonymization as in diag.ps1: public addresses become PUB-01, PUB-02, ...,
    the user name and the computer name become <user> and <pc>. Private,
    loopback and link-local addresses are kept.

    Blocks by Windows Firewall are recorded too. Inbound ones are usually
    unrelated to stop-internet.

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
        '6'  { 'TCP' }
        '17' { 'UDP' }
        '58' { 'ICMPv6' }
        default { $Number }
    }
}

function Format-Port([string]$Port) {
    if ([int]$Port -lt 10000) { $Port } else { 'high' }
}

# --- record ------------------------------------------------------------------

$backup = Join-Path $env:TEMP ('stopinet-audit-{0}.csv' -f [guid]::NewGuid())
auditpol /backup "/file:$backup" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'auditpol /backup failed' }

try {
    auditpol /set "/subcategory:$subcategory" /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol /set failed' }
    $start = Get-Date
    Write-Host "Recording blocked connections for $Seconds s. Repeat the action that fails now."
    for ($left = $Seconds; $left -gt 0; $left--) {
        Write-Progress -Activity 'Recording blocked connections' -SecondsRemaining $left
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity 'Recording blocked connections' -Completed
}
finally {
    auditpol /restore "/file:$backup" | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Remove-Item $backup -ErrorAction SilentlyContinue
        Write-Host 'Audit policy restored.'
    } else {
        Write-Host "Could not restore the audit policy, the backup stays in $backup"
    }
}

# --- report ------------------------------------------------------------------

$filter = @{ LogName = 'Security'; Id = 5157; StartTime = $start }
$events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)

# Source is the local end and Destination the remote end, in both directions.
$rows = foreach ($event in $events) {
    $data = @{}
    foreach ($field in ([xml]$event.ToXml()).Event.EventData.Data) {
        $data[$field.Name] = $field.'#text'
    }
    [pscustomobject]@{
        Program   = Format-Program $data.Application
        Direction = if ($data.Direction -eq '%%14592') { 'in' } else { 'out' }
        Protocol  = Format-Protocol $data.Protocol
        Remote    = Get-IpLabel $data.DestAddress
        Port      = Format-Port $data.DestPort
    }
}

''
"Blocked connections, $($events.Count) events in $Seconds s:"
if (-not $rows) {
    '(none)'
    exit 0
}
$rows |
    Group-Object Program, Direction, Protocol, Remote, Port |
    Sort-Object Count -Descending |
    ForEach-Object {
        $first = $_.Group[0]
        [pscustomobject]@{
            Count     = $_.Count
            Direction = $first.Direction
            Protocol  = $first.Protocol
            Remote    = $first.Remote
            Port      = $first.Port
            Program   = $first.Program
        }
    } |
    Format-Table -AutoSize -Wrap |
    Out-String -Width 300
