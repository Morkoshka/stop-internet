<#
.SYNOPSIS
    Read-only, anonymized network diagnostics for stop-internet.

.DESCRIPTION
    Collects adapter, route, DNS and connection information that is needed
    to design firewall rules for a TUN-based VPN client. Nothing on the
    system is changed.

    Anonymization happens before anything is written:
      - public IP addresses are replaced with stable labels (PUB-01, PUB-02, ...),
        so the same address keeps the same label within one run;
      - the user name and the computer name are replaced with <user> and <pc>;
      - URLs are replaced with <url>;
      - adapter GUIDs are shown only for tunnel adapters.
    Private, loopback and link-local addresses are kept as is.

    Run from an elevated PowerShell, otherwise paths of system processes
    are not visible.

.PARAMETER Label
    Scenario name, used in the output file name (for example: tun, proxy, off).

.PARAMETER Client
    Regex that matches process names of the VPN client.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\diag.ps1 -Label tun
#>
param(
    [string]$Label = 'run',
    [string]$Client = 'happ|xray|sing-box'
)

$ErrorActionPreference = 'SilentlyContinue'

$desktop = [Environment]::GetFolderPath('Desktop')
$outFile = Join-Path $desktop ('stopinet-diag-{0}-{1:yyyyMMdd-HHmmss}.txt' -f $Label, (Get-Date))
$userRx = [regex]::Escape($env:USERNAME)
$pcRx = [regex]::Escape($env:COMPUTERNAME)
$publicLabels = @{}
$splitRoutes = @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1', '::/0', '::/1', '8000::/1')

function Hide-Text([string]$Text) {
    if (-not $Text) { return $Text }
    $Text = $Text -replace $userRx, '<user>' -replace $pcRx, '<pc>'
    $Text -replace '[a-zA-Z][a-zA-Z0-9+.-]*://\S+', '<url>'
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

$processes = @{}
Get-CimInstance Win32_Process | ForEach-Object { $processes[[int]$_.ProcessId] = $_ }

$services = @{}
Get-CimInstance Win32_Service | Where-Object { $_.ProcessId } | ForEach-Object {
    $id = [int]$_.ProcessId
    if ($services.ContainsKey($id)) { $services[$id] += $_.Name } else { $services[$id] = @($_.Name) }
}

function Get-ProcPath([int]$Id) {
    $p = $processes[$Id]
    if (-not $p) { return "pid:$Id" }
    if ($p.ExecutablePath) { return (Hide-Text $p.ExecutablePath) }
    $p.Name
}

function Get-ProcName([int]$Id) {
    $name = (Get-ProcPath $Id) -replace '^.*\\', ''
    if ($name -eq 'svchost.exe' -and $services.ContainsKey($Id)) {
        $name = 'svchost(' + ($services[$Id] -join ',') + ')'
    }
    $name
}

function Test-Client([int]$Id) {
    ((Get-ProcPath $Id) -replace '^.*\\', '') -match $Client
}

$ifaceByIp = @{}
Get-NetIPAddress | ForEach-Object { $ifaceByIp[$_.IPAddress] = $_.InterfaceAlias }

function Get-Iface([string]$Ip) {
    $class = Get-IpClass $Ip
    if ($class -in @('loopback', 'any')) { return $class }
    $alias = $ifaceByIp[($Ip -replace '%\d+$', '')]
    if ($alias) { $alias } else { '?' }
}

function Format-Port([int]$Port) {
    if ($Port -lt 10000) { "$Port" } else { 'high' }
}

function Write-Section([string]$Title, $Data) {
    ''
    "### $Title"
    if ($Data) { ($Data | Format-Table -AutoSize -Wrap | Out-String -Width 400).TrimEnd() } else { '(none)' }
}

# --- collect -----------------------------------------------------------------

$uninstallKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$install = Get-ItemProperty $uninstallKeys |
    Where-Object { $_.DisplayName -match $Client } |
    Select-Object DisplayName, @{ n = 'Location'; e = { Hide-Text $_.InstallLocation } }

$fastStartup = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' |
    Select-Object HiberbootEnabled

$clientServices = Get-CimInstance Win32_Service |
    Where-Object { ($_.PathName -replace '^.*\\', '') -match $Client } |
    Select-Object Name, State, StartMode, StartName, @{ n = 'Path'; e = { Hide-Text $_.PathName } }

$clientProcesses = Get-CimInstance Win32_Process |
    Where-Object { $_.Name -match $Client } |
    ForEach-Object {
        $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
        [pscustomobject]@{
            PID     = $_.ProcessId
            Name    = $_.Name
            Parent  = Get-ProcName $_.ParentProcessId
            Owner   = Hide-Text ('{0}\{1}' -f $owner.Domain, $owner.User)
            Path    = Hide-Text $_.ExecutablePath
            Command = Hide-Text $_.CommandLine
        }
    }

$adapters = Get-NetAdapter -IncludeHidden |
    Where-Object {
        $_.Status -eq 'Up' -or
        $_.ComponentID -match 'wintun|^tap' -or
        $_.InterfaceDescription -match 'tunnel|wintun|\btap\b'
    } |
    ForEach-Object {
        $idx = $_.ifIndex
        $isTunnel = ($_.ComponentID -match 'wintun|^tap') -or ($_.InterfaceDescription -match 'tunnel|wintun|\btap\b')
        [pscustomobject]@{
            Name      = $_.Name
            Desc      = $_.InterfaceDescription
            Component = $_.ComponentID
            Index     = $idx
            Status    = $_.Status
            Guid      = $(if ($isTunnel) { $_.InterfaceGuid } else { '-' })
            Addresses = (Get-NetIPAddress -InterfaceIndex $idx | ForEach-Object { '{0}/{1}' -f (Get-IpLabel $_.IPAddress), $_.PrefixLength }) -join ' '
            Dns       = ((Get-DnsClientServerAddress -InterfaceIndex $idx).ServerAddresses | ForEach-Object { Get-IpLabel $_ }) -join ' '
        }
    }

$routes = Get-NetRoute |
    Where-Object {
        ($splitRoutes -contains $_.DestinationPrefix) -or
        ((Get-IpClass ($_.DestinationPrefix -replace '/\d+$', '')) -eq 'public')
    } |
    ForEach-Object {
        $prefix, $len = $_.DestinationPrefix -split '/'
        [pscustomobject]@{
            Interface = $_.InterfaceAlias
            Dest      = $(if ($splitRoutes -contains $_.DestinationPrefix) { $_.DestinationPrefix } else { '{0}/{1}' -f (Get-IpLabel $prefix), $len })
            NextHop   = Get-IpLabel $_.NextHop
            Metric    = $_.RouteMetric
            IfMetric  = (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily $_.AddressFamily).InterfaceMetric
        }
    }

$established = @(Get-NetTCPConnection -State Established)

$clientTcp = $established |
    Where-Object { Test-Client $_.OwningProcess } |
    ForEach-Object {
        [pscustomobject]@{
            Process = Get-ProcName $_.OwningProcess
            Iface   = Get-Iface $_.LocalAddress
            Remote  = '{0}:{1}' -f (Get-IpLabel $_.RemoteAddress), (Format-Port $_.RemotePort)
        }
    } |
    Group-Object Process, Iface, Remote | Sort-Object Name | Select-Object Count, Name

$otherTcp = $established |
    Where-Object { -not (Test-Client $_.OwningProcess) } |
    ForEach-Object {
        [pscustomobject]@{
            Process = Get-ProcName $_.OwningProcess
            Iface   = Get-Iface $_.LocalAddress
            Remote  = '{0}:{1}' -f (Get-IpClass $_.RemoteAddress), (Format-Port $_.RemotePort)
        }
    } |
    Where-Object { $_.Iface -ne 'loopback' } |
    Group-Object Process, Iface, Remote | Sort-Object Name | Select-Object Count, Name

$clientListen = Get-NetTCPConnection -State Listen |
    Where-Object { Test-Client $_.OwningProcess } |
    Select-Object @{ n = 'Process'; e = { Get-ProcName $_.OwningProcess } },
                  @{ n = 'Address'; e = { Get-IpLabel $_.LocalAddress } },
                  LocalPort |
    Sort-Object Process, LocalPort

$clientUdp = Get-NetUDPEndpoint |
    Where-Object { Test-Client $_.OwningProcess } |
    Select-Object @{ n = 'Process'; e = { Get-ProcName $_.OwningProcess } },
                  @{ n = 'Iface'; e = { Get-Iface $_.LocalAddress } },
                  @{ n = 'Address'; e = { Get-IpLabel $_.LocalAddress } },
                  LocalPort |
    Sort-Object Process, LocalPort

# --- write -------------------------------------------------------------------

$report = @(
    "stop-internet diagnostics | label: $Label | $(Get-Date -Format s)"
    Write-Section 'Client installation' $install
    Write-Section 'Fast Startup' $fastStartup
    Write-Section 'Client services' $clientServices
    Write-Section 'Client processes' $clientProcesses
    Write-Section 'Adapters (up or tunnel-like)' $adapters
    Write-Section 'Default, split and host routes' $routes
    Write-Section 'TCP established: client processes' $clientTcp
    Write-Section 'TCP established: other processes (non-loopback)' $otherTcp
    Write-Section 'TCP listeners: client processes' $clientListen
    Write-Section 'UDP endpoints: client processes' $clientUdp
)

$report | Out-File -FilePath $outFile -Encoding utf8 -Width 400
Write-Host "Saved: $outFile"
notepad $outFile
