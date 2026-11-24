<#
.SYNOPSIS
    Shows what this computer sent through its physical network adapters,
    anonymized.

.DESCRIPTION
    Records packets on the network adapters with pktmon for a while, then
    lists what the computer sent over the cable or the air: protocol,
    remote address, port, packets out and in, and the programs. Traffic
    inside the tunnel does not appear here, only what left through a
    physical adapter. With stop-internet in a protected mode that is the
    VPN server, DHCP, ARP, IPv6 neighbor discovery and the apps from the
    `direct` list.

    Programs come from the audit events of permitted connections (5156):
    the program that opened that very connection. A connection that was
    open before the recording has no event; then the report names, in
    brackets, the programs that owned its local port at some time, which
    is only a guess. A packet with a source address that the physical
    adapters do not have, the tunnel's for example, gets a warning.

    Meanwhile the script tries the network itself every 5 seconds, like an
    ordinary program that knows nothing of the tunnel or the proxy:
    TCP 443 and a DNS query to 1.1.1.1, a ping to 1.1.1.1, a DNS query to
    the router and TCP 443 to 2606:4700:4700::1111. -NoProbe turns this off.

    What changes, only while the script runs: a pktmon capture, and the
    audit of permitted connections (subcategory "Filtering Platform
    Connection", success), which writes every permitted connection to the
    Security log, tunnel and loopback included. Both are put back at the
    end, also after Ctrl+C. On a busy computer the audit can push older
    entries out of the Security log, which keeps 20 MB by default; with
    -NoAudit the audit stays as it is, and the programs are only guesses.
    The capture files go to a new folder in %TEMP% and are deleted at the
    end, unless -Keep is given; they contain real addresses.

    Anonymization as in diag.ps1: public addresses become PUB-01, PUB-02,
    ..., the busiest first. The probe addresses are shown as they are.
    Private, link-local and multicast addresses are kept. Programs are
    shown by name only.

    Run from an elevated PowerShell. The capture reads Ethernet frames;
    Wi-Fi adapters usually hand them over in that form too.

.PARAMETER Seconds
    How long to record, 10 to 600 seconds. Time in sleep does not count.

.PARAMETER NoProbe
    Send no test traffic.

.PARAMETER NoAudit
    Leave the audit setting alone. The programs are only guesses then.

.PARAMETER Keep
    Keep the capture files (capture.pcapng opens in Wireshark) and print
    their folder.

.PARAMETER Read
    Report on a capture.pcapng saved with -Keep instead of recording. The
    programs are unknown then.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\leaks.ps1 -Seconds 60
#>
param(
    [ValidateRange(10, 600)]
    [int]$Seconds = 60,
    [switch]$NoProbe,
    [switch]$NoAudit,
    [switch]$Keep,
    [string]$Read
)

$ErrorActionPreference = 'Stop'

$probeV4 = '1.1.1.1'
$probeV6 = '2606:4700:4700::1111'
$probeAddresses = if ($Read -or $NoProbe) { @() } else { @($probeV4, $probeV6) }

if (-not $Read) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host 'Run this from an elevated PowerShell.'
        exit 1
    }
    if (-not (Get-Command pktmon.exe -ErrorAction SilentlyContinue)) {
        Write-Host 'pktmon.exe not found: it comes with Windows 10 2004 and later.'
        exit 1
    }
}

$adapters = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
if (-not $adapters) {
    Write-Host 'No physical network adapter is connected.'
    exit 1
}
$macs = [string[]]@($adapters | ForEach-Object { $_.MacAddress })
$gateway = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object { $adapters.ifIndex -contains $_.InterfaceIndex -and $_.NextHop -ne '0.0.0.0' } |
    Sort-Object RouteMetric |
    Select-Object -First 1 -ExpandProperty NextHop

# --- pcapng ------------------------------------------------------------------

# Reads Ethernet frames from a pcapng file and counts them by direction,
# protocol, remote address, remote port and local port. Only frames to or
# from one of the given MAC addresses count: those crossed a physical
# adapter. Packets of the tunnel adapter have no such address.
$pcapngSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace StopinetLeaks
{
    public sealed class Flow
    {
        public string Direction;
        public string Protocol;
        public string Remote;
        // The address of this computer in the packet.
        public string Local;
        // Port, ICMP type, or -1.
        public int RemotePort;
        public int LocalPort;
        public long Packets;
    }

    public sealed class Capture
    {
        public long Frames;
        public long Wire;
        public SortedDictionary<int, long> OtherLinkTypes = new SortedDictionary<int, long>();
        public List<Flow> Flows = new List<Flow>();
    }

    public static class Pcapng
    {
        const int Ethernet = 1;

        public static Capture Read(string path, string[] macs)
        {
            HashSet<long> own = new HashSet<long>();
            foreach (string mac in macs)
            {
                own.Add(Convert.ToInt64(mac.Replace("-", "").Replace(":", ""), 16));
            }
            byte[] d = File.ReadAllBytes(path);
            Capture capture = new Capture();
            Dictionary<string, Flow> flows = new Dictionary<string, Flow>();
            List<int> linkTypes = new List<int>();
            bool little = true;
            int pos = 0;
            while (pos + 12 <= d.Length)
            {
                // The type of a section header reads the same in both byte orders.
                uint type = U32(d, pos, little);
                if (type == 0x0A0D0D0A)
                {
                    uint magic = U32(d, pos + 8, true);
                    if (magic == 0x1A2B3C4D) little = true;
                    else if (magic == 0x4D3C2B1A) little = false;
                    else throw new InvalidDataException("not a pcapng file");
                    linkTypes.Clear();
                }
                long length = U32(d, pos + 4, little);
                if (length < 12 || pos + length > d.Length) break;
                if (type == 1 && length >= 20)
                {
                    linkTypes.Add(U16(d, pos + 8, little));
                }
                else if (type == 6 && length >= 32)
                {
                    // Enhanced packet: interface, timestamp, captured and original length.
                    uint iface = U32(d, pos + 8, little);
                    long captured = U32(d, pos + 20, little);
                    if (iface < (uint)linkTypes.Count && captured <= length - 32)
                    {
                        Frame(capture, flows, own, d, pos + 28, (int)captured, linkTypes[(int)iface]);
                    }
                }
                else if (type == 3 && length >= 16 && linkTypes.Count > 0)
                {
                    // Simple packet: original length, then as much as the block holds.
                    long captured = Math.Min(U32(d, pos + 8, little), length - 16);
                    Frame(capture, flows, own, d, pos + 12, (int)captured, linkTypes[0]);
                }
                pos += (int)length;
            }
            capture.Flows.AddRange(flows.Values);
            return capture;
        }

        static void Frame(Capture capture, Dictionary<string, Flow> flows, HashSet<long> own,
            byte[] d, int off, int len, int linkType)
        {
            capture.Frames++;
            if (linkType != Ethernet)
            {
                long seen;
                capture.OtherLinkTypes.TryGetValue(linkType, out seen);
                capture.OtherLinkTypes[linkType] = seen + 1;
                return;
            }
            if (len < 14) return;
            bool outbound = own.Contains(Mac(d, off + 6));
            if (!outbound && !own.Contains(Mac(d, off))) return;
            capture.Wire++;

            string dir = outbound ? "out" : "in";
            int end = off + len;
            int p = off + 12;
            int etherType = BE16(d, p);
            p += 2;
            while ((etherType == 0x8100 || etherType == 0x88A8) && p + 4 <= end)
            {
                etherType = BE16(d, p + 2);
                p += 4;
            }

            if (etherType == 0x0806)
            {
                Add(flows, dir, "ARP", "", -1, "", -1);
            }
            else if (etherType == 0x0800 && p + 20 <= end)
            {
                int headerLength = (d[p] & 0x0F) * 4;
                bool fragment = (BE16(d, p + 6) & 0x1FFF) != 0;
                string remote = Address(d, outbound ? p + 16 : p + 12, 4);
                string local = Address(d, outbound ? p + 12 : p + 16, 4);
                Transport(flows, d, dir, outbound, d[p + 9], remote, local, p + headerLength, end, fragment);
            }
            else if (etherType == 0x86DD && p + 40 <= end)
            {
                int next = d[p + 6];
                string remote = Address(d, outbound ? p + 24 : p + 8, 16);
                string local = Address(d, outbound ? p + 8 : p + 24, 16);
                int l4 = p + 40;
                bool fragment = false;
                for (int i = 0; i < 8 && l4 + 8 <= end; i++)
                {
                    if (next == 0 || next == 43 || next == 60)
                    {
                        int size = (d[l4 + 1] + 1) * 8;
                        next = d[l4];
                        l4 += size;
                    }
                    else if (next == 44)
                    {
                        fragment = (BE16(d, l4 + 2) >> 3) != 0;
                        next = d[l4];
                        l4 += 8;
                    }
                    else break;
                }
                Transport(flows, d, dir, outbound, next, remote, local, l4, end, fragment);
            }
            else
            {
                Add(flows, dir, "EtherType 0x" + etherType.ToString("X4"), "", -1, "", -1);
            }
        }

        static void Transport(Dictionary<string, Flow> flows, byte[] d, string dir, bool outbound,
            int protocol, string remote, string local, int l4, int end, bool fragment)
        {
            string name;
            switch (protocol)
            {
                case 1: name = "ICMP"; break;
                case 2: name = "IGMP"; break;
                case 6: name = "TCP"; break;
                case 17: name = "UDP"; break;
                case 58: name = "ICMPv6"; break;
                default: name = "IP protocol " + protocol; break;
            }
            int remotePort = -1;
            int localPort = -1;
            if (!fragment && (protocol == 6 || protocol == 17) && l4 + 4 <= end)
            {
                int source = BE16(d, l4);
                int destination = BE16(d, l4 + 2);
                remotePort = outbound ? destination : source;
                localPort = outbound ? source : destination;
            }
            else if (!fragment && (protocol == 1 || protocol == 58) && l4 < end)
            {
                remotePort = d[l4];
            }
            Add(flows, dir, name, remote, remotePort, local, localPort);
        }

        static void Add(Dictionary<string, Flow> flows, string dir, string protocol, string remote,
            int remotePort, string local, int localPort)
        {
            string key = dir + "|" + protocol + "|" + remote + "|" + remotePort + "|" + local + "|" + localPort;
            Flow flow;
            if (!flows.TryGetValue(key, out flow))
            {
                flow = new Flow();
                flow.Direction = dir;
                flow.Protocol = protocol;
                flow.Remote = remote;
                flow.RemotePort = remotePort;
                flow.Local = local;
                flow.LocalPort = localPort;
                flows.Add(key, flow);
            }
            flow.Packets++;
        }

        static string Address(byte[] d, int off, int size)
        {
            byte[] bytes = new byte[size];
            Buffer.BlockCopy(d, off, bytes, 0, size);
            return new IPAddress(bytes).ToString();
        }

        static long Mac(byte[] d, int off)
        {
            long value = 0;
            for (int i = 0; i < 6; i++) value = (value << 8) | d[off + i];
            return value;
        }

        static int BE16(byte[] d, int off)
        {
            return (d[off] << 8) | d[off + 1];
        }

        static int U16(byte[] d, int off, bool little)
        {
            return little ? d[off] | (d[off + 1] << 8) : BE16(d, off);
        }

        static uint U32(byte[] d, int off, bool little)
        {
            if (little)
            {
                return (uint)(d[off] | (d[off + 1] << 8) | (d[off + 2] << 16) | (d[off + 3] << 24));
            }
            return (uint)((d[off] << 24) | (d[off + 1] << 16) | (d[off + 2] << 8) | d[off + 3]);
        }
    }
}
'@
if (-not ('StopinetLeaks.Pcapng' -as [type])) {
    Add-Type -TypeDefinition $pcapngSource -Language CSharp
}

# --- probes ------------------------------------------------------------------

# Runs as a job, in its own powershell.exe: an ordinary program that is in
# no list of the configuration. Each result says whether the program got
# through; the capture says whether anything left through the adapter.
$probeScript = {
    param([string]$V4, [string]$V6, [string]$Gateway)

    function Test-Tcp([string]$Address, [int]$Port) {
        $ip = [System.Net.IPAddress]::Parse($Address)
        $tcp = New-Object System.Net.Sockets.TcpClient($ip.AddressFamily)
        try { $tcp.ConnectAsync($ip, $Port).Wait(2000) -and $tcp.Connected }
        catch { $false }
        finally { $tcp.Close() }
    }

    # A query for the A record of example.com. Any answer shows that UDP got
    # there and back.
    function Test-Dns([string]$Server) {
        $query = [byte[]](
            0x51, 0x7A, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0,
            0x00, 0x01, 0x00, 0x01)
        $ip = [System.Net.IPAddress]::Parse($Server)
        $udp = New-Object System.Net.Sockets.UdpClient($ip.AddressFamily)
        try {
            $udp.Client.ReceiveTimeout = 2000
            [void]$udp.Send($query, $query.Length, (New-Object System.Net.IPEndPoint($ip, 53)))
            $from = New-Object System.Net.IPEndPoint($ip, 0)
            $reply = $udp.Receive([ref]$from)
            $reply.Length -ge 12 -and $reply[0] -eq 0x51 -and $reply[1] -eq 0x7A
        }
        catch { $false }
        finally { $udp.Close() }
    }

    function Test-Ping([string]$Address) {
        try { (New-Object System.Net.NetworkInformation.Ping).Send($Address, 2000).Status -eq 'Success' }
        catch { $false }
    }

    while ($true) {
        $round = [Diagnostics.Stopwatch]::StartNew()
        [pscustomobject]@{ Probe = "TCP 443 to $V4"; Ok = (Test-Tcp $V4 443) }
        [pscustomobject]@{ Probe = "DNS to $V4"; Ok = (Test-Dns $V4) }
        [pscustomobject]@{ Probe = "ping $V4"; Ok = (Test-Ping $V4) }
        if ($Gateway) {
            [pscustomobject]@{ Probe = "DNS to the router $Gateway"; Ok = (Test-Dns $Gateway) }
        }
        [pscustomobject]@{ Probe = "TCP 443 to $V6"; Ok = (Test-Tcp $V6 443) }
        $rest = 5000 - $round.ElapsedMilliseconds
        if ($rest -gt 0) { Start-Sleep -Milliseconds $rest }
    }
}

# --- programs ----------------------------------------------------------------

# Owners of local ports, by "TCP 51234" or "UDP 51234", sampled every second
# while recording.
$owners = @{}
$processNames = @{}

function Add-Owner([string]$Protocol, [int]$Port, [int]$ProcessId) {
    if ($ProcessId -le 0) { return }
    if (-not $processNames.ContainsKey($ProcessId)) {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        $processNames[$ProcessId] = if ($process) { $process.ProcessName } else { "pid $ProcessId" }
    }
    $key = "$Protocol $Port"
    if (-not $owners.ContainsKey($key)) {
        $owners[$key] = New-Object 'System.Collections.Generic.HashSet[string]'
    }
    [void]$owners[$key].Add($processNames[$ProcessId])
}

function Read-Owners {
    foreach ($connection in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        if ($connection.RemoteAddress -match '^(127\.|::1$|0\.0\.0\.0$|::$)') { continue }
        Add-Owner 'TCP' $connection.LocalPort $connection.OwningProcess
    }
    foreach ($endpoint in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        if ($endpoint.LocalAddress -match '^(127\.|::1$)') { continue }
        Add-Owner 'UDP' $endpoint.LocalPort $endpoint.OwningProcess
    }
}

# Programs by connection, from the audit events of permitted connections
# (5156), keyed like the flows of the capture. Unlike the owners of local
# ports, which are reused, this is exact, but only for connections that
# started while recording.
$connections = @{}

# "Filtering Platform Connection": 5156 is its success, 5157 its failure.
# The GUID works with any display language.
$subcategory = '{0CCE9226-69AE-11D9-BED3-505054503030}'

# auditpol /backup writes headers in the display language, but the GUID and
# the last column, the numeric setting (0 none, 1 success, 2 failure,
# 3 both), are the same everywhere. "auditpol /restore" of such a file can
# fail, so only this one subcategory is read and set back, as in
# blocked.ps1.
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

function Get-ProtocolName([string]$Number) {
    switch ($Number) {
        '1'  { 'ICMP' }
        '2'  { 'IGMP' }
        '6'  { 'TCP' }
        '17' { 'UDP' }
        '58' { 'ICMPv6' }
        default { "IP protocol $Number" }
    }
}

# The same text for the same address, as the capture writes it.
function ConvertTo-Address([string]$Text) {
    $address = $null
    if ([System.Net.IPAddress]::TryParse(($Text -replace '%\d+$', ''), [ref]$address)) {
        $address.ToString()
    } else {
        $Text
    }
}

# For ICMP, WFP puts the type and the code where the ports would be.
function Get-ConnectionKey([string]$Protocol, [string]$Local, [string]$LocalPort, [string]$Remote, [string]$RemotePort) {
    if ($Protocol -like 'ICMP*') { "$Protocol|$Local|$Remote" } else { "$Protocol|$Local|$LocalPort|$Remote|$RemotePort" }
}

# Source is the local end and Destination the remote end, in both
# directions. Only connections from the addresses of the physical adapters
# are read: only they can show up on the wire, while those through the
# tunnel and over loopback can be tens of thousands. Returns the number of
# events.
function Read-Connections([datetime]$Since) {
    $sources = @($ownAddresses | Where-Object { $_ } | ForEach-Object { "Data[@Name='SourceAddress']='$_'" })
    if (-not $sources) { return 0 }
    $time = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $xpath = "*[System[EventID=5156 and TimeCreated[@SystemTime>='$time']]] and *[EventData[$($sources -join ' or ')]]"
    $events = @(Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction SilentlyContinue)
    if (-not $events) { return 0 }
    # Positions of the fields, by their names in the first event.
    $at = @{}
    $i = 0
    foreach ($field in ([xml]$events[0].ToXml()).Event.EventData.Data) {
        $at[$field.Name] = $i
        $i++
    }
    foreach ($name in 'Application', 'Protocol', 'SourceAddress', 'SourcePort', 'DestAddress', 'DestPort') {
        if (-not $at.ContainsKey($name)) {
            Write-Host "Connection events have no field $name, so programs are only guesses."
            return 0
        }
    }
    foreach ($event in $events) {
        $values = $event.Properties
        $path = [string]$values[$at.Application].Value
        $program = if ($path -and $path -ne '-') { [IO.Path]::GetFileNameWithoutExtension($path) } else { '(kernel)' }
        $key = Get-ConnectionKey (Get-ProtocolName ([string]$values[$at.Protocol].Value)) `
            (ConvertTo-Address ([string]$values[$at.SourceAddress].Value)) ([string]$values[$at.SourcePort].Value) `
            (ConvertTo-Address ([string]$values[$at.DestAddress].Value)) ([string]$values[$at.DestPort].Value)
        if (-not $connections.ContainsKey($key)) {
            $connections[$key] = New-Object 'System.Collections.Generic.SortedSet[string]'
        }
        [void]$connections[$key].Add($program)
    }
    $events.Count
}

# Addresses of the physical adapters, at the start and at the end.
$ownAddresses = New-Object 'System.Collections.Generic.HashSet[string]'
function Add-OwnAddresses {
    foreach ($ip in @(Get-NetIPAddress -InterfaceIndex $adapters.ifIndex -ErrorAction SilentlyContinue)) {
        [void]$ownAddresses.Add((ConvertTo-Address $ip.IPAddress))
    }
}

# Programs of a flow: those of its connection events, or else the owners
# of its local port, which are only a guess.
function Get-FlowPrograms($Flow) {
    $key = Get-ConnectionKey $Flow.Protocol $Flow.Local ([string]$Flow.LocalPort) $Flow.Remote ([string]$Flow.RemotePort)
    $exact = $connections[$key]
    if ($exact) {
        return [pscustomobject]@{ Exact = $true; Names = @($exact) }
    }
    # The set is unrolled into its names on purpose.
    $guess = if ($Flow.LocalPort -ge 0) { $owners['{0} {1}' -f $Flow.Protocol, $Flow.LocalPort] }
    [pscustomobject]@{ Exact = $false; Names = @($guess) }
}

# Adds the programs of the flows to the two sets. The sets are passed as
# they are: "$set = if (...) { $Exact } else { $Guesses }" would unroll
# them into their elements.
function Add-FlowPrograms($Flows, $Exact, $Guesses) {
    foreach ($flow in $Flows) {
        $found = Get-FlowPrograms $flow
        foreach ($name in $found.Names) {
            if (-not $name) { continue }
            if ($found.Exact) { [void]$Exact.Add($name) } else { [void]$Guesses.Add($name) }
        }
    }
}

# Names from connection events plainly, guesses in brackets.
function Format-Programs($Exact, $Guesses) {
    $names = @($Exact) + @($Guesses | Where-Object { -not $Exact.Contains($_) } | ForEach-Object { "[$_]" })
    $names -join ', '
}

# Rows of the report: one per protocol, remote address and port; local
# ports only lead to the programs.
function Group-Flows($Flows) {
    $groups = @{}
    foreach ($flow in $Flows) {
        $port = Format-Port $flow.Protocol $flow.RemotePort
        $key = '{0}|{1}|{2}' -f $flow.Protocol, $flow.Remote, $port
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = [pscustomobject]@{
                Protocol = $flow.Protocol
                Address  = $flow.Remote
                Port     = $port
                Out      = [long]0
                In       = [long]0
                Programs = New-Object 'System.Collections.Generic.SortedSet[string]'
                Guesses  = New-Object 'System.Collections.Generic.SortedSet[string]'
            }
        }
        $group = $groups[$key]
        if ($flow.Direction -eq 'out') { $group.Out += $flow.Packets } else { $group.In += $flow.Packets }
        Add-FlowPrograms @($flow) $group.Programs $group.Guesses
    }
    $groups.Values
}

# A packet of this computer with an address that the physical adapters do
# not have, the tunnel's for example, went out by a route it should not
# have taken. One row per source, protocol and remote address.
function Get-ForeignRows($Flows) {
    $Flows |
        Where-Object {
            $_.Direction -eq 'out' -and $_.Local -and @('0.0.0.0', '::') -notcontains $_.Local -and
            -not $ownAddresses.Contains($_.Local)
        } |
        Group-Object Local, Protocol, Remote |
        ForEach-Object {
            $first = $_.Group[0]
            $exact = New-Object 'System.Collections.Generic.SortedSet[string]'
            $guesses = New-Object 'System.Collections.Generic.SortedSet[string]'
            Add-FlowPrograms $_.Group $exact $guesses
            [pscustomobject]@{
                Source   = Get-IpLabel $first.Local
                Remote   = Get-IpLabel $first.Remote
                Protocol = $first.Protocol
                Out      = ($_.Group | Measure-Object Packets -Sum).Sum
                Programs = Format-Programs $exact $guesses
            }
        }
}

# --- addresses ---------------------------------------------------------------

$publicLabels = @{}

function Get-IpClass([string]$Ip) {
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

# Shared address space of the provider (CGNAT) is not the local network.
function Test-Internet([string]$Ip) {
    @('public', 'cgnat') -contains (Get-IpClass $Ip)
}

function Get-IpLabel([string]$Ip) {
    if (-not $Ip) { return '-' }
    if ($probeAddresses -contains $Ip) { return "$Ip (probe)" }
    if ((Get-IpClass $Ip) -ne 'public') { return $Ip }
    if (-not $publicLabels.ContainsKey($Ip)) {
        $publicLabels[$Ip] = 'PUB-{0:D2}' -f ($publicLabels.Count + 1)
    }
    $publicLabels[$Ip]
}

function Format-Port([string]$Protocol, [int]$Port) {
    if ($Port -lt 0) { return '-' }
    if ($Protocol -like 'ICMP*') { return "type $Port" }
    if ($Port -lt 10000) { "$Port" } else { 'high' }
}

# --- record ------------------------------------------------------------------

$work = $null
$probeResults = @()
try {
    if ($Read) {
        $pcap = (Resolve-Path -LiteralPath $Read).Path
    }
    else {
        $work = Join-Path $env:TEMP ('stopinet-leaks-{0:yyyyMMdd-HHmmss}' -f (Get-Date))
        New-Item -ItemType Directory -Path $work | Out-Null
        $etl = Join-Path $work 'capture.etl'
        $pcap = Join-Path $work 'capture.pcapng'

        $capturing = $false
        $auditBefore = $null
        $job = $null
        try {
            $since = Get-Date
            if (-not $NoAudit) {
                $auditBefore = Get-AuditValue
                if (-not (Set-AuditValue ($auditBefore -bor 1))) { throw 'auditpol /set failed.' }
            }
            Add-OwnAddresses
            $output = pktmon start --capture --comp nics --pkt-size 128 --file-name $etl | Out-String
            if ($LASTEXITCODE -ne 0) {
                throw "pktmon start failed. If another capture is running, pktmon stop ends it.`n$output"
            }
            $capturing = $true
            if (-not $NoProbe) {
                $job = Start-Job -ScriptBlock $probeScript -ArgumentList $probeV4, $probeV6, $gateway
            }
            Write-Host "Recording for $Seconds s. Do what you want to check now."
            for ($left = $Seconds; $left -gt 0; $left--) {
                Write-Progress -Activity 'Recording what leaves through the physical adapters' -SecondsRemaining $left
                $tick = [Diagnostics.Stopwatch]::StartNew()
                Read-Owners
                $rest = 1000 - $tick.ElapsedMilliseconds
                if ($rest -gt 0) { Start-Sleep -Milliseconds $rest }
            }
            Write-Progress -Activity 'Recording what leaves through the physical adapters' -Completed
        }
        finally {
            if ($job) {
                Stop-Job $job
                $probeResults = @(Receive-Job $job -ErrorAction SilentlyContinue)
                Remove-Job $job -Force
            }
            if ($capturing) {
                pktmon stop | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host 'Capture stopped.'
                } else {
                    Write-Host 'pktmon stop failed. Run it once more: pktmon stop'
                }
            }
            if ($null -ne $auditBefore) {
                if (Set-AuditValue $auditBefore) {
                    Write-Host 'Audit setting restored.'
                } else {
                    Write-Host "Could not restore the audit setting. It was $auditBefore (0 none, 1 success, 2 failure, 3 both)."
                }
            }
        }

        Write-Host 'Converting the capture...'
        pktmon etl2pcap $etl --out $pcap | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pcap)) {
            throw 'pktmon etl2pcap failed.'
        }
        Add-OwnAddresses
        $eventCount = 0
        if (-not $NoAudit) {
            Write-Host 'Reading connection events...'
            $eventCount = Read-Connections $since
        }
    }
    Add-OwnAddresses
    Write-Host 'Reading the capture...'

    $capture = [StopinetLeaks.Pcapng]::Read($pcap, $macs)

    # --- report --------------------------------------------------------------

    # Labels go to the busiest addresses first, so PUB-01 is usually the
    # VPN server.
    $groups = @(Group-Flows $capture.Flows)
    $sent = @($groups | Where-Object { $_.Out -gt 0 } | Sort-Object Out -Descending)
    $received = @($groups | Where-Object { $_.Out -eq 0 })
    $rows = foreach ($group in $sent) {
        [pscustomobject]@{
            Remote   = Get-IpLabel $group.Address
            Protocol = $group.Protocol
            Port     = $group.Port
            Out      = $group.Out
            In       = $group.In
            Programs = Format-Programs $group.Programs $group.Guesses
            Internet = Test-Internet $group.Address
        }
    }
    $columns = 'Remote', 'Protocol', 'Port', 'Out', 'In', 'Programs'

    $adapterNames = ($adapters | ForEach-Object { '{0} ({1})' -f $_.Name, $_.InterfaceDescription }) -join ', '
    ''
    if ($Read) { "Capture $Read, adapters $adapterNames." } else { "Recorded $Seconds s on $adapterNames." }
    "Frames: $($capture.Frames) recorded, $($capture.Wire) through the physical adapters."
    if ($capture.OtherLinkTypes.Count -gt 0) {
        $other = foreach ($type in $capture.OtherLinkTypes.Keys) {
            'link type {0}: {1}' -f $type, $capture.OtherLinkTypes[$type]
        }
        "Not read, not Ethernet (the tunnel adapter can be one of them): $($other -join ', ')."
    }
    if ($Read -or $NoAudit) {
        'No connection events: names in [brackets] only owned the local port at some time.'
    } else {
        "Programs from $eventCount connection events; names in [brackets] only owned the local port at some time."
    }
    if ($capture.Wire -eq 0) {
        ''
        'WARNING: nothing went through the physical adapters, not even DHCP or ARP.'
        'The capture does not see them, so this report proves nothing.'
    }

    $foreign = @(Get-ForeignRows $capture.Flows)
    if ($foreign) {
        ''
        'WARNING: sent with a source address that the physical adapters do not have:'
        ''
        ($foreign | Format-Table -AutoSize -Wrap | Out-String -Width 300).Trim()
    }

    ''
    'Sent to the internet (public addresses):'
    $internet = @($rows | Where-Object Internet)
    if ($internet) {
        ($internet | Format-Table $columns -AutoSize -Wrap | Out-String -Width 300).Trim()
        ''
    } else {
        '(none)'
        ''
    }

    'Sent to the local network:'
    $local = @($rows | Where-Object { -not $_.Internet })
    if ($local) {
        ($local | Format-Table $columns -AutoSize -Wrap | Out-String -Width 300).Trim()
        ''
    } else {
        '(none)'
        ''
    }

    if ($received) {
        $packets = ($received | Measure-Object In -Sum).Sum
        "Not shown: $packets packets that only came in and were never answered."
        ''
    }

    if ($probeResults) {
        'Probes (an ordinary program; succeeded means it got through, by any way):'
        ''
        ($probeResults |
            Group-Object Probe |
            ForEach-Object {
                [pscustomobject]@{
                    Probe     = $_.Name
                    Succeeded = '{0} of {1}' -f @($_.Group | Where-Object Ok).Count, $_.Count
                }
            } |
            Format-Table -AutoSize |
            Out-String -Width 300).Trim()
        ''
    }

    if ($work -and $Keep) {
        "Capture kept in $work. It contains real addresses."
    }
}
finally {
    if ($work -and -not $Keep) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
