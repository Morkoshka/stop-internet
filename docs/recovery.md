# Recovery guide

English | [Русский](recovery.ru.md)

What to do when the internet does not work and stop-internet may be the
reason: from the quickest step to the last resort. None of the steps needs
the network.

Copies of this guide: `C:\Program Files\stop-internet\docs` and the Start
menu ("stop-internet - recovery guide") on the computer, the
[wiki](https://github.com/Morkoshka/stop-internet/wiki) for a phone.

Commands are for PowerShell started as administrator (Win+X, "Terminal
(Admin)"). The program is not on `PATH`; this makes the short `stopinet`
command work in that window, and changes nothing in the system:

```powershell
Set-Alias stopinet 'C:\Program Files\stop-internet\stopinet.exe'
```

## First, look at the icon

- **Green with a check mark.** stop-internet lets the internet through the
  VPN. If nothing loads, look at the VPN client first. One case is still
  stop-internet: the client was updated or moved, and its tunnel daemon is
  no longer where the configuration says, see
  [The tunnel is up, but nothing loads](#the-tunnel-is-up-but-nothing-loads).
- **Red with a cross.** Blocked on purpose: the tunnel is down in "tunnel
  only" mode, or the service is not running. The tooltip says which.
  Connect the VPN client, or go on below.
- **Grey with a dash.** Protection is off, stop-internet blocks nothing.
- **No icon.** It was closed or did not start; start it from the Start
  menu ("stop-internet"). Protection works without it.

## 1. Turn protection off for a while

Tray menu → **Normal internet** → "For 15 minutes", "For 1 hour" or "Until
reboot or sleep", then confirm the UAC prompt. It ends by itself, and also
at every reboot, wake-up from sleep and sign-in. It needs the running
service.

The same from the terminal, until the next reboot:

```powershell
stopinet mode normal --minutes 0
```

## 2. Emergency off

When the service does not run or does not answer, its menu cannot help.

- Start menu → **stop-internet - emergency off** → "Yes" → UAC prompt.
- Or in the terminal:

  ```powershell
  stopinet panic
  ```

It stops the service and removes every filter of stop-internet, the
persistent and boot-time ones included. The service stays installed, so
protection returns at the next start of Windows or of the service:

```powershell
Start-Service stopinet
```

To keep it off over reboots, for example while you fix the configuration,
disable the service as well, and set it back afterwards:

```powershell
Set-Service stopinet -StartupType Disabled
stopinet panic

# later, to turn protection on again
Set-Service stopinet -StartupType Automatic
Start-Service stopinet
```

## 3. Uninstall

Settings → Apps → Installed apps → **stop-internet** → Uninstall. Installed
from the source, without the installer: `stopinet uninstall`.

This removes the service, every filter, the autostart of the icon and the
programs. The installer asks whether to delete the configuration and the
log too; `stopinet uninstall` keeps them. If a step fails, the uninstall
stops and the programs stay, so that it can be run again or
`stopinet panic` can be used.

## Common causes

### After editing the configuration

The configuration, `C:\ProgramData\stop-internet\config.toml`, is read when
the service starts. Only administrators can change it, so open it with an
editor started as administrator. Check it, then restart the service:

```powershell
stopinet policy
Restart-Service stopinet
```

`policy` prints the rules or the error in the file. While the service
restarts, the baseline keeps blocking.

### The service does not start

The icon is red with "Service stopped", `stopinet status` shows the same.
The persistent baseline then blocks everything except loopback, DHCP and
the apps in the `direct` list: that is fail-closed, by design. The reason
is at the end of the service log, `C:\ProgramData\stop-internet\service.log`
(tray menu → Service log). Most often it is an error in the configuration:
fix it as above and start the service. If that does not help, use
[Emergency off](#2-emergency-off).

### The tunnel is up, but nothing loads

The tunnel daemon of the VPN client (`[client] tunnel_apps`, for Happ
`happd.exe`) is not at the path in the configuration, so stop-internet
blocks it. This happens when the client is installed elsewhere or moves
its files in an update. The service log then has lines like
`note: app happd.exe skipped`. Correct the path, check that the file is
there and restart the service:

```powershell
Test-Path 'C:\Program Files\FlyFrogLLC\Happ\happd.exe'
```

The same goes for `proxy_apps` in proxy mode and for the apps in the
`direct` list.

### The icon stays red with the VPN connected

stop-internet does not see the tunnel adapter: its name or driver is not
the one in `[tunnel]`. `stopinet status` shows the tunnel and, when it is
down, why. The names of all adapters:

```powershell
Get-NetAdapter -IncludeHidden | Format-Table Name, InterfaceDescription, Status
```

### A program works only through the VPN

That is the point of stop-internet. A program that must go out directly,
also when the tunnel drops (a game, for example), goes into the `direct`
list with its full path. It usually also has to be excluded from the
tunnel in the VPN client itself.

## The programs are missing

If `C:\Program Files\stop-internet` was deleted without uninstalling, or an
antivirus removed a program, the persistent filters stay and keep blocking,
and nothing on the computer removes them.

1. Run the installer again, `stop-internet-<version>-setup.exe`; it needs
   no network. It puts the programs back and starts the service. Then use
   any step above, or uninstall.
2. No installer at hand: download it on another device from the
   [releases](https://github.com/Morkoshka/stop-internet/releases) and
   bring it over on a USB stick, or from a phone over a USB cable.

Keep the installer of the installed version, for example in Downloads.

## Check that nothing is left

```powershell
stopinet status
```

After an emergency off or an uninstall: `wfp: provider none, sublayer none`
and `filters: 0 persistent, 0 boot-time, 0 session`.

Without `stopinet.exe`, Windows can list every WFP filter itself. This
writes `filters.xml` into the current folder; the objects of stop-internet
have "stop-internet" in their names:

```powershell
cd $env:TEMP
netsh wfp show filters
Select-String -Path filters.xml -Pattern 'stop-internet' -SimpleMatch | Measure-Object
```

A count of 0 means no filter of stop-internet is left.
