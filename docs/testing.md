# Manual tests

English | [Русский](testing.ru.md)

Everything that installs filters or services is tested by hand on a real
machine. Unit tests cover the logic; these steps cover what only Windows can
show. Each step says what it changes, how to undo it and what to expect.

This page covers the Windows service (roadmap step 4), the tray icon with
mode switching and the automatic choice of the mode (step 5), the
installer with the emergency switch-off (step 6), captures of what leaves
through the physical adapter, and the release (step 7).

## Before you start

- Build: `cargo build --release`. Run the commands below from the
  repository folder in an **elevated** PowerShell, and keep that window open
  for the whole test. To make the short `stopinet` command work in that
  window, run this after the install (step A1):

  ```powershell
  Set-Alias stopinet 'C:\Program Files\stop-internet\stopinet.exe'
  ```

  It is an alias for the current PowerShell window only and changes nothing
  in the system. Before the install, use `.\target\release\stopinet.exe`
  instead of `stopinet`.
- Put your configuration in `config\stopinet.local.toml` (ignored by git)
  and check it with a trial first: `.\target\release\stopinet.exe trial
  --config config\stopinet.local.toml`.
- Emergency exit, works without network:

  ```powershell
  & 'C:\Program Files\stop-internet\stopinet.exe' panic
  ```

  It stops the service and removes every filter of stop-internet,
  persistent ones included. `.\target\release\stopinet.exe panic` does the
  same.
- The tray speaks the display language of Windows: Russian on a Russian
  Windows, English otherwise. The steps quote the English texts; the
  [Russian checklist](testing.ru.md) quotes the Russian ones.
- What to look at:
  - `stopinet status`: service state, mode, objects of stop-internet in the
    Base Filtering Engine, tunnel state. Changes nothing.
  - `Get-Content C:\ProgramData\stop-internet\service.log -Tail 20`: the
    service log. It contains no addresses and is safe to share.

## A. Session-only service

Nothing persistent: stopping the service, a crash or a reboot leaves the
machine without stop-internet filters.

| # | Do | Expect |
|---|---|---|
| A1 | `.\target\release\stopinet.exe install --config config\stopinet.local.toml --session-only` | "service running". Changes: programs in `C:\Program Files\stop-internet`, configuration in `C:\ProgramData\stop-internet` (writable by administrators only), service `stopinet` set to start automatically. Undo: `stopinet uninstall`. |
| A2 | `stopinet status` | service running, start AutoStart, session-only; provider and sublayer "session"; 0 persistent, 0 boot-time, some session filters; tunnel as in Happ. |
| A3 | Disconnect Happ, open a site, connect again | Sites stop loading within about 2 s; after reconnecting they load again. The log shows "tunnel down" and "tunnel up". |
| A4 | `Stop-Service stopinet`, then `stopinet status` | All filters gone, internet unrestricted. `Start-Service stopinet` brings them back. |
| A5 | `Stop-Process -Name stopinet-service -Force` | Within about 5 s the service runs again (`stopinet status`), the log shows a new start. |
| A6 | Sleep, wake up | The log shows "woke up, mode TunnelOnly"; the tunnel is followed as before. |
| A7 | Restart Windows | The service starts by itself; until it does, the internet is open (session-only). |

## B. Persistent baseline

| # | Do | Expect |
|---|---|---|
| B1 | `stopinet install` (keeps the installed configuration) | "service running". `stopinet status`: provider and sublayer "persistent", some persistent filters, the same number of boot-time copies (or 0 and a note in the log), session filters on top. Undo: `stopinet panic` or `stopinet uninstall`. |
| B2 | **Escape hatch first:** `stopinet panic`, then `stopinet status` | No provider, no sublayer, 0 filters; internet unrestricted. `Start-Service stopinet` returns to the state of B1. Do not go on unless this works. |
| B3 | `Stop-Service stopinet` | Internet blocked, Happ connected or not. Apps in `direct` keep working only while Happ is disconnected: a connected Happ carries them through `happd.exe`, which is blocked now. `stopinet status`: persistent filters stay, 0 session. `Start-Service stopinet` restores the internet through the tunnel. |
| B4 | `Stop-Process -Name stopinet-service -Force` | Blocked for about 5 s, then the service runs again and the tunnel works. |
| B5 | Disconnect Happ; run `Resolve-DnsName example.com -DnsOnly` | The name does not resolve and sites do not load while the tunnel is down; an app from `direct` keeps its connections. Connect again: everything works. |
| B6 | Sleep, wake up | As A6; nothing passes before the tunnel is back. |
| B7 | Restart Windows, then shut down and power on (Fast Startup) | Before Happ connects nothing loads; after it connects everything works. The log shows a new start of the service and the baseline both times. |
| B8 | `stopinet uninstall` | "service removed", every filter removed, programs deleted; configuration and log stay in `C:\ProgramData\stop-internet`. |

## C. Tray icon and modes

The service is installed with the persistent baseline, as after B1. Build the
new version and install it from the elevated window; the installed
configuration stays. A few steps need an ordinary PowerShell window, not
elevated; they say so.

| # | Do | Expect |
|---|---|---|
| C1 | `cargo build --release`, then `.\target\release\stopinet.exe install` | "tray icon set to start at every sign-in", "service running", "tray icon started". A shield appears in the notification area, maybe under the ^ arrow (drag it next to the clock to keep it in view). Changes: `stopinet-tray.exe` in `C:\Program Files\stop-internet`, the value `stop-internet` in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. Undo: `stopinet uninstall`, or turn off `stopinet-tray` in Task Manager, Startup apps. |
| C2 | Hover over the icon; `stopinet status` | With Happ connected: a green shield with a check mark, tooltip "Tunnel only", "internet through the VPN"; `status` shows `mode: tunnel only, tunnel up`. A click opens the menu with its left edge at the cursor and wholly above the taskbar; with the dark app theme of Windows the menu is dark. |
| C3 | Disconnect Happ, then connect again | Within about 2 s the shield turns red with a cross, "no tunnel, internet blocked"; after the reconnect it is green again. |
| C4 | In an ordinary PowerShell: `& 'C:\Program Files\stop-internet\stopinet.exe' status`, then the same with `mode normal --minutes 1` | `status` shows the mode too: the pipe admits the interactive user. `mode normal` is refused: "normal internet lowers protection: run this from an elevated terminal". The log shows "normal internet refused". Nothing changes. |
| C5 | Tray menu: Proxy | The round mark moves to Proxy, the shield stays green; the log shows "mode Proxy asked". With Happ in system proxy mode (TUN off) sites load through the proxy, and `stopinet policy --mode proxy` lists "Windows DNS client (svchost.exe, port 53)"; apps that ignore the proxy, for example Telegram without a proxy set, stay blocked. Back: menu, Tunnel only. |
| C6 | Menu: Normal internet, For 15 minutes; answer **No** in the UAC prompt (program `stopinet-tray.exe`, unknown publisher) | Nothing changes. |
| C7 | The same, answer **Yes** | The shield turns grey with a dash, tooltip "Protection off", "15 min left"; with Happ disconnected sites load directly. Log: "normal internet for 15 min, asked by an administrator". Back: menu, Tunnel only, without a prompt. |
| C8 | Disconnect Happ. In the elevated window: `stopinet mode normal --minutes 1`; start a large download or a video in the browser; wait | After a minute and at most 2 s more the shield turns red, the log shows "normal internet time is up", and the download or video stops: returning to a protected mode cuts direct connections. Connect Happ again. |
| C9 | Menu: Proxy; sleep, wake up | Still Proxy (log "woke up, mode Proxy"). Then menu: Normal internet, Until reboot or sleep (UAC), sleep and wake up again: log "woke up, mode TunnelOnly", the shield is green or red. |
| C10 | Normal internet until reboot as in C9, then sign out (Start, your name, Sign out) and sign in | The log shows "user logged on, mode TunnelOnly". The tray icon starts by itself after the sign-in. |
| C11 | Normal internet until reboot, then shut down and power on (Fast Startup) | Tunnel only after the power-on: the log shows a new start of the service or "user logged on, mode TunnelOnly". |
| C12 | `Stop-Service stopinet`, look at the icon, then `Start-Service stopinet` | While stopped: a red shield, "Service stopped", the menu offers only the log and closing. After the start the icon follows the tunnel again within a second or two. |
| C13 | Menu: Service log; then menu: Close icon | The log opens in Notepad. Closing removes the icon only; `stopinet status` still shows the service running. Start the icon again with Win+R: `"C:\Program Files\stop-internet\stopinet-tray.exe"`. Starting it a second time adds no second icon. |
| C14 | Optional: `stopinet uninstall`, then install again as in C1 | The icon disappears, "tray icon no longer starts at sign-in"; Task Manager no longer lists it under Startup apps. `install` brings back the service, the baseline and the icon. |
| C15 | Settings, Personalization, Colors: switch "Choose your mode" between Dark and Light, open the tray menu after each switch | The menu follows the app theme: dark, then light. Switch back afterwards. |

## D. Automatic choice of the mode

"Automatic" in the tray menu switches between tunnel-only and proxy mode
by itself, following the system proxy of Windows. What Happ sets can be seen
in Settings, Network & internet, Proxy: in system proxy mode "Use a proxy
server" is on with a loopback address such as 127.0.0.1. Start with Happ
connected in TUN mode. Choosing a mode in the menu turns "Automatic"
off; turn it on again before the next step.

| # | Do | Expect |
|---|---|---|
| D1 | `cargo build --release`, then `.\target\release\stopinet.exe install`; open the tray menu | "Automatic" has a check mark, the round mark is on "Tunnel only", the shield is green. Nothing new is written: the setting appears in `HKCU\Software\stop-internet` only when it changes. |
| D2 | In Happ, switch to system proxy mode (TUN off) | Within about 2 s the round mark moves to "Proxy", the shield is green, "only the client's proxy is open"; sites load. Log: "mode Proxy asked". Between TUN off and the proxy on, the shield may turn red for a moment. |
| D3 | In Happ, switch back to TUN | The mark returns to "Tunnel only", the shield is green once the tunnel is up; log: "mode TunnelOnly asked". If the mark stays on "Proxy", Happ keeps the system proxy on in TUN mode as well: harmless, but worth noting. |
| D4 | In system proxy mode, disconnect Happ; then connect again | "Tunnel only", red, sites do not load; after the reconnect "Proxy" again. If the mark stays on "Proxy" after the disconnect, Happ left the system proxy on: still safe, nothing listens on it. |
| D5 | Happ in system proxy mode. Menu: "Tunnel only" | The check mark of "Automatic" disappears, the mode stays "Tunnel only", sites stop loading. In an ordinary PowerShell, `Get-ItemProperty HKCU:\Software\stop-internet` shows `FollowSystemProxy : 0`. Then menu: "Automatic": the check mark is back, "Proxy" within a second, `FollowSystemProxy : 1`. Undo: `Remove-Item HKCU:\Software\stop-internet` removes the setting, which then counts as on. |
| D6 | Happ in system proxy mode, "Automatic" on. In the elevated window: `stopinet mode normal --minutes 1` | The shield stays grey for the whole minute: the tray leaves normal internet alone. Then the log shows "normal internet time is up" and, within about 2 s, "mode Proxy asked"; the shield is green. |
| D7 | Happ in TUN mode, "Automatic" on. In the elevated window: `stopinet mode proxy` | Within a second the tray sets "Tunnel only" again; the log shows both requests. This is expected while "Automatic" is on. |
| D8 | Happ in system proxy mode. `Restart-Service stopinet` | The log shows a new start of the service in tunnel-only mode, and within about 2 s "mode Proxy asked". |
| D9 | Menu: "Close icon", start the icon again as in C13, open the menu | "Automatic" is as it was. Turn it off, close the icon and start it again: still off. Turn it on at the end. |

## E. Installer and recovery

The installer takes over an installation made with `stopinet install`, so
start as after D1: the persistent baseline and your configuration
installed. Build it with Inno Setup 6.4 or later (`winget install --id
JRSoftware.InnoSetup -e`); building changes nothing outside `target\`.
Steps E2 to E7 work as well when started by double-clicking the installer
in Explorer.

| # | Do | Expect |
|---|---|---|
| E1 | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build-installer.ps1` | "Built target\installer\stop-internet-0.1.0-setup.exe". |
| E2 | `.\target\installer\stop-internet-0.1.0-setup.exe`; UAC: Yes (unknown publisher); keep "Trial mode" off; Install | The wizard speaks the display language of Windows. "Ready to Install" shows "Configuration: keep C:\ProgramData\stop-internet\config.toml". A few seconds of "Preparing to Install": the icon disappears and comes back. `stopinet status`: running, persistent, the same filters as before; the log shows a stop and a new start; the configuration is unchanged. Changes: Start menu folder "stop-internet" with three shortcuts, "stop-internet" in Settings, Apps, `docs\`, `config.example.toml`, `LICENSE.txt` and `unins000.*` in `C:\Program Files\stop-internet`. Undo: E9. |
| E3 | Start menu: "stop-internet - recovery guide"; then "stop-internet" | The guide opens in Notepad, in the language of the wizard. The second shortcut adds no second icon. |
| E4 | Run the installer again | As in E2: an upgrade over itself. Settings, Apps still lists stop-internet once. |
| E5 | Start menu: "stop-internet - emergency off". Answer **No**; then again, **Yes**, and **No** in the UAC prompt | Nothing changes, `stopinet status` as before. |
| E6 | The same, **Yes** and UAC **Yes** | A message "Protection is off: the service is stopped and the filters of stop-internet are removed". `stopinet status`: stopped, provider none, 0 filters; the icon is red, "Service stopped"; sites load with Happ disconnected. The `netsh wfp` check of the [recovery guide](recovery.md#check-that-nothing-is-left) counts 0. `Start-Service stopinet`: protected again, the count is above 0. |
| E7 | A broken configuration: `Set-Content $env:TEMP\broken.toml 'tunnel = ['`, then `.\target\installer\stop-internet-0.1.0-setup.exe /CONFIG="$env:TEMP\broken.toml"`, Install | "Ready to Install" names the file. Setup stops on "Preparing to Install" with "stopinet install did not finish" and the parse error. Nothing changes: `stopinet status` as in E2, no second entry in Settings, Apps. Undo: `Remove-Item $env:TEMP\broken.toml`. |
| E8 | Silent upgrade: `(Start-Process .\target\installer\stop-internet-0.1.0-setup.exe '/VERYSILENT' -Wait -PassThru).ExitCode` | `0`, no windows; `stopinet status` as in E2. |
| E9 | Settings, Apps, stop-internet, Uninstall; answer **No** to deleting the configuration | The icon disappears. `Get-Service stopinet` finds nothing, the `netsh wfp` check counts 0, `C:\Program Files\stop-internet` and the Start menu folder are gone, `C:\ProgramData\stop-internet` stays. Sites load with Happ disconnected. |
| E10 | Run the installer with "Trial mode" on | `stopinet status`: session-only, provider "session". `Stop-Service stopinet` removes every filter, `Start-Service stopinet` brings them back. Then run it again with "Trial mode" off (the wizard remembers the last choice): persistent, as in E2. |
| E11 | Run the installer with "Start menu folder" off | Everything as in E4, but the Start menu folder "stop-internet" is gone. Win+R: `"C:\Program Files\stop-internet\stopinet-tray.exe" --panic` asks as in E5; answer **No**. Then run the installer again with the folder on (the wizard remembers the last choice): the folder is back. |

## F. Leaks

`tools\leaks.ps1` shows what the computer sent through its physical
adapter, over the cable or the air. `pktmon`, which comes with Windows,
records the packets. Traffic inside the tunnel does not show up here: in a
protected mode only packets to the VPN server, Windows' own packets for the
local network and the apps from `direct` leave the computer.

While it records, the script tries the network itself every 5 s, like an
ordinary program that knows nothing of the tunnel or the proxy: TCP 443 and
a DNS query to 1.1.1.1, a ping to 1.1.1.1, a DNS query to the router and
TCP 443 to 2606:4700:4700::1111. `-NoProbe` turns this off.

Changes, only while the script runs: a `pktmon` capture, and the audit of
permitted connections (event 5156, Security log), which tells the script
which program opened each connection. At the end, also after Ctrl+C, the
capture stops, the audit setting goes back to what it was, and the capture
files in `%TEMP%` are deleted. The audit writes every permitted
connection, through the tunnel and over loopback too, and on a busy
computer it can push older entries out of the Security log (it keeps 20 MB
by default). With `-NoAudit` the audit stays as it is, but the programs in
the report are only guesses. After the recording the script reads the
events for a while: it says "Reading connection events...", wait for the
report. The report
replaces public addresses with labels PUB-01, PUB-02 and so on, the
busiest first; the probe addresses are shown as they are. The report is
safe to share.

Run it from an elevated window, with the `-Seconds` of each step:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\leaks.ps1 -Seconds 60
```

How to read the report:

- **Sent to the internet**: everything sent to public addresses. In a
  protected mode it holds only `happd` and the apps from `direct`. `happd`
  is Happ itself: its connection to the VPN server (usually PUB-01), its
  other connections (to port 5228, for example) and what it sends directly
  by its own rules: the apps excluded from the tunnel and, if its DNS is
  set up so, DNS queries. While the tunnel is up, stop-internet does not
  restrict `happd`. Any other program is a leak.
- **Sent to the local network**: packets of Windows itself and of the
  network card driver are normal here: ARP, LLDP (EtherType 0x88CC), DHCP
  (port 67), DHCPv6 (547), ICMPv6 types 133–137 (neighbor discovery) and
  143 (MLD), IGMP. A leak is DNS (port 53) to the router, except in proxy
  mode without the tunnel, and mDNS (5353), LLMNR (5355), SSDP (1900) and
  NetBIOS (137, 138): the local network is closed.
- **Out** and **In**: packets sent and received by this computer. Rows with
  incoming packets only are not shown.
- **Programs**: the program that opened that connection, from its audit
  event. A connection opened before the recording started has no event;
  then square brackets name the programs that owned its local port at some
  time during the recording. That is only a guess: ports are reused. Empty
  means unknown, packets of the kernel for example.
- **WARNING** about the source address: a packet left through a physical
  adapter with an address that adapter does not have, the tunnel's for
  example. That must not happen.
- **Probes**: "2 of 12" means 2 attempts out of 12 got somewhere, by any
  way, through the tunnel for example. A leak is a probe address under
  "Sent to the internet" with program `powershell`. With program `happd`,
  Happ itself sent the probe directly.

Boot cannot be checked this way: the capture does not survive a reboot.
B7 checks it.

| # | Do | Expect |
|---|---|---|
| F1 | First check the capture itself. Disconnect Happ; tray menu: Normal internet, For 15 minutes (UAC: Yes); `leaks.ps1 -Seconds 30` | The probes to 1.1.1.1 succeed. "Sent to the internet" lists `1.1.1.1 (probe)`: TCP 443 and UDP 53 with program `powershell`, and ICMP type 8 with program `System` (Windows sends the ping itself); "Sent to the local network" lists UDP 53 to the router. So the capture sees the wire. If `1.1.1.1` is missing or the report has a WARNING, stop here: the other steps would prove nothing. Back: menu, Tunnel only. |
| F2 | Tunnel only, Happ connected. `leaks.ps1 -Seconds 60`; meanwhile open a few sites and a YouTube video (QUIC, UDP 443) | The TCP and DNS probes to 1.1.1.1 succeed, ping and "DNS to the router" do not: the tunnel of Happ does not carry ICMP, and the router is in the local network. "Sent to the internet" holds only program `happd`. If Happ sends DNS directly, it lists UDP 53 from `happd`, to `1.1.1.1 (probe)` too: the provider sees which names programs look up; that is a DNS setting of Happ itself. "Sent to the local network" holds only Windows' own packets. |
| F3 | Disconnect Happ. `leaks.ps1 -Seconds 60`; try to open sites | No probe succeeds. "Sent to the internet" is empty, apart from apps from `direct` if they run. No port 53 under "Sent to the local network". |
| F4 | Kill the client and its core. Connect Happ; `leaks.ps1 -Seconds 90`; after 20 s, in a second elevated window, `Stop-Process -Name xray -Force`, 20 s later `Stop-Process -Name happd -Force` | A report as in F2: the server and `happd`, no new public addresses. After the second command the tunnel goes away and the shield turns red. If Happ starts them again, the report shows the same program `happd`. Connect Happ again at the end. |
| F5 | Pull the cable. Happ connected; `leaks.ps1 -Seconds 90`; after 20 s unplug the network cable, plug it back 15 s later | A report as in F2, plus DHCP and ARP after the cable is back: while Happ reconnected, nothing went to public addresses, connectivity checks of Windows (`svchost`, TCP 80 and 443) included. |
| F6 | Sleep. Happ connected; `leaks.ps1 -Seconds 120`; after 20 s put the computer to sleep, wake it a minute later | After the wake-up the script counts on: time in sleep does not count. A report as in F2, although the probes also ran right after the wake-up, before the tunnel was back: no program but `happd` outside square brackets, and no WARNING about the source address. |
| F7 | The service. Happ disconnected; `leaks.ps1 -Seconds 60`; after 10 s, in a second elevated window, `Stop-Process -Name stopinet-service -Force`; once the service runs again (`stopinet status`), `Stop-Service stopinet` and 10 s later `Start-Service stopinet` | A report as in F3: while the service restarts and while it is stopped, the persistent filters hold. |
| F8 | IPv6 and Teredo: look at the reports of F2 and F3 | No IPv6 addresses and no port 3544 (Teredo) among the public addresses. Without the tunnel the probe to 2606:4700:4700::1111 fails. |
| F9 | An excluded app. Connect Happ, start a game from `direct`; `leaks.ps1 -Seconds 120`; after 40 s disconnect Happ and keep playing | The game stays online. "Sent to the internet" lists its servers: before the disconnect with program `happd` (Happ takes its exclusions out of the tunnel itself), after it with the program of the game. Apart from them, only the VPN server. Connect Happ again at the end. |
| F10 | Proxy. Happ in system proxy mode (TUN off), tray menu: Proxy; `leaks.ps1 -Seconds 60`; open sites | Sites load. "Sent to the internet" holds only the server with program `xray`. DNS from `svchost` to the router, or to the DNS server of the network settings: in this mode system DNS is open on purpose, see the [design](design.md). The probes fail: `powershell` does not use the proxy, and it is not `svchost`. |

## G. Before a release

Release builds come from GitHub Actions, the Release workflow. A version
tag builds the programs and the installer from its commit with the
dependencies of `Cargo.lock`, computes SHA-256, signs a build provenance
attestation and creates a draft release. A person publishes the draft,
after the steps below. The example is for version 0.1.0.

| # | Do | Expect |
|---|---|---|
| G1 | The version in `Cargo.toml` (`[workspace.package]`), then `cargo build`, which updates `Cargo.lock`. In `CHANGELOG.md` and `CHANGELOG.ru.md` replace `## Unreleased` with `## 0.1.0 - <date>` and add an empty `## Unreleased` above it. Preview the release text: `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-notes.ps1 -Version 0.1.0`. Commit and push | The release text in both languages. CI is green. |
| G2 | `git tag -a v0.1.0 -m "stop-internet 0.1.0"`, then `git push origin v0.1.0` | Release starts in Actions; a few minutes later the Releases page has a draft with `stop-internet-0.1.0-setup.exe` and `SHA256SUMS.txt`. If the tag does not match the version, or the changelogs have no section for it, the workflow stops without creating anything: delete the tag (`git push origin :refs/tags/v0.1.0`, then `git tag -d v0.1.0`), fix it, repeat. |
| G3 | Download both files from the page of the draft into an empty folder; there run `Get-FileHash .\stop-internet-0.1.0-setup.exe` and `Get-Content .\SHA256SUMS.txt`; then `gh attestation verify .\stop-internet-0.1.0-setup.exe --repo Morkoshka/stop-internet` | The hashes match (letter case does not matter); `gh` reports a successful verification and names the Release workflow and the tag. |
| G4 | Install the downloaded installer over the current version, as in E2; go through B2, C2, C3, E6 and F1–F3 | As in those steps. |
| G5 | Publish the draft: the button on the page of the release, or `gh release edit v0.1.0 --draft=false` | The release is public and marked Latest; the link to the releases in the [recovery guide](recovery.md) leads to it. |
