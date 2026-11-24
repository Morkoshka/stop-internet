# Manual tests

English | [Русский](testing.ru.md)

Everything that installs filters or services is tested by hand on a real
machine. Unit tests cover the logic; these steps cover what only Windows can
show. Each step says what it changes, how to undo it and what to expect.

This page covers the Windows service (roadmap step 4) and the tray icon with
mode switching and the automatic choice of the mode (step 5). The full
checklist with traffic captures comes with step 7.

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
