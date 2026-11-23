# Manual tests

English | [Русский](testing.ru.md)

Everything that installs filters or services is tested by hand on a real
machine. Unit tests cover the logic; these steps cover what only Windows can
show. Each step says what it changes, how to undo it and what to expect.

This page covers the Windows service (roadmap step 4) and the tray icon with
mode switching (step 5). The full checklist with traffic captures comes with
step 7.

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
| C1 | `cargo build --release`, then `.\target\release\stopinet.exe install` | "tray icon set to start at every sign-in", "service running", "tray icon started". A colored dot appears in the notification area, maybe under the ^ arrow (drag it next to the clock to keep it in view). Changes: `stopinet-tray.exe` in `C:\Program Files\stop-internet`, the value `stop-internet` in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. Undo: `stopinet uninstall`, or turn off `stopinet-tray` in Task Manager, Startup apps. |
| C2 | Hover over the icon; `stopinet status` | With Happ connected: green dot, tooltip "Только туннель: интернет через VPN"; `status` shows `mode: tunnel only, tunnel up`. |
| C3 | Disconnect Happ, then connect again | Within about 2 s the dot turns red, "туннеля нет, интернет закрыт"; after the reconnect it is green again. |
| C4 | In an ordinary PowerShell: `& 'C:\Program Files\stop-internet\stopinet.exe' status`, then the same with `mode normal --minutes 1` | `status` shows the mode too: the pipe admits the interactive user. `mode normal` is refused: "normal internet lowers protection: run this from an elevated terminal". The log shows "normal internet refused". Nothing changes. |
| C5 | Tray menu: Прокси | The round mark moves to Прокси, the dot stays green; the log shows "mode Proxy asked". With Happ in system proxy mode (TUN off) sites load through the proxy; apps that ignore the proxy stay blocked. Back: menu, Только туннель. |
| C6 | Menu: Обычный интернет, На 15 минут; answer **No** in the UAC prompt (program `stopinet-tray.exe`, unknown publisher) | Nothing changes. |
| C7 | The same, answer **Yes** | The dot turns grey, tooltip "Обычный интернет: защита выключена, ещё 15 мин"; with Happ disconnected sites load directly. Log: "normal internet for 15 min, asked by an administrator". Back: menu, Только туннель, without a prompt. |
| C8 | Disconnect Happ. In the elevated window: `stopinet mode normal --minutes 1`; start a large download or a video in the browser; wait | After a minute and at most 2 s more the dot turns red, the log shows "normal internet time is up", and the download or video stops: returning to a protected mode cuts direct connections. Connect Happ again. |
| C9 | Menu: Прокси; sleep, wake up | Still Прокси (log "woke up, mode Proxy"). Then menu: Обычный интернет, До перезагрузки или сна (UAC), sleep and wake up again: log "woke up, mode TunnelOnly", the dot is green or red. |
| C10 | Normal internet until reboot as in C9, then sign out (Start, your name, Sign out) and sign in | The log shows "user logged on, mode TunnelOnly". The tray icon starts by itself after the sign-in. |
| C11 | Normal internet until reboot, then shut down and power on (Fast Startup) | Tunnel only after the power-on: the log shows a new start of the service or "user logged on, mode TunnelOnly". |
| C12 | `Stop-Service stopinet`, look at the icon, then `Start-Service stopinet` | While stopped: red dot, "Служба stop-internet остановлена", the menu offers only the log and closing. After the start the icon follows the tunnel again within a second or two. |
| C13 | Menu: Журнал службы; then menu: Закрыть значок | The log opens in Notepad. Closing removes the icon only; `stopinet status` still shows the service running. Start the icon again with Win+R: `"C:\Program Files\stop-internet\stopinet-tray.exe"`. Starting it a second time adds no second icon. |
| C14 | Optional: `stopinet uninstall`, then install again as in C1 | The icon disappears, "tray icon no longer starts at sign-in"; Task Manager no longer lists it under Startup apps. `install` brings back the service, the baseline and the icon. |
