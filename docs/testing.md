# Manual tests

English | [Русский](testing.ru.md)

Everything that installs filters or services is tested by hand on a real
machine. Unit tests cover the logic; these steps cover what only Windows can
show. Each step says what it changes, how to undo it and what to expect.

This page covers the Windows service (roadmap step 4). The full checklist
with traffic captures comes with step 7.

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
  - `stopinet status`: service state, objects of stop-internet in the Base
    Filtering Engine, tunnel state. Changes nothing.
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
