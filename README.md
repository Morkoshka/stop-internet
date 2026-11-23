# stop-internet

English | [Русский](README.ru.md)

Fail-closed kill switch for TUN-based VPN clients on Windows, built on the
Windows Filtering Platform (WFP).

> **Status:** early development. The firewall engine and the Windows service
> are implemented and being tested by hand; the tray icon is next. Not ready
> for daily use.

## Why

A TUN-based VPN client routes traffic into its virtual adapter, but nothing
stops applications from using the physical adapter when the tunnel is not
there. Diagnostics with [Happ](https://www.happ.su) 4.3 on Windows showed two
real leaks:

- connections opened during a reconnect stayed on the physical adapter after
  the tunnel came back;
- a Windows system service kept a connection from boot outside the tunnel for
  the whole session.

Built-in protections of VPN cores are removed when the core exits, which is
exactly when they are needed.

## What it does

- While protection is on, applications reach the internet only through the
  tunnel. When the tunnel goes down, traffic is blocked at once.
- The routing of the VPN client keeps working: rule sets, direct rules and
  per-app exclusions are untouched.
- Apps excluded from the tunnel keep working when it drops, for example a
  game.
- Fail-closed: if the VPN client, its core or stop-internet crashes, or the
  machine reboots, the block stays.
- DNS to the router, IPv6 and Teredo outside the tunnel are blocked.
- A tray icon shows the state and switches modes; turning protection off
  needs a UAC prompt and is time-limited.

## Modes

| Mode | Internet for applications | Icon |
|---|---|---|
| Tunnel only (default after every boot and wake-up) | only through the tunnel | green / red |
| Proxy | through the tunnel or the VPN client's system proxy | green / red |
| Normal internet (15 min, 1 h or until reboot) | unrestricted | grey |

## How it works

```mermaid
flowchart LR
    Tray["stopinet-tray<br/>(user session)"] -- named pipe --> Svc["stopinet-service<br/>(LocalSystem)"]
    CLI["stopinet CLI"] -- named pipe --> Svc
    Svc -- "WFP filters" --> BFE["Base Filtering Engine"]
    Win["Windows"] -- "adapter and power events" --> Svc
```

The service keeps a persistent baseline of WFP filters that blocks everything
except loopback, DHCP, IPv6 neighbor discovery and excluded apps. When the
tunnel adapter is up, it adds session filters for the tunnel adapter and for
the VPN daemon that carries the tunnel. The baseline survives reboots and
crashes; session filters vanish with the service.

See [docs/design.md](docs/design.md) for the threat model, the rule table and
the WFP mapping. The same documents, in English and Russian, are in the
[wiki](https://github.com/Morkoshka/stop-internet/wiki).

## Building

Requirements: Windows 10 or 11, Rust (MSVC toolchain).

```powershell
cargo build --release
cargo test
```

Dry run of the policy, without touching the system:

```powershell
cargo run -p stopinet-cli -- policy --config config/stopinet.example.toml --mode tunnel --tunnel down
```

Service, from an elevated terminal (see [docs/testing.md](docs/testing.md)
before the first run):

```powershell
.\target\release\stopinet.exe install --config <your config> --session-only
.\target\release\stopinet.exe status
.\target\release\stopinet.exe panic
.\target\release\stopinet.exe uninstall
```

`--session-only` keeps nothing persistent and is meant for testing; without
it the baseline survives reboots and service crashes. `panic` removes every
filter in an emergency.

## Repository layout

| Path | Content |
|---|---|
| `crates/stopinet-core` | configuration and policy model |
| `crates/stopinet-win` | WFP engine, persistent baseline, tunnel adapter lookup |
| `crates/stopinet-service` | Windows service |
| `crates/stopinet-tray` | tray icon (planned) |
| `crates/stopinet-cli` | `stopinet` command-line tool |
| `config/` | example configuration |
| `docs/` | design, manual tests |
| `tools/diag.ps1` | read-only, anonymized network diagnostics |
| `tools/blocked.ps1` | anonymized report of blocked connections (turns on auditing while it runs) |

## Roadmap

- [x] Design, configuration, policy model
- [x] WFP engine and CLI with automatic rollback
- [x] Tunnel monitor
- [ ] Windows service: persistent and boot-time filters (implemented, testing)
- [ ] Tray icon, mode switching, UAC, timed normal mode
- [ ] Installer package and recovery guide
- [ ] Test checklist and releases

## License

[MIT](LICENSE)
