# Changelog

English | [Русский](CHANGELOG.ru.md)

Notable changes of stop-internet, newest first. Versions follow
[Semantic Versioning](https://semver.org); while the version starts with
0, a minor version may change behavior. The section of each version
becomes the text of its
[GitHub release](https://github.com/Morkoshka/stop-internet/releases).

## Unreleased

## 0.1.0 - 2026-11-24

The first release.

### Added

- Windows service with a persistent and boot-time baseline of WFP filters:
  without the tunnel only loopback, DHCP, IPv6 neighbor discovery and the
  apps from `direct` get through. The baseline survives crashes and
  reboots; `stopinet panic` removes it.
- Session filters for the tunnel adapter and the VPN daemon while the
  tunnel is up; a drop of the tunnel blocks traffic within about 2
  seconds.
- A packet filter that keeps the tunnel's addresses on the tunnel adapter:
  a connection opened through the tunnel cannot go on sending through the
  physical adapter when the routes of the tunnel go away, as after a
  wake-up.
- Modes: tunnel only, the default after every boot, wake-up and sign-in;
  proxy, for a VPN client in system proxy mode; normal internet for 15
  minutes, an hour or until the next reboot, sleep or sign-in, behind a
  UAC prompt.
- Tray icon in English or Russian: shields for the state, mode switching,
  the automatic choice of the mode by the system proxy, the service log.
- `stopinet` command-line tool: `install`, `uninstall`, `status`, `mode`,
  `panic`, `policy` and `trial`, which tries rules that roll back by
  themselves.
- Installer in English or Russian, with a trial mode, an optional Start
  menu folder with "emergency off" and the recovery guide, and an
  uninstaller that keeps the programs if the filters cannot be removed.
- Design document, recovery guide and the manual test checklist with leak
  tests, in English and Russian.
- Anonymized diagnostics: `tools/diag.ps1` (network), `tools/blocked.ps1`
  (blocked connections) and `tools/leaks.ps1` (what left through the
  physical adapter).

### Known limitations

- The programs and the installer are not signed: SmartScreen may warn, and
  UAC shows "Unknown publisher". The checksum and the attestation of the
  release show that the installer was built from this repository.
- x64 Windows 10 and 11 only; tested on Windows 11 with Happ 4.3.
- In proxy mode without the tunnel the Windows DNS client reaches the DNS
  server directly: the router and the provider see the names programs look
  up.
