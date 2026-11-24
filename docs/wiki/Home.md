**stop-internet** is a fail-closed kill switch for TUN-based VPN clients on
Windows, built on the Windows Filtering Platform. While protection is on,
applications reach the internet only through the tunnel; when the tunnel,
the VPN client or stop-internet fails, traffic stays blocked.

**stop-internet** — kill switch для VPN-клиентов с TUN-адаптером под
Windows на основе Windows Filtering Platform. Пока защита включена,
приложения выходят в интернет только через туннель; если упал туннель,
VPN-клиент или сам stop-internet, трафик остаётся заблокированным.

| English | Русский |
|---|---|
| [Design](Design): threat model, modes, rules, WFP filters, lifecycle | [Архитектура](Архитектура): модель угроз, режимы, правила, фильтры WFP, жизненный цикл |
| [Manual tests](Manual-tests): testing the service on a real machine | [Ручные тесты](Ручные-тесты): проверка службы на реальной машине |
| [Recovery](Recovery): what to do when the internet does not work | [Восстановление](Восстановление): что делать, если не работает интернет |

Code, build instructions and the roadmap are in the
[repository](https://github.com/Morkoshka/stop-internet):
[README](https://github.com/Morkoshka/stop-internet/blob/main/README.md) ·
[README на русском](https://github.com/Morkoshka/stop-internet/blob/main/README.ru.md).
