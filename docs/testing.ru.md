# Ручные тесты

[English](testing.md) | Русский

Всё, что ставит фильтры или службы, проверяется вручную на реальной машине.
Модульные тесты покрывают логику, а эти шаги — то, что может показать только
Windows. Для каждого шага сказано, что он меняет, как его откатить и чего
ожидать.

Здесь описана проверка службы Windows (шаг 4 плана). Полный чек-лист с
записью трафика появится на шаге 7.

## Перед началом

- Сборка: `cargo build --release`. Команды ниже запускайте из папки
  репозитория в PowerShell **от имени администратора** и не закрывайте это
  окно до конца проверки. Чтобы короткая команда `stopinet` работала в этом
  окне, после установки (шаг A1) выполните:

  ```powershell
  Set-Alias stopinet 'C:\Program Files\stop-internet\stopinet.exe'
  ```

  Это псевдоним только для текущего окна PowerShell, в системе ничего не
  меняется. До установки вместо `stopinet` пишите
  `.\target\release\stopinet.exe`.
- Положите свою конфигурацию в `config\stopinet.local.toml` (git её
  игнорирует) и сначала проверьте её пробным запуском:
  `.\target\release\stopinet.exe trial --config config\stopinet.local.toml`.
- Аварийный выход, работает без сети:

  ```powershell
  & 'C:\Program Files\stop-internet\stopinet.exe' panic
  ```

  Он останавливает службу и снимает все фильтры stop-internet, включая
  постоянные. `.\target\release\stopinet.exe panic` делает то же самое.
- На что смотреть:
  - `stopinet status`: состояние службы, объекты stop-internet в Base
    Filtering Engine, состояние туннеля. Ничего не меняет.
  - `Get-Content C:\ProgramData\stop-internet\service.log -Tail 20`: журнал
    службы. Адресов в нём нет, им можно делиться.

## A. Служба в режиме session-only

Ничего постоянного: остановка службы, её падение или перезагрузка оставляют
машину без фильтров stop-internet.

| # | Действие | Ожидание |
|---|---|---|
| A1 | `.\target\release\stopinet.exe install --config config\stopinet.local.toml --session-only` | «service running». Что меняется: программы в `C:\Program Files\stop-internet`, конфигурация в `C:\ProgramData\stop-internet` (запись только у администраторов), служба `stopinet` с автоматическим запуском. Откат: `stopinet uninstall`. |
| A2 | `stopinet status` | служба running, start AutoStart, session-only; provider и sublayer «session»; 0 persistent, 0 boot-time, сколько-то session-фильтров; туннель — как в Happ. |
| A3 | Отключить Happ, открыть сайт, подключиться снова | Сайты перестают открываться примерно за 2 с; после подключения снова открываются. В журнале «tunnel down» и «tunnel up». |
| A4 | `Stop-Service stopinet`, затем `stopinet status` | Фильтров нет, интернет без ограничений. `Start-Service stopinet` возвращает их. |
| A5 | `Stop-Process -Name stopinet-service -Force` | Примерно через 5 с служба снова работает (`stopinet status`), в журнале новый запуск. |
| A6 | Сон, пробуждение | В журнале «woke up, mode TunnelOnly»; туннель отслеживается как раньше. |
| A7 | Перезагрузить Windows | Служба запускается сама; до её запуска интернет открыт (session-only). |

## B. Постоянный базовый набор

| # | Действие | Ожидание |
|---|---|---|
| B1 | `stopinet install` (оставляет установленную конфигурацию) | «service running». `stopinet status`: provider и sublayer «persistent», сколько-то постоянных фильтров, столько же boot-time копий (или 0 и примечание в журнале), сверху session-фильтры. Откат: `stopinet panic` или `stopinet uninstall`. |
| B2 | **Сначала аварийный выход:** `stopinet panic`, затем `stopinet status` | Нет провайдера, нет подуровня, 0 фильтров; интернет без ограничений. `Start-Service stopinet` возвращает к состоянию B1. Если это не работает, дальше не идите. |
| B3 | `Stop-Service stopinet` | Интернет закрыт, подключён Happ или нет. Приложения из `direct` работают, только если Happ отключён: подключённый Happ ведёт их через `happd.exe`, а он сейчас закрыт. `stopinet status`: постоянные фильтры на месте, 0 session. `Start-Service stopinet` возвращает интернет через туннель. |
| B4 | `Stop-Process -Name stopinet-service -Force` | Примерно 5 с всё закрыто, потом служба снова работает и туннель работает. |
| B5 | Отключить Happ; выполнить `Resolve-DnsName example.com -DnsOnly` | Пока туннеля нет, имя не разрешается и сайты не открываются; приложение из `direct` сохраняет свои соединения. После подключения всё работает. |
| B6 | Сон, пробуждение | Как в A6; до возвращения туннеля ничего не проходит. |
| B7 | Перезагрузить Windows, затем завершить работу и включить (Fast Startup) | Пока Happ не подключился, ничего не открывается; после подключения всё работает. В журнале после перезагрузки — запуск службы и установка базового набора, после включения с Fast Startup — «woke up». |
| B8 | `stopinet uninstall` | «service removed», все фильтры сняты, программы удалены; конфигурация и журнал остаются в `C:\ProgramData\stop-internet`. |
