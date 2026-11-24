{{changes}}

### Install

`stop-internet-{{version}}-setup.exe` is for x64 Windows 10 and 11. Read
[Getting started](https://github.com/Morkoshka/stop-internet/blob/v{{version}}/README.md#getting-started)
first and keep the
[recovery guide](https://github.com/Morkoshka/stop-internet/blob/v{{version}}/docs/recovery.md)
at hand. To check that the installer is the one the Release workflow
built from this tag:

```powershell
(Get-FileHash .\stop-internet-{{version}}-setup.exe).Hash   # as in SHA256SUMS.txt
gh attestation verify .\stop-internet-{{version}}-setup.exe --repo Morkoshka/stop-internet
```

<details>
<summary><b>По-русски</b></summary>

{{changes.ru}}

### Установка

`stop-internet-{{version}}-setup.exe` — для x64 Windows 10 и 11. Сначала
прочитайте
[«Как начать»](https://github.com/Morkoshka/stop-internet/blob/v{{version}}/README.ru.md#как-начать)
и держите под рукой
[инструкцию по восстановлению](https://github.com/Morkoshka/stop-internet/blob/v{{version}}/docs/recovery.ru.md).
Проверить, что установщик собран workflow Release из этого тега:

```powershell
(Get-FileHash .\stop-internet-{{version}}-setup.exe).Hash   # как в SHA256SUMS.txt
gh attestation verify .\stop-internet-{{version}}-setup.exe --repo Morkoshka/stop-internet
```

</details>
