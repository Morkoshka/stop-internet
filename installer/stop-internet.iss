; Installer of stop-internet, for Inno Setup 6.4 or later.
;
; The installer wraps `stopinet install` and `stopinet uninstall`, which do
; the real work: the programs in Program Files, the service, the WFP filters
; and the autostart of the tray icon. Inno Setup adds the wizard in English or
; Russian, the entry in Settings > Apps, the shortcuts in the Start menu and an
; offline copy of the recovery guide.
;
; - Install: the programs are extracted to {tmp}, and {tmp}\stopinet.exe
;   install closes the running icons, stops the service, copies the programs,
;   registers the service and starts it. If it fails, Setup stops with its
;   output and installs nothing of its own.
; - Configuration: an existing one is kept. Without one, the example for Happ
;   is installed, after a warning if Happ is not where it expects. /CONFIG=<file>
;   installs another one.
; - Uninstall: {app}\stopinet.exe uninstall runs first. If it fails, the
;   uninstallation stops, so that the programs that remove the filters stay.
;
; Build with tools/build-installer.ps1, which passes the version.

#if Ver < EncodeVer(6, 4, 0)
  #error Inno Setup 6.4 or later is needed (ExecAndCaptureOutput).
#endif
#ifndef AppVersion
  #error Pass /DAppVersion=<version>; tools/build-installer.ps1 does it.
#endif
#ifndef Bin
  #define Bin "..\target\release"
#endif

; Must match INSTALL_DIR in crates/stopinet-cli/src/manage.rs and DATA_DIR in
; crates/stopinet-core/src/config.rs.
#define InstallDir "C:\Program Files\stop-internet"
#define DataDir "C:\ProgramData\stop-internet"
; Where the example configuration expects the tunnel daemon of Happ.
#define HappDaemon "C:\Program Files\FlyFrogLLC\Happ\happd.exe"

[Setup]
AppId={{58C1D658-CA81-40D1-98B9-E52BA2B10F8A}
AppName=stop-internet
AppVersion={#AppVersion}
AppPublisher=Morkoshka
AppPublisherURL=https://github.com/Morkoshka/stop-internet
AppSupportURL=https://github.com/Morkoshka/stop-internet/issues
AppUpdatesURL=https://github.com/Morkoshka/stop-internet/releases
VersionInfoVersion={#AppVersion}
DefaultDirName={#InstallDir}
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
; WFP and the service are tested on x64 Windows only.
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0
; `stopinet install` closes the icons and stops the service itself.
CloseApplications=no
OutputDir=..\target\installer
OutputBaseFilename=stop-internet-{#AppVersion}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
UninstallDisplayName=stop-internet

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "trial"; Description: "{cm:TrialTask}"; Flags: unchecked

[Files]
; Put in place by `stopinet install`, see PrepareToInstall.
Source: "{#Bin}\stopinet.exe"; Flags: dontcopy
Source: "{#Bin}\stopinet-service.exe"; Flags: dontcopy
Source: "{#Bin}\stopinet-tray.exe"; Flags: dontcopy
Source: "..\config\stopinet.example.toml"; Flags: dontcopy
; For reading without the network.
Source: "..\docs\recovery.md"; DestDir: "{app}\docs"
Source: "..\docs\recovery.ru.md"; DestDir: "{app}\docs"
Source: "..\config\stopinet.example.toml"; DestDir: "{app}"; DestName: "config.example.toml"
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"

[Icons]
Name: "{autoprograms}\stop-internet\stop-internet"; Filename: "{app}\stopinet-tray.exe"; Comment: "{cm:IconComment}"
Name: "{autoprograms}\stop-internet\{cm:PanicName}"; Filename: "{app}\stopinet-tray.exe"; Parameters: "--panic"; Comment: "{cm:PanicComment}"
Name: "{autoprograms}\stop-internet\{cm:GuideName}"; Filename: "{win}\notepad.exe"; Parameters: """{app}\docs\recovery.md"""; Languages: en
Name: "{autoprograms}\stop-internet\{cm:GuideName}"; Filename: "{win}\notepad.exe"; Parameters: """{app}\docs\recovery.ru.md"""; Languages: ru

[Run]
Filename: "{win}\notepad.exe"; Parameters: """{app}\docs\recovery.md"""; Description: "{cm:OpenGuide}"; Flags: postinstall unchecked skipifsilent nowait runasoriginaluser; Languages: en
Filename: "{win}\notepad.exe"; Parameters: """{app}\docs\recovery.ru.md"""; Description: "{cm:OpenGuide}"; Flags: postinstall unchecked skipifsilent nowait runasoriginaluser; Languages: ru

[CustomMessages]
en.TrialTask=Trial mode: nothing persistent, stopping the service removes every filter (for the first tests)
ru.TrialTask=Пробный режим: ничего постоянного, остановка службы снимает все фильтры (для первых проверок)
en.IconComment=Status icon and mode switching
ru.IconComment=Значок состояния и переключение режимов
en.PanicName=stop-internet - emergency off
ru.PanicName=stop-internet — аварийное отключение
en.PanicComment=Stop the service and remove every filter of stop-internet
ru.PanicComment=Остановить службу и удалить все фильтры stop-internet
en.GuideName=stop-internet - recovery guide
ru.GuideName=stop-internet — инструкция по восстановлению
en.OpenGuide=Open the recovery guide
ru.OpenGuide=Открыть инструкцию по восстановлению
en.ReadyConfig=Configuration:
ru.ReadyConfig=Конфигурация:
en.ConfigKept=keep %1
ru.ConfigKept=оставить %1
en.ConfigExample=the example for Happ, into %1
ru.ConfigExample=пример для Happ, в %1
en.ConfigGiven=%1, into %2
ru.ConfigGiven=%1, в %2
en.WrongFolders=stop-internet installs only into %1 and %2, and the program folders of this Windows are elsewhere.
ru.WrongFolders=stop-internet ставится только в %1 и %2, а папки программ этой Windows находятся в другом месте.
en.NoConfig=Configuration file not found: %1
ru.NoConfig=Файл конфигурации не найден: %1
en.NoHapp=Happ was not found: %1.%n%nThe configuration to be installed is the example for Happ. With another VPN client the internet will stay blocked until you set the client in %2 and restart the service (see the recovery guide).%n%nInstall anyway?
ru.NoHapp=Happ не найден: %1.%n%nБудет установлена конфигурация-пример для Happ. С другим VPN-клиентом интернет останется заблокирован, пока вы не укажете клиент в %2 и не перезапустите службу (см. инструкцию по восстановлению).%n%nВсё равно установить?
en.NoHappStop=Installation cancelled: Happ was not found. Install Happ first, or give your configuration with /CONFIG=<file>.
ru.NoHappStop=Установка отменена: Happ не найден. Сначала установите Happ или передайте свою конфигурацию параметром /CONFIG=<файл>.
en.InstallFailed=stopinet install did not finish:%n%n%1%n%nIf the internet is blocked now, run "%2" panic in an elevated terminal.
ru.InstallFailed=stopinet install не завершился:%n%n%1%n%nЕсли интернет сейчас заблокирован, выполните "%2" panic в терминале администратора.
en.UninstallFailed=stopinet uninstall did not finish, so the uninstallation stopped:%n%n%1%n%nRun it again, or see the recovery guide in %2.
ru.UninstallFailed=stopinet uninstall не завершился, поэтому удаление остановлено:%n%n%1%n%nЗапустите его ещё раз или откройте инструкцию по восстановлению: %2.
en.DeleteData=Delete the configuration and the service log in %1 too?
ru.DeleteData=Удалить также конфигурацию и журнал службы в %1?

[Code]
const
  ConfigFile = '{#DataDir}\config.toml';

var
  { From /CONFIG, as a full path, or empty. }
  GivenConfig: String;

function InitializeSetup(): Boolean;
begin
  Result := False;
  if (CompareText(ExpandConstant('{commonpf64}\stop-internet'), '{#InstallDir}') <> 0) or
     (CompareText(ExpandConstant('{commonappdata}\stop-internet'), '{#DataDir}') <> 0) then
  begin
    SuppressibleMsgBox(FmtMessage(CustomMessage('WrongFolders'), ['{#InstallDir}', '{#DataDir}']),
      mbCriticalError, MB_OK, IDOK);
    Exit;
  end;
  GivenConfig := ExpandConstant('{param:CONFIG|}');
  if GivenConfig <> '' then
  begin
    GivenConfig := ExpandFileName(GivenConfig);
    if not FileExists(GivenConfig) then
    begin
      SuppressibleMsgBox(FmtMessage(CustomMessage('NoConfig'), [GivenConfig]), mbCriticalError, MB_OK, IDOK);
      Exit;
    end;
  end;
  Result := True;
end;

{ Whether the example configuration is going to be installed. }
function UsesExample(): Boolean;
begin
  Result := (GivenConfig = '') and not FileExists(ConfigFile);
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  Config: String;
begin
  if GivenConfig <> '' then
    Config := FmtMessage(CustomMessage('ConfigGiven'), [GivenConfig, ConfigFile])
  else if UsesExample() then
    Config := FmtMessage(CustomMessage('ConfigExample'), [ConfigFile])
  else
    Config := FmtMessage(CustomMessage('ConfigKept'), [ConfigFile]);
  Result := MemoDirInfo + NewLine + NewLine + CustomMessage('ReadyConfig') + NewLine + Space + Config;
  if MemoTasksInfo <> '' then
    Result := Result + NewLine + NewLine + MemoTasksInfo;
end;

{ Runs stopinet.exe without a window and logs what it printed. Returns an
  empty string on success, otherwise the output or the reason it did not
  start. }
function RunTool(const FileName, Params: String): String;
var
  ResultCode, I: Integer;
  Captured: TExecOutput;
  Printed: String;
begin
  Log('Running ' + FileName + ' ' + Params);
  try
    { Console programs always run hidden. }
    if not ExecAndCaptureOutput(FileName, Params, '', SW_SHOWNORMAL, ewWaitUntilTerminated,
      ResultCode, Captured) then
    begin
      Result := SysErrorMessage(ResultCode);
      Log('Not started: ' + Result);
      Exit;
    end;
  except
    Result := GetExceptionMessage();
    Log('Not started: ' + Result);
    Exit;
  end;
  Printed := '';
  for I := 0 to GetArrayLength(Captured.StdOut) - 1 do
    Printed := Printed + Captured.StdOut[I] + #13#10;
  for I := 0 to GetArrayLength(Captured.StdErr) - 1 do
    Printed := Printed + Captured.StdErr[I] + #13#10;
  Printed := Trim(Printed);
  Log(Format('Exit code %d:', [ResultCode]) + #13#10 + Printed);
  if ResultCode = 0 then
    Result := ''
  else if Printed = '' then
    Result := Format('exit code %d', [ResultCode])
  else
    Result := Printed;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Config, Params, Failure: String;
begin
  Result := '';
  Config := GivenConfig;
  if UsesExample() then
  begin
    if not FileExists('{#HappDaemon}') and
       (SuppressibleMsgBox(FmtMessage(CustomMessage('NoHapp'), ['{#HappDaemon}', ConfigFile]),
         mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) <> IDYES) then
    begin
      Result := CustomMessage('NoHappStop');
      Exit;
    end;
    ExtractTemporaryFile('stopinet.example.toml');
    Config := ExpandConstant('{tmp}\stopinet.example.toml');
  end;
  ExtractTemporaryFile('stopinet.exe');
  ExtractTemporaryFile('stopinet-service.exe');
  ExtractTemporaryFile('stopinet-tray.exe');

  Params := 'install';
  if Config <> '' then
    Params := Params + ' --config "' + Config + '"';
  if WizardIsTaskSelected('trial') then
    Params := Params + ' --session-only';
  Failure := RunTool(ExpandConstant('{tmp}\stopinet.exe'), Params);
  if Failure <> '' then
    Result := FmtMessage(CustomMessage('InstallFailed'), [Failure, '{#InstallDir}\stopinet.exe']);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Tool, Failure, Text: String;
begin
  case CurUninstallStep of
    usUninstall:
      begin
        Tool := ExpandConstant('{app}\stopinet.exe');
        if FileExists(Tool) then
        begin
          Failure := RunTool(Tool, 'uninstall');
          if Failure <> '' then
          begin
            { A line of the script must not begin with a bracket: Inno Setup
              would take it for a section. }
            Text := FmtMessage(CustomMessage('UninstallFailed'), [Failure, ExpandConstant('{app}\docs')]);
            SuppressibleMsgBox(Text, mbCriticalError, MB_OK, IDOK);
            Abort;
          end;
          { It removes the other programs, but not itself while it runs. }
          DeleteFile(Tool);
        end;
      end;
    usPostUninstall:
      if DirExists('{#DataDir}') and
         (SuppressibleMsgBox(FmtMessage(CustomMessage('DeleteData'), ['{#DataDir}']),
           mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES) then
        DelTree('{#DataDir}', True, True, True);
  end;
end;
