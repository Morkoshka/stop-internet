//! Emergency switch-off for the Start menu shortcut of the installer.
//!
//! `stopinet-tray.exe --panic` asks for confirmation and starts itself again
//! through a UAC prompt as `--panic-now`. That instance runs
//! `stopinet.exe panic` from its own folder without a console window and
//! shows the result. It works without the service, so it helps also when
//! the service does not start or the configuration is broken.
//!
//! The menu of the icon has no such item: while the service runs, "normal
//! internet" turns protection off, and it ends by itself.

use std::io;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use crate::lang::Lang;
use crate::shell;

/// Argument of the shortcut: asks, then elevates.
pub const ASK_ARG: &str = "--panic";
/// Argument of the elevated instance.
pub const RUN_ARG: &str = "--panic-now";

const CLI_EXE: &str = "stopinet.exe";

/// The shortcut: confirmation, then the UAC prompt.
pub fn ask() -> ExitCode {
    let lang = Lang::current();
    let question = lang.pick(
        "Аварийное отключение защиты.\n\n\
         Служба stop-internet будет остановлена, а все её фильтры, в том числе \
         постоянные, удалены. Интернет пойдёт мимо туннеля, пока служба не \
         запустится снова: после перезагрузки или командой sc.exe start stopinet.\n\n\
         Нужны права администратора. Продолжить?",
        "Emergency switch-off of the protection.\n\n\
         The stop-internet service will be stopped and all its filters, the \
         persistent ones included, removed. The internet will bypass the tunnel \
         until the service starts again: after a restart of Windows or with \
         sc.exe start stopinet.\n\n\
         This needs administrator rights. Continue?",
    );
    if !shell::confirm(question) {
        return ExitCode::SUCCESS;
    }
    match shell::run_elevated(RUN_ARG) {
        // Declined in the UAC prompt: nothing has changed.
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            let text = lang.pick(
                "Не удалось запросить права администратора",
                "Could not ask for administrator rights",
            );
            shell::message_box(&format!("{text}: {error}"));
            ExitCode::FAILURE
        }
    }
}

/// The elevated instance: runs `stopinet panic` and shows what it did.
pub fn run() -> ExitCode {
    let outcome = match cli_path() {
        Ok(cli) => switch_off(&cli),
        Err(error) => Outcome::NotStarted {
            program: PathBuf::from(CLI_EXE),
            error: error.to_string(),
        },
    };
    let text = message(&outcome, Lang::current());
    if outcome == Outcome::Done {
        shell::inform(&text);
        ExitCode::SUCCESS
    } else {
        shell::message_box(&text);
        ExitCode::FAILURE
    }
}

/// How `stopinet panic` ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Done,
    /// It ran and failed; what it printed.
    Failed(String),
    /// It could not be started.
    NotStarted {
        program: PathBuf,
        error: String,
    },
}

/// `stopinet.exe` next to this program.
fn cli_path() -> io::Result<PathBuf> {
    let program = std::env::current_exe()?;
    let folder = program
        .parent()
        .ok_or_else(|| io::Error::other("the program has no folder"))?;
    Ok(folder.join(CLI_EXE))
}

fn switch_off(cli: &Path) -> Outcome {
    match Command::new(cli)
        .arg("panic")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(output) if output.status.success() => Outcome::Done,
        Ok(output) => {
            let printed = [&output.stdout, &output.stderr]
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).trim().to_owned())
                .filter(|text| !text.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            Outcome::Failed(printed)
        }
        Err(error) => Outcome::NotStarted {
            program: cli.to_path_buf(),
            error: error.to_string(),
        },
    }
}

fn message(outcome: &Outcome, lang: Lang) -> String {
    match outcome {
        Outcome::Done => lang
            .pick(
                "Защита выключена: служба остановлена, фильтры stop-internet удалены.\n\n\
                 Она вернётся, когда служба запустится снова: после перезагрузки или \
                 командой sc.exe start stopinet.",
                "Protection is off: the service is stopped and the filters of \
                 stop-internet are removed.\n\n\
                 It returns when the service starts again: after a restart of Windows \
                 or with sc.exe start stopinet.",
            )
            .to_owned(),
        Outcome::Failed(printed) => format!(
            "{}\n\n{printed}",
            lang.pick(
                "Выключить защиту не удалось или удалось не полностью. \
                 stopinet panic ответил:",
                "Protection could not be turned off, or not completely. \
                 stopinet panic answered:",
            )
        ),
        Outcome::NotStarted { program, error } => format!(
            "{} {}: {error}\n\n{}",
            lang.pick("Не удалось запустить", "Could not start"),
            program.display(),
            lang.pick(
                "Он должен лежать рядом со значком. Что делать без него, сказано в \
                 инструкции по восстановлению.",
                "It must be next to the icon program. The recovery guide tells what \
                 to do without it.",
            )
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tool_is_next_to_the_icon_program() {
        let cli = cli_path().unwrap();
        assert_eq!(cli.file_name().unwrap(), CLI_EXE);
        assert_eq!(cli.parent(), std::env::current_exe().unwrap().parent());
    }

    #[test]
    fn a_missing_tool_is_reported_with_its_path() {
        let missing = std::env::temp_dir().join("stopinet-missing").join(CLI_EXE);
        let outcome = switch_off(&missing);
        assert!(matches!(&outcome, Outcome::NotStarted { program, .. } if *program == missing));
        let text = message(&outcome, Lang::English);
        assert!(text.contains(&missing.display().to_string()));
        assert!(text.contains("recovery guide"));
    }

    #[test]
    fn a_failure_shows_what_the_tool_printed() {
        let outcome = Outcome::Failed("cannot stop the service: denied".into());
        for lang in [Lang::Russian, Lang::English] {
            assert!(message(&outcome, lang).ends_with("\n\ncannot stop the service: denied"));
        }
        assert!(message(&Outcome::Done, Lang::Russian).contains("sc.exe start stopinet"));
    }
}
