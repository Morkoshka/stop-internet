//! Writes the icon of the programs, the green shield, as an `.ico` file for
//! the installer: `cargo run -p stopinet-icon --example ico -- <file>`.
//! `tools/build-installer.ps1` runs it.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: ico <file>");
        return ExitCode::FAILURE;
    };
    match std::fs::write(&path, stopinet_icon::ico(stopinet_icon::Color::Green)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cannot write {}: {error}", Path::new(&path).display());
            ExitCode::FAILURE
        }
    }
}
