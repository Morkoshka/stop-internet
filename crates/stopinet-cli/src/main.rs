//! `stopinet` command-line tool.
//!
//! For now it offers a dry run of the policy: it prints the rules that the
//! service would apply for a mode and a tunnel state, without touching the
//! system.

use std::path::PathBuf;
use std::process::ExitCode;

use stopinet_core::config::{self, Config};
use stopinet_core::policy::{Mode, Policy, TunnelState};

const USAGE: &str = "\
Usage:
  stopinet policy [--config <file>] [--mode tunnel|proxy|normal] [--tunnel up|down]
      Print the firewall rules for a mode and a tunnel state. Changes nothing.

Planned: status, mode, install, uninstall, panic.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("policy") => policy(&args[1..]),
        Some("-h" | "--help" | "help") | None => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn policy(args: &[String]) -> Result<(), String> {
    let mut config_path = PathBuf::from(config::DEFAULT_PATH);
    let mut mode = Mode::TunnelOnly;
    let mut tunnel = TunnelState::Down;

    let mut args = args.iter();
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("option '{option}' needs a value"))?;
        match option.as_str() {
            "--config" => config_path = PathBuf::from(value),
            "--mode" => mode = value.parse()?,
            "--tunnel" => tunnel = value.parse()?,
            other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
        }
    }

    let config = Config::load(&config_path).map_err(|e| e.to_string())?;
    let policy = Policy::build(&config, mode, tunnel);

    println!("mode: {mode:?}, tunnel: {tunnel:?}");
    println!("rules, highest precedence first:");
    for (index, rule) in policy.rules().iter().enumerate() {
        println!("{:>3}  {rule}", index + 1);
    }
    Ok(())
}
