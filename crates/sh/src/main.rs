//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2024-2025 Jarkko Sakkinen
//! Copyright (c) 2025 Opinsys Oy

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

pub mod cli;
pub mod command;
pub mod error;
pub mod handle;
pub mod io;
pub mod pcr;
pub mod response;
pub mod task;
pub mod unmarshal;

use crate::{
    cli::{Task, TopLevel},
    command::common::build_auth_map,
    error::device_err,
    task::{TaskState, TaskStateProgress},
};

use anyhow::{Result, anyhow};

use std::{
    cell::RefCell, collections::HashMap, fs, io::IsTerminal, path::PathBuf, process, rc::Rc,
    sync::atomic::Ordering, time::Duration,
};

use argh::{EarlyExit, FromArgs};
use indicatif::ProgressBar;
use tpm2_device::{TpmDevice, TpmPosixDevice};
use tpm2_vtpm::VtpmCache;

/// A global flag to signal graceful teardown of the application.
///
/// Set by the Ctrl-C handler to allow the main loop to finish its current
/// operation and perform necessary teardown (e.g., flushing TPM contexts)
/// before exiting.
pub static TEARDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct CliProgress(ProgressBar);

impl TaskStateProgress for CliProgress {
    fn start(&self) {
        self.0.set_message("Waiting for TPM...");
        self.0.enable_steady_tick(Duration::from_millis(100));
    }

    fn stop(&self) {
        self.0.finish_and_clear();
    }
}

/// CTRL-C exits with 130 as exit codes larger than 128 commonly refer to an
/// external signal indexed by the signal number.
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if ctrlc::set_handler(move || {
        TEARDOWN.store(true, Ordering::Relaxed);
    })
    .is_err()
    {
        eprintln!("CTRL-C handler failed");
        process::exit(1);
    }

    let cli = parse_cli();

    if cli.version {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return;
    }

    if cli.command.is_none() {
        eprintln!("Usage: {} [OPTIONS] <COMMAND>", env!("CARGO_PKG_NAME"));
        eprintln!();
        eprintln!("For more information, try '--help'.");
        process::exit(2);
    }

    let cache_dir = if let Ok(path) = std::env::var("TPM2SH_CACHE_PATH") {
        PathBuf::from(path)
    } else {
        let Some(project) = directories::ProjectDirs::from("", "", "tpm2sh") else {
            eprintln!("Could not locate cache directory path.");
            process::exit(1);
        };
        project.cache_dir().join("vtpm")
    };

    if let Err(err) = fs::create_dir_all(&cache_dir) {
        eprintln!("{err}");
        process::exit(1);
    }

    if let Err(err) = execute_cli(&cli, &cache_dir) {
        if TEARDOWN.load(Ordering::Relaxed) {
            process::exit(130);
        }

        eprintln!("{err:#}");
        process::exit(1);
    }

    if TEARDOWN.load(Ordering::Relaxed) {
        process::exit(130);
    }
}

fn parse_cli() -> TopLevel {
    let strings: Vec<String> = std::env::args_os()
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|arg| {
            eprintln!("Invalid UTF-8: {}", arg.to_string_lossy());
            process::exit(1);
        });

    if strings.is_empty() {
        eprintln!("No program name, argv is empty");
        process::exit(1);
    }

    let command_name = std::path::Path::new(&strings[0])
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&strings[0]);
    let args: Vec<&str> = strings.iter().map(String::as_str).collect();

    TopLevel::from_args(&[command_name], &args[1..]).unwrap_or_else(|early_exit| {
        exit_cli_parse(command_name, &early_exit);
    })
}

fn exit_cli_parse(command_name: &str, early_exit: &EarlyExit) -> ! {
    if let Ok(()) = early_exit.status {
        print!("{}", early_exit.output);
        process::exit(0);
    }

    eprint!("{}", early_exit.output);
    eprintln!("For more information, try '{command_name} --help'.");
    process::exit(2);
}

fn execute_cli(cli: &TopLevel, cache_dir: &std::path::Path) -> Result<()> {
    let command = cli
        .command
        .as_ref()
        .ok_or_else(|| anyhow!("invalid input: missing command"))?;

    command.validate()?;
    let shared_device = if command.is_local() {
        None
    } else {
        let device = TpmDevice::new(Box::new(
            TpmPosixDevice::builder()
                .with_path(&cli.device)
                .with_interrupted(|| TEARDOWN.load(Ordering::Relaxed))
                .build()
                .map_err(device_err)?,
        ));
        Some(Rc::new(RefCell::new(device)))
    };

    let persistent_handles = if let Some(device_rc) = &shared_device {
        let mut device = device_rc.borrow_mut();
        let name_map = command::common::fetch_persistent_names(&mut device)?;
        name_map.into_iter().map(|(h, name)| (name, h)).collect()
    } else {
        HashMap::new()
    };

    let cache = VtpmCache::new(cache_dir, persistent_handles)?;

    let mut stdout = std::io::stdout();
    let is_tty = stdout.is_terminal();

    let progress: Option<Box<dyn TaskStateProgress>> = if is_tty {
        Some(Box::new(CliProgress(ProgressBar::new_spinner())))
    } else {
        None
    };

    let auth_entries = cli.auth_entries();
    let auth_map = build_auth_map(&auth_entries)?;

    let mut job = TaskState::new(shared_device, cache, progress, auth_map)?;
    command.run(&mut job, &mut stdout, is_tty)
}
