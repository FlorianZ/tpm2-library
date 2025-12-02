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
pub mod task;

use crate::{
    cli::{Task, TopLevel},
    command::CommandError,
    task::{TaskState, TaskStateProgress},
};

use std::{
    cell::RefCell, collections::HashMap, fs, io::IsTerminal, path::PathBuf, process, rc::Rc,
    sync::atomic::Ordering, time::Duration,
};

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};
use indicatif::ProgressBar;
use tpm2_device::TpmDevice;
use tpm2_protocol::{basic::TpmHandle, data::Tpm2bName};
use tpm2_vtpm::VtpmCache;
use tracing_subscriber::EnvFilter;

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
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_timer(tracing_subscriber::fmt::time::SystemTime)
        .init();

    if ctrlc::set_handler(move || {
        TEARDOWN.store(true, Ordering::Relaxed);
    })
    .is_err()
    {
        eprintln!("CTRL-C handler failed");
        process::exit(1);
    }

    let cli = match TopLevel::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            if e.kind() == ErrorKind::MissingRequiredArgument {
                let mut cmd = TopLevel::command();
                eprintln!("{}", cmd.render_usage());
                eprintln!();
                eprintln!("For more information, try '--help'.");
                process::exit(2);
            } else {
                e.exit();
            }
        }
    };

    let cache_dir = if let Ok(path) = std::env::var("TPM2SH_CACHE_PATH") {
        PathBuf::from(path)
    } else {
        let Some(project) = directories::ProjectDirs::from("", "", "tpm2sh") else {
            eprintln!("Could not locate cache directory path.");
            std::process::exit(1);
        };
        project.cache_dir().join("vtpm")
    };

    if let Err(err) = fs::create_dir_all(&cache_dir) {
        eprintln!("{err}");
        process::exit(1);
    }

    if let Err(err) = execute_cli(&cli, &cache_dir) {
        eprintln!("{err:#}");
        process::exit(1);
    }

    if TEARDOWN.load(Ordering::Relaxed) {
        process::exit(130);
    }
}

fn fetch_persistent_key_map(
    device: &mut TpmDevice,
) -> Result<HashMap<Tpm2bName, TpmHandle>, CommandError> {
    let handles = device.fetch_handles(tpm2_protocol::data::TpmHt::Persistent)?;
    let mut persistent_keys = HashMap::new();
    for handle_val in handles {
        let phandle = handle_val;
        if let Ok((_, name)) = device.read_public(phandle) {
            persistent_keys.insert(name, phandle);
        }
    }
    Ok(persistent_keys)
}

fn execute_cli(cli: &TopLevel, cache_dir: &std::path::Path) -> Result<(), CommandError> {
    let shared_device = if cli.command.is_local() {
        None
    } else {
        let device = TpmDevice::builder()
            .with_path(&cli.device)
            .with_interrupted(|| TEARDOWN.load(Ordering::Relaxed))
            .build()?;
        Some(Rc::new(RefCell::new(device)))
    };

    let persistent_handles = if let Some(device_rc) = &shared_device {
        let mut device = device_rc.borrow_mut();
        fetch_persistent_key_map(&mut device)?
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

    let mut job = TaskState::new(shared_device, cache, progress)?;
    cli.command.run(&mut job, &mut stdout, is_tty)
}
