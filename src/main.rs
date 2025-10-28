// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};
use cli::{
    auth::Auth,
    cli::{Task, TopLevel},
    command::CommandError,
    device::{Device, DeviceError},
    session::Session,
    vtpm::VtpmCache,
};
use std::{
    cell::RefCell, fs, io::Write, os::unix::io::AsRawFd, path::Path, process, rc::Rc,
    sync::atomic::Ordering,
};

/// CTRL-C exits with 130 as exit codes larger than 128 commonly refer to an
/// external signal indexed by the signal number.
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();

    if ctrlc::set_handler(move || {
        cli::TEARDOWN.store(true, Ordering::Relaxed);
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "\x1B[?25h");
        let _ = stderr.flush();
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
                if let Some(usage) = e
                    .to_string()
                    .lines()
                    .find(|line| line.trim().starts_with("Usage:"))
                {
                    eprintln!("{}", usage.trim());
                    eprintln!();
                    eprintln!("For more information, try '--help'.");
                } else {
                    let mut cmd = TopLevel::command();
                    eprintln!("{}", cmd.render_usage());
                    eprintln!();
                    eprintln!("For more information, try '--help'.");
                }
                process::exit(2);
            } else {
                e.exit();
            }
        }
    };

    let Some(project) = directories::ProjectDirs::from("", "", "tpm2sh") else {
        eprintln!("Could not locate cache directory path.");
        std::process::exit(1);
    };

    let cache_dir = project.cache_dir().join("vtpm");

    if let Err(err) = fs::create_dir_all(&cache_dir) {
        eprintln!("{err}");
        process::exit(1);
    }

    if let Err(err) = execute_cli(&cli, &cache_dir) {
        eprintln!("{err:#}");
        process::exit(1);
    }

    if cli::TEARDOWN.load(Ordering::Relaxed) {
        process::exit(130);
    }
}

fn execute_cli(cli: &TopLevel, cache_dir: &Path) -> Result<(), CommandError> {
    let shared_device = init_device(cli)?;
    let mut stdout = std::io::stdout();
    let mut cache = VtpmCache::new(cache_dir)?;

    let auth_list = if cli.auth.is_empty() {
        &[Auth::default()]
    } else {
        cli.auth.as_slice()
    };

    let mut job = Session::new(shared_device, &mut cache, auth_list, &mut stdout);
    cli.command.run(&mut job)
}

fn init_device(cli: &TopLevel) -> Result<Option<Rc<RefCell<Device>>>, CommandError> {
    if cli.command.is_local() {
        return Ok(None);
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&cli.device)
        .map_err(CommandError::Io)?;

    let fd = file.as_raw_fd();
    let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL)
        .map_err(|e| CommandError::from(DeviceError::from(e)))?;
    let mut oflags = nix::fcntl::OFlag::from_bits_truncate(flags);
    oflags.insert(nix::fcntl::OFlag::O_NONBLOCK);
    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFL(oflags))
        .map_err(|e| CommandError::from(DeviceError::from(e)))?;

    let device = Device::new(file, cli.log_format)?;

    Ok(Some(Rc::new(RefCell::new(device))))
}
