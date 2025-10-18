// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use clap::Parser;
use cli::{
    cli::{SubCommand, TopLevel},
    command::CommandError,
    device::{Device, DeviceError},
    job::Job,
    key::KeyCache,
    session::SessionCache,
    transport::FileTransport,
};
use std::{
    cell::RefCell, fs, io::Write, os::unix::io::AsRawFd, process, rc::Rc, sync::atomic::Ordering,
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

    let cli: TopLevel = TopLevel::parse();

    let Some(project) = directories::ProjectDirs::from("", "", "tpm2sh") else {
        eprintln!("Could not determine directory.");
        std::process::exit(1);
    };
    let cache_dir = project.cache_dir();
    if let Err(e) = fs::create_dir_all(cache_dir) {
        eprintln!("Failed to create cache directory: {e}");
        process::exit(1);
    }

    if let Err(err) = execute_cli(&cli, cache_dir) {
        eprintln!("{:#}", err);
        process::exit(1);
    }

    if cli::TEARDOWN.load(Ordering::Relaxed) {
        process::exit(130);
    }
}

fn execute_cli(cli: &TopLevel, cache_dir: &std::path::Path) -> Result<(), CommandError> {
    let shared_device = init_device(cli)?;
    let mut stdout = std::io::stdout();

    let mut session_cache = SessionCache::new(cache_dir);
    session_cache.load_sessions()?;

    let mut job = if let Some(dev_rc) = &shared_device {
        let mut dev_guard = dev_rc
            .try_borrow_mut()
            .map_err(|_| DeviceError::AlreadyBorrowed)?;

        if let Err(e) = session_cache.refresh_sessions(&mut dev_guard) {
            log::warn!("One or more sessions failed to refresh: {e}");
        }

        let key_cache = KeyCache::new(Some(&mut dev_guard), cache_dir, &mut stdout)?;
        Job::new(shared_device.clone(), key_cache, session_cache)
    } else {
        let key_cache = KeyCache::new(None, cache_dir, &mut stdout)?;
        Job::new(None, key_cache, session_cache)
    };

    cli.command.run(&mut job, cli.plain)
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

    let transport = FileTransport(file);
    let device = Device::new(transport, cli.log_format)?;

    Ok(Some(Rc::new(RefCell::new(device))))
}
