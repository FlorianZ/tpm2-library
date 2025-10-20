// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

pub mod auth;
pub mod cli;
pub mod command;
pub mod convert;
pub mod crypto;
pub mod device;
pub mod job;
pub mod key;
pub mod pcr;
pub mod policy;
pub mod print;
pub mod scheme;
pub mod session;
pub mod template;
pub mod transport;
pub mod x509;

/// A global flag to signal graceful teardown of the application.
///
/// Set by the Ctrl-C handler to allow the main loop to finish its current
/// operation and perform necessary teardown (e.g., flushing TPM contexts)
/// before exiting.
pub static TEARDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
