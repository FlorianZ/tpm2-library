// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::doc_markdown)]

use crate::{
    command::{
        Algorithm, CommandError, Create, CreatePrimary, Delete, Evict, Import, Load, Memory,
        PcrEvent, ResetLock, ReturnCode, Seal, Unseal, common::parse_auth,
    },
    task::{Auth, TaskState},
};
use argh::FromArgs;
use std::{io::Write, path::PathBuf};
use strum::{Display, EnumString};
use tpm2_protocol::{basic::TpmHandle, data::TpmRh};

/// A subcommand of the main CLI application.
pub trait Task {
    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns an error if the execution fails.
    fn run(
        &self,
        job: &mut TaskState,
        writer: &mut dyn Write,
        is_tty: bool,
    ) -> Result<(), CommandError>;

    /// Validates command-line arguments before opening a TPM device.
    ///
    /// # Errors
    ///
    /// Returns an error if argument validation fails.
    fn validate(&self) -> Result<(), CommandError> {
        Ok(())
    }

    /// Returns `true` if the command can be run without a TPM device.
    #[must_use]
    fn is_local(&self) -> bool {
        false
    }
}

/// Authentication entries parsed from one `--auth` argument.
#[derive(Debug, Clone)]
pub struct AuthEntries(pub Vec<(TpmHandle, Auth)>);

fn parse_auth_entries(s: &str) -> Result<AuthEntries, String> {
    let entries: Result<Vec<_>, _> = s
        .split(',')
        .filter(|entry| !entry.trim().is_empty())
        .map(parse_auth)
        .collect();

    let entries = entries?;
    if entries.is_empty() {
        Err("format must be <handle>:<value>".to_string())
    } else {
        Ok(AuthEntries(entries))
    }
}

/// TPM 2.0 command-line interface.
#[derive(FromArgs, Debug)]
#[argh(
    description = "TPM 2.0 command-line interface",
    usage = "[-d <device>] [-A <auth...>] [-V] <command> [<args>]",
    help_triggers("-h", "--help", "help")
)]
pub struct TopLevel {
    /// device file
    #[argh(option, short = 'd', default = "PathBuf::from(\"/dev/tpmrm0\")")]
    pub device: PathBuf,

    /// list of authentication values in the format '<handle>:<hex string>'
    #[argh(option, short = 'A', long = "auth", from_str_fn(parse_auth_entries))]
    pub auth: Vec<AuthEntries>,

    /// print version information
    #[argh(switch, short = 'V')]
    pub version: bool,

    /// command to execute
    #[argh(subcommand)]
    pub command: Option<Command>,
}

impl TopLevel {
    /// Returns flattened authentication entries.
    #[must_use]
    pub fn auth_entries(&self) -> Vec<(TpmHandle, Auth)> {
        self.auth
            .iter()
            .flat_map(|entries| entries.0.iter().cloned())
            .collect()
    }
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum Command {
    Algorithm(Algorithm),
    Create(Create),
    CreatePrimary(CreatePrimary),
    Delete(Delete),
    Evict(Evict),
    Import(Import),
    Load(Load),
    Memory(Memory),
    PcrEvent(PcrEvent),
    ReturnCode(ReturnCode),
    ResetLock(ResetLock),
    Seal(Seal),
    Unseal(Unseal),
}

impl Command {
    fn as_task(&self) -> &dyn Task {
        match self {
            Self::Algorithm(cmd) => cmd,
            Self::Create(cmd) => cmd,
            Self::CreatePrimary(cmd) => cmd,
            Self::Delete(cmd) => cmd,
            Self::Evict(cmd) => cmd,
            Self::Import(cmd) => cmd,
            Self::Load(cmd) => cmd,
            Self::Memory(cmd) => cmd,
            Self::PcrEvent(cmd) => cmd,
            Self::ReturnCode(cmd) => cmd,
            Self::ResetLock(cmd) => cmd,
            Self::Seal(cmd) => cmd,
            Self::Unseal(cmd) => cmd,
        }
    }
}

impl Task for Command {
    fn run(
        &self,
        job: &mut TaskState,
        writer: &mut dyn std::io::Write,
        is_tty: bool,
    ) -> Result<(), CommandError> {
        self.as_task().run(job, writer, is_tty)
    }

    fn validate(&self) -> Result<(), CommandError> {
        self.as_task().validate()
    }

    fn is_local(&self) -> bool {
        self.as_task().is_local()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum Hierarchy {
    #[default]
    Owner,
    Platform,
    Endorsement,
    Null,
}

impl From<Hierarchy> for TpmRh {
    fn from(h: Hierarchy) -> Self {
        match h {
            Hierarchy::Owner => TpmRh::Owner,
            Hierarchy::Platform => TpmRh::Platform,
            Hierarchy::Endorsement => TpmRh::Endorsement,
            Hierarchy::Null => TpmRh::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2_protocol::basic::TpmUint32;

    #[test]
    fn parse_global_auth_before_subcommand() {
        let cli = TopLevel::from_args(
            &["tpm2sh"],
            &["--auth", "owner:deadbeef", "return-code", "0"],
        )
        .unwrap();

        assert!(matches!(cli.command.as_ref(), Some(Command::ReturnCode(_))));
        assert_eq!(
            cli.auth_entries(),
            vec![(
                TpmUint32::new(TpmRh::Owner as u32),
                Auth::Password(vec![0xde, 0xad, 0xbe, 0xef]),
            ),]
        );
    }

    #[test]
    fn reject_global_auth_after_subcommand() {
        let result = TopLevel::from_args(
            &["tpm2sh"],
            &["return-code", "--auth", "owner:deadbeef", "0"],
        );

        assert!(result.is_err());
    }

    #[test]
    fn parse_version_without_command() {
        let cli = TopLevel::from_args(&["tpm2sh"], &["--version"]).unwrap();

        assert!(cli.version);
        assert!(cli.command.is_none());
    }
}
