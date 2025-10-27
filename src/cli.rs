// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::doc_markdown)]

use crate::{
    auth::Auth,
    command::{
        Algorithm, Cache, CommandError, Convert, Create, CreatePrimary, Delete, Evict, Load,
        Memory, PcrEvent, Policy, ResetLock, ReturnCode, Unseal,
    },
    job::Job,
};
use clap::{
    builder::styling::{Style, Styles},
    Parser, Subcommand, ValueEnum,
};
use std::path::PathBuf;
use strum::{Display, EnumString};
use tpm2_protocol::data::TpmRh;

const STYLES: Styles = Styles::styled()
    .header(Style::new().bold())
    .usage(Style::new().bold())
    .literal(Style::new())
    .placeholder(Style::new());

/// A subcommand of the main CLI application.
pub trait SubCommand {
    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns an error if the execution fails.
    fn run(&self, job: &mut Job) -> Result<(), CommandError>;

    /// Returns `true` if the command can be run without a TPM device.
    #[must_use]
    fn is_local(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Display, EnumString, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum LogFormat {
    #[default]
    Plain,
    Pretty,
}

/// TPM 2.0 shell
#[derive(Parser, Debug)]
#[command(version, about, styles = STYLES)]
pub struct TopLevel {
    /// Device file
    #[arg(short = 'd', long, default_value = "/dev/tpmrm0")]
    pub device: PathBuf,

    /// Either 'plain' or 'pretty'
    #[arg(long, value_enum, default_value_t = LogFormat::default())]
    pub log_format: LogFormat,

    /// List of 'password:<hex>', 'policy:<hex>' or 'vtpm:<handle>' entries.
    #[arg(short = 'A', long = "auth", value_delimiter = ',')]
    pub auth: Vec<Auth>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Algorithm(Algorithm),
    Cache(Cache),
    Convert(Convert),
    Create(Create),
    CreatePrimary(CreatePrimary),
    Delete(Delete),
    Evict(Evict),
    Load(Load),
    Memory(Memory),
    PcrEvent(PcrEvent),
    Policy(Policy),
    ReturnCode(ReturnCode),
    ResetLock(ResetLock),
    Unseal(Unseal),
}

impl Command {
    fn as_subcommand(&self) -> &dyn SubCommand {
        match self {
            Self::Algorithm(cmd) => cmd,
            Self::Cache(cmd) => cmd,
            Self::Convert(cmd) => cmd,
            Self::Create(cmd) => cmd,
            Self::CreatePrimary(cmd) => cmd,
            Self::Delete(cmd) => cmd,
            Self::Evict(cmd) => cmd,
            Self::Load(cmd) => cmd,
            Self::Memory(cmd) => cmd,
            Self::PcrEvent(cmd) => cmd,
            Self::Policy(cmd) => cmd,
            Self::ReturnCode(cmd) => cmd,
            Self::ResetLock(cmd) => cmd,
            Self::Unseal(cmd) => cmd,
        }
    }
}

impl SubCommand for Command {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        self.as_subcommand().run(job)
    }

    fn is_local(&self) -> bool {
        self.as_subcommand().is_local()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Display, EnumString, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum Hierarchy {
    #[default]
    Owner,
    Platform,
    Endorsement,
}

impl From<Hierarchy> for TpmRh {
    fn from(h: Hierarchy) -> Self {
        match h {
            Hierarchy::Owner => TpmRh::Owner,
            Hierarchy::Platform => TpmRh::Platform,
            Hierarchy::Endorsement => TpmRh::Endorsement,
        }
    }
}
