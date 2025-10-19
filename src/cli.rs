// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::doc_markdown)]

use crate::{
    command::{
        Algorithm, Certificate, CommandError, Convert, Create, CreatePrimary, Delete, Evict, Key,
        Load, Memory, PcrEvent, Policy, ResetLock, ReturnCode, /* Seal, */ Session, Unseal,
    },
    job::Job,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use strum::{Display, EnumString};
use tpm2_protocol::data::TpmRh;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum LogFormat {
    #[default]
    Plain,
    Pretty,
}

/// TPM 2.0 shell
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct TopLevel {
    /// Device path
    #[arg(short = 'd', long, default_value = "/dev/tpmrm0")]
    pub device: PathBuf,

    /// Log format: 'plain' or 'pretty'
    #[arg(long, default_value_t = LogFormat::default(), value_parser = clap::value_parser!(LogFormat))]
    pub log_format: LogFormat,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Algorithm(Algorithm),
    Certificate(Certificate),
    Convert(Convert),
    Create(Create),
    CreatePrimary(CreatePrimary),
    Delete(Delete),
    Evict(Evict),
    Key(Key),
    Load(Load),
    Memory(Memory),
    PcrEvent(PcrEvent),
    Policy(Policy),
    ReturnCode(ReturnCode),
    ResetLock(ResetLock),
    Session(Session),
    Unseal(Unseal),
}

impl Command {
    fn as_subcommand(&self) -> &dyn SubCommand {
        match self {
            Self::Algorithm(cmd) => cmd,
            Self::Certificate(cmd) => cmd,
            Self::Convert(cmd) => cmd,
            Self::Create(cmd) => cmd,
            Self::CreatePrimary(cmd) => cmd,
            Self::Delete(cmd) => cmd,
            Self::Evict(cmd) => cmd,
            Self::Key(cmd) => cmd,
            Self::Load(cmd) => cmd,
            Self::Memory(cmd) => cmd,
            Self::PcrEvent(cmd) => cmd,
            Self::Policy(cmd) => cmd,
            Self::ReturnCode(cmd) => cmd,
            Self::ResetLock(cmd) => cmd,
            Self::Session(cmd) => cmd,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Display, EnumString)]
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
