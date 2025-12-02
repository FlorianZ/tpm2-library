// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::doc_markdown)]

use crate::{
    command::{
        Algorithm, CommandError, Create, CreatePrimary, Delete, Evict, Import, Load, Memory,
        PcrEvent, ResetLock, ReturnCode, Seal, Unseal,
    },
    task::TaskState,
};
use clap::{
    builder::styling::{Style, Styles},
    Parser, Subcommand, ValueEnum,
};
use std::{io::Write, path::PathBuf};
use strum::{Display, EnumString};
use tpm2_protocol::data::TpmRh;

const STYLES: Styles = Styles::styled()
    .header(Style::new().bold())
    .usage(Style::new().bold())
    .literal(Style::new())
    .placeholder(Style::new());

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

    /// Returns `true` if the command can be run without a TPM device.
    #[must_use]
    fn is_local(&self) -> bool {
        false
    }
}

/// TPM 2.0 shell
#[derive(Parser, Debug)]
#[command(version, about, styles = STYLES)]
pub struct TopLevel {
    /// Device file
    #[arg(short = 'd', long, default_value = "/dev/tpmrm0")]
    pub device: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
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

    fn is_local(&self) -> bool {
        self.as_task().is_local()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Display, EnumString, ValueEnum)]
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
