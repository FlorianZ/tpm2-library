// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::doc_markdown)]

use crate::{
    command::{
        session::SessionType, Algorithm, Certificate, CommandError, Convert, Create, CreatePrimary,
        Delete, Key, Load, Memory, PcrEvent, Policy, ResetLock, ReturnCode, Save, Seal, Session,
        StartSession, Unseal,
    },
    device::{Auth, Device},
    session::SessionCache,
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, env, path::PathBuf, rc::Rc, str::FromStr};
use strum::{Display, EnumString};
use tpm2_protocol::data::{TpmRh, TpmSe};

pub(crate) fn get_auth(
    arg: Option<&String>,
    env_var: &str,
    session_map: &SessionCache,
    allowed_types: &[TpmSe],
) -> Result<Auth, CommandError> {
    let auth_str = arg.cloned().or_else(|| env::var(env_var).ok());

    let Some(s) = auth_str else {
        return Ok(Auth::Password(Vec::new()));
    };

    let uri = Uri::from_str(&s)?;
    match uri {
        Uri::Password(p) => Ok(Auth::Password(p)),
        Uri::Session(h) => {
            let session = session_map.get(&uri.to_string())?;
            if allowed_types.contains(&session.session_type) {
                Ok(Auth::Tracked(h))
            } else {
                let session_type_str = SessionType::from(session.session_type).to_string();
                Err(CommandError::UnsupportedSession(session_type_str))
            }
        }
        _ => Err(CommandError::InvalidInput(
            "auth must be a session:// or password:// URI".to_string(),
        )),
    }
}

/// A subcommand of the main CLI application.
pub trait SubCommand {
    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns an error if the execution fails.
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut crate::context::ContextCache,
        plain: bool,
    ) -> Result<(), CommandError>;

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
#[derive(FromArgs, Debug)]
pub struct TopLevel {
    /// device path
    #[argh(option, short = 'd', default = "PathBuf::from(\"/dev/tpmrm0\")")]
    pub device: PathBuf,

    /// log format: 'plain' or 'pretty'
    #[argh(option, default = "Default::default()")]
    pub log_format: LogFormat,

    /// print tables without headers and with space-separated columns
    #[argh(switch, short = 'P')]
    pub plain: bool,

    #[argh(subcommand)]
    pub command: Command,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum Command {
    Algorithm(Algorithm),
    Certificate(Certificate),
    Convert(Convert),
    Create(Create),
    CreatePrimary(CreatePrimary),
    Delete(Delete),
    Key(Key),
    Load(Load),
    Memory(Memory),
    PcrEvent(PcrEvent),
    Policy(Policy),
    ReturnCode(ReturnCode),
    ResetLock(ResetLock),
    Save(Save),
    Seal(Seal),
    Session(Session),
    StartSession(StartSession),
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
            Self::Key(cmd) => cmd,
            Self::Load(cmd) => cmd,
            Self::Memory(cmd) => cmd,
            Self::PcrEvent(cmd) => cmd,
            Self::Policy(cmd) => cmd,
            Self::ReturnCode(cmd) => cmd,
            Self::ResetLock(cmd) => cmd,
            Self::Save(cmd) => cmd,
            Self::Seal(cmd) => cmd,
            Self::Session(cmd) => cmd,
            Self::StartSession(cmd) => cmd,
            Self::Unseal(cmd) => cmd,
        }
    }
}

impl SubCommand for Command {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut crate::context::ContextCache,
        plain: bool,
    ) -> Result<(), CommandError> {
        self.as_subcommand().run(device, context, plain)
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
