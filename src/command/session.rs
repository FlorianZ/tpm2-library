// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::SubCommand, command::CommandError, context::ContextCache, device::Device};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use strum::{Display, EnumString};
use tabled::Tabled;
use tpm2_protocol::data::TpmSe;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Display, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum SessionType {
    Hmac,
    Policy,
    Trial,
}

impl From<TpmSe> for SessionType {
    fn from(val: TpmSe) -> Self {
        match val {
            TpmSe::Hmac => Self::Hmac,
            TpmSe::Policy => Self::Policy,
            TpmSe::Trial => Self::Trial,
        }
    }
}

#[derive(Tabled)]
struct SessionRow {
    #[tabled(rename = "HANDLE")]
    handle: String,
    #[tabled(rename = "DETAILS")]
    details: String,
}

/// Lists cached authorization sessions.
#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "session",
    note = "Lists cached authorization sessions."
)]
pub struct Session {
    /// filter by session type
    #[argh(option, long = "type")]
    pub type_filter: Option<SessionType>,
}

impl SubCommand for Session {
    fn run(
        &self,
        _device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        plain: bool,
    ) -> Result<(), CommandError> {
        let mut results: Vec<(u32, SessionType)> = Vec::new();

        for (_, session) in &context.session_map {
            let handle = session.context.saved_handle.0;
            results.push((handle, session.session_type.into()));
        }

        if let Some(filter_type) = self.type_filter {
            results.retain(|(_, session_type)| *session_type == filter_type);
        }

        results.sort_unstable();

        let rows: Vec<SessionRow> = results
            .into_iter()
            .map(|(handle, session_type)| SessionRow {
                handle: format!("session:{handle:08x}"),
                details: session_type.to_string(),
            })
            .collect();

        super::print_table(&mut context.writer, rows, plain)?;

        Ok(())
    }
}
