// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{print_table, CommandError},
    job::Job,
};
use clap::Args;
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
}

/// Lists cached authorization sessions.
#[derive(Args, Debug)]
#[command(about = "Lists cached authorization sessions.")]
pub struct Session {
    /// Filter by session type
    #[arg(long = "type")]
    pub type_filter: Option<SessionType>,
}

impl SubCommand for Session {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        let mut results: Vec<(u32, SessionType)> = Vec::new();

        for (_, session) in &job.session_cache {
            let handle = session.context.saved_handle.0;
            results.push((handle, session.session_type.into()));
        }

        if let Some(filter_type) = self.type_filter {
            results.retain(|(_, session_type)| *session_type == filter_type);
        }

        results.sort_unstable();

        let rows: Vec<SessionRow> = results
            .into_iter()
            .map(|(handle, _)| SessionRow {
                handle: format!("{handle:08x}"),
            })
            .collect();

        print_table(&mut job.key_cache.writer, rows)?;

        Ok(())
    }
}
