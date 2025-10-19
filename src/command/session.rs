// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{print_table, CommandError},
    job::Job,
};
use clap::Args;
use tabled::Tabled;
use tpm2_protocol::data::TpmSe;

#[derive(Tabled)]
struct SessionRow {
    #[tabled(rename = "HANDLE")]
    handle: String,
}

/// Lists cached authorization sessions.
#[derive(Args, Debug)]
#[command(about = "Lists cached authorization sessions.")]
pub struct Session {}

impl SubCommand for Session {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        let mut handles: Vec<u32> = Vec::new();
        for (_, session) in &job.session_cache {
            let handle = session.context.saved_handle.0;
            if session.session_type == TpmSe::Policy {
                handles.push(handle);
            }
        }
        handles.sort_unstable();
        let rows: Vec<SessionRow> = handles
            .into_iter()
            .map(|handle| SessionRow {
                handle: format!("{handle:08x}"),
            })
            .collect();
        print_table(&mut job.key_cache.writer, rows)?;
        Ok(())
    }
}
