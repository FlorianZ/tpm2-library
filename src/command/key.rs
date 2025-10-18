// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{print_table, CommandError},
    job::Job,
    key::{self, KeyError},
};
use clap::Args;
use tabled::Tabled;
use tpm2_protocol::{data::Tpm2bPublic, TpmParse};

#[derive(Tabled)]
struct KeyRow {
    #[tabled(rename = "GRIP")]
    grip: String,
    #[tabled(rename = "DETAILS")]
    details: String,
}

/// Lists cached keys.
#[derive(Args, Debug)]
#[command(about = "Lists keys from local cache.")]
pub struct Key {}

impl SubCommand for Key {
    fn run(&self, job: &mut Job, plain: bool) -> Result<(), CommandError> {
        let mut rows: Vec<KeyRow> = Vec::new();
        for (grip, key) in &job.key_cache.contexts {
            let (public_blob, _) =
                Tpm2bPublic::parse(&key.public).map_err(|e| KeyError::Device(e.into()))?;
            rows.push(KeyRow {
                grip: grip.clone(),
                details: key::format_alg_from_public(&public_blob.inner),
            });
        }
        rows.sort_unstable_by(|a, b| a.grip.cmp(&b.grip));
        print_table(&mut job.key_cache.writer, rows, plain)?;
        Ok(())
    }

    fn is_local(&self) -> bool {
        true
    }
}
