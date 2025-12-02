// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

#![allow(clippy::doc_markdown)]

pub mod algorithm;
pub mod common;
pub mod create;
pub mod create_primary;
pub mod delete;
pub mod evict;
pub mod import;
pub mod load;
pub mod memory;
pub mod pcr_event;
pub mod reset_lock;
pub mod return_code;
pub mod seal;
pub mod unseal;

pub use algorithm::*;
pub use common::*;
pub use create::*;
pub use create_primary::*;
pub use delete::*;
pub use evict::*;
pub use import::*;
pub use load::*;
pub use memory::*;
pub use pcr_event::*;
pub use reset_lock::*;
pub use return_code::*;
pub use seal::*;
pub use unseal::*;

pub use crate::error::CommandError;

use std::io::Write;

use tabled::{
    settings::{object::Rows, Color, Modify, Padding, Style},
    Table, Tabled,
};

/// Creates, styles, and prints a table from a vector of `Tabled` items.
///
/// # Errors
///
/// Returns [`Io`](CommandError::Io) if writing to the writer fails.
pub fn print_table<T>(items: &[T], writer: &mut dyn Write, is_tty: bool) -> Result<(), CommandError>
where
    T: Tabled,
{
    if items.is_empty() {
        return Ok(());
    }

    let mut table = Table::new(items);

    table.with(Style::blank()).with(Padding::new(0, 2, 0, 0));

    if is_tty {
        table.with(Modify::new(Rows::first()).with(Color::BOLD));
    }

    writeln!(writer, "{table}").map_err(CommandError::Io)?;
    Ok(())
}
