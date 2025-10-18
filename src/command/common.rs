// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{auth::Auth, uri::Uri};
use clap::Args;

/// Arguments for specifying an input source.
#[derive(Args, Debug, Clone)]
pub struct InputArgs {
    /// Input file path (if not specified, reads from stdin)
    #[arg(short = 'i', long)]
    pub input: Option<Uri>,
}

/// Arguments for specifying an output destination.
#[derive(Args, Debug, Clone)]
pub struct OutputArgs {
    /// Output file path (if not specified, writes to stdout)
    #[arg(short = 'o', long)]
    pub output: Option<Uri>,
}

/// Arguments for specifying a parent key and its authentication.
#[derive(Args, Debug, Clone)]
pub struct ParentArgs {
    /// Parent key: 'tpm:<handle>', or 'key:<name grip>'
    #[arg(short = 'P', long)]
    pub parent: Uri,

    /// Parent auth: 'password:<hex>' or 'session:<handle>'
    #[arg(short = 'p', long = "parent-auth")]
    pub parent_auth: Option<Auth>,
}
