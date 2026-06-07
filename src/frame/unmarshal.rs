// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::data::TpmCc;

/// A unified struct holding all dispatch info for a given Command Code.
pub(crate) struct TpmDispatch {
    pub cc: TpmCc,
    pub handles: usize,
    pub response_handles: usize,
}
