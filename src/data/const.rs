// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

pub const TPM_HEADER_SIZE: usize = 10;

/// 6.2 `TPM_CONSTANTS32`
pub const TPM_GENERATED_VALUE: u32 = 0xFF544347;

pub const TPM_RH_FIRST: u32 = 0x4000_0000;
pub const TPM_RH_LAST: u32 = 0x4004_FFFF;
pub const TPM_RH_PERSISTENT_FIRST: u32 = 0x8100_0000;
pub const TPM_RH_TRANSIENT_FIRST: u32 = 0x8000_0000;
