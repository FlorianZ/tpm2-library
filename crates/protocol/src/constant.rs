// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

pub const MAX_BUFFER_SIZE: usize = 1024;
pub const MAX_DIGEST_SIZE: usize = 64;
/// `sizeof(TPMT_HA)`: a `TPM_ALG_ID` selector plus the largest digest. This is
/// the capacity Part 2 assigns to `TPM2B_DATA`.
pub const MAX_DATA_SIZE: usize = MAX_DIGEST_SIZE + 2;
pub const MAX_ECC_KEY_BYTES: usize = 66;
pub const MAX_EVENT_SIZE: usize = 1024;
pub const MAX_HANDLES: usize = 8;
pub const MAX_NV_BUFFER_SIZE: usize = 1024;
pub const MAX_PRIVATE_SIZE: usize = 1408;
pub const MAX_RSA_KEY_BYTES: usize = 512;
pub const MAX_SENSITIVE_DATA: usize = 256;
pub const MAX_SESSIONS: usize = 8;
pub const MAX_SYM_KEY_BYTES: usize = 32;
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;
pub const TPM_MAX_COMMAND_SIZE: usize = 4096;
pub const TPM_PCR_SELECT_MAX: u8 = 4;
