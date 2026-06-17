// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use anyhow::anyhow;
use tpm2_device::TpmDeviceError;
use tpm2_protocol::data::TpmRcBase;

/// Maps a [`TpmDeviceError`] to a user-facing error.
///
/// Known TPM return codes are translated into concise diagnostics; every other
/// device error is reported verbatim. Apply this at TPM call sites instead of
/// relying on `?`, whose blanket conversion would discard the translation.
#[must_use]
pub fn device_err(err: TpmDeviceError) -> anyhow::Error {
    let rc = match err {
        TpmDeviceError::TpmRc(rc) => rc,
        other => return anyhow!("device: {other}"),
    };
    match rc.base() {
        TpmRcBase::Handle | TpmRcBase::ReferenceH0 | TpmRcBase::Type => {
            anyhow!("invalid parent handle")
        }
        TpmRcBase::AuthFail => anyhow!("access denied"),
        TpmRcBase::AuthMissing => anyhow!("authentication missing"),
        TpmRcBase::Lockout => anyhow!("dictionary attack lockout is active"),
        TpmRcBase::PolicyFail => anyhow!("policy denied"),
        _ => anyhow!("device: {}", TpmDeviceError::TpmRc(rc)),
    }
}
