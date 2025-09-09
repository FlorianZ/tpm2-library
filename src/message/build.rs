// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    data::{TpmRc, TpmSt, TpmsAuthCommand, TpmsAuthResponse, TPM_HEADER_SIZE},
    message::{TpmCommandBuild, TpmHeader, TpmResponseBuild},
    TpmBuild, TpmErrorKind, TpmResult, TpmSized,
};
use core::{convert::TryFrom, mem::size_of};

/// Builds a TPM command into a writer and returns the total bytes written.
///
/// # Errors
///
/// Returns `Err(TpmErrorKind)` on a build failure.
pub fn tpm_build_command<C>(
    command: &C,
    tag: TpmSt,
    sessions: &[TpmsAuthCommand],
    writer: &mut crate::TpmWriter,
) -> TpmResult<()>
where
    C: TpmHeader + TpmCommandBuild,
{
    if tag != TpmSt::NoSessions && tag != TpmSt::Sessions {
        return Err(TpmErrorKind::InvalidValue);
    }

    let handle_area_size = C::HANDLES * size_of::<u32>();
    let param_area_size = command.len() - handle_area_size;
    let auth_area_size = if tag == TpmSt::Sessions {
        let sessions_len: usize = sessions.iter().map(TpmSized::len).sum();
        size_of::<u32>() + sessions_len
    } else {
        0
    };

    let total_body_len = handle_area_size + auth_area_size + param_area_size;
    let command_size = u32::try_from(TPM_HEADER_SIZE + total_body_len)
        .map_err(|_| TpmErrorKind::Capacity(usize::try_from(u32::MAX).unwrap_or(usize::MAX)))?;

    (tag as u16).build(writer)?;
    command_size.build(writer)?;
    (C::CC as u32).build(writer)?;

    command.build_handles(writer)?;

    if tag == TpmSt::Sessions {
        let sessions_len = u32::try_from(auth_area_size - size_of::<u32>())
            .map_err(|_| TpmErrorKind::Capacity(usize::try_from(u32::MAX).unwrap_or(usize::MAX)))?;
        sessions_len.build(writer)?;
        for s in sessions {
            s.build(writer)?;
        }
    }

    command.build_parameters(writer)
}

/// Builds a TPM response.
///
/// # Errors
///
/// Returns `Err(TpmErrorKind)` on a build failure.
pub fn tpm_build_response<R>(
    response: &R,
    sessions: &[TpmsAuthResponse],
    rc: TpmRc,
    writer: &mut crate::TpmWriter,
) -> TpmResult<()>
where
    R: TpmHeader + TpmResponseBuild,
{
    let tag = if !rc.is_error() && !sessions.is_empty() {
        TpmSt::Sessions
    } else {
        TpmSt::NoSessions
    };

    if rc.is_error() || rc.is_warning() {
        (TpmSt::NoSessions as u16).build(writer)?;
        u32::try_from(TPM_HEADER_SIZE)?.build(writer)?;
        rc.value().build(writer)?;
        return Ok(());
    }

    let handle_area_size = R::HANDLES * size_of::<u32>();
    let param_area_size = response.len() - handle_area_size;
    let sessions_len: usize = sessions.iter().map(TpmSized::len).sum();

    let parameter_area_size_field_len = if tag == TpmSt::Sessions {
        size_of::<u32>()
    } else {
        0
    };

    let total_body_len =
        handle_area_size + parameter_area_size_field_len + param_area_size + sessions_len;

    let response_size = u32::try_from(TPM_HEADER_SIZE + total_body_len)
        .map_err(|_| TpmErrorKind::Capacity(usize::try_from(u32::MAX).unwrap_or(usize::MAX)))?;

    (tag as u16).build(writer)?;
    response_size.build(writer)?;
    rc.value().build(writer)?;

    response.build_handles(writer)?;

    if tag == TpmSt::Sessions {
        let params_len = u32::try_from(param_area_size)
            .map_err(|_| TpmErrorKind::Capacity(usize::try_from(u32::MAX).unwrap_or(usize::MAX)))?;
        params_len.build(writer)?;
    }

    response.build_parameters(writer)?;

    if tag == TpmSt::Sessions {
        for s in sessions {
            s.build(writer)?;
        }
    }
    Ok(())
}
