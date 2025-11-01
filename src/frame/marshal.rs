// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    constant::TPM_HEADER_SIZE,
    data::{TpmRc, TpmRcBase, TpmSt, TpmsAuthCommand, TpmsAuthResponse},
    frame::TpmFrame,
    TpmError, TpmMarshal, TpmResult, TpmSized,
};
use core::{convert::TryFrom, mem::size_of};

/// Marshals a TPM command into a writer and returns the total bytes written.
///
/// # Errors
///
/// Returns `Err(TpmError)` on a marshal failure.
pub fn tpm_marshal_command<C>(
    command: &C,
    tag: TpmSt,
    sessions: &[TpmsAuthCommand],
    writer: &mut crate::TpmWriter,
) -> TpmResult<()>
where
    C: TpmFrame,
{
    if tag != TpmSt::NoSessions && tag != TpmSt::Sessions {
        return Err(TpmError::Malformed);
    }

    let handle_area_size = command.handles() * size_of::<u32>();
    let param_area_size = command.len() - handle_area_size;
    let auth_area_size = if tag == TpmSt::Sessions {
        let sessions_len: usize = sessions.iter().map(TpmSized::len).sum();
        size_of::<u32>() + sessions_len
    } else {
        0
    };

    let total_body_len = handle_area_size + auth_area_size + param_area_size;
    let command_size = u32::try_from(TPM_HEADER_SIZE as usize + total_body_len)
        .map_err(|_| TpmError::Malformed)?;

    (tag as u16).marshal(writer)?;
    command_size.marshal(writer)?;
    (command.cc() as u32).marshal(writer)?;

    command.marshal_handles(writer)?;

    if tag == TpmSt::Sessions {
        let sessions_len =
            u32::try_from(auth_area_size - size_of::<u32>()).map_err(|_| TpmError::Malformed)?;
        sessions_len.marshal(writer)?;
        for s in sessions {
            s.marshal(writer)?;
        }
    }

    command.marshal_parameters(writer)
}

/// Marshals a TPM response.
///
/// # Errors
///
/// Returns `Err(TpmError)` on a marshal failure.
pub fn tpm_marshal_response<R>(
    response: &R,
    sessions: &[TpmsAuthResponse],
    rc: TpmRc,
    writer: &mut crate::TpmWriter,
) -> TpmResult<()>
where
    R: TpmFrame,
{
    if !matches!(rc, TpmRc::Fmt0(TpmRcBase::Success)) {
        (TpmSt::NoSessions as u16).marshal(writer)?;
        TPM_HEADER_SIZE.marshal(writer)?;
        rc.value().marshal(writer)?;
        return Ok(());
    }

    let tag = if sessions.is_empty() {
        TpmSt::NoSessions
    } else {
        TpmSt::Sessions
    };

    let handle_area_size = response.handles() * size_of::<u32>();
    let param_area_size = response.len() - handle_area_size;
    let sessions_len: usize = sessions.iter().map(TpmSized::len).sum();

    let parameter_area_size_field_len = if tag == TpmSt::Sessions {
        size_of::<u32>()
    } else {
        0
    };

    let total_body_len =
        handle_area_size + parameter_area_size_field_len + param_area_size + sessions_len;

    let response_size = u32::try_from(TPM_HEADER_SIZE as usize + total_body_len)
        .map_err(|_| TpmError::Malformed)?;

    (tag as u16).marshal(writer)?;
    response_size.marshal(writer)?;
    rc.value().marshal(writer)?;

    response.marshal_handles(writer)?;

    if tag == TpmSt::Sessions {
        let params_len = u32::try_from(param_area_size).map_err(|_| TpmError::Malformed)?;
        params_len.marshal(writer)?;
    }

    response.marshal_parameters(writer)?;

    if tag == TpmSt::Sessions {
        for s in sessions {
            s.marshal(writer)?;
        }
    }
    Ok(())
}
