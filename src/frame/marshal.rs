// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{TPM_HEADER_SIZE, TpmFrame};
use crate::{
    TpmError, TpmMarshal, TpmResult, TpmSized,
    basic::TpmUint32,
    data::{TpmRc, TpmRcBase, TpmSt, TpmsAuthCommand, TpmsAuthResponse},
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
        return Err(TpmError::InvalidTag(
            crate::TpmErrorValue::new(writer.len()).value(u64::from(tag.value())),
        ));
    }

    let handle_area_size = command.handles() * size_of::<u32>();
    let param_area_size = command.len() - handle_area_size;
    let auth_area_size = if tag == TpmSt::Sessions {
        let sessions_len: usize = sessions.iter().map(TpmSized::len).sum();
        size_of::<u32>() + sessions_len
    } else {
        0
    };

    let total_body_len = handle_area_size
        .checked_add(auth_area_size)
        .and_then(|len| len.checked_add(param_area_size))
        .ok_or(TpmError::IntegerTooLarge(
            crate::TpmErrorValue::new(writer.len()).value_usize(param_area_size),
        ))?;

    let command_size_usize = (TPM_HEADER_SIZE as usize)
        .checked_add(total_body_len)
        .ok_or(TpmError::IntegerTooLarge(
            crate::TpmErrorValue::new(writer.len()).value_usize(total_body_len),
        ))?;

    let command_size = TpmUint32::try_from(command_size_usize).map_err(|_| {
        TpmError::IntegerTooLarge(
            crate::TpmErrorValue::new(writer.len()).value_usize(command_size_usize),
        )
    })?;

    tag.marshal(writer)?;
    command_size.marshal(writer)?;
    command.cc().marshal(writer)?;

    command.marshal_handles(writer)?;

    if tag == TpmSt::Sessions {
        let sessions_len =
            TpmUint32::try_from(auth_area_size - size_of::<TpmUint32>()).map_err(|_| {
                TpmError::IntegerTooLarge(
                    crate::TpmErrorValue::new(writer.len()).value_usize(auth_area_size),
                )
            })?;
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
        TpmSt::NoSessions.marshal(writer)?;
        TpmUint32::from(TPM_HEADER_SIZE).marshal(writer)?;
        rc.marshal(writer)?;
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
        size_of::<TpmUint32>()
    } else {
        0
    };

    let total_body_len = handle_area_size
        .checked_add(parameter_area_size_field_len)
        .and_then(|len| len.checked_add(param_area_size))
        .and_then(|len| len.checked_add(sessions_len))
        .ok_or(TpmError::IntegerTooLarge(
            crate::TpmErrorValue::new(writer.len()).value_usize(param_area_size),
        ))?;

    let response_size_usize = (TPM_HEADER_SIZE as usize)
        .checked_add(total_body_len)
        .ok_or(TpmError::IntegerTooLarge(
            crate::TpmErrorValue::new(writer.len()).value_usize(total_body_len),
        ))?;

    let response_size = TpmUint32::try_from(response_size_usize).map_err(|_| {
        TpmError::IntegerTooLarge(
            crate::TpmErrorValue::new(writer.len()).value_usize(response_size_usize),
        )
    })?;

    tag.marshal(writer)?;
    response_size.marshal(writer)?;
    rc.marshal(writer)?;

    response.marshal_handles(writer)?;

    if tag == TpmSt::Sessions {
        let params_len = TpmUint32::try_from(param_area_size).map_err(|_| {
            TpmError::IntegerTooLarge(
                crate::TpmErrorValue::new(writer.len()).value_usize(param_area_size),
            )
        })?;
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
