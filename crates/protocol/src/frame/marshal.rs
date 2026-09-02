// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{TPM_HEADER_SIZE, TpmFrame};
use crate::{
    TpmError, TpmMarshal, TpmResult, TpmSized,
    basic::TpmUint32,
    constant::MAX_SESSIONS,
    data::{TpmRc, TpmRcBase, TpmSt, TpmsAuthCommand, TpmsAuthResponse},
};
use core::{convert::TryFrom, mem::size_of};

/// Computes the handle area size for a frame body.
///
/// `TpmFrame` is a public trait, so `handles()` is caller-controlled and the
/// multiplication is checked rather than assumed to fit.
fn handle_area_size<F: TpmFrame>(frame: &F, offset: usize) -> TpmResult<usize> {
    frame
        .handles()
        .checked_mul(size_of::<u32>())
        .ok_or(TpmError::IntegerTooLarge {
            offset,
            value: crate::tpm_value(frame.handles()),
        })
}

/// Splits a frame body length into its handle and parameter areas.
///
/// `TpmSized::len` and `TpmFrame::handles` are independent public methods, so a
/// body shorter than its own declared handle area is rejected instead of
/// underflowing.
fn body_areas<F: TpmFrame>(frame: &F, offset: usize) -> TpmResult<(usize, usize)> {
    let handle_area_size = handle_area_size(frame, offset)?;
    let param_area_size =
        frame
            .len()
            .checked_sub(handle_area_size)
            .ok_or(TpmError::UnexpectedEnd {
                offset,
                needed: handle_area_size,
                available: frame.len(),
            })?;

    Ok((handle_area_size, param_area_size))
}

/// Sums the wire lengths of an authorization area.
fn sessions_len<S: TpmSized>(sessions: &[S], offset: usize) -> TpmResult<usize> {
    sessions.iter().try_fold(0usize, |total, session| {
        total
            .checked_add(session.len())
            .ok_or(TpmError::IntegerTooLarge {
                offset,
                value: crate::tpm_value(total),
            })
    })
}

/// Rejects an authorization area larger than the wire format allows.
fn check_session_count<S>(sessions: &[S], offset: usize) -> TpmResult<()> {
    if sessions.len() > MAX_SESSIONS {
        return Err(TpmError::TooManyItems {
            offset,
            limit: MAX_SESSIONS,
            actual: sessions.len(),
        });
    }

    Ok(())
}

/// Adds two lengths, reporting overflow at `offset`.
fn checked_add(lhs: usize, rhs: usize, offset: usize) -> TpmResult<usize> {
    lhs.checked_add(rhs).ok_or(TpmError::IntegerTooLarge {
        offset,
        value: crate::tpm_value(lhs),
    })
}

/// Marshals a TPM command into a writer and returns the total bytes written.
///
/// # Errors
///
/// Returns [`InvalidTag`](TpmError::InvalidTag) when `tag` is neither
/// [`NoSessions`](TpmSt::NoSessions) nor [`Sessions`](TpmSt::Sessions), or when
/// `sessions` does not match `tag`.
/// Returns [`TooManyItems`](TpmError::TooManyItems) when `sessions` exceeds
/// [`MAX_SESSIONS`].
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
        return Err(TpmError::InvalidTag {
            offset: writer.len(),
            value: u64::from(tag.value()),
        });
    }

    // A session slice paired with `TPM_ST_NO_SESSIONS` would be silently
    // dropped, producing a frame that does not carry the requested
    // authorization.
    if (tag == TpmSt::Sessions) == sessions.is_empty() {
        return Err(TpmError::InvalidTag {
            offset: writer.len(),
            value: u64::from(tag.value()),
        });
    }

    check_session_count(sessions, writer.len())?;

    let offset = writer.len();
    let (handle_area_size, param_area_size) = body_areas(command, offset)?;
    let auth_area_size = if tag == TpmSt::Sessions {
        checked_add(size_of::<u32>(), sessions_len(sessions, offset)?, offset)?
    } else {
        0
    };

    let total_body_len = checked_add(
        checked_add(handle_area_size, auth_area_size, offset)?,
        param_area_size,
        offset,
    )?;
    let command_size_usize = checked_add(TPM_HEADER_SIZE as usize, total_body_len, offset)?;

    let command_size =
        TpmUint32::try_from(command_size_usize).map_err(|_| TpmError::IntegerTooLarge {
            offset,
            value: crate::tpm_value(command_size_usize),
        })?;

    tag.marshal(writer)?;
    command_size.marshal(writer)?;
    command.cc().marshal(writer)?;

    command.marshal_handles(writer)?;

    if tag == TpmSt::Sessions {
        let sessions_len =
            TpmUint32::try_from(auth_area_size - size_of::<TpmUint32>()).map_err(|_| {
                TpmError::IntegerTooLarge {
                    offset,
                    value: crate::tpm_value(auth_area_size),
                }
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
/// Returns [`InvalidTag`](TpmError::InvalidTag) when `sessions` is non-empty for
/// a non-success response, which the wire format encodes as a bare header.
/// Returns [`TooManyItems`](TpmError::TooManyItems) when `sessions` exceeds
/// [`MAX_SESSIONS`].
/// Returns `Err(TpmError)` on a marshal failure.
pub fn tpm_marshal_response<R>(
    response: &R,
    rc: TpmRc,
    sessions: &[TpmsAuthResponse],
    writer: &mut crate::TpmWriter,
) -> TpmResult<()>
where
    R: TpmFrame,
{
    check_session_count(sessions, writer.len())?;

    if !matches!(rc, TpmRc::Fmt0(TpmRcBase::Success)) {
        // An error response is a bare header, so any session would be dropped.
        if !sessions.is_empty() {
            return Err(TpmError::InvalidTag {
                offset: writer.len(),
                value: u64::from(TpmSt::Sessions.value()),
            });
        }

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

    let offset = writer.len();
    let (handle_area_size, param_area_size) = body_areas(response, offset)?;
    let sessions_len = sessions_len(sessions, offset)?;

    let parameter_area_size_field_len = if tag == TpmSt::Sessions {
        size_of::<TpmUint32>()
    } else {
        0
    };

    let total_body_len = checked_add(
        checked_add(
            checked_add(handle_area_size, parameter_area_size_field_len, offset)?,
            param_area_size,
            offset,
        )?,
        sessions_len,
        offset,
    )?;
    let response_size_usize = checked_add(TPM_HEADER_SIZE as usize, total_body_len, offset)?;

    let response_size =
        TpmUint32::try_from(response_size_usize).map_err(|_| TpmError::IntegerTooLarge {
            offset,
            value: crate::tpm_value(response_size_usize),
        })?;

    tag.marshal(writer)?;
    response_size.marshal(writer)?;
    rc.marshal(writer)?;

    response.marshal_handles(writer)?;

    if tag == TpmSt::Sessions {
        let params_len =
            TpmUint32::try_from(param_area_size).map_err(|_| TpmError::IntegerTooLarge {
                offset,
                value: crate::tpm_value(param_area_size),
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
