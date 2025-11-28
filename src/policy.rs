// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::VtpmError;
use std::fmt::Debug;
use tpm2_protocol::{
    basic::{TpmHandle, TpmInt32, TpmUint32},
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bDigest, Tpm2bName, Tpm2bPublic, TpmCc, TpmlDigest, TpmlPcrSelection, TpmtSignature,
    },
    frame::{
        TpmCommand, TpmFrame, TpmMarshalBody, TpmPolicyAuthValueCommand, TpmPolicyGetDigestCommand,
        TpmPolicyOrCommand, TpmPolicyPasswordCommand, TpmPolicyPcrCommand,
        TpmPolicyPhysicalPresenceCommand, TpmPolicyRestartCommand, TpmPolicySecretCommand,
    },
    TpmMarshal, TpmProtocolError, TpmSized, TpmUnmarshal, TpmWriter,
};

const ZERO_HANDLE: TpmHandle = TpmUint32(0);

/// A trait representing a single TPM policy command step.
pub trait VtpmPolicyCommand: Debug + Send + Sync {
    /// Returns the TPM command code.
    fn cc(&self) -> TpmCc;

    /// Returns marshaled body.
    fn body(&self) -> Vec<u8>;

    /// Returns the length of the marshaled command (CC + size + body) in bytes.
    fn len(&self) -> usize;

    /// Returns `true` if the command is empty.
    ///
    /// Always returns `false` for policy commands as they contain at least the
    /// command code.
    fn is_empty(&self) -> bool {
        false
    }

    /// Converts this policy step into a typed TPM command using a fixed policy
    /// session handle.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPolicy`](crate::VtpmError::InvalidPolicy) when the body
    /// cannot be decoded as the parameter area for the command.
    /// Returns [`InvalidCc`](crate::VtpmError::InvalidCc) when the command code
    /// has no mapping to a TPM command in this crate.
    fn to_command(&self) -> Result<TpmCommand, VtpmError>;

    /// Returns a boxed clone of the command.
    fn box_clone(&self) -> Box<dyn VtpmPolicyCommand>;
}

impl Clone for Box<dyn VtpmPolicyCommand> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

impl PartialEq for Box<dyn VtpmPolicyCommand> {
    fn eq(&self, other: &Self) -> bool {
        self.cc() == other.cc() && self.body() == other.body()
    }
}

impl Eq for Box<dyn VtpmPolicyCommand> {}

impl std::convert::TryInto<TpmCommand> for Box<dyn VtpmPolicyCommand> {
    type Error = VtpmError;

    fn try_into(self) -> Result<TpmCommand, Self::Error> {
        self.to_command()
    }
}

/// Creates a `VtpmPolicyCommand` from a command code and raw body.
///
/// # Errors
///
/// Returns [`InvalidCc`](crate::VtpmError::InvalidCc) when `cc` is not valid.
/// Returns [`InvalidPolicy`](crate::VtpmError::InvalidPolicy) when `body`
/// violates command-specific constraints.
pub fn vtpm_policy_command_from_parts(
    cc: TpmCc,
    body: &[u8],
) -> Result<Box<dyn VtpmPolicyCommand>, VtpmError> {
    match cc {
        TpmCc::PolicyAuthValue
        | TpmCc::PolicyPassword
        | TpmCc::PolicyGetDigest
        | TpmCc::PolicyRestart
        | TpmCc::PolicyPhysicalPresence => {
            if !body.is_empty() {
                return Err(VtpmError::InvalidPolicy);
            }

            Ok(Box::new(VtpmPolicyDefaultCommand {
                cc,
                body: body.into(),
            }))
        }
        TpmCc::PolicyAuthorize => {
            let (command, remainder) =
                VtpmPolicyAuthorizeCommand::unmarshal(body).map_err(VtpmError::Unmarshal)?;

            if !remainder.is_empty() {
                return Err(VtpmError::InvalidPolicy);
            }

            Ok(Box::new(command))
        }
        TpmCc::PolicySecret => {
            let (command, remainder) =
                VtpmPolicySecretCommand::unmarshal(body).map_err(VtpmError::Unmarshal)?;

            if !remainder.is_empty() {
                return Err(VtpmError::InvalidPolicy);
            }

            Ok(Box::new(command))
        }
        TpmCc::PolicyPcr => {
            let (pcr_digest, rest) = Tpm2bDigest::unmarshal(body).map_err(VtpmError::Unmarshal)?;
            let (pcrs, rest) = TpmlPcrSelection::unmarshal(rest).map_err(VtpmError::Unmarshal)?;
            if !rest.is_empty() {
                return Err(VtpmError::InvalidPolicy);
            }
            let _ = (pcr_digest, pcrs);
            Ok(Box::new(VtpmPolicyDefaultCommand {
                cc,
                body: body.into(),
            }))
        }
        TpmCc::PolicyOr => {
            let (p_hash_list, rest) = TpmlDigest::unmarshal(body).map_err(VtpmError::Unmarshal)?;
            if !rest.is_empty() {
                return Err(VtpmError::InvalidPolicy);
            }
            let _ = p_hash_list;
            Ok(Box::new(VtpmPolicyDefaultCommand {
                cc,
                body: body.into(),
            }))
        }
        _ => Err(VtpmError::InvalidCc(cc)),
    }
}

/// Constructs a `VtpmPolicyCommand` from a typed TPM policy command.
///
/// # Errors
///
/// Returns [`InvalidPolicy`](crate::VtpmError::InvalidPolicy) when the command
/// is not representable as a `CommandPolicy` step without additional context.
/// Returns [`InvalidCc`](crate::VtpmError::InvalidCc) when the command code is
/// not supported.
pub fn vtpm_policy_command_from(
    cmd: &TpmCommand,
    object_name: &Tpm2bName,
) -> Result<Box<dyn VtpmPolicyCommand>, VtpmError> {
    match cmd {
        TpmCommand::PolicyPcr(_) | TpmCommand::PolicyOr(_) => {
            let buf = vtpm_marshal_command_parameters(cmd)?;
            Ok(Box::new(VtpmPolicyDefaultCommand {
                cc: cmd.cc(),
                body: buf,
            }))
        }
        TpmCommand::PolicySecret(inner) => {
            let command = VtpmPolicySecretCommand {
                object_handle_hint: inner.handles[0],
                object_name: *object_name,
                policy_ref: inner.policy_ref,
            };
            Ok(Box::new(command))
        }
        TpmCommand::PolicyAuthValue(_)
        | TpmCommand::PolicyPassword(_)
        | TpmCommand::PolicyGetDigest(_)
        | TpmCommand::PolicyRestart(_)
        | TpmCommand::PolicyPhysicalPresence(_) => Ok(Box::new(VtpmPolicyDefaultCommand {
            cc: cmd.cc(),
            body: Vec::new(),
        })),
        _ => Err(VtpmError::InvalidCc(cmd.cc())),
    }
}

fn vtpm_marshal_command_parameters(command: &TpmCommand) -> Result<Vec<u8>, VtpmError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        command
            .marshal_parameters(&mut writer)
            .map_err(VtpmError::Marshal)?;
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

pub(crate) fn vtpm_marshal_policy_list(
    policies: &[Box<dyn VtpmPolicyCommand>],
    writer: &mut TpmWriter,
) -> Result<(), VtpmError> {
    let count = u32::try_from(policies.len()).map_err(|_| VtpmError::OperationFailed)?;
    count.marshal(writer).map_err(VtpmError::Marshal)?;

    for command in policies {
        command.cc().marshal(writer).map_err(VtpmError::Marshal)?;

        let body = command.body();
        let body_len = u32::try_from(body.len()).map_err(|_| VtpmError::OperationFailed)?;
        body_len.marshal(writer).map_err(VtpmError::Marshal)?;
        writer.write_bytes(&body).map_err(VtpmError::Marshal)?;
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
pub(crate) fn vtpm_unmarshal_policy_list(
    buffer: &[u8],
) -> Result<(Vec<Box<dyn VtpmPolicyCommand>>, &[u8]), VtpmError> {
    let (count, mut tail) = TpmUint32::unmarshal(buffer).map_err(VtpmError::Unmarshal)?;
    let mut policy = Vec::new();

    for _ in 0..count.value() {
        let (cc, tail_next) = TpmCc::unmarshal(tail).map_err(VtpmError::Unmarshal)?;
        let (len_u32, tail_next) = TpmUint32::unmarshal(tail_next).map_err(VtpmError::Unmarshal)?;
        let len = len_u32.value() as usize;

        if tail_next.len() < len {
            return Err(VtpmError::UnexpectedEnd);
        }

        let (body, tail_next) = tail_next.split_at(len);
        tail = tail_next;

        policy.push(vtpm_policy_command_from_parts(cc, body)?);
    }

    Ok((policy, tail))
}

/// A generic policy command with an uninterpreted body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtpmPolicyDefaultCommand {
    pub cc: TpmCc,
    pub body: Vec<u8>,
}

impl VtpmPolicyCommand for VtpmPolicyDefaultCommand {
    fn cc(&self) -> TpmCc {
        self.cc
    }

    fn body(&self) -> Vec<u8> {
        self.body.clone()
    }

    fn len(&self) -> usize {
        TpmCc::SIZE + u32::SIZE + self.body.len()
    }

    fn to_command(&self) -> Result<TpmCommand, VtpmError> {
        match self.cc {
            TpmCc::PolicyAuthValue => {
                let inner = TpmPolicyAuthValueCommand {
                    handles: [ZERO_HANDLE],
                };
                Ok(TpmCommand::PolicyAuthValue(inner))
            }
            TpmCc::PolicyGetDigest => {
                let inner = TpmPolicyGetDigestCommand {
                    handles: [ZERO_HANDLE],
                };
                Ok(TpmCommand::PolicyGetDigest(inner))
            }
            TpmCc::PolicyPassword => {
                let inner = TpmPolicyPasswordCommand {
                    handles: [ZERO_HANDLE],
                };
                Ok(TpmCommand::PolicyPassword(inner))
            }
            TpmCc::PolicyRestart => {
                let inner = TpmPolicyRestartCommand {
                    handles: [ZERO_HANDLE],
                };
                Ok(TpmCommand::PolicyRestart(inner))
            }
            TpmCc::PolicyPhysicalPresence => {
                let inner = TpmPolicyPhysicalPresenceCommand {
                    handles: [ZERO_HANDLE],
                };
                Ok(TpmCommand::PolicyPhysicalPresence(inner))
            }
            TpmCc::PolicyPcr => {
                let (pcr_digest, rest) =
                    Tpm2bDigest::unmarshal(self.body.as_slice()).map_err(VtpmError::Unmarshal)?;
                let (pcrs, rest) =
                    TpmlPcrSelection::unmarshal(rest).map_err(VtpmError::Unmarshal)?;
                if !rest.is_empty() {
                    return Err(VtpmError::InvalidPolicy);
                }

                let inner = TpmPolicyPcrCommand {
                    pcr_digest,
                    pcrs,
                    handles: [ZERO_HANDLE],
                };

                Ok(TpmCommand::PolicyPcr(inner))
            }
            TpmCc::PolicyOr => {
                let (p_hash_list, rest) =
                    TpmlDigest::unmarshal(self.body.as_slice()).map_err(VtpmError::Unmarshal)?;
                if !rest.is_empty() {
                    return Err(VtpmError::InvalidPolicy);
                }

                let inner = TpmPolicyOrCommand {
                    handles: [ZERO_HANDLE],
                    p_hash_list,
                };

                Ok(TpmCommand::PolicyOr(inner))
            }
            other => Err(VtpmError::InvalidCc(other)),
        }
    }

    fn box_clone(&self) -> Box<dyn VtpmPolicyCommand> {
        Box::new(self.clone())
    }
}

/// The command structure for `TPM2_PolicyAuthorize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtpmPolicyAuthorizeCommand {
    pub key_sign: Tpm2bPublic,
    pub policy_ref: Tpm2bDigest,
    pub policy_signature: TpmtSignature,
}

impl VtpmPolicyCommand for VtpmPolicyAuthorizeCommand {
    fn cc(&self) -> TpmCc {
        TpmCc::PolicyAuthorize
    }

    fn body(&self) -> Vec<u8> {
        let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            if self.marshal(&mut writer).is_err() {
                return Vec::new();
            }
            writer.len()
        };
        buf.truncate(len);
        buf
    }

    fn len(&self) -> usize {
        TpmCc::SIZE
            + u32::SIZE
            + self.key_sign.len()
            + self.policy_ref.len()
            + self.policy_signature.len()
    }

    fn to_command(&self) -> Result<TpmCommand, VtpmError> {
        Err(VtpmError::InvalidPolicy)
    }

    fn box_clone(&self) -> Box<dyn VtpmPolicyCommand> {
        Box::new(self.clone())
    }
}

impl TpmSized for VtpmPolicyAuthorizeCommand {
    const SIZE: usize = Tpm2bPublic::SIZE + Tpm2bDigest::SIZE + TpmtSignature::SIZE;

    fn len(&self) -> usize {
        self.key_sign.len() + self.policy_ref.len() + self.policy_signature.len()
    }
}

impl TpmMarshal for VtpmPolicyAuthorizeCommand {
    fn marshal(&self, writer: &mut TpmWriter) -> Result<(), TpmProtocolError> {
        self.key_sign.marshal(writer)?;
        self.policy_ref.marshal(writer)?;
        self.policy_signature.marshal(writer)?;

        Ok(())
    }
}

impl TpmUnmarshal for VtpmPolicyAuthorizeCommand {
    fn unmarshal(buffer: &[u8]) -> Result<(Self, &[u8]), TpmProtocolError> {
        let (key_sign, remainder) = Tpm2bPublic::unmarshal(buffer)?;
        let (policy_ref, remainder) = Tpm2bDigest::unmarshal(remainder)?;
        let (policy_signature, remainder) = TpmtSignature::unmarshal(remainder)?;

        Ok((
            Self {
                key_sign,
                policy_ref,
                policy_signature,
            },
            remainder,
        ))
    }
}

/// The command structure for `TPM2_PolicySecret`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtpmPolicySecretCommand {
    pub object_handle_hint: TpmHandle,
    pub object_name: Tpm2bName,
    pub policy_ref: Tpm2bDigest,
}

impl VtpmPolicyCommand for VtpmPolicySecretCommand {
    fn cc(&self) -> TpmCc {
        TpmCc::PolicySecret
    }

    fn body(&self) -> Vec<u8> {
        let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            if self.marshal(&mut writer).is_err() {
                return Vec::new();
            }
            writer.len()
        };
        buf.truncate(len);
        buf
    }

    fn len(&self) -> usize {
        TpmCc::SIZE
            + u32::SIZE
            + self.object_handle_hint.len()
            + self.object_name.len()
            + self.policy_ref.len()
    }

    fn to_command(&self) -> Result<TpmCommand, VtpmError> {
        let inner = TpmPolicySecretCommand {
            nonce_tpm: Tpm2bDigest::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: self.policy_ref,
            expiration: TpmInt32(0),
            handles: [self.object_handle_hint, ZERO_HANDLE],
        };
        Ok(TpmCommand::PolicySecret(inner))
    }

    fn box_clone(&self) -> Box<dyn VtpmPolicyCommand> {
        Box::new(self.clone())
    }
}

impl TpmSized for VtpmPolicySecretCommand {
    const SIZE: usize = TpmHandle::SIZE + Tpm2bName::SIZE + Tpm2bDigest::SIZE;

    fn len(&self) -> usize {
        self.object_handle_hint.len() + self.object_name.len() + self.policy_ref.len()
    }
}

impl TpmMarshal for VtpmPolicySecretCommand {
    fn marshal(&self, writer: &mut TpmWriter) -> Result<(), TpmProtocolError> {
        self.object_handle_hint.marshal(writer)?;
        self.object_name.marshal(writer)?;
        self.policy_ref.marshal(writer)?;

        Ok(())
    }
}

impl TpmUnmarshal for VtpmPolicySecretCommand {
    fn unmarshal(buffer: &[u8]) -> Result<(Self, &[u8]), TpmProtocolError> {
        let (object_handle_hint, remainder) = TpmHandle::unmarshal(buffer)?;
        let (object_name, remainder) = Tpm2bName::unmarshal(remainder)?;
        let (policy_ref, remainder) = Tpm2bDigest::unmarshal(remainder)?;

        Ok((
            Self {
                object_handle_hint,
                object_name,
                policy_ref,
            },
            remainder,
        ))
    }
}
