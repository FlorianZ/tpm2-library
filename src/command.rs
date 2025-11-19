// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    asn1::{tpm_marshal_array, TpmKeyCommandAsn1},
    TpmKeyError,
};
use std::fmt::Debug;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bDigest, Tpm2bName, Tpm2bPublic, TpmCc, TpmlDigest, TpmlPcrSelection, TpmtSignature,
    },
    frame::{
        TpmCommand, TpmFrame, TpmMarshalBody, TpmPolicyAuthValueCommand, TpmPolicyGetDigestCommand,
        TpmPolicyOrCommand, TpmPolicyPasswordCommand, TpmPolicyPcrCommand,
        TpmPolicyPhysicalPresenceCommand, TpmPolicyRestartCommand, TpmPolicySecretCommand,
    },
    TpmHandle, TpmMarshal, TpmProtocolError, TpmSized, TpmUnmarshal, TpmWriter,
};

const ZERO_HANDLE: TpmHandle = TpmHandle(0);

/// A trait representing a single TPM policy command step.
pub trait TpmKeyCommand: Debug + Send + Sync {
    /// Returns the TPM command code.
    fn cc(&self) -> TpmCc;

    /// Returns marshaled body.
    fn body(&self) -> Vec<u8>;

    /// Converts this policy step into a typed TPM command using a fixed policy
    /// session handle.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPolicy`](crate::TpmKeyError::InvalidPolicy) when the body
    /// cannot be decoded as the parameter area for the command.
    /// Returns [`InvalidCc`](crate::TpmKeyError::InvalidCc) when the command code
    /// has no mapping to a TPM command in this crate.
    fn to_command(&self) -> Result<TpmCommand, TpmKeyError>;

    /// Returns a boxed clone of the command.
    fn box_clone(&self) -> Box<dyn TpmKeyCommand>;
}

impl Clone for Box<dyn TpmKeyCommand> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

impl PartialEq for Box<dyn TpmKeyCommand> {
    fn eq(&self, other: &Self) -> bool {
        self.cc() == other.cc() && self.body() == other.body()
    }
}

impl Eq for Box<dyn TpmKeyCommand> {}

/// Creates a `TpmKeyCommand` from a command code and raw body.
///
/// # Errors
///
/// Returns [`InvalidCc`](crate::TpmKeyError::InvalidCc) when `cc` is not valid.
/// Returns [`InvalidPolicy`](crate::TpmKeyError::InvalidPolicy) when `body`
/// violates command-specific constraints.
pub fn tpm_key_command_from_parts(
    cc: TpmCc,
    body: Vec<u8>,
) -> Result<Box<dyn TpmKeyCommand>, TpmKeyError> {
    match cc {
        TpmCc::PolicyAuthValue
        | TpmCc::PolicyPassword
        | TpmCc::PolicyGetDigest
        | TpmCc::PolicyRestart
        | TpmCc::PolicyPhysicalPresence => {
            if !body.is_empty() {
                return Err(TpmKeyError::InvalidPolicy);
            }

            Ok(Box::new(TpmKeyDefaultCommand { cc, body }))
        }
        TpmCc::PolicyAuthorize => {
            let (command, remainder) =
                TpmKeyAuthorizeCommand::unmarshal(&body).map_err(TpmKeyError::Unmarshal)?;

            if !remainder.is_empty() {
                return Err(TpmKeyError::InvalidPolicy);
            }

            Ok(Box::new(command))
        }
        TpmCc::PolicySecret => {
            let (command, remainder) =
                TpmKeySecretCommand::unmarshal(&body).map_err(TpmKeyError::Unmarshal)?;

            if !remainder.is_empty() {
                return Err(TpmKeyError::InvalidPolicy);
            }

            Ok(Box::new(command))
        }
        TpmCc::PolicyPcr => {
            let (pcr_digest, rest) =
                Tpm2bDigest::unmarshal(body.as_slice()).map_err(TpmKeyError::Unmarshal)?;
            let (pcrs, rest) = TpmlPcrSelection::unmarshal(rest).map_err(TpmKeyError::Unmarshal)?;
            if !rest.is_empty() {
                return Err(TpmKeyError::InvalidPolicy);
            }
            let _ = (pcr_digest, pcrs);
            Ok(Box::new(TpmKeyDefaultCommand { cc, body }))
        }
        TpmCc::PolicyOr => {
            let (p_hash_list, rest) =
                TpmlDigest::unmarshal(body.as_slice()).map_err(TpmKeyError::Unmarshal)?;
            if !rest.is_empty() {
                return Err(TpmKeyError::InvalidPolicy);
            }
            let _ = p_hash_list;
            Ok(Box::new(TpmKeyDefaultCommand { cc, body }))
        }
        _ => Err(TpmKeyError::InvalidCc(cc)),
    }
}

/// Constructs a `TpmKeyCommand` from a typed TPM policy command.
///
/// # Errors
///
/// Returns [`InvalidPolicy`](crate::TpmKeyError::InvalidPolicy) when the command
/// is not representable as a `CommandPolicy` step without additional context.
/// Returns [`InvalidCc`](crate::TpmKeyError::InvalidCc) when the command code is
/// not supported.
pub fn tpm_key_command_from_command(
    cmd: &TpmCommand,
    object_name: &Tpm2bName,
) -> Result<Box<dyn TpmKeyCommand>, TpmKeyError> {
    match cmd {
        TpmCommand::PolicyPcr(_) | TpmCommand::PolicyOr(_) => {
            let buf = tpm_marshal_command_parameters(cmd)?;
            Ok(Box::new(TpmKeyDefaultCommand {
                cc: cmd.cc(),
                body: buf,
            }))
        }
        TpmCommand::PolicySecret(inner) => {
            let command = TpmKeySecretCommand {
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
        | TpmCommand::PolicyPhysicalPresence(_) => Ok(Box::new(TpmKeyDefaultCommand {
            cc: cmd.cc(),
            body: Vec::new(),
        })),
        _ => Err(TpmKeyError::InvalidCc(cmd.cc())),
    }
}

/// A generic policy command with an uninterpreted body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyDefaultCommand {
    pub cc: TpmCc,
    pub body: Vec<u8>,
}

impl TpmKeyCommand for TpmKeyDefaultCommand {
    fn cc(&self) -> TpmCc {
        self.cc
    }

    fn body(&self) -> Vec<u8> {
        self.body.clone()
    }

    fn to_command(&self) -> Result<TpmCommand, TpmKeyError> {
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
                    Tpm2bDigest::unmarshal(self.body.as_slice()).map_err(TpmKeyError::Unmarshal)?;
                let (pcrs, rest) =
                    TpmlPcrSelection::unmarshal(rest).map_err(TpmKeyError::Unmarshal)?;
                if !rest.is_empty() {
                    return Err(TpmKeyError::InvalidPolicy);
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
                    TpmlDigest::unmarshal(self.body.as_slice()).map_err(TpmKeyError::Unmarshal)?;
                if !rest.is_empty() {
                    return Err(TpmKeyError::InvalidPolicy);
                }

                let inner = TpmPolicyOrCommand {
                    handles: [ZERO_HANDLE],
                    p_hash_list,
                };

                Ok(TpmCommand::PolicyOr(inner))
            }
            other => Err(TpmKeyError::InvalidCc(other)),
        }
    }

    fn box_clone(&self) -> Box<dyn TpmKeyCommand> {
        Box::new(self.clone())
    }
}

/// The command structure for `TPM2_PolicyAuthorize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyAuthorizeCommand {
    pub key_sign: Tpm2bPublic,
    pub policy_ref: Tpm2bDigest,
    pub policy_signature: TpmtSignature,
}

impl TpmKeyCommand for TpmKeyAuthorizeCommand {
    fn cc(&self) -> TpmCc {
        TpmCc::PolicyAuthorize
    }

    fn body(&self) -> Vec<u8> {
        tpm_marshal_array(&[self]).unwrap_or_default()
    }

    fn to_command(&self) -> Result<TpmCommand, TpmKeyError> {
        Err(TpmKeyError::InvalidPolicy)
    }

    fn box_clone(&self) -> Box<dyn TpmKeyCommand> {
        Box::new(self.clone())
    }
}

impl TpmSized for TpmKeyAuthorizeCommand {
    const SIZE: usize = Tpm2bPublic::SIZE + Tpm2bDigest::SIZE + TpmtSignature::SIZE;

    fn len(&self) -> usize {
        self.key_sign.len() + self.policy_ref.len() + self.policy_signature.len()
    }
}

impl TpmMarshal for TpmKeyAuthorizeCommand {
    fn marshal(&self, writer: &mut TpmWriter) -> Result<(), TpmProtocolError> {
        self.key_sign.marshal(writer)?;
        self.policy_ref.marshal(writer)?;
        self.policy_signature.marshal(writer)?;

        Ok(())
    }
}

impl TpmUnmarshal for TpmKeyAuthorizeCommand {
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
pub struct TpmKeySecretCommand {
    pub object_handle_hint: TpmHandle,
    pub object_name: Tpm2bName,
    pub policy_ref: Tpm2bDigest,
}

impl TpmKeyCommand for TpmKeySecretCommand {
    fn cc(&self) -> TpmCc {
        TpmCc::PolicySecret
    }

    fn body(&self) -> Vec<u8> {
        tpm_marshal_array(&[self]).unwrap_or_default()
    }

    fn to_command(&self) -> Result<TpmCommand, TpmKeyError> {
        let inner = TpmPolicySecretCommand {
            nonce_tpm: Tpm2bDigest::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: self.policy_ref,
            expiration: 0,
            handles: [self.object_handle_hint, ZERO_HANDLE],
        };
        Ok(TpmCommand::PolicySecret(inner))
    }

    fn box_clone(&self) -> Box<dyn TpmKeyCommand> {
        Box::new(self.clone())
    }
}

impl TpmSized for TpmKeySecretCommand {
    const SIZE: usize = TpmHandle::SIZE + Tpm2bName::SIZE + Tpm2bDigest::SIZE;

    fn len(&self) -> usize {
        self.object_handle_hint.len() + self.object_name.len() + self.policy_ref.len()
    }
}

impl TpmMarshal for TpmKeySecretCommand {
    fn marshal(&self, writer: &mut TpmWriter) -> Result<(), TpmProtocolError> {
        self.object_handle_hint.marshal(writer)?;
        self.object_name.marshal(writer)?;
        self.policy_ref.marshal(writer)?;

        Ok(())
    }
}

impl TpmUnmarshal for TpmKeySecretCommand {
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

impl TryFrom<TpmKeyCommandAsn1> for Box<dyn TpmKeyCommand> {
    type Error = TpmKeyError;

    fn try_from(val: TpmKeyCommandAsn1) -> Result<Self, Self::Error> {
        let cc = TpmCc::try_from(val.command_code).map_err(TpmKeyError::Unmarshal)?;
        tpm_key_command_from_parts(cc, val.command_policy.as_ref().to_vec())
    }
}

impl From<&dyn TpmKeyCommand> for TpmKeyCommandAsn1 {
    fn from(c: &dyn TpmKeyCommand) -> Self {
        let body = c.body();
        Self {
            command_code: c.cc() as u32,
            command_policy: rasn::types::OctetString::copy_from_slice(&body),
        }
    }
}

fn tpm_marshal_command_parameters(command: &TpmCommand) -> Result<Vec<u8>, TpmKeyError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        command
            .marshal_parameters(&mut writer)
            .map_err(TpmKeyError::Marshal)?;
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

#[cfg(test)]
fn validate_policy_command(cc: TpmCc, body: &[u8]) -> Result<(), TpmKeyError> {
    let _ = tpm_key_command_from_parts(cc, body.to_vec())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tpm2_protocol::constant::TPM_MAX_COMMAND_SIZE;

    #[rstest]
    #[case(TpmCc::PolicyAuthValue)]
    #[case(TpmCc::PolicyPassword)]
    #[case(TpmCc::PolicyGetDigest)]
    #[case(TpmCc::PolicyRestart)]
    #[case(TpmCc::PolicyPhysicalPresence)]
    fn zero_param_non_empty_err(#[case] cc: TpmCc) {
        assert!(matches!(
            validate_policy_command(cc, &[0x00]),
            Err(TpmKeyError::InvalidPolicy)
        ));
        assert!(tpm_key_command_from_parts(cc, vec![0]).is_err());
    }

    #[test]
    fn policy_secret_minimal_ok() {
        let body = [0u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(validate_policy_command(TpmCc::PolicySecret, &body).is_ok());
    }

    #[test]
    fn policy_secret_truncated_err() {
        let body = [0u8, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            validate_policy_command(TpmCc::PolicySecret, &body),
            Err(TpmKeyError::Unmarshal(_))
        ));
    }

    #[test]
    fn policy_authorize_empty_err() {
        assert!(matches!(
            validate_policy_command(TpmCc::PolicyAuthorize, &[]),
            Err(TpmKeyError::Unmarshal(_))
        ));
    }

    #[test]
    fn policy_pcr_to_and_from_command_roundtrip() {
        let mut body = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
        let len = {
            let mut writer = TpmWriter::new(&mut body);
            Tpm2bDigest::default().marshal(&mut writer).unwrap();
            TpmlPcrSelection::default().marshal(&mut writer).unwrap();
            writer.len()
        };
        body.truncate(len);

        let step = tpm_key_command_from_parts(TpmCc::PolicyPcr, body).unwrap();
        let cmd = step.to_command().unwrap();

        match cmd {
            TpmCommand::PolicyPcr(inner) => {
                assert_eq!(inner.handles[0], ZERO_HANDLE);
                let back = tpm_key_command_from_command(&cmd, &Tpm2bName::default()).unwrap();
                assert_eq!(&back, &step);
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn policy_or_to_and_from_command_roundtrip() {
        let mut body = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
        let len = {
            let mut writer = TpmWriter::new(&mut body);
            TpmlDigest::default().marshal(&mut writer).unwrap();
            writer.len()
        };
        body.truncate(len);

        let step = tpm_key_command_from_parts(TpmCc::PolicyOr, body).unwrap();
        let cmd = step.to_command().unwrap();

        match cmd {
            TpmCommand::PolicyOr(inner) => {
                assert_eq!(inner.handles[0], ZERO_HANDLE);
                let back = tpm_key_command_from_command(&cmd, &Tpm2bName::default()).unwrap();
                assert_eq!(&back, &step);
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn policy_secret_from_command_requires_name() {
        let cmd = TpmPolicySecretCommand {
            handles: [TpmHandle(0x8100_0000), ZERO_HANDLE],
            ..Default::default()
        };
        let name = Tpm2bName::default();

        let step = tpm_key_command_from_command(&TpmCommand::PolicySecret(cmd), &name).unwrap();
        assert_eq!(step.cc(), TpmCc::PolicySecret);

        let body = step.body();
        let (decoded, _) = TpmHandle::unmarshal(&body).unwrap();
        assert_eq!(decoded, TpmHandle(0x8100_0000));
    }
}
