// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{TpmKeyError, asn1::TpmKeyCommandAsn1};
use tpm2_protocol::data::TpmCc;

/// A TPM policy command blob encoded according to the ASN.1 specification
/// encoding rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyPolicyCommand {
    cc: TpmCc,
    body: Vec<u8>,
}

impl TpmKeyPolicyCommand {
    #[must_use]
    pub const fn new(cc: TpmCc, body: Vec<u8>) -> Self {
        TpmKeyPolicyCommand { cc, body }
    }

    #[must_use]
    pub const fn cc(&self) -> TpmCc {
        self.cc
    }

    #[must_use]
    pub const fn body(&self) -> &Vec<u8> {
        &self.body
    }
}

/// A TPM key policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyAuthPolicy {
    name: Option<String>,
    policy: Vec<TpmKeyPolicyCommand>,
}

impl TpmKeyAuthPolicy {
    #[must_use]
    pub const fn new(name: Option<String>, policy: Vec<TpmKeyPolicyCommand>) -> Self {
        TpmKeyAuthPolicy { name, policy }
    }

    #[must_use]
    pub const fn empty() -> Self {
        TpmKeyAuthPolicy {
            name: None,
            policy: Vec::new(),
        }
    }

    #[must_use]
    pub const fn name(&self) -> &Option<String> {
        &self.name
    }

    #[must_use]
    pub const fn policy(&self) -> &Vec<TpmKeyPolicyCommand> {
        &self.policy
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.policy.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policy.is_empty()
    }
}

impl Default for TpmKeyAuthPolicy {
    fn default() -> Self {
        Self::empty()
    }
}

impl TryFrom<&TpmKeyCommandAsn1> for TpmKeyPolicyCommand {
    type Error = TpmKeyError;

    fn try_from(val: &TpmKeyCommandAsn1) -> Result<Self, Self::Error> {
        let cc = TpmCc::try_from(val.command_code)
            .map_err(|_| TpmKeyError::InvalidCc(val.command_code))?;

        let is_policy = matches!(
            cc,
            TpmCc::PolicyNv
                | TpmCc::PolicySecret
                | TpmCc::PolicySigned
                | TpmCc::PolicyAuthorize
                | TpmCc::PolicyAuthValue
                | TpmCc::PolicyCommandCode
                | TpmCc::PolicyCounterTimer
                | TpmCc::PolicyCpHash
                | TpmCc::PolicyLocality
                | TpmCc::PolicyNameHash
                | TpmCc::PolicyOr
                | TpmCc::PolicyTicket
                | TpmCc::PolicyPcr
                | TpmCc::PolicyRestart
                | TpmCc::PolicyPhysicalPresence
                | TpmCc::PolicyDuplicationSelect
                | TpmCc::PolicyGetDigest
                | TpmCc::PolicyPassword
                | TpmCc::PolicyNvWritten
                | TpmCc::PolicyTemplate
                | TpmCc::PolicyAuthorizeNv
                | TpmCc::PolicyAcSendSelect
                | TpmCc::PolicyCapability
                | TpmCc::PolicyParameters
                | TpmCc::PolicyTransportSpdm
        );

        if !is_policy {
            return Err(TpmKeyError::InvalidCc(val.command_code));
        }

        Ok(Self {
            cc,
            body: val.command_policy.as_ref().to_vec(),
        })
    }
}

impl From<&TpmKeyPolicyCommand> for TpmKeyCommandAsn1 {
    fn from(c: &TpmKeyPolicyCommand) -> Self {
        Self {
            command_code: c.cc as u32,
            command_policy: rasn::types::OctetString::copy_from_slice(&c.body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2_protocol::constant::TPM_MAX_COMMAND_SIZE;
    use tpm2_protocol::data::TpmlDigest;
    use tpm2_protocol::{TpmMarshal, TpmWriter};

    #[test]
    fn policy_or_roundtrip() {
        let mut body = vec![0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut body);
            TpmlDigest::default().marshal(&mut writer).unwrap();
            writer.len()
        };
        body.truncate(len);

        let cmd = TpmKeyPolicyCommand {
            cc: TpmCc::PolicyOr,
            body: body.clone(),
        };

        let asn1 = TpmKeyCommandAsn1::from(&cmd);
        assert_eq!(asn1.command_code, TpmCc::PolicyOr as u32);
        assert_eq!(asn1.command_policy.as_ref(), &body);

        let back = TpmKeyPolicyCommand::try_from(&asn1).unwrap();
        assert_eq!(back.cc, TpmCc::PolicyOr);
        assert_eq!(back.body, body);
    }

    #[test]
    fn conversion_asn1_roundtrip() {
        let body = vec![1, 2, 3, 4];
        let cmd = TpmKeyPolicyCommand {
            cc: TpmCc::PolicySecret,
            body: body.clone(),
        };

        let asn1 = TpmKeyCommandAsn1::from(&cmd);
        assert_eq!(asn1.command_code, TpmCc::PolicySecret as u32);

        let back = TpmKeyPolicyCommand::try_from(&asn1).unwrap();
        assert_eq!(back.cc, TpmCc::PolicySecret);
        assert_eq!(back.body, body);
    }
}
