// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{asn1::TpmKeyCommandAsn1, TpmKeyError, TpmKeyPolicyCommand};
use tpm2_protocol::data::TpmCc;

impl TryFrom<TpmKeyCommandAsn1> for TpmKeyPolicyCommand {
    type Error = TpmKeyError;

    fn try_from(val: TpmKeyCommandAsn1) -> Result<Self, Self::Error> {
        let cc = TpmCc::try_from(val.command_code)
            .map_err(|_| TpmKeyError::InvalidCc(val.command_code))?;
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
        let mut body = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
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

        let back = TpmKeyPolicyCommand::try_from(asn1).unwrap();
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

        let back = TpmKeyPolicyCommand::try_from(asn1).unwrap();
        assert_eq!(back.cc, TpmCc::PolicySecret);
        assert_eq!(back.body, body);
    }
}
