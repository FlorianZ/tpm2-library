// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{asn1::TpmKeyCommandAsn1, TpmKeyError};
use tpm2_protocol::data::TpmCc;
use tpm2_vtpm::{vtpm_policy_command_from_parts, VtpmPolicyCommand};

impl TryFrom<TpmKeyCommandAsn1> for Box<dyn VtpmPolicyCommand> {
    type Error = TpmKeyError;

    fn try_from(val: TpmKeyCommandAsn1) -> Result<Self, Self::Error> {
        let cc = TpmCc::try_from(val.command_code).map_err(TpmKeyError::Unmarshal)?;
        Ok(vtpm_policy_command_from_parts(
            cc,
            val.command_policy.as_ref().to_vec(),
        )?)
    }
}

impl From<&dyn VtpmPolicyCommand> for TpmKeyCommandAsn1 {
    fn from(c: &dyn VtpmPolicyCommand) -> Self {
        let body = c.body();
        Self {
            command_code: c.cc() as u32,
            command_policy: rasn::types::OctetString::copy_from_slice(&body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2_protocol::constant::TPM_MAX_COMMAND_SIZE;
    use tpm2_protocol::data::{Tpm2bDigest, Tpm2bName, TpmlDigest, TpmlPcrSelection};
    use tpm2_protocol::{TpmHandle, TpmMarshal, TpmWriter};
    use tpm2_vtpm::{VtpmPolicyDefaultCommand, VtpmPolicySecretCommand};

    fn validate_policy_command(cc: TpmCc, body: &[u8]) -> Result<(), TpmKeyError> {
        let _ = vtpm_policy_command_from_parts(cc, body.to_vec())?;
        Ok(())
    }

    #[test]
    fn zero_param_non_empty_err() {
        assert!(matches!(
            validate_policy_command(TpmCc::PolicyAuthValue, &[0x00]),
            Err(TpmKeyError::Vtpm(_))
        ));
    }

    #[test]
    fn policy_secret_minimal_ok() {
        let body = [0u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(validate_policy_command(TpmCc::PolicySecret, &body).is_ok());
    }

    #[test]
    fn policy_pcr_roundtrip() {
        let mut body = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
        let len = {
            let mut writer = TpmWriter::new(&mut body);
            Tpm2bDigest::default().marshal(&mut writer).unwrap();
            TpmlPcrSelection::default().marshal(&mut writer).unwrap();
            writer.len()
        };
        body.truncate(len);

        let step = vtpm_policy_command_from_parts(TpmCc::PolicyPcr, body.clone()).unwrap();
        assert_eq!(step.cc(), TpmCc::PolicyPcr);
        assert_eq!(step.body(), body);
    }

    #[test]
    fn policy_or_roundtrip() {
        let mut body = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
        let len = {
            let mut writer = TpmWriter::new(&mut body);
            TpmlDigest::default().marshal(&mut writer).unwrap();
            writer.len()
        };
        body.truncate(len);

        let step = vtpm_policy_command_from_parts(TpmCc::PolicyOr, body.clone()).unwrap();
        assert_eq!(step.cc(), TpmCc::PolicyOr);
        assert_eq!(step.body(), body);
    }

    #[test]
    fn conversion_asn1_roundtrip() {
        let cmd = VtpmPolicySecretCommand {
            object_handle_hint: TpmHandle(0x8100_0000),
            object_name: Tpm2bName::default(),
            policy_ref: Tpm2bDigest::default(),
        };

        let boxed: Box<dyn VtpmPolicyCommand> = Box::new(cmd.clone());
        let asn1 = TpmKeyCommandAsn1::from(boxed.as_ref());

        assert_eq!(asn1.command_code, TpmCc::PolicySecret as u32);

        let back: Box<dyn VtpmPolicyCommand> =
            Box::<dyn VtpmPolicyCommand>::try_from(asn1).unwrap();
        assert_eq!(back.cc(), TpmCc::PolicySecret);
        assert_eq!(back.body(), boxed.body());
    }

    #[test]
    fn conversion_default_command_roundtrip() {
        let cmd = VtpmPolicyDefaultCommand {
            cc: TpmCc::PolicyAuthValue,
            body: vec![],
        };
        let boxed: Box<dyn VtpmPolicyCommand> = Box::new(cmd);
        let asn1 = TpmKeyCommandAsn1::from(boxed.as_ref());

        let back: Box<dyn VtpmPolicyCommand> =
            Box::<dyn VtpmPolicyCommand>::try_from(asn1).unwrap();
        assert_eq!(back.cc(), TpmCc::PolicyAuthValue);
        assert!(back.body().is_empty());
    }
}
