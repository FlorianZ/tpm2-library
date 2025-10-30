// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

//! A policy session that interacts directly with a TPM device.

use super::{PolicyError, PolicySession};
use crate::{
    device::{Device, DeviceError},
    vtpm::build_password_session,
};
use tpm2_protocol::{
    data::{Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc, TpmlDigest, TpmlPcrSelection},
    message::{
        TpmPolicyGetDigestCommand, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicyRestartCommand, TpmPolicySecretCommand,
    },
    TpmHandle,
};

/// A session that sends policy commands to a real TPM device.
pub struct TpmPolicySession<'a> {
    device: &'a mut Device,
    handle: TpmHandle,
    hash_alg: TpmAlgId,
}

impl<'a> TpmPolicySession<'a> {
    /// Creates a new TPM policy session.
    #[must_use]
    pub fn new(device: &'a mut Device, handle: TpmHandle, hash_alg: TpmAlgId) -> Self {
        Self {
            device,
            handle,
            hash_alg,
        }
    }
}

impl PolicySession for TpmPolicySession<'_> {
    fn policy_pcr(
        &mut self,
        pcr_digest: &Tpm2bDigest,
        pcrs: TpmlPcrSelection,
    ) -> Result<(), PolicyError> {
        let cmd = TpmPolicyPcrCommand {
            policy_session: self.handle.0.into(),
            pcr_digest: *pcr_digest,
            pcrs,
        };
        self.device.execute(&cmd, &[])?;
        Ok(())
    }

    fn policy_or(&mut self, p_hash_list: &TpmlDigest) -> Result<(), PolicyError> {
        let cmd = TpmPolicyOrCommand {
            policy_session: self.handle.0.into(),
            p_hash_list: *p_hash_list,
        };
        self.device.execute(&cmd, &[])?;
        Ok(())
    }

    fn policy_secret(
        &mut self,
        auth_handle: u32,
        _auth_handle_name: &Tpm2bName,
        password: Option<&[u8]>,
        cp_hash: Option<Tpm2bDigest>,
    ) -> Result<(), PolicyError> {
        let cmd = TpmPolicySecretCommand {
            auth_handle: auth_handle.into(),
            policy_session: self.handle.0.into(),
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: cp_hash.unwrap_or_default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
        };

        let password_auth = build_password_session(password.unwrap_or_default())?;
        let sessions = vec![password_auth];

        self.device.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn policy_restart(&mut self) -> Result<(), PolicyError> {
        let cmd = TpmPolicyRestartCommand {
            session_handle: self.handle.0.into(),
        };
        self.device.execute(&cmd, &[])?;
        Ok(())
    }

    fn get_digest(&mut self) -> Result<Tpm2bDigest, PolicyError> {
        let cmd = TpmPolicyGetDigestCommand {
            policy_session: self.handle.0.into(),
        };
        let (resp, _) = self.device.execute(&cmd, &[])?;
        let digest_resp = resp
            .PolicyGetDigest()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::PolicyGetDigest))?;
        Ok(digest_resp.policy_digest)
    }

    fn hash_alg(&self) -> TpmAlgId {
        self.hash_alg
    }
}
