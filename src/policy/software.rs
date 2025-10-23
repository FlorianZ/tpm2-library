// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

//! A pure software implementation of a policy session for dry-run calculations.

use super::{PolicyError, PolicySession};
use crate::{
    convert::from_tpm_object_to_vec,
    crypto::{crypto_digest, crypto_hash_size},
    device::Device,
};
use tpm2_protocol::data::{
    Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc, TpmlDigest, TpmlPcrSelection,
};

/// Updates a policy digest with a new command, mimicking the TPM's internal
/// hashing. This can be shared between the software session and the mock TPM.
///
/// # Errors
///
/// Returns an error if the hash algorithm is unsupported.
pub fn update_policy_digest(
    current_digest: &mut Tpm2bDigest,
    hash_alg: TpmAlgId,
    cc: TpmCc,
    params: &[&[u8]],
) -> Result<(), PolicyError> {
    let cc_bytes = (cc as u32).to_be_bytes();
    let mut chunks: Vec<&[u8]> = Vec::with_capacity(2 + params.len());
    chunks.push(current_digest.as_ref());
    chunks.push(&cc_bytes);
    chunks.extend(params.iter());

    let new_digest_bytes = crypto_digest(hash_alg, &chunks)?;
    *current_digest = Tpm2bDigest::try_from(new_digest_bytes.as_slice())?;
    Ok(())
}

/// A session that simulates TPM policy digest calculations in software.
pub struct SoftwarePolicySession<'a> {
    digest: Tpm2bDigest,
    hash_alg: TpmAlgId,
    digest_size: usize,
    device: &'a mut Device,
}

impl<'a> SoftwarePolicySession<'a> {
    /// Creates a new software policy session.
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::InvalidAlgorithm` if the hash algorithm is not supported.
    pub fn new(hash_alg: TpmAlgId, device: &'a mut Device) -> Result<Self, PolicyError> {
        let digest_size =
            crypto_hash_size(hash_alg).ok_or(PolicyError::InvalidAlgorithm(hash_alg))?;
        let digest = Tpm2bDigest::try_from(vec![0; digest_size].as_slice())?;
        Ok(Self {
            digest,
            hash_alg,
            digest_size,
            device,
        })
    }
}

impl PolicySession for SoftwarePolicySession<'_> {
    fn device(&mut self) -> &mut Device {
        self.device
    }

    fn policy_pcr(
        &mut self,
        pcr_digest: &Tpm2bDigest,
        pcrs: TpmlPcrSelection,
    ) -> Result<(), PolicyError> {
        let pcrs_bytes = from_tpm_object_to_vec(&pcrs)?;
        update_policy_digest(
            &mut self.digest,
            self.hash_alg,
            TpmCc::PolicyPcr,
            &[&pcrs_bytes, pcr_digest.as_ref()],
        )
    }

    fn policy_or(&mut self, p_hash_list: &TpmlDigest) -> Result<(), PolicyError> {
        let digests_as_bytes: Vec<u8> = p_hash_list
            .iter()
            .flat_map(std::convert::AsRef::as_ref)
            .copied()
            .collect();

        self.digest = Tpm2bDigest::try_from(vec![0; self.digest_size].as_slice())?;

        update_policy_digest(
            &mut self.digest,
            self.hash_alg,
            TpmCc::PolicyOR,
            &[&digests_as_bytes],
        )
    }

    fn policy_secret(
        &mut self,
        _auth_handle: u32,
        auth_handle_name: &Tpm2bName,
        _password: Option<&[u8]>,
        _cp_hash: Option<Tpm2bDigest>,
    ) -> Result<(), PolicyError> {
        let command_code = TpmCc::PolicySecret;
        let policy_ref = Tpm2bNonce::default();
        let cc_bytes = (command_code as u32).to_be_bytes();

        let intermediate_digest_bytes = crypto_digest(
            self.hash_alg,
            &[self.digest.as_ref(), &cc_bytes, auth_handle_name.as_ref()],
        )?;

        let final_digest_bytes = crypto_digest(
            self.hash_alg,
            &[&intermediate_digest_bytes, policy_ref.as_ref()],
        )?;

        self.digest = Tpm2bDigest::try_from(final_digest_bytes.as_slice())?;
        Ok(())
    }

    fn policy_restart(&mut self) -> Result<(), PolicyError> {
        self.digest = Tpm2bDigest::try_from(vec![0; self.digest_size].as_slice())?;
        Ok(())
    }

    fn get_digest(&mut self) -> Result<Tpm2bDigest, PolicyError> {
        Ok(self.digest)
    }

    fn hash_alg(&self) -> TpmAlgId {
        self.hash_alg
    }
}
