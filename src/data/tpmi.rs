// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

use crate::{
    data::{TpmAlgId, TpmSt},
    tpm_bool, tpm_enum, TpmDiscriminant, TpmHandle,
};

tpm_bool! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct TpmiYesNo(bool);
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Default)]
    pub enum TpmiEccKeyExchange(u16) {
        #[default]
        (None, 0x0000, "TPM_ECC_NONE"),
        (Ecdh, 0x0019, "TPM_ALG_ECDH"),
        (Ecmqv, 0x001D, "TPM_ALG_ECMQV"),
        (Sm2, 0x001B, "TPM_ALG_SM2"),
    }
}

pub type TpmiAlgHash = TpmAlgId;
pub type TpmiAlgSymObject = TpmAlgId;
pub type TpmiStCommandTag = TpmSt;

pub type TpmiDhObject = TpmHandle;
pub type TpmiDhParent = TpmHandle;
pub type TpmiShAuthSession = TpmHandle;
pub type TpmiRhHierarchy = TpmHandle;
pub type TpmiRhNvExpIndex = TpmHandle;
