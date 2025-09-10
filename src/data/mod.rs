// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

mod r#enum;
mod tpm_rc;
mod tpma;
mod tpmi;
mod tpms;
mod tpmt;
mod tpmu;

pub use self::r#enum::*;
pub use self::tpm_rc::*;
pub use self::tpma::*;
pub use self::tpmi::*;
pub use self::tpms::*;
pub use self::tpmt::*;
pub use self::tpmu::*;

use crate::{
    constant::{
        MAX_BUFFER_SIZE, MAX_DIGEST_SIZE, MAX_ECC_KEY_BYTES, MAX_EVENT_SIZE, MAX_NV_BUFFER_SIZE,
        MAX_PRIVATE_SIZE, MAX_RSA_KEY_BYTES, MAX_SENSITIVE_DATA, MAX_SYM_KEY_BYTES,
        TPM_MAX_COMMAND_SIZE,
    },
    tpm2b, tpm2b_struct, tpml,
};
use core::{convert::TryFrom, fmt::Debug};

tpm2b!(Tpm2b, TPM_MAX_COMMAND_SIZE);
tpm2b!(Tpm2bAuth, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bDigest, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bEccParameter, MAX_ECC_KEY_BYTES);
tpm2b!(Tpm2bEncryptedSecret, MAX_RSA_KEY_BYTES);
tpm2b!(Tpm2bEvent, MAX_EVENT_SIZE);
tpm2b!(Tpm2bMaxBuffer, MAX_BUFFER_SIZE);
tpm2b!(Tpm2bMaxNvBuffer, MAX_NV_BUFFER_SIZE);
tpm2b!(Tpm2bName, { MAX_DIGEST_SIZE + 2 });
tpm2b!(Tpm2bNonce, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bOperand, MAX_DIGEST_SIZE);
tpm2b!(Tpm2bPrivate, MAX_PRIVATE_SIZE);
tpm2b!(Tpm2bPrivateKeyRsa, { MAX_RSA_KEY_BYTES / 2 });
tpm2b!(Tpm2bPublicKeyRsa, MAX_RSA_KEY_BYTES);
tpm2b!(Tpm2bSensitiveData, MAX_SENSITIVE_DATA);
tpm2b!(Tpm2bSymKey, MAX_SYM_KEY_BYTES);
tpm2b!(Tpm2bData, MAX_SENSITIVE_DATA);
tpm2b!(Tpm2bTimeout, 8);
tpm2b!(Tpm2bIv, 16);

tpm2b_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bPublic,
    TpmtPublic
}

pub type Tpm2bTemplate = Tpm2bPublic;

tpm2b_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bSensitiveCreate,
    TpmsSensitiveCreate
}

tpm2b_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    Tpm2bSensitive,
    TpmtSensitive
}

tpm2b_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bCreationData,
    TpmsCreationData
}

tpm2b_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    Tpm2bAttest,
    TpmsAttest
}

tpm2b_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    Tpm2bNvPublic,
    TpmsNvPublic
}

tpm2b_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    Tpm2bIdObject,
    TpmsIdObject
}

tpm2b_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    Tpm2bEccPoint,
    TpmsEccPoint
}

tpm2b_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    Tpm2bNvPublic2,
    TpmtNvPublic2
}

tpml!(TpmlAcCapabilities, TpmsAcOutput, 64);
tpml!(TpmlAlgProperty, TpmsAlgProperty, 64);
tpml!(TpmlAlg, TpmAlgId, 64);
tpml!(TpmlCc, TpmCc, 256);
tpml!(TpmlCca, TpmaCc, 256);
tpml!(TpmlDigest, Tpm2bDigest, 8);
tpml!(TpmlDigestValues, TpmtHa, 8);
tpml!(TpmlHandle, u32, 128);
tpml!(TpmlPcrSelection, TpmsPcrSelection, 8);
tpml!(TpmlEccCurve, TpmEccCurve, 64);
tpml!(TpmlTaggedTpmProperty, TpmsTaggedProperty, 64);
