// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    basic::{Int32, Uint16, Uint32, Uint64},
    data::{
        Tpm2bAttest, Tpm2bAuth, Tpm2bCreationData, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter,
        Tpm2bEccPoint, Tpm2bEncryptedSecret, Tpm2bEvent, Tpm2bIdObject, Tpm2bIv, Tpm2bMaxBuffer,
        Tpm2bMaxNvBuffer, Tpm2bName, Tpm2bNonce, Tpm2bNvPublic, Tpm2bPrivate, Tpm2bPublic,
        Tpm2bPublicKeyRsa, Tpm2bSensitive, Tpm2bSensitiveCreate, Tpm2bSensitiveData, Tpm2bTemplate,
        Tpm2bTimeout, TpmAlgId, TpmAt, TpmCap, TpmCc, TpmClockAdjust, TpmEccCurve, TpmEo, TpmRh,
        TpmSe, TpmSu, TpmaLocality, TpmiAlgCipherMode, TpmiAlgHash, TpmiEccKeyExchange, TpmiYesNo,
        TpmlAcCapabilities, TpmlAlg, TpmlCc, TpmlDigest, TpmlDigestValues, TpmlPcrSelection,
        TpmsAcOutput, TpmsAlgorithmDetailEcc, TpmsCapabilityData, TpmsContext, TpmsTimeInfo,
        TpmtHa, TpmtKdfScheme, TpmtPublicParms, TpmtRsaDecrypt, TpmtSignature, TpmtSymDef,
        TpmtSymDefObject, TpmtTkAuth, TpmtTkCreation, TpmtTkHashcheck, TpmtTkVerified,
    },
    frame::TpmHeader,
    tpm_struct, TpmHandle,
};
use core::fmt::Debug;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmAcGetCapabilityCommand,
    cc: TpmCc::AcGetCapability,
    handles: 1,
    parameters: {
        pub capability: TpmAt,
        pub count: Uint32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmAcGetCapabilityResponse,
    cc: TpmCc::AcGetCapability,
    handles: 0,
    parameters: {
        pub more_data: TpmiYesNo,
        pub capabilities_data: TpmlAcCapabilities,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmAcSendCommand,
    cc: TpmCc::AcSend,
    handles: 3,
    parameters: {
        pub ac_data_in: Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmAcSendResponse,
    cc: TpmCc::AcSend,
    handles: 0,
    parameters: {
        pub ac_data_out: TpmsAcOutput,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmActivateCredentialCommand,
    cc: TpmCc::ActivateCredential,
    handles: 2,
    parameters: {
        pub credential_blob: Tpm2bIdObject,
        pub secret: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmActivateCredentialResponse,
    cc: TpmCc::ActivateCredential,
    handles: 0,
    parameters: {
        pub cert_info: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmActSetTimeoutCommand,
    cc: TpmCc::ActSetTimeout,
    handles: 1,
    parameters: {
        pub start_timeout: Uint32,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmActSetTimeoutResponse,
    cc: TpmCc::ActSetTimeout,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmChangeEpsCommand,
    cc: TpmCc::ChangeEps,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmChangeEpsResponse,
    cc: TpmCc::ChangeEps,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmChangePpsCommand,
    cc: TpmCc::ChangePps,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmChangePpsResponse,
    cc: TpmCc::ChangePps,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmCertifyCommand,
    cc: TpmCc::Certify,
    handles: 2,
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmCertifyResponse,
    cc: TpmCc::Certify,
    handles: 0,
    parameters: {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmCertifyCreationCommand,
    cc: TpmCc::CertifyCreation,
    handles: 2,
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub creation_hash: Tpm2bDigest,
        pub in_scheme: TpmtSignature,
        pub creation_ticket: TpmtTkCreation,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmCertifyCreationResponse,
    cc: TpmCc::CertifyCreation,
    handles: 0,
    parameters: {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmClearCommand,
    cc: TpmCc::Clear,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmClearResponse,
    cc: TpmCc::Clear,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmClearControlCommand,
    cc: TpmCc::ClearControl,
    handles: 1,
    parameters: {
        pub disable: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmClearControlResponse,
    cc: TpmCc::ClearControl,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmClockRateAdjustCommand,
    cc: TpmCc::ClockRateAdjust,
    handles: 1,
    parameters: {
        pub rate_adjust: TpmClockAdjust,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmClockRateAdjustResponse,
    cc: TpmCc::ClockRateAdjust,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmClockSetCommand,
    cc: TpmCc::ClockSet,
    handles: 1,
    parameters: {
        pub new_time: Uint64,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmClockSetResponse,
    cc: TpmCc::ClockSet,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmCommitCommand,
    cc: TpmCc::Commit,
    handles: 1,
    parameters: {
        pub p1: Tpm2bEccPoint,
        pub s2: Tpm2bSensitiveData,
        pub y2: Tpm2bEccParameter,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmCommitResponse,
    cc: TpmCc::Commit,
    handles: 0,
    parameters: {
        pub k: Tpm2bEccPoint,
        pub l: Tpm2bEccPoint,
        pub e: Tpm2bEccPoint,
        pub counter: Uint16,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmContextLoadCommand,
    cc: TpmCc::ContextLoad,
    handles: 0,
    parameters: {
        pub context: TpmsContext,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmContextLoadResponse,
    cc: TpmCc::ContextLoad,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmContextSaveCommand,
    cc: TpmCc::ContextSave,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmContextSaveResponse,
    cc: TpmCc::ContextSave,
    handles: 0,
    parameters: {
        pub context: TpmsContext,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmCreateCommand,
    cc: TpmCc::Create,
    handles: 1,
    parameters: {
        pub in_sensitive: Tpm2bSensitiveCreate,
        pub in_public: Tpm2bPublic,
        pub outside_info: Tpm2bData,
        pub creation_pcr: TpmlPcrSelection,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmCreateResponse,
    cc: TpmCc::Create,
    handles: 0,
    parameters: {
        pub out_private: Tpm2bPrivate,
        pub out_public: Tpm2bPublic,
        pub creation_data: Tpm2bCreationData,
        pub creation_hash: Tpm2bDigest,
        pub creation_ticket: TpmtTkCreation,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmCreateLoadedCommand,
    cc: TpmCc::CreateLoaded,
    handles: 1,
    parameters: {
        pub in_sensitive: Tpm2bSensitiveCreate,
        pub in_public: Tpm2bTemplate,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmCreateLoadedResponse,
    cc: TpmCc::CreateLoaded,
    handles: 1,
    parameters: {
        pub out_private: Tpm2bPrivate,
        pub out_public: Tpm2bPublic,
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmCreatePrimaryCommand,
    cc: TpmCc::CreatePrimary,
    handles: 1,
    parameters: {
        pub in_sensitive: Tpm2bSensitiveCreate,
        pub in_public: Tpm2bPublic,
        pub outside_info: Tpm2bData,
        pub creation_pcr: TpmlPcrSelection,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmCreatePrimaryResponse,
    cc: TpmCc::CreatePrimary,
    handles: 1,
    parameters: {
        pub out_public: Tpm2bPublic,
        pub creation_data: Tpm2bCreationData,
        pub creation_hash: Tpm2bDigest,
        pub creation_ticket: TpmtTkCreation,
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmDictionaryAttackLockResetCommand,
    cc: TpmCc::DictionaryAttackLockReset,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmDictionaryAttackLockResetResponse,
    cc: TpmCc::DictionaryAttackLockReset,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmDictionaryAttackParametersCommand,
    cc: TpmCc::DictionaryAttackParameters,
    handles: 1,
    parameters: {
        pub new_max_tries: Uint32,
        pub new_recovery_time: Uint32,
        pub lockout_recovery: Uint32,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmDictionaryAttackParametersResponse,
    cc: TpmCc::DictionaryAttackParameters,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmDuplicateCommand,
    cc: TpmCc::Duplicate,
    handles: 2,
    parameters: {
        pub encryption_key_in: Tpm2bData,
        pub symmetric_alg: TpmtSymDefObject,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmDuplicateResponse,
    cc: TpmCc::Duplicate,
    handles: 0,
    parameters: {
        pub encryption_key_out: Tpm2bData,
        pub duplicate: Tpm2bPrivate,
        pub out_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmEccDecryptCommand,
    cc: TpmCc::EccDecrypt,
    handles: 1,
    parameters: {
        pub c1: Tpm2bEccPoint,
        pub c2: crate::data::Tpm2bMaxBuffer,
        pub c3: crate::data::Tpm2bDigest,
        pub in_scheme: TpmtKdfScheme,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEccDecryptResponse,
    cc: TpmCc::EccDecrypt,
    handles: 0,
    parameters: {
        pub plaintext: crate::data::Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmEcEphemeralCommand,
    cc: TpmCc::EcEphemeral,
    handles: 0,
    parameters: {
        pub curve_id: TpmEccCurve,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmEcEphemeralResponse,
    cc: TpmCc::EcEphemeral,
    handles: 0,
    parameters: {
        pub q: Tpm2bEccPoint,
        pub counter: Uint16,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEccEncryptCommand,
    cc: TpmCc::EccEncrypt,
    handles: 1,
    parameters: {
        pub plaintext: Tpm2bMaxBuffer,
        pub in_scheme: TpmtKdfScheme,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEccEncryptResponse,
    cc: TpmCc::EccEncrypt,
    handles: 0,
    parameters: {
        pub c1: Tpm2bEccPoint,
        pub c2: crate::data::Tpm2bMaxBuffer,
        pub c3: crate::data::Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmEccParametersCommand,
    cc: TpmCc::EccParameters,
    handles: 0,
    parameters: {
        pub curve_id: TpmEccCurve,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEccParametersResponse,
    cc: TpmCc::EccParameters,
    handles: 0,
    parameters: {
        pub parameters: TpmsAlgorithmDetailEcc,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmEcdhKeyGenCommand,
    cc: TpmCc::EcdhKeyGen,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEcdhKeyGenResponse,
    cc: TpmCc::EcdhKeyGen,
    handles: 0,
    parameters: {
        pub z_point: Tpm2bEccPoint,
        pub pub_point: Tpm2bEccPoint,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmEcdhZGenCommand,
    cc: TpmCc::EcdhZGen,
    handles: 1,
    parameters: {
        pub in_point: Tpm2bEccPoint,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEcdhZGenResponse,
    cc: TpmCc::EcdhZGen,
    handles: 0,
    parameters: {
        pub out_point: Tpm2bEccPoint,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEncryptDecryptCommand,
    cc: TpmCc::EncryptDecrypt,
    handles: 1,
    parameters: {
        pub decrypt: TpmiYesNo,
        pub mode: TpmiAlgCipherMode,
        pub iv_in: Tpm2bIv,
        pub in_data: Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEncryptDecryptResponse,
    cc: TpmCc::EncryptDecrypt,
    handles: 0,
    parameters: {
        pub out_data: Tpm2bMaxBuffer,
        pub iv_out: Tpm2bIv,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEncryptDecrypt2Command,
    cc: TpmCc::EncryptDecrypt2,
    handles: 1,
    parameters: {
        pub in_data: Tpm2bMaxBuffer,
        pub decrypt: TpmiYesNo,
        pub mode: TpmAlgId,
        pub iv_in: Tpm2bIv,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEncryptDecrypt2Response,
    cc: TpmCc::EncryptDecrypt2,
    handles: 0,
    parameters: {
        pub out_data: Tpm2bMaxBuffer,
        pub iv_out: Tpm2bIv,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEventSequenceCompleteCommand,
    cc: TpmCc::EventSequenceComplete,
    handles: 2,
    parameters: {
        pub buffer: Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmEventSequenceCompleteResponse,
    cc: TpmCc::EventSequenceComplete,
    handles: 0,
    parameters: {
        pub results: TpmlDigestValues,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEvictControlCommand,
    cc: TpmCc::EvictControl,
    handles: 2,
    parameters: {
        pub persistent_handle: TpmHandle,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmEvictControlResponse,
    cc: TpmCc::EvictControl,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmFieldUpgradeDataCommand,
    cc: TpmCc::FieldUpgradeData,
    handles: 0,
    parameters: {
        pub fu_data: crate::data::Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmFieldUpgradeDataResponse,
    cc: TpmCc::FieldUpgradeData,
    handles: 0,
    parameters: {
        pub next_digest: TpmtHa,
        pub first_digest: TpmtHa,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmFieldUpgradeStartCommand,
    cc: TpmCc::FieldUpgradeStart,
    handles: 2,
    parameters: {
        pub fu_digest: Tpm2bDigest,
        pub manifest_signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmFieldUpgradeStartResponse,
    cc: TpmCc::FieldUpgradeStart,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmFirmwareReadCommand,
    cc: TpmCc::FirmwareRead,
    handles: 0,
    parameters: {
        pub sequence_number: Uint32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmFirmwareReadResponse,
    cc: TpmCc::FirmwareRead,
    handles: 0,
    parameters: {
        pub fu_data: crate::data::Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmFlushContextCommand,
    cc: TpmCc::FlushContext,
    handles: 0,
    parameters: {
        pub flush_handle: TpmHandle,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmFlushContextResponse,
    cc: TpmCc::FlushContext,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmGetCapabilityCommand,
    cc: TpmCc::GetCapability,
    handles: 0,
    parameters: {
        pub cap: TpmCap,
        pub property: Uint32,
        pub property_count: Uint32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetCapabilityResponse,
    cc: TpmCc::GetCapability,
    handles: 0,
    parameters: {
        pub more_data: TpmiYesNo,
        pub capability_data: TpmsCapabilityData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmGetCommandAuditDigestCommand,
    cc: TpmCc::GetCommandAuditDigest,
    handles: 2,
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetCommandAuditDigestResponse,
    cc: TpmCc::GetCommandAuditDigest,
    handles: 0,
    parameters: {
        pub audit_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmGetRandomCommand,
    cc: TpmCc::GetRandom,
    handles: 0,
    parameters: {
        pub bytes_requested: Uint16,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetRandomResponse,
    cc: TpmCc::GetRandom,
    handles: 0,
    parameters: {
        pub random_bytes: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmGetSessionAuditDigestCommand,
    cc: TpmCc::GetSessionAuditDigest,
    handles: 3,
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetSessionAuditDigestResponse,
    cc: TpmCc::GetSessionAuditDigest,
    handles: 0,
    parameters: {
        pub audit_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmGetTestResultCommand,
    cc: TpmCc::GetTestResult,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetTestResultResponse,
    cc: TpmCc::GetTestResult,
    handles: 0,
    parameters: {
        pub out_data: Tpm2bMaxBuffer,
        pub test_result: crate::data::TpmRc,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmGetTimeCommand,
    cc: TpmCc::GetTime,
    handles: 2,
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmGetTimeResponse,
    cc: TpmCc::GetTime,
    handles: 0,
    parameters: {
        pub time_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmHashCommand,
    cc: TpmCc::Hash,
    handles: 0,
    parameters: {
        pub data: Tpm2bMaxBuffer,
        pub hash_alg: TpmAlgId,
        pub hierarchy: TpmRh,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmHashResponse,
    cc: TpmCc::Hash,
    handles: 0,
    parameters: {
        pub out_hash: Tpm2bDigest,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmHashSequenceStartCommand,
    cc: TpmCc::HashSequenceStart,
    handles: 0,
    parameters: {
        pub auth: Tpm2bAuth,
        pub hash_alg: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmHashSequenceStartResponse,
    cc: TpmCc::HashSequenceStart,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmHierarchyChangeAuthCommand,
    cc: TpmCc::HierarchyChangeAuth,
    handles: 1,
    parameters: {
        pub new_auth: Tpm2bAuth,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmHierarchyChangeAuthResponse,
    cc: TpmCc::HierarchyChangeAuth,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmHierarchyControlCommand,
    cc: TpmCc::HierarchyControl,
    handles: 1,
    parameters: {
        pub enable: TpmRh,
        pub state: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmHierarchyControlResponse,
    cc: TpmCc::HierarchyControl,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmHmacCommand,
    cc: TpmCc::Hmac,
    handles: 1,
    parameters: {
        pub buffer: Tpm2bMaxBuffer,
        pub hash_alg: TpmiAlgHash,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmHmacResponse,
    cc: TpmCc::Hmac,
    handles: 0,
    parameters: {
        pub out_hmac: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmHmacStartCommand,
    cc: TpmCc::HmacStart,
    handles: 1,
    parameters: {
        pub auth: Tpm2bAuth,
        pub hash_alg: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmHmacStartResponse,
    cc: TpmCc::HmacStart,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmImportCommand,
    cc: TpmCc::Import,
    handles: 1,
    parameters: {
        pub encryption_key: Tpm2bData,
        pub object_public: Tpm2bPublic,
        pub duplicate: Tpm2bPrivate,
        pub in_sym_seed: Tpm2bEncryptedSecret,
        pub symmetric_alg: TpmtSymDef,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmImportResponse,
    cc: TpmCc::Import,
    handles: 0,
    parameters: {
        pub out_private: Tpm2bPrivate,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmIncrementalSelfTestCommand,
    cc: TpmCc::IncrementalSelfTest,
    handles: 0,
    parameters: {
        pub to_test: TpmlAlg,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmIncrementalSelfTestResponse,
    cc: TpmCc::IncrementalSelfTest,
    handles: 0,
    parameters: {
        pub to_do_list: TpmlAlg,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmLoadCommand,
    cc: TpmCc::Load,
    handles: 1,
    parameters: {
        pub in_private: Tpm2bPrivate,
        pub in_public: Tpm2bPublic,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmLoadResponse,
    cc: TpmCc::Load,
    handles: 1,
    parameters: {
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmLoadExternalCommand,
    cc: TpmCc::LoadExternal,
    handles: 0,
    parameters: {
        pub in_private: Tpm2bSensitive,
        pub in_public: Tpm2bPublic,
        pub hierarchy: TpmRh,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmLoadExternalResponse,
    cc: TpmCc::LoadExternal,
    handles: 1,
    parameters: {
        pub name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmMakeCredentialCommand,
    cc: TpmCc::MakeCredential,
    handles: 1,
    parameters: {
        pub credential: Tpm2bDigest,
        pub object_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmMakeCredentialResponse,
    cc: TpmCc::MakeCredential,
    handles: 0,
    parameters: {
        pub credential_blob: Tpm2bIdObject,
        pub secret: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvCertifyCommand,
    cc: TpmCc::NvCertify,
    handles: 3,
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
        pub size: Uint16,
        pub offset: Uint16,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmNvCertifyResponse,
    cc: TpmCc::NvCertify,
    handles: 0,
    parameters: {
        pub certify_info: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvChangeAuthCommand,
    cc: TpmCc::NvChangeAuth,
    handles: 1,
    parameters: {
        pub new_auth: Tpm2bAuth,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvChangeAuthResponse,
    cc: TpmCc::NvChangeAuth,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvDefineSpaceCommand,
    cc: TpmCc::NvDefineSpace,
    handles: 1,
    parameters: {
        pub auth: Tpm2bAuth,
        pub public_info: Tpm2bNvPublic,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvDefineSpaceResponse,
    cc: TpmCc::NvDefineSpace,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvDefineSpace2Command,
    cc: TpmCc::NvDefineSpace2,
    handles: 1,
    parameters: {
        pub auth: Tpm2bAuth,
        pub public_info: crate::data::Tpm2bNvPublic2,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvDefineSpace2Response,
    cc: TpmCc::NvDefineSpace2,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvExtendCommand,
    cc: TpmCc::NvExtend,
    handles: 2,
    parameters: {
        pub data: Tpm2bMaxNvBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvExtendResponse,
    cc: TpmCc::NvExtend,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvGlobalWriteLockCommand,
    cc: TpmCc::NvGlobalWriteLock,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvGlobalWriteLockResponse,
    cc: TpmCc::NvGlobalWriteLock,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvIncrementCommand,
    cc: TpmCc::NvIncrement,
    handles: 2,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvIncrementResponse,
    cc: TpmCc::NvIncrement,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvReadCommand,
    cc: TpmCc::NvRead,
    handles: 2,
    parameters: {
        pub size: Uint16,
        pub offset: Uint16,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmNvReadResponse,
    cc: TpmCc::NvRead,
    handles: 0,
    parameters: {
        pub data: Tpm2bMaxNvBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvReadLockCommand,
    cc: TpmCc::NvReadLock,
    handles: 2,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvReadLockResponse,
    cc: TpmCc::NvReadLock,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvReadPublicCommand,
    cc: TpmCc::NvReadPublic,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmNvReadPublicResponse,
    cc: TpmCc::NvReadPublic,
    handles: 0,
    parameters: {
        pub nv_public: Tpm2bNvPublic,
        pub nv_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvReadPublic2Command,
    cc: TpmCc::NvReadPublic2,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmNvReadPublic2Response,
    cc: TpmCc::NvReadPublic2,
    handles: 0,
    parameters: {
        pub nv_public: crate::data::Tpm2bNvPublic2,
        pub nv_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvSetBitsCommand,
    cc: TpmCc::NvSetBits,
    handles: 2,
    parameters: {
        pub bits: Uint64,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvSetBitsResponse,
    cc: TpmCc::NvSetBits,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvUndefineSpaceCommand,
    cc: TpmCc::NvUndefineSpace,
    handles: 2,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvUndefineSpaceResponse,
    cc: TpmCc::NvUndefineSpace,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvUndefineSpaceSpecialCommand,
    cc: TpmCc::NvUndefineSpaceSpecial,
    handles: 2,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvUndefineSpaceSpecialResponse,
    cc: TpmCc::NvUndefineSpaceSpecial,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmNvWriteCommand,
    cc: TpmCc::NvWrite,
    handles: 2,
    parameters: {
        pub data: Tpm2bMaxNvBuffer,
        pub offset: Uint16,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvWriteResponse,
    cc: TpmCc::NvWrite,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmNvWriteLockCommand,
    cc: TpmCc::NvWriteLock,
    handles: 2,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmNvWriteLockResponse,
    cc: TpmCc::NvWriteLock,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmObjectChangeAuthCommand,
    cc: TpmCc::ObjectChangeAuth,
    handles: 2,
    parameters: {
        pub new_auth: Tpm2bAuth,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmObjectChangeAuthResponse,
    cc: TpmCc::ObjectChangeAuth,
    handles: 0,
    parameters: {
        pub out_private: Tpm2bPrivate,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrAllocateCommand,
    cc: TpmCc::PcrAllocate,
    handles: 1,
    parameters: {
        pub pcr_allocation: TpmlPcrSelection,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmPcrAllocateResponse,
    cc: TpmCc::PcrAllocate,
    handles: 0,
    parameters: {
        pub allocation_success: TpmiYesNo,
        pub max_pcr: Uint32,
        pub size_needed: Uint32,
        pub size_available: Uint32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPcrEventCommand,
    cc: TpmCc::PcrEvent,
    handles: 1,
    parameters: {
        pub event_data: Tpm2bEvent,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmPcrEventResponse,
    cc: TpmCc::PcrEvent,
    handles: 0,
    parameters: {
        pub digests: TpmlDigestValues,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrExtendCommand,
    cc: TpmCc::PcrExtend,
    handles: 1,
    parameters: {
        pub digests: TpmlDigestValues,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPcrExtendResponse,
    cc: TpmCc::PcrExtend,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPcrResetCommand,
    cc: TpmCc::PcrReset,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPcrResetResponse,
    cc: TpmCc::PcrReset,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrReadCommand,
    cc: TpmCc::PcrRead,
    handles: 0,
    parameters: {
        pub pcr_selection_in: TpmlPcrSelection,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmPcrReadResponse,
    cc: TpmCc::PcrRead,
    handles: 0,
    parameters: {
        pub pcr_update_counter: Uint32,
        pub pcr_selection_out: TpmlPcrSelection,
        pub pcr_values: TpmlDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrSetAuthPolicyCommand,
    cc: TpmCc::PcrSetAuthPolicy,
    handles: 1,
    parameters: {
        pub auth_policy: Tpm2bDigest,
        pub hash_alg: TpmAlgId,
        pub pcr_num: TpmRh,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPcrSetAuthPolicyResponse,
    cc: TpmCc::PcrSetAuthPolicy,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPcrSetAuthValueCommand,
    cc: TpmCc::PcrSetAuthValue,
    handles: 1,
    parameters: {
        pub auth: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPcrSetAuthValueResponse,
    cc: TpmCc::PcrSetAuthValue,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmPolicyAcSendSelectCommand,
    cc: TpmCc::PolicyAcSendSelect,
    handles: 1,
    parameters: {
        pub object_name: Tpm2bName,
        pub auth_handle_name: Tpm2bName,
        pub ac_name: Tpm2bName,
        pub include_object: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    kind: Response,
    name: TpmPolicyAcSendSelectResponse,
    cc: TpmCc::PolicyAcSendSelect,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyAuthorizeCommand,
    cc: TpmCc::PolicyAuthorize,
    handles: 1,
    parameters: {
        pub approved_policy: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub key_sign: Tpm2bName,
        pub check_ticket: TpmtTkVerified,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyAuthorizeResponse,
    cc: TpmCc::PolicyAuthorize,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyAuthorizeNvCommand,
    cc: TpmCc::PolicyAuthorizeNv,
    handles: 3,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyAuthorizeNvResponse,
    cc: TpmCc::PolicyAuthorizeNv,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyAuthValueCommand,
    cc: TpmCc::PolicyAuthValue,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyAuthValueResponse,
    cc: TpmCc::PolicyAuthValue,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyCapabilityCommand,
    cc: TpmCc::PolicyCapability,
    handles: 1,
    parameters: {
        pub capability: TpmCap,
        pub property: Uint32,
        pub op: TpmEo,
        pub operand_b: Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyCapabilityResponse,
    cc: TpmCc::PolicyCapability,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmPolicyCommandCodeCommand,
    cc: TpmCc::PolicyCommandCode,
    handles: 1,
    parameters: {
        pub code: TpmCc,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyCommandCodeResponse,
    cc: TpmCc::PolicyCommandCode,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyCounterTimerCommand,
    cc: TpmCc::PolicyCounterTimer,
    handles: 1,
    parameters: {
        pub operand_b: Tpm2bMaxBuffer,
        pub offset: Uint16,
        pub operation: TpmEo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyCounterTimerResponse,
    cc: TpmCc::PolicyCounterTimer,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyCpHashCommand,
    cc: TpmCc::PolicyCpHash,
    handles: 1,
    parameters: {
        pub cp_hash_a: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyCpHashResponse,
    cc: TpmCc::PolicyCpHash,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyDuplicationSelectCommand,
    cc: TpmCc::PolicyDuplicationSelect,
    handles: 1,
    parameters: {
        pub object_name: Tpm2bName,
        pub new_parent_name: Tpm2bName,
        pub include_object: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyDuplicationSelectResponse,
    cc: TpmCc::PolicyDuplicationSelect,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyGetDigestCommand,
    cc: TpmCc::PolicyGetDigest,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmPolicyGetDigestResponse,
    cc: TpmCc::PolicyGetDigest,
    handles: 0,
    parameters: {
        pub policy_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyLocalityCommand,
    cc: TpmCc::PolicyLocality,
    handles: 1,
    parameters: {
        pub locality: TpmaLocality,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyLocalityResponse,
    cc: TpmCc::PolicyLocality,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyNameHashCommand,
    cc: TpmCc::PolicyNameHash,
    handles: 1,
    parameters: {
        pub name_hash: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyNameHashResponse,
    cc: TpmCc::PolicyNameHash,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyNvCommand,
    cc: TpmCc::PolicyNv,
    handles: 3,
    parameters: {
        pub operand_b: Tpm2bMaxBuffer,
        pub offset: Uint16,
        pub operation: TpmEo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyNvResponse,
    cc: TpmCc::PolicyNv,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyNvWrittenCommand,
    cc: TpmCc::PolicyNvWritten,
    handles: 1,
    parameters: {
        pub written_set: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyNvWrittenResponse,
    cc: TpmCc::PolicyNvWritten,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyOrCommand,
    cc: TpmCc::PolicyOr,
    handles: 1,
    parameters: {
        pub p_hash_list: TpmlDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyOrResponse,
    cc: TpmCc::PolicyOr,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyParametersCommand,
    cc: TpmCc::PolicyParameters,
    handles: 1,
    parameters: {
        pub p_hash: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyParametersResponse,
    cc: TpmCc::PolicyParameters,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyPasswordCommand,
    cc: TpmCc::PolicyPassword,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyPasswordResponse,
    cc: TpmCc::PolicyPassword,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyPhysicalPresenceCommand,
    cc: TpmCc::PolicyPhysicalPresence,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyPhysicalPresenceResponse,
    cc: TpmCc::PolicyPhysicalPresence,
    handles: 0,
    parameters: {}
}

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyPcrCommand,
    cc: TpmCc::PolicyPcr,
    handles: 1,
    parameters: {
        pub pcr_digest: Tpm2bDigest,
        pub pcrs: TpmlPcrSelection,
    }
);

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyPcrResponse,
    cc: TpmCc::PolicyPcr,
    handles: 0,
    parameters: {}
);

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyRestartCommand,
    cc: TpmCc::PolicyRestart,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyRestartResponse,
    cc: TpmCc::PolicyRestart,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicySecretCommand,
    cc: TpmCc::PolicySecret,
    handles: 2,
    parameters: {
        pub nonce_tpm: Tpm2bNonce,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub expiration: Int32,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicySecretResponse,
    cc: TpmCc::PolicySecret,
    handles: 0,
    parameters: {
        pub timeout: Tpm2bTimeout,
        pub policy_ticket: TpmtTkAuth,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicySignedCommand,
    cc: TpmCc::PolicySigned,
    handles: 2,
    parameters: {
        pub nonce_tpm: Tpm2bNonce,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub expiration: Int32,
        pub auth: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmPolicySignedResponse,
    cc: TpmCc::PolicySigned,
    handles: 0,
    parameters: {
        pub timeout: Tpm2bTimeout,
        pub policy_ticket: TpmtTkAuth,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyTemplateCommand,
    cc: TpmCc::PolicyTemplate,
    handles: 1,
    parameters: {
        pub template_hash: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyTemplateResponse,
    cc: TpmCc::PolicyTemplate,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyTicketCommand,
    cc: TpmCc::PolicyTicket,
    handles: 1,
    parameters: {
        pub timeout: Tpm2bTimeout,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub auth_name: Tpm2bName,
        pub ticket: TpmtTkAuth,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyTicketResponse,
    cc: TpmCc::PolicyTicket,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyTransportSpdmCommand,
    cc: TpmCc::PolicyTransportSpdm,
    handles: 1,
    parameters: {
        pub req_key_name: Tpm2bName,
        pub tpm_key_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyTransportSpdmResponse,
    cc: TpmCc::PolicyTransportSpdm,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPpCommandsCommand,
    cc: TpmCc::PpCommands,
    handles: 1,
    parameters: {
        pub set_list: TpmlCc,
        pub clear_list: TpmlCc,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPpCommandsResponse,
    cc: TpmCc::PpCommands,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmQuoteCommand,
    cc: TpmCc::Quote,
    handles: 1,
    parameters: {
        pub qualifying_data: Tpm2bData,
        pub in_scheme: TpmtSignature,
        pub pcr_select: TpmlPcrSelection,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmQuoteResponse,
    cc: TpmCc::Quote,
    handles: 0,
    parameters: {
        pub quoted: Tpm2bAttest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmReadClockCommand,
    cc: TpmCc::ReadClock,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmReadClockResponse,
    cc: TpmCc::ReadClock,
    handles: 0,
    parameters: {
        pub current_time: TpmsTimeInfo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmReadOnlyControlCommand,
    cc: TpmCc::ReadOnlyControl,
    handles: 1,
    parameters: {
        pub state: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmReadOnlyControlResponse,
    cc: TpmCc::ReadOnlyControl,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmReadPublicCommand,
    cc: TpmCc::ReadPublic,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmReadPublicResponse,
    cc: TpmCc::ReadPublic,
    handles: 0,
    parameters: {
        pub out_public: Tpm2bPublic,
        pub name: Tpm2bName,
        pub qualified_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmRewrapCommand,
    cc: TpmCc::Rewrap,
    handles: 2,
    parameters: {
        pub in_duplicate: Tpm2bPrivate,
        pub name: Tpm2bName,
        pub in_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmRewrapResponse,
    cc: TpmCc::Rewrap,
    handles: 0,
    parameters: {
        pub out_duplicate: Tpm2bPrivate,
        pub out_sym_seed: Tpm2bEncryptedSecret,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmRsaDecryptCommand,
    cc: TpmCc::RsaDecrypt,
    handles: 1,
    parameters: {
        pub cipher_text: Tpm2bPublicKeyRsa,
        pub in_scheme: TpmtRsaDecrypt,
        pub label: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmRsaDecryptResponse,
    cc: TpmCc::RsaDecrypt,
    handles: 0,
    parameters: {
        pub message: Tpm2bPublicKeyRsa,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmRsaEncryptCommand,
    cc: TpmCc::RsaEncrypt,
    handles: 1,
    parameters: {
        pub message: Tpm2bPublicKeyRsa,
        pub in_scheme: TpmtRsaDecrypt,
        pub label: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmRsaEncryptResponse,
    cc: TpmCc::RsaEncrypt,
    handles: 0,
    parameters: {
        pub out_data: Tpm2bPublicKeyRsa,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmSelfTestCommand,
    cc: TpmCc::SelfTest,
    handles: 0,
    parameters: {
        pub full_test: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmSelfTestResponse,
    cc: TpmCc::SelfTest,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSequenceCompleteCommand,
    cc: TpmCc::SequenceComplete,
    handles: 1,
    parameters: {
        pub buffer: Tpm2bMaxBuffer,
        pub hierarchy: TpmRh,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmSequenceCompleteResponse,
    cc: TpmCc::SequenceComplete,
    handles: 0,
    parameters: {
        pub result: Tpm2bDigest,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSequenceUpdateCommand,
    cc: TpmCc::SequenceUpdate,
    handles: 1,
    parameters: {
        pub buffer: Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmSequenceUpdateResponse,
    cc: TpmCc::SequenceUpdate,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSetAlgorithmSetCommand,
    cc: TpmCc::SetAlgorithmSet,
    handles: 1,
    parameters: {
        pub algorithm_set: Uint32,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmSetAlgorithmSetResponse,
    cc: TpmCc::SetAlgorithmSet,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSetCommandCodeAuditStatusCommand,
    cc: TpmCc::SetCommandCodeAuditStatus,
    handles: 1,
    parameters: {
        pub audit_alg: TpmiAlgHash,
        pub set_list: TpmlCc,
        pub clear_list: TpmlCc,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmSetCommandCodeAuditStatusResponse,
    cc: TpmCc::SetCommandCodeAuditStatus,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSetPrimaryPolicyCommand,
    cc: TpmCc::SetPrimaryPolicy,
    handles: 1,
    parameters: {
        pub auth_policy: Tpm2bDigest,
        pub hash_alg: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmSetPrimaryPolicyResponse,
    cc: TpmCc::SetPrimaryPolicy,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmShutdownCommand,
    cc: TpmCc::Shutdown,
    handles: 0,
    parameters: {
        pub shutdown_type: TpmSu,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmShutdownResponse,
    cc: TpmCc::Shutdown,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmSignCommand,
    cc: TpmCc::Sign,
    handles: 1,
    parameters: {
        pub digest: Tpm2bDigest,
        pub in_scheme: TpmtSignature,
        pub validation: TpmtTkHashcheck,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmSignResponse,
    cc: TpmCc::Sign,
    handles: 0,
    parameters: {
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmStartAuthSessionCommand,
    cc: TpmCc::StartAuthSession,
    handles: 2,
    parameters: {
        pub nonce_caller: Tpm2bNonce,
        pub encrypted_salt: Tpm2bEncryptedSecret,
        pub session_type: TpmSe,
        pub symmetric: TpmtSymDefObject,
        pub auth_hash: TpmAlgId,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmStartAuthSessionResponse,
    cc: TpmCc::StartAuthSession,
    handles: 1,
    parameters: {
        pub nonce_tpm: Tpm2bNonce,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmStartupCommand,
    cc: TpmCc::Startup,
    handles: 0,
    parameters: {
        pub startup_type: TpmSu,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmStartupResponse,
    cc: TpmCc::Startup,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmStirRandomCommand,
    cc: TpmCc::StirRandom,
    handles: 0,
    parameters: {
        pub in_data: Tpm2bSensitiveData,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmStirRandomResponse,
    cc: TpmCc::StirRandom,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmTestParmsCommand,
    cc: TpmCc::TestParms,
    handles: 0,
    parameters: {
        pub parameters: TpmtPublicParms,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmTestParmsResponse,
    cc: TpmCc::TestParms,
    handles: 0,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmUnsealCommand,
    cc: TpmCc::Unseal,
    handles: 1,
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmUnsealResponse,
    cc: TpmCc::Unseal,
    handles: 0,
    parameters: {
        pub out_data: Tpm2bSensitiveData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmVendorTcgTestCommand,
    cc: TpmCc::VendorTcgTest,
    handles: 0,
    parameters: {
        pub input_data: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmVendorTcgTestResponse,
    cc: TpmCc::VendorTcgTest,
    handles: 0,
    parameters: {
        pub output_data: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmVerifySignatureCommand,
    cc: TpmCc::VerifySignature,
    handles: 1,
    parameters: {
        pub digest: Tpm2bDigest,
        pub signature: TpmtSignature,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmVerifySignatureResponse,
    cc: TpmCc::VerifySignature,
    handles: 0,
    parameters: {
        pub validation: TpmtTkVerified,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmZGen2PhaseCommand,
    cc: TpmCc::ZGen2Phase,
    handles: 1,
    parameters: {
        pub in_qsb: Tpm2bEccPoint,
        pub in_qeb: Tpm2bEccPoint,
        pub in_scheme: TpmiEccKeyExchange,
        pub counter: Uint16,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmZGen2PhaseResponse,
    cc: TpmCc::ZGen2Phase,
    handles: 0,
    parameters: {
        pub out_z1: Tpm2bEccPoint,
        pub out_z2: Tpm2bEccPoint,
    }
}
