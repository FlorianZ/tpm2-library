// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{tpm_dispatch, TpmBuild, TpmList, TpmResult, TpmSized, TpmWriter};
use core::fmt::Debug;

mod build;
mod data;
mod parse;

pub use self::{build::*, data::*, parse::*};

use crate::constant::{MAX_HANDLES, MAX_SESSIONS};

/// A fixed-capacity list for TPM handles.
pub type TpmHandles = TpmList<crate::TpmHandle, MAX_HANDLES>;

/// A fixed-capacity list for command authorization sessions.
pub type TpmAuthCommands = TpmList<crate::data::TpmsAuthCommand, MAX_SESSIONS>;

/// A fixed-capacity list for response authorization sessions.
pub type TpmAuthResponses = TpmList<crate::data::TpmsAuthResponse, MAX_SESSIONS>;

/// A trait for TPM commands and responses that provides header information.
pub trait TpmHeader: TpmBuild + Debug {
    const CC: crate::data::TpmCc;
    const HANDLES: usize;

    fn cc(&self) -> crate::data::TpmCc {
        Self::CC
    }
}

/// A trait for building command/response bodies in separate handle and parameter sections.
pub trait TpmBodyBuild: TpmSized {
    /// Builds the handle area.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` on a build failure.
    fn build_handles(&self, writer: &mut TpmWriter) -> TpmResult<()>;

    /// Builds the parameter area.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` on a build failure.
    fn build_parameters(&self, writer: &mut TpmWriter) -> TpmResult<()>;
}

/// Parses a command body from the slices point out to the handle area and
/// parameter area of the original buffer.
pub(crate) trait TpmCommandBodyParse: Sized {
    /// Parses the command body from the handle and parameter area.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` on a parse failure.
    fn parse_body<'a>(handles: &'a [u8], params: &'a [u8]) -> TpmResult<(Self, &'a [u8])>;
}

/// Parses a response body using the response tag to handle structural variations.
pub trait TpmResponseBodyParse: Sized {
    /// Parses the response body from a buffer, using the response tag
    /// dynamically to determine the structure.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` on a parse failure.
    fn parse_body(tag: crate::data::TpmSt, buf: &[u8]) -> TpmResult<(Self, &[u8])>;
}

tpm_dispatch! {
    (TpmNvUndefineSpaceSpecialCommand, TpmNvUndefineSpaceSpecialResponse, NvUndefineSpaceSpecial),
    (TpmEvictControlCommand, TpmEvictControlResponse, EvictControl),
    (TpmHierarchyControlCommand, TpmHierarchyControlResponse, HierarchyControl),
    (TpmNvUndefineSpaceCommand, TpmNvUndefineSpaceResponse, NvUndefineSpace),
    (TpmChangeEpsCommand, TpmChangeEpsResponse, ChangeEps),
    (TpmChangePpsCommand, TpmChangePpsResponse, ChangePps),
    (TpmClearCommand, TpmClearResponse, Clear),
    (TpmClearControlCommand, TpmClearControlResponse, ClearControl),
    (TpmClockSetCommand, TpmClockSetResponse, ClockSet),
    (TpmHierarchyChangeAuthCommand, TpmHierarchyChangeAuthResponse, HierarchyChangeAuth),
    (TpmNvDefineSpaceCommand, TpmNvDefineSpaceResponse, NvDefineSpace),
    (TpmPcrAllocateCommand, TpmPcrAllocateResponse, PcrAllocate),
    (TpmPcrSetAuthPolicyCommand, TpmPcrSetAuthPolicyResponse, PcrSetAuthPolicy),
    (TpmPpCommandsCommand, TpmPpCommandsResponse, PpCommands),
    (TpmSetPrimaryPolicyCommand, TpmSetPrimaryPolicyResponse, SetPrimaryPolicy),
    (TpmFieldUpgradeStartCommand, TpmFieldUpgradeStartResponse, FieldUpgradeStart),
    (TpmClockRateAdjustCommand, TpmClockRateAdjustResponse, ClockRateAdjust),
    (TpmCreatePrimaryCommand, TpmCreatePrimaryResponse, CreatePrimary),
    (TpmNvGlobalWriteLockCommand, TpmNvGlobalWriteLockResponse, NvGlobalWriteLock),
    (TpmGetCommandAuditDigestCommand, TpmGetCommandAuditDigestResponse, GetCommandAuditDigest),
    (TpmNvIncrementCommand, TpmNvIncrementResponse, NvIncrement),
    (TpmNvSetBitsCommand, TpmNvSetBitsResponse, NvSetBits),
    (TpmNvExtendCommand, TpmNvExtendResponse, NvExtend),
    (TpmNvWriteCommand, TpmNvWriteResponse, NvWrite),
    (TpmNvWriteLockCommand, TpmNvWriteLockResponse, NvWriteLock),
    (TpmDictionaryAttackLockResetCommand, TpmDictionaryAttackLockResetResponse, DictionaryAttackLockReset),
    (TpmDictionaryAttackParametersCommand, TpmDictionaryAttackParametersResponse, DictionaryAttackParameters),
    (TpmNvChangeAuthCommand, TpmNvChangeAuthResponse, NvChangeAuth),
    (TpmPcrEventCommand, TpmPcrEventResponse, PcrEvent),
    (TpmPcrResetCommand, TpmPcrResetResponse, PcrReset),
    (TpmSequenceCompleteCommand, TpmSequenceCompleteResponse, SequenceComplete),
    (TpmSetAlgorithmSetCommand, TpmSetAlgorithmSetResponse, SetAlgorithmSet),
    (TpmSetCommandCodeAuditStatusCommand, TpmSetCommandCodeAuditStatusResponse, SetCommandCodeAuditStatus),
    (TpmFieldUpgradeDataCommand, TpmFieldUpgradeDataResponse, FieldUpgradeData),
    (TpmIncrementalSelfTestCommand, TpmIncrementalSelfTestResponse, IncrementalSelfTest),
    (TpmSelfTestCommand, TpmSelfTestResponse, SelfTest),
    (TpmStartupCommand, TpmStartupResponse, Startup),
    (TpmShutdownCommand, TpmShutdownResponse, Shutdown),
    (TpmStirRandomCommand, TpmStirRandomResponse, StirRandom),
    (TpmActivateCredentialCommand, TpmActivateCredentialResponse, ActivateCredential),
    (TpmCertifyCommand, TpmCertifyResponse, Certify),
    (TpmPolicyNvCommand, TpmPolicyNvResponse, PolicyNv),
    (TpmCertifyCreationCommand, TpmCertifyCreationResponse, CertifyCreation),
    (TpmDuplicateCommand, TpmDuplicateResponse, Duplicate),
    (TpmGetTimeCommand, TpmGetTimeResponse, GetTime),
    (TpmGetSessionAuditDigestCommand, TpmGetSessionAuditDigestResponse, GetSessionAuditDigest),
    (TpmNvReadCommand, TpmNvReadResponse, NvRead),
    (TpmNvReadLockCommand, TpmNvReadLockResponse, NvReadLock),
    (TpmObjectChangeAuthCommand, TpmObjectChangeAuthResponse, ObjectChangeAuth),
    (TpmPolicySecretCommand, TpmPolicySecretResponse, PolicySecret),
    (TpmRewrapCommand, TpmRewrapResponse, Rewrap),
    (TpmCreateCommand, TpmCreateResponse, Create),
    (TpmEcdhZGenCommand, TpmEcdhZGenResponse, EcdhZGen),
    (TpmHmacCommand, TpmHmacResponse, Hmac),
    (TpmImportCommand, TpmImportResponse, Import),
    (TpmLoadCommand, TpmLoadResponse, Load),
    (TpmQuoteCommand, TpmQuoteResponse, Quote),
    (TpmRsaDecryptCommand, TpmRsaDecryptResponse, RsaDecrypt),
    (TpmHmacStartCommand, TpmHmacStartResponse, HmacStart),
    (TpmSequenceUpdateCommand, TpmSequenceUpdateResponse, SequenceUpdate),
    (TpmSignCommand, TpmSignResponse, Sign),
    (TpmUnsealCommand, TpmUnsealResponse, Unseal),
    (TpmPolicySignedCommand, TpmPolicySignedResponse, PolicySigned),
    (TpmContextLoadCommand, TpmContextLoadResponse, ContextLoad),
    (TpmContextSaveCommand, TpmContextSaveResponse, ContextSave),
    (TpmEcdhKeyGenCommand, TpmEcdhKeyGenResponse, EcdhKeyGen),
    (TpmEncryptDecryptCommand, TpmEncryptDecryptResponse, EncryptDecrypt),
    (TpmFlushContextCommand, TpmFlushContextResponse, FlushContext),
    (TpmLoadExternalCommand, TpmLoadExternalResponse, LoadExternal),
    (TpmMakeCredentialCommand, TpmMakeCredentialResponse, MakeCredential),
    (TpmNvReadPublicCommand, TpmNvReadPublicResponse, NvReadPublic),
    (TpmPolicyAuthorizeCommand, TpmPolicyAuthorizeResponse, PolicyAuthorize),
    (TpmPolicyAuthValueCommand, TpmPolicyAuthValueResponse, PolicyAuthValue),
    (TpmPolicyCommandCodeCommand, TpmPolicyCommandCodeResponse, PolicyCommandCode),
    (TpmPolicyCounterTimerCommand, TpmPolicyCounterTimerResponse, PolicyCounterTimer),
    (TpmPolicyCpHashCommand, TpmPolicyCpHashResponse, PolicyCpHash),
    (TpmPolicyLocalityCommand, TpmPolicyLocalityResponse, PolicyLocality),
    (TpmPolicyNameHashCommand, TpmPolicyNameHashResponse, PolicyNameHash),
    (TpmPolicyOrCommand, TpmPolicyOrResponse, PolicyOr),
    (TpmPolicyTicketCommand, TpmPolicyTicketResponse, PolicyTicket),
    (TpmReadPublicCommand, TpmReadPublicResponse, ReadPublic),
    (TpmRsaEncryptCommand, TpmRsaEncryptResponse, RsaEncrypt),
    (TpmStartAuthSessionCommand, TpmStartAuthSessionResponse, StartAuthSession),
    (TpmVerifySignatureCommand, TpmVerifySignatureResponse, VerifySignature),
    (TpmEccParametersCommand, TpmEccParametersResponse, EccParameters),
    (TpmFirmwareReadCommand, TpmFirmwareReadResponse, FirmwareRead),
    (TpmGetCapabilityCommand, TpmGetCapabilityResponse, GetCapability),
    (TpmGetRandomCommand, TpmGetRandomResponse, GetRandom),
    (TpmGetTestResultCommand, TpmGetTestResultResponse, GetTestResult),
    (TpmHashCommand, TpmHashResponse, Hash),
    (TpmPcrReadCommand, TpmPcrReadResponse, PcrRead),
    (TpmPolicyPcrCommand, TpmPolicyPcrResponse, PolicyPcr),
    (TpmPolicyRestartCommand, TpmPolicyRestartResponse, PolicyRestart),
    (TpmReadClockCommand, TpmReadClockResponse, ReadClock),
    (TpmPcrExtendCommand, TpmPcrExtendResponse, PcrExtend),
    (TpmPcrSetAuthValueCommand, TpmPcrSetAuthValueResponse, PcrSetAuthValue),
    (TpmNvCertifyCommand, TpmNvCertifyResponse, NvCertify),
    (TpmEventSequenceCompleteCommand, TpmEventSequenceCompleteResponse, EventSequenceComplete),
    (TpmHashSequenceStartCommand, TpmHashSequenceStartResponse, HashSequenceStart),
    (TpmPolicyPhysicalPresenceCommand, TpmPolicyPhysicalPresenceResponse, PolicyPhysicalPresence),
    (TpmPolicyDuplicationSelectCommand, TpmPolicyDuplicationSelectResponse, PolicyDuplicationSelect),
    (TpmPolicyGetDigestCommand, TpmPolicyGetDigestResponse, PolicyGetDigest),
    (TpmTestParmsCommand, TpmTestParmsResponse, TestParms),
    (TpmCommitCommand, TpmCommitResponse, Commit),
    (TpmPolicyPasswordCommand, TpmPolicyPasswordResponse, PolicyPassword),
    (TpmZGen2PhaseCommand, TpmZGen2PhaseResponse, ZGen2Phase),
    (TpmEcEphemeralCommand, TpmEcEphemeralResponse, EcEphemeral),
    (TpmPolicyNvWrittenCommand, TpmPolicyNvWrittenResponse, PolicyNvWritten),
    (TpmPolicyTemplateCommand, TpmPolicyTemplateResponse, PolicyTemplate),
    (TpmCreateLoadedCommand, TpmCreateLoadedResponse, CreateLoaded),
    (TpmPolicyAuthorizeNvCommand, TpmPolicyAuthorizeNvResponse, PolicyAuthorizeNv),
    (TpmEncryptDecrypt2Command, TpmEncryptDecrypt2Response, EncryptDecrypt2),
    (TpmAcGetCapabilityCommand, TpmAcGetCapabilityResponse, AcGetCapability),
    (TpmAcSendCommand, TpmAcSendResponse, AcSend),
    (TpmPolicyAcSendSelectCommand, TpmPolicyAcSendSelectResponse, PolicyAcSendSelect),
    (TpmActSetTimeoutCommand, TpmActSetTimeoutResponse, ActSetTimeout),
    (TpmEccEncryptCommand, TpmEccEncryptResponse, EccEncrypt),
    (TpmEccDecryptCommand, TpmEccDecryptResponse, EccDecrypt),
    (TpmPolicyCapabilityCommand, TpmPolicyCapabilityResponse, PolicyCapability),
    (TpmPolicyParametersCommand, TpmPolicyParametersResponse, PolicyParameters),
    (TpmNvDefineSpace2Command, TpmNvDefineSpace2Response, NvDefineSpace2),
    (TpmNvReadPublic2Command, TpmNvReadPublic2Response, NvReadPublic2),
    (TpmReadOnlyControlCommand, TpmReadOnlyControlResponse, ReadOnlyControl),
    (TpmPolicyTransportSpdmCommand, TpmPolicyTransportSpdmResponse, PolicyTransportSpdm),
    (TpmVendorTcgTestCommand, TpmVendorTcgTestResponse, VendorTcgTest),
}
