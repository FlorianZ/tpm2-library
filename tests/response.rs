// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::{convert::TryFrom, io::IsTerminal, panic, vec::Vec};
use tpm2_protocol::{
    data::TpmCc,
    message::{tpm_build_response, tpm_parse_response, TpmResponseBody},
    TpmWriter, TPM_MAX_COMMAND_SIZE,
};

const RESPONSE_DATA: &str = include_str!("response.txt");

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "Invalid hex character")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn print_ok() {
    if std::io::stderr().is_terminal() {
        println!("\x1B[32mOK\x1B[0m");
    } else {
        println!("OK");
    }
}

fn print_failed() {
    if std::io::stderr().is_terminal() {
        println!("\x1B[31mFAILED\x1B[0m");
    } else {
        println!("FAILED");
    }
}

fn run_test(name: &str, test_fn: impl FnOnce() + panic::UnwindSafe) -> bool {
    print!("Test {name} ... ");
    let result = panic::catch_unwind(test_fn);
    if result.is_err() {
        print_failed();
        false
    } else {
        print_ok();
        true
    }
}

fn main() {
    let mut failed_count = 0;
    let mut test_count = 0;

    for (i, line) in RESPONSE_DATA.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        test_count += 1;
        let test_name = format!("response_{}", i + 1);
        let success = run_test(&test_name, || {
            let (cc_hex_str, hex_str) = trimmed
                .split_once(' ')
                .expect("Invalid format in response.txt: expected '<CC> <DUMP>'");

            if cc_hex_str.len() != 4 {
                panic!(
                    "Invalid CC format: must be 4 hex characters wide, got {}",
                    cc_hex_str.len()
                );
            }

            let cc_val = u16::from_str_radix(cc_hex_str, 16).expect("Invalid hex for CC");
            let cc = TpmCc::try_from(cc_val as u32).expect("Unknown command code");

            let original_bytes = hex_to_bytes(hex_str).expect("Failed to parse hex");
            let (rc, body, sessions) = tpm_parse_response(cc, &original_bytes)
                .expect("Failed to parse response")
                .expect("Response contained an error code");

            let mut built_bytes = [0u8; TPM_MAX_COMMAND_SIZE];
            let built_len = {
                let mut writer = TpmWriter::new(&mut built_bytes);
                let resp_struct = match body {
                    TpmResponseBody::NvUndefineSpaceSpecial(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::EvictControl(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::HierarchyControl(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvUndefineSpace(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ChangeEps(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ChangePps(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Clear(r) => tpm_build_response(&r, &sessions, rc, &mut writer),
                    TpmResponseBody::ClearControl(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ClockSet(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::HierarchyChangeAuth(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvDefineSpace(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PcrAllocate(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PcrSetAuthPolicy(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PpCommands(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::SetPrimaryPolicy(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::FieldUpgradeStart(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ClockRateAdjust(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::CreatePrimary(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvGlobalWriteLock(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::GetCommandAuditDigest(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvIncrement(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvSetBits(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvExtend(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvWrite(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvWriteLock(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::DictionaryAttackLockReset(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::DictionaryAttackParameters(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvChangeAuth(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PcrEvent(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PcrReset(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::SequenceComplete(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::SetAlgorithmSet(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::SetCommandCodeAuditStatus(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::FieldUpgradeData(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::IncrementalSelfTest(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::SelfTest(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Startup(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Shutdown(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::StirRandom(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ActivateCredential(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Certify(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyNv(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::CertifyCreation(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Duplicate(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::GetTime(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::GetSessionAuditDigest(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvRead(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvReadLock(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ObjectChangeAuth(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicySecret(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Rewrap(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Create(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::EcdhZGen(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Hmac(r) => tpm_build_response(&r, &sessions, rc, &mut writer),
                    TpmResponseBody::Import(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Load(r) => tpm_build_response(&r, &sessions, rc, &mut writer),
                    TpmResponseBody::Quote(r) => tpm_build_response(&r, &sessions, rc, &mut writer),
                    TpmResponseBody::RsaDecrypt(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::HmacStart(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::SequenceUpdate(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Sign(r) => tpm_build_response(&r, &sessions, rc, &mut writer),
                    TpmResponseBody::Unseal(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicySigned(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ContextLoad(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ContextSave(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::EcdhKeyGen(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::EncryptDecrypt(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::FlushContext(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::LoadExternal(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::MakeCredential(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvReadPublic(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyAuthorize(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyAuthValue(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyCommandCode(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyCounterTimer(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyCpHash(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyLocality(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyNameHash(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyOr(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyTicket(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ReadPublic(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::RsaEncrypt(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::StartAuthSession(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::VerifySignature(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::EccParameters(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::FirmwareRead(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::GetCapability(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::GetRandom(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::GetTestResult(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Hash(r) => tpm_build_response(&r, &sessions, rc, &mut writer),
                    TpmResponseBody::PcrRead(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyPcr(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyRestart(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ReadClock(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PcrExtend(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PcrSetAuthValue(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvCertify(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::EventSequenceComplete(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::HashSequenceStart(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyPhysicalPresence(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyDuplicationSelect(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyGetDigest(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::TestParms(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::Commit(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyPassword(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ZGen2Phase(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::EcEphemeral(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyNvWritten(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyTemplate(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::CreateLoaded(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyAuthorizeNv(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::EncryptDecrypt2(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::AcGetCapability(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::AcSend(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyAcSendSelect(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ActSetTimeout(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyCapability(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyParameters(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvDefineSpace2(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::NvReadPublic2(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::ReadOnlyControl(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::PolicyTransportSpdm(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                    TpmResponseBody::VendorTcgTest(r) => {
                        tpm_build_response(&r, &sessions, rc, &mut writer)
                    }
                };
                resp_struct.expect("Failed to build response");
                writer.len()
            };
            let rebuilt_slice = &built_bytes[..built_len];

            assert_eq!(
                rebuilt_slice,
                original_bytes.as_slice(),
                "\nOriginal: {}\nRebuilt:  {}\n",
                bytes_to_hex(&original_bytes),
                bytes_to_hex(rebuilt_slice)
            );
        });
        if !success {
            failed_count += 1;
        }
    }

    eprintln!("\n{test_count} tests run.");
    if failed_count > 0 {
        eprintln!("{failed_count} test(s) failed.");
        std::process::exit(1);
    }
    eprintln!("All tests passed.");
}
