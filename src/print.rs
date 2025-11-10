//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use std::{io::Write, vec::Vec};
use tpm2_protocol::{
    self,
    basic::{TpmBuffer, TpmList},
    data::{
        self, Tpm2bNvPublic, Tpm2bPublic, Tpm2bSensitiveCreate, TpmAlgId, TpmCap, TpmCc,
        TpmEccCurve, TpmPt, TpmRh, TpmSe, TpmSt, TpmaAlgorithm, TpmaCc, TpmaLocality, TpmaNv,
        TpmaObject, TpmaSession, TpmiYesNo, TpmsAlgProperty, TpmsAuthCommand, TpmsCapabilityData,
        TpmsContext, TpmsCreationData, TpmsEccPoint, TpmsKeyedhashParms, TpmsNvPublic,
        TpmsPcrSelect, TpmsPcrSelection, TpmsSchemeHash, TpmsSchemeXor, TpmsSensitiveCreate,
        TpmsSymcipherParms, TpmsTaggedProperty, TpmtEccScheme, TpmtHa, TpmtKdfScheme,
        TpmtKeyedhashScheme, TpmtPublic, TpmtPublicParms, TpmtRsaScheme, TpmtSymDefObject,
        TpmtTkAuth, TpmtTkCreation, TpmtTkHashcheck, TpmuAsymScheme, TpmuCapabilities, TpmuHa,
        TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicParms, TpmuSensitiveComposite, TpmuSymKeyBits,
        TpmuSymMode,
    },
    frame::{
        TpmCommand, TpmContextLoadCommand, TpmContextLoadResponse, TpmContextSaveCommand,
        TpmContextSaveResponse, TpmCreateCommand, TpmCreatePrimaryCommand,
        TpmCreatePrimaryResponse, TpmCreateResponse, TpmDictionaryAttackLockResetCommand,
        TpmDictionaryAttackLockResetResponse, TpmEccParametersCommand, TpmEvictControlCommand,
        TpmEvictControlResponse, TpmFlushContextCommand, TpmFlushContextResponse,
        TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmImportCommand, TpmImportResponse,
        TpmLoadCommand, TpmLoadResponse, TpmNvReadCommand, TpmNvReadPublicCommand,
        TpmNvReadPublicResponse, TpmNvReadResponse, TpmPcrEventCommand, TpmPcrEventResponse,
        TpmPcrReadCommand, TpmPcrReadResponse, TpmPolicyGetDigestCommand,
        TpmPolicyGetDigestResponse, TpmPolicyOrCommand, TpmPolicyPcrCommand, TpmPolicyPcrResponse,
        TpmPolicyRestartCommand, TpmPolicyRestartResponse, TpmPolicySecretCommand,
        TpmPolicySecretResponse, TpmReadPublicCommand, TpmReadPublicResponse, TpmResponse,
        TpmStartAuthSessionCommand, TpmStartAuthSessionResponse, TpmTestParmsCommand,
        TpmUnsealCommand, TpmUnsealResponse,
    },
    TpmHandle,
};

pub const INDENT: usize = 2;

pub trait TpmPrint {
    /// # Errors
    ///
    /// Returns `std::io::Error` on I/O failure.
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error>;
}

macro_rules! tpm_print_simple {
    ($type:ty, $format:literal) => {
        impl TpmPrint for $type {
            fn print(
                &self,
                writer: &mut dyn Write,
                name: &str,
                indent: usize,
            ) -> Result<(), std::io::Error> {
                let prefix = " ".repeat(indent * INDENT);
                writeln!(
                    writer,
                    "{prefix}{name}: {value}",
                    prefix = prefix,
                    name = name,
                    value = format_args!($format, self)
                )
            }
        }
    };
}

macro_rules! tpm_print_bitflags {
    ($type:ty) => {
        impl TpmPrint for $type {
            fn print(
                &self,
                writer: &mut dyn Write,
                name: &str,
                indent: usize,
            ) -> Result<(), std::io::Error> {
                let prefix = " ".repeat(indent * INDENT);
                let flags: Vec<&str> = self.flag_names().collect();
                let flags_str = if flags.is_empty() {
                    "NONE".to_string()
                } else {
                    flags.join(" | ")
                };
                writeln!(
                    writer,
                    "{prefix}{name}: {flags_str} ({value:#x})",
                    name = name,
                    prefix = prefix,
                    flags_str = flags_str,
                    value = self.bits()
                )
            }
        }
    };
}

tpm_print_simple!(u8, "{:02x}");
tpm_print_simple!(u16, "{:04x}");
tpm_print_simple!(u32, "{:08x}");
tpm_print_simple!(u64, "{:16x}");
tpm_print_simple!(i32, "{}");
tpm_print_simple!(TpmHandle, "{:08x}");
tpm_print_simple!(TpmAlgId, "{}");
tpm_print_simple!(TpmCc, "{}");
tpm_print_simple!(TpmPt, "{}");
tpm_print_simple!(TpmRh, "{}");
tpm_print_simple!(TpmCap, "{}");
tpm_print_simple!(TpmSe, "{:?}");
tpm_print_simple!(TpmSt, "{:?}");
tpm_print_simple!(TpmEccCurve, "{:?}");
tpm_print_simple!(TpmiYesNo, "{:?}");

tpm_print_bitflags!(TpmaObject);
tpm_print_bitflags!(TpmaAlgorithm);
tpm_print_bitflags!(TpmaSession);
tpm_print_bitflags!(TpmaLocality);
tpm_print_bitflags!(TpmaNv);
tpm_print_bitflags!(TpmaCc);

impl<const CAPACITY: usize> TpmPrint for TpmBuffer<CAPACITY> {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        writeln!(
            writer,
            "{}{}: (size={}) {}",
            prefix,
            name,
            self.len(),
            hex::encode(self)
        )
    }
}

impl TpmPrint for TpmsPcrSelect {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        writeln!(
            writer,
            "{}{}: (size={}) {}",
            prefix,
            name,
            self.len(),
            hex::encode(self.as_ref())
        )
    }
}

impl<T, const CAPACITY: usize> TpmPrint for TpmList<T, CAPACITY>
where
    T: TpmPrint + Copy,
{
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        writeln!(writer, "{}{}: (count={})", prefix, name, self.len())?;
        for item in self.iter() {
            item.print(writer, "", indent + 1)?;
        }
        Ok(())
    }
}

macro_rules! tpm_print_struct {
    ($type:ty, $($field:ident => $name:literal),* $(,)?) => {
        impl TpmPrint for $type {
            fn print(
                &self,
                writer: &mut dyn Write,
                name: &str,
                indent: usize,
            ) -> Result<(), std::io::Error> {
                let prefix = " ".repeat(indent * INDENT);
                if !name.is_empty() {
                    writeln!(writer, "{}{}:", prefix, name)?;
                } else if stringify!($($field),*).is_empty() {
                    return Ok(());
                }

                #[allow(unused_variables)]
                let field_indent = if name.is_empty() { indent } else { indent + 1 };
                $(
                    self.$field.print(writer, $name, field_indent)?;
                )*
                Ok(())
            }
        }
    };
}

tpm_print_struct!(TpmsAlgProperty, alg => "alg", alg_properties => "algProperties");
tpm_print_struct!(TpmsTaggedProperty, property => "property", value => "value");
tpm_print_struct!(TpmsPcrSelection, hash => "hash", pcr_select => "pcrSelect");
tpm_print_struct!(TpmsKeyedhashParms, scheme => "scheme");
tpm_print_struct!(TpmsSymcipherParms, sym => "sym");
tpm_print_struct!(TpmtKdfScheme, scheme => "scheme");
tpm_print_struct!(TpmsEccPoint, x => "x", y => "y");
tpm_print_struct!(TpmsContext, sequence => "sequence", saved_handle => "savedHandle", hierarchy => "hierarchy", context_blob => "contextBlob");
tpm_print_struct!(TpmsAuthCommand, session_handle => "sessionHandle", nonce => "nonce", session_attributes => "sessionAttributes", hmac => "hmac");
tpm_print_struct!(TpmsSensitiveCreate, user_auth => "userAuth", data => "data");
tpm_print_struct!(TpmtTkCreation, tag => "tag", hierarchy => "hierarchy", digest => "digest");
tpm_print_struct!(TpmtTkAuth, tag => "tag", hierarchy => "hierarchy", digest => "digest");
tpm_print_struct!(TpmtTkHashcheck, tag => "tag", hierarchy => "hierarchy", digest => "digest");
tpm_print_struct!(TpmsSchemeHash, hash_alg => "hashAlg");
tpm_print_struct!(TpmsSchemeXor, hash_alg => "hashAlg", kdf => "kdf");
tpm_print_struct!(TpmtRsaScheme, scheme => "scheme", details => "details");
tpm_print_struct!(TpmtEccScheme, scheme => "scheme", details => "details");
tpm_print_struct!(
    TpmsCreationData,
    pcr_select => "pcrSelect",
    pcr_digest => "pcrDigest",
    locality => "locality",
    parent_name_alg => "parentNameAlg",
    parent_name => "parentName",
    parent_qualified_name => "parentQualifiedName",
    outside_info => "outsideInfo",
);
tpm_print_struct!(Tpm2bPublic, inner => "inner");
tpm_print_struct!(Tpm2bSensitiveCreate, inner => "inner");
tpm_print_struct!(data::Tpm2bCreationData, inner => "inner");
tpm_print_struct!(TpmsNvPublic, nv_index => "nvIndex", name_alg => "nameAlg", attributes => "attributes", auth_policy => "authPolicy", data_size => "dataSize");
tpm_print_struct!(Tpm2bNvPublic, inner => "inner");

tpm_print_struct!(TpmCreatePrimaryCommand, primary_handle => "primaryHandle", in_sensitive => "inSensitive", in_public => "inPublic", outside_info => "outsideInfo", creation_pcr => "creationPcr");
tpm_print_struct!(TpmContextSaveCommand, save_handle => "saveHandle");
tpm_print_struct!(TpmEvictControlCommand, auth => "auth", object_handle => "objectHandle", persistent_handle => "persistentHandle");
tpm_print_struct!(TpmFlushContextCommand, flush_handle => "flushHandle");
tpm_print_struct!(TpmReadPublicCommand, object_handle => "objectHandle");
tpm_print_struct!(TpmImportCommand, parent_handle => "parentHandle", encryption_key => "encryptionKey", object_public => "objectPublic", duplicate => "duplicate", in_sym_seed => "inSymSeed", symmetric_alg => "symmetricAlg");
tpm_print_struct!(TpmLoadCommand, parent_handle => "parentHandle", in_private => "inPrivate", in_public => "inPublic");
tpm_print_struct!(TpmNvReadPublicCommand, nv_index => "nvIndex");
tpm_print_struct!(TpmNvReadCommand, auth_handle => "authHandle", nv_index => "nvIndex", size => "size", offset => "offset");
tpm_print_struct!(TpmPcrEventCommand, pcr_handle => "pcrHandle", event_data => "eventData");
tpm_print_struct!(TpmPcrReadCommand, pcr_selection_in => "pcrSelectionIn");
tpm_print_struct!(TpmPolicyPcrCommand, policy_session => "policySession", pcr_digest => "pcrDigest", pcrs => "pcrs");
tpm_print_struct!(TpmPolicySecretCommand, auth_handle => "authHandle", policy_session => "policySession", nonce_tpm => "nonceTpm", cp_hash_a => "cpHashA", policy_ref => "policyRef", expiration => "expiration");
tpm_print_struct!(TpmPolicyOrCommand, policy_session => "policySession", p_hash_list => "pHashList");
tpm_print_struct!(TpmPolicyGetDigestCommand, policy_session => "policySession");
tpm_print_struct!(TpmPolicyRestartCommand, session_handle => "sessionHandle");
tpm_print_struct!(TpmDictionaryAttackLockResetCommand, lock_handle => "lockHandle");
tpm_print_struct!(TpmCreateCommand, parent_handle => "parentHandle", in_sensitive => "inSensitive", in_public => "inPublic", outside_info => "outsideInfo", creation_pcr => "creationPcr");
tpm_print_struct!(TpmUnsealCommand, item_handle => "itemHandle");
tpm_print_struct!(TpmGetCapabilityCommand, cap => "cap", property => "property", property_count => "propertyCount");
tpm_print_struct!(TpmStartAuthSessionCommand, tpm_key => "tpmKey", bind => "bind", nonce_caller => "nonceCaller", encrypted_salt => "encryptedSalt", session_type => "sessionType", symmetric => "symmetric", auth_hash => "authHash");
tpm_print_struct!(TpmContextLoadCommand, context => "context");
tpm_print_struct!(TpmTestParmsCommand, parameters => "parameters");
tpm_print_struct!(TpmEccParametersCommand, curve_id => "curveId");

tpm_print_struct!(TpmCreatePrimaryResponse, object_handle => "objectHandle", out_public => "outPublic", creation_data => "creationData", creation_hash => "creationHash", creation_ticket => "creationTicket", name => "name");
tpm_print_struct!(TpmContextSaveResponse, context => "context");
tpm_print_struct!(TpmEvictControlResponse,);
tpm_print_struct!(TpmFlushContextResponse,);
tpm_print_struct!(TpmReadPublicResponse, out_public => "outPublic", name => "name", qualified_name => "qualifiedName");
tpm_print_struct!(TpmImportResponse, out_private => "outPrivate");
tpm_print_struct!(TpmLoadResponse, object_handle => "objectHandle", name => "name");
tpm_print_struct!(TpmNvReadPublicResponse, nv_public => "nvPublic", nv_name => "nvName");
tpm_print_struct!(TpmNvReadResponse, data => "data");
tpm_print_struct!(TpmPcrEventResponse, digests => "digests");
tpm_print_struct!(TpmPolicyPcrResponse,);
tpm_print_struct!(TpmPolicySecretResponse, timeout => "timeout", policy_ticket => "policyTicket");
tpm_print_struct!(TpmPolicyGetDigestResponse, policy_digest => "policyDigest");
tpm_print_struct!(TpmPolicyRestartResponse,);
tpm_print_struct!(TpmDictionaryAttackLockResetResponse,);
tpm_print_struct!(TpmCreateResponse, out_private => "outPrivate", out_public => "outPublic", creation_data => "creationData", creation_hash => "creationHash", creation_ticket => "creationTicket");
tpm_print_struct!(TpmUnsealResponse, out_data => "outData");
tpm_print_struct!(TpmGetCapabilityResponse, more_data => "moreData", capability_data => "capabilityData");
tpm_print_struct!(TpmPcrReadResponse, pcr_update_counter => "pcrUpdateCounter", pcr_selection_out => "pcrSelectionOut", pcr_values => "pcrValues");
tpm_print_struct!(TpmStartAuthSessionResponse, session_handle => "sessionHandle", nonce_tpm => "nonceTpm");
tpm_print_struct!(TpmContextLoadResponse, loaded_handle => "loadedHandle");

impl TpmPrint for TpmuHa {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        let (variant, bytes): (&str, &[u8]) = match self {
            Self::Null => ("Null", &[]),
            Self::Digest(d) => ("Digest", d),
        };
        writeln!(
            writer,
            "{}{}: (size={}) {} ({})",
            prefix,
            name,
            bytes.len(),
            hex::encode(bytes),
            variant,
        )
    }
}

impl TpmPrint for TpmtHa {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        writeln!(writer, "{prefix}{name}:")?;
        self.hash_alg.print(writer, "hashAlg", indent + 1)?;
        self.digest.print(writer, "digest", indent + 1)?;
        Ok(())
    }
}

impl TpmPrint for TpmsCapabilityData {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        writeln!(writer, "{prefix}{name}:")?;
        self.capability.print(writer, "capability", indent + 1)?;
        self.data.print(writer, "data", indent + 1)?;
        Ok(())
    }
}

impl TpmPrint for TpmuCapabilities {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        match self {
            Self::Algs(algs) => algs.print(writer, name, indent),
            Self::Handles(handles) => handles.print(writer, name, indent),
            Self::Commands(commands) => commands.print(writer, name, indent),
            Self::Pcrs(pcrs) => pcrs.print(writer, name, indent),
            Self::EccCurves(curves) => curves.print(writer, name, indent),
            Self::TpmProperties(props) => props.print(writer, name, indent),
        }
    }
}

impl TpmPrint for TpmtPublic {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        writeln!(writer, "{prefix}{name}:")?;
        self.object_type.print(writer, "type", indent + 1)?;
        self.name_alg.print(writer, "nameAlg", indent + 1)?;
        self.object_attributes
            .print(writer, "objectAttributes", indent + 1)?;
        self.auth_policy.print(writer, "authPolicy", indent + 1)?;
        self.parameters.print(writer, "parameters", indent + 1)?;
        self.unique.print(writer, "unique", indent + 1)?;
        Ok(())
    }
}

impl TpmPrint for TpmuPublicId {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::KeyedHash(b) => b.print(writer, &format!("{name} (keyedHash)"), indent),
            Self::SymCipher(b) => b.print(writer, &format!("{name} (sym)"), indent),
            Self::Rsa(b) => b.print(writer, &format!("{name} (rsa)"), indent),
            Self::Ecc(p) => p.print(writer, &format!("{name} (ecc)"), indent),
            Self::Null => writeln!(writer, "{prefix}{name}: null"),
        }
    }
}

impl TpmPrint for TpmtPublicParms {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        writeln!(writer, "{prefix}{name}:")?;
        self.object_type.print(writer, "type", indent + 1)?;
        self.parameters.print(writer, "parameters", indent + 1)?;
        Ok(())
    }
}

impl TpmPrint for TpmuPublicParms {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::KeyedHash(details) => {
                details.print(writer, &format!("{name} (keyedHash)"), indent)?;
            }
            Self::SymCipher(details) => details.print(writer, &format!("{name} (sym)"), indent)?,
            Self::Rsa(params) => {
                writeln!(writer, "{prefix}{name}: (rsa)")?;
                params.symmetric.print(writer, "symmetric", indent + 1)?;
                params.scheme.print(writer, "scheme", indent + 1)?;
                params.key_bits.print(writer, "keyBits", indent + 1)?;
                params.exponent.print(writer, "exponent", indent + 1)?;
            }
            Self::Ecc(params) => {
                writeln!(writer, "{prefix}{name}: (ecc)")?;
                params.symmetric.print(writer, "symmetric", indent + 1)?;
                params.scheme.print(writer, "scheme", indent + 1)?;
                params.curve_id.print(writer, "curveId", indent + 1)?;
                params.kdf.print(writer, "kdf", indent + 1)?;
            }
            Self::Null => writeln!(writer, "{prefix}{name}: null")?,
        }
        Ok(())
    }
}

impl TpmPrint for TpmtSymDefObject {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        if self.algorithm == TpmAlgId::Null {
            self.algorithm.print(writer, name, indent)
        } else {
            let prefix = " ".repeat(indent * INDENT);
            writeln!(writer, "{prefix}{name}:")?;
            self.algorithm.print(writer, "algorithm", indent + 1)?;
            self.key_bits.print(writer, "keyBits", indent + 1)?;
            self.mode.print(writer, "mode", indent + 1)?;
            Ok(())
        }
    }
}

impl TpmPrint for TpmuSymKeyBits {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::Aes(v) => v.print(writer, &format!("{name} (aes)"), indent),
            Self::Sm4(v) => v.print(writer, &format!("{name} (sm4)"), indent),
            Self::Camellia(v) => v.print(writer, &format!("{name} (camellia)"), indent),
            Self::Xor(v) => v.print(writer, &format!("{name} (xor)"), indent),
            Self::Null => writeln!(writer, "{prefix}{name}: null"),
        }
    }
}

impl TpmPrint for TpmuSymMode {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::Aes(v) => v.print(writer, &format!("{name} (aes)"), indent),
            Self::Sm4(v) => v.print(writer, &format!("{name} (sm4)"), indent),
            Self::Camellia(v) => v.print(writer, &format!("{name} (camellia)"), indent),
            Self::Xor(v) => v.print(writer, &format!("{name} (xor)"), indent),
            Self::Null => writeln!(writer, "{prefix}{name}: null"),
        }
    }
}

impl TpmPrint for TpmuAsymScheme {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::Any(s) => s.print(writer, &format!("{name} (any)"), indent),
            Self::Null => writeln!(writer, "{prefix}{name}: null"),
        }
    }
}

impl TpmPrint for TpmuSensitiveComposite {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        match self {
            Self::Rsa(b) => b.print(writer, &format!("{name} (rsa)"), indent),
            Self::Ecc(b) => b.print(writer, &format!("{name} (ecc)"), indent),
            Self::Bits(b) => b.print(writer, &format!("{name} (bits)"), indent),
            Self::Sym(b) => b.print(writer, &format!("{name} (sym)"), indent),
        }
    }
}

impl TpmPrint for TpmtKeyedhashScheme {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        writeln!(writer, "{prefix}{name}:")?;
        self.scheme.print(writer, "scheme", indent + 1)?;
        self.details.print(writer, "details", indent + 1)?;
        Ok(())
    }
}

impl TpmPrint for TpmuKeyedhashScheme {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::Hmac(s) => s.print(writer, &format!("{name} (hmac)"), indent),
            Self::Xor(s) => s.print(writer, &format!("{name} (xor)"), indent),
            Self::Null => writeln!(writer, "{prefix}{name}: null"),
        }
    }
}

impl TpmPrint for TpmCommand {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        match self {
            Self::CreatePrimary(cmd) => cmd.print(writer, name, indent),
            Self::ContextSave(cmd) => cmd.print(writer, name, indent),
            Self::EvictControl(cmd) => cmd.print(writer, name, indent),
            Self::FlushContext(cmd) => cmd.print(writer, name, indent),
            Self::ReadPublic(cmd) => cmd.print(writer, name, indent),
            Self::Import(cmd) => cmd.print(writer, name, indent),
            Self::Load(cmd) => cmd.print(writer, name, indent),
            Self::NvRead(cmd) => cmd.print(writer, name, indent),
            Self::NvReadPublic(cmd) => cmd.print(writer, name, indent),
            Self::PcrEvent(cmd) => cmd.print(writer, name, indent),
            Self::PcrRead(cmd) => cmd.print(writer, name, indent),
            Self::PolicyPcr(cmd) => cmd.print(writer, name, indent),
            Self::PolicySecret(cmd) => cmd.print(writer, name, indent),
            Self::PolicyOr(cmd) => cmd.print(writer, name, indent),
            Self::PolicyGetDigest(cmd) => cmd.print(writer, name, indent),
            Self::PolicyRestart(cmd) => cmd.print(writer, name, indent),
            Self::DictionaryAttackLockReset(cmd) => cmd.print(writer, name, indent),
            Self::Create(cmd) => cmd.print(writer, name, indent),
            Self::Unseal(cmd) => cmd.print(writer, name, indent),
            Self::GetCapability(cmd) => cmd.print(writer, name, indent),
            Self::StartAuthSession(cmd) => cmd.print(writer, name, indent),
            Self::ContextLoad(cmd) => cmd.print(writer, name, indent),
            Self::TestParms(cmd) => cmd.print(writer, name, indent),
            Self::EccParameters(cmd) => cmd.print(writer, name, indent),
            _ => {
                let prefix = " ".repeat(indent * INDENT);
                writeln!(
                    writer,
                    "{prefix}{name}: {self:?} (unimplemented pretty trace)"
                )
            }
        }
    }
}

impl TpmPrint for TpmResponse {
    fn print(
        &self,
        writer: &mut dyn Write,
        name: &str,
        indent: usize,
    ) -> Result<(), std::io::Error> {
        match self {
            Self::GetCapability(resp) => resp.print(writer, name, indent),
            Self::PcrRead(resp) => resp.print(writer, name, indent),
            Self::StartAuthSession(resp) => resp.print(writer, name, indent),
            Self::CreatePrimary(resp) => resp.print(writer, name, indent),
            Self::ContextSave(resp) => resp.print(writer, name, indent),
            Self::EvictControl(resp) => resp.print(writer, name, indent),
            Self::FlushContext(resp) => resp.print(writer, name, indent),
            Self::ReadPublic(resp) => resp.print(writer, name, indent),
            Self::Import(resp) => resp.print(writer, name, indent),
            Self::Load(resp) => resp.print(writer, name, indent),
            Self::NvRead(resp) => resp.print(writer, name, indent),
            Self::NvReadPublic(resp) => resp.print(writer, name, indent),
            Self::PcrEvent(resp) => resp.print(writer, name, indent),
            Self::PolicyPcr(resp) => resp.print(writer, name, indent),
            Self::PolicySecret(resp) => resp.print(writer, name, indent),
            Self::PolicyGetDigest(resp) => resp.print(writer, name, indent),
            Self::PolicyRestart(resp) => resp.print(writer, name, indent),
            Self::DictionaryAttackLockReset(resp) => resp.print(writer, name, indent),
            Self::Create(resp) => resp.print(writer, name, indent),
            Self::Unseal(resp) => resp.print(writer, name, indent),
            Self::ContextLoad(resp) => resp.print(writer, name, indent),
            _ => {
                let prefix = " ".repeat(indent * INDENT);
                writeln!(
                    writer,
                    "{prefix}{name}: {self:?} (unimplemented pretty trace)"
                )
            }
        }
    }
}
