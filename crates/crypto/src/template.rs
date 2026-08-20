// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! TPM 2.0 public key templates.

use crate::{TpmCryptoError, TpmEllipticCurve, TpmHash};
use std::str::FromStr;
use tpm2_protocol::{
    basic::{TpmBuffer, TpmUint16, TpmUint32},
    data::{
        Tpm2bDigest, TpmAlgId, TpmEccCurve, TpmaObject, TpmsEccParms, TpmsKeyedhashParms,
        TpmsRsaParms, TpmsSchemeHash, TpmsSchemeXor, TpmtEccScheme, TpmtKdfScheme,
        TpmtKeyedhashScheme, TpmtPublic, TpmtRsaScheme, TpmtSymDefObject, TpmuAsymScheme,
        TpmuKdfScheme, TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits,
        TpmuSymMode,
    },
};

/// A template describing a TPM public area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPublicTemplate {
    object_type: TpmAlgId,
    name_alg: TpmAlgId,
    auth_policy: Tpm2bDigest,
    object_attributes: TpmaObject,
    symmetric: TpmtSymDefObject,
    public_id: TpmuPublicId,
    public_parms: TpmuPublicParms,
}

impl Default for TpmPublicTemplate {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmPublicTemplate {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            object_type: TpmAlgId::KeyedHash,
            name_alg: TpmAlgId::Null,
            auth_policy: Tpm2bDigest::new(),
            object_attributes: TpmaObject::empty(),
            symmetric: TpmtSymDefObject {
                algorithm: TpmAlgId::Null,
                key_bits: TpmuSymKeyBits::Null,
                mode: TpmuSymMode::Null,
            },
            public_id: TpmuPublicId::KeyedHash(TpmBuffer::new()),
            public_parms: TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                scheme: TpmtKeyedhashScheme {
                    scheme: TpmAlgId::Null,
                    details: TpmuKeyedhashScheme::Null,
                },
            }),
        }
    }

    /// Sets the public ID and parameters.
    ///
    /// This method implicitly sets the object type.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObjectType`](crate::TpmCryptoError::InvalidObjectType)
    /// if the public ID and parameters do not match.
    pub fn with_public(
        mut self,
        public_id: TpmuPublicId,
        public_parms: TpmuPublicParms,
    ) -> Result<Self, TpmCryptoError> {
        self.object_type = match (&public_id, &public_parms) {
            (TpmuPublicId::Rsa(_), TpmuPublicParms::Rsa(_)) => TpmAlgId::Rsa,
            (TpmuPublicId::Ecc(_), TpmuPublicParms::Ecc(_)) => TpmAlgId::Ecc,
            (TpmuPublicId::KeyedHash(_), TpmuPublicParms::KeyedHash(_)) => TpmAlgId::KeyedHash,
            (TpmuPublicId::SymCipher(_), TpmuPublicParms::SymCipher(_)) => TpmAlgId::SymCipher,
            _ => return Err(TpmCryptoError::InvalidObjectType),
        };

        self.public_id = public_id;
        self.public_parms = public_parms;
        Ok(self)
    }

    #[must_use]
    pub fn with_name_alg(mut self, name_alg: TpmHash) -> Self {
        self.name_alg = name_alg.into();
        self
    }

    #[must_use]
    pub const fn with_auth_policy(mut self, auth_policy: Tpm2bDigest) -> Self {
        self.auth_policy = auth_policy;
        self
    }

    #[must_use]
    pub const fn with_object_attributes(mut self, object_attributes: TpmaObject) -> Self {
        self.object_attributes = object_attributes;
        self
    }

    #[must_use]
    pub const fn with_symmetric(mut self, symmetric: TpmtSymDefObject) -> Self {
        self.symmetric = symmetric;
        self
    }

    /// Returns the object type.
    #[must_use]
    pub const fn object_type(&self) -> TpmAlgId {
        self.object_type
    }

    /// Returns the name algorithm.
    #[must_use]
    pub const fn name_alg(&self) -> TpmAlgId {
        self.name_alg
    }

    /// Returns the authentication policy.
    #[must_use]
    pub const fn auth_policy(&self) -> Tpm2bDigest {
        self.auth_policy
    }

    /// Returns the object attributes.
    #[must_use]
    pub const fn object_attributes(&self) -> TpmaObject {
        self.object_attributes
    }

    /// Returns the symmetric algorithm definition.
    #[must_use]
    pub const fn symmetric(&self) -> TpmtSymDefObject {
        self.symmetric
    }

    /// Returns the public ID.
    #[must_use]
    pub const fn public_id(&self) -> &TpmuPublicId {
        &self.public_id
    }

    /// Returns the public parameters.
    #[must_use]
    pub const fn public_parms(&self) -> &TpmuPublicParms {
        &self.public_parms
    }

    /// Returns the RSA/ECC scheme from the public parameters, if any.
    #[must_use]
    pub const fn scheme(&self) -> Option<TpmAlgId> {
        match &self.public_parms {
            TpmuPublicParms::Rsa(parms) => Some(parms.scheme.scheme),
            TpmuPublicParms::Ecc(parms) => Some(parms.scheme.scheme),
            _ => None,
        }
    }

    /// Returns `true` when this template describes a restricted storage parent.
    ///
    /// Storage parents are RSA/ECC decrypt keys with a NULL scheme and
    /// `RESTRICTED` set (`rsa-2048:sha256`, `ecc-nist-p256:sha256`).
    #[must_use]
    pub const fn is_storage_parent(&self) -> bool {
        matches!(self.object_type, TpmAlgId::Rsa | TpmAlgId::Ecc)
            && matches!(self.scheme(), Some(TpmAlgId::Null))
            && self.object_attributes.contains(TpmaObject::RESTRICTED)
            && self.object_attributes.contains(TpmaObject::DECRYPT)
    }

    /// Returns the usage bits implied by the algorithm string.
    ///
    /// These are the `DECRYPT`, `SIGN_ENCRYPT`, and `RESTRICTED` bits stored on
    /// the template. Parse writes them from the scheme suffix; a live public
    /// area already carries them.
    #[must_use]
    pub fn usage_attributes(&self) -> TpmaObject {
        self.object_attributes
            & (TpmaObject::DECRYPT | TpmaObject::SIGN_ENCRYPT | TpmaObject::RESTRICTED)
    }

    /// Returns the RSA scheme for this template.
    ///
    /// When the template is not an RSA object, OAEP with the template name
    /// algorithm is used. That fallback matches the historical `to_public()`
    /// default for empty templates.
    #[must_use]
    pub fn rsa_scheme(&self) -> TpmtRsaScheme {
        match self.public_parms {
            TpmuPublicParms::Rsa(parms) => {
                let (scheme, details) =
                    fill_scheme_hash(parms.scheme.scheme, parms.scheme.details, self.name_alg);
                TpmtRsaScheme { scheme, details }
            }
            _ => TpmtRsaScheme {
                scheme: TpmAlgId::Oaep,
                details: TpmuAsymScheme::Hash(TpmsSchemeHash {
                    hash_alg: self.name_alg,
                }),
            },
        }
    }

    /// Returns the ECC scheme for this template.
    ///
    /// When the template is not an ECC object, ECDH with the template name
    /// algorithm is used. That fallback matches the historical `to_public()`
    /// default for empty templates.
    #[must_use]
    pub fn ecc_scheme(&self) -> TpmtEccScheme {
        match self.public_parms {
            TpmuPublicParms::Ecc(parms) => {
                let (scheme, details) =
                    fill_scheme_hash(parms.scheme.scheme, parms.scheme.details, self.name_alg);
                TpmtEccScheme { scheme, details }
            }
            _ => TpmtEccScheme {
                scheme: TpmAlgId::Ecdh,
                details: TpmuAsymScheme::Hash(TpmsSchemeHash {
                    hash_alg: self.name_alg,
                }),
            },
        }
    }
}

impl TryFrom<&TpmtPublic> for TpmPublicTemplate {
    type Error = TpmCryptoError;

    fn try_from(public: &TpmtPublic) -> Result<Self, TpmCryptoError> {
        let name_alg = TpmHash::try_from(public.name_alg)?;
        let symmetric = match &public.parameters {
            TpmuPublicParms::Rsa(parms) => parms.symmetric,
            TpmuPublicParms::Ecc(parms) => parms.symmetric,
            TpmuPublicParms::SymCipher(parms) => parms.sym,
            _ => TpmtSymDefObject::default(),
        };

        Self::new()
            .with_public(public.unique.clone(), public.parameters)
            .map(|template| {
                template
                    .with_name_alg(name_alg)
                    .with_object_attributes(public.object_attributes)
                    .with_auth_policy(public.auth_policy)
                    .with_symmetric(symmetric)
            })
    }
}

impl TryFrom<&TpmPublicTemplate> for TpmtPublic {
    type Error = TpmCryptoError;

    fn try_from(template: &TpmPublicTemplate) -> Result<Self, TpmCryptoError> {
        let mut parameters = template.public_parms;

        match &mut parameters {
            TpmuPublicParms::Rsa(p) => p.symmetric = template.symmetric,
            TpmuPublicParms::Ecc(p) => p.symmetric = template.symmetric,
            TpmuPublicParms::SymCipher(p) => p.sym = template.symmetric,
            _ => {}
        }

        Ok(TpmtPublic {
            object_type: template.object_type,
            name_alg: template.name_alg,
            object_attributes: template.object_attributes,
            auth_policy: template.auth_policy,
            parameters,
            unique: template.public_id.clone(),
        })
    }
}

impl TryFrom<&TpmPublicTemplate> for String {
    type Error = TpmCryptoError;

    fn try_from(template: &TpmPublicTemplate) -> Result<Self, TpmCryptoError> {
        let name_alg_str = TpmHash::try_from(template.name_alg)?.to_string();
        match &template.public_parms {
            TpmuPublicParms::Rsa(parms) => {
                let key_bits = parms.key_bits;
                if key_bits.value() == 0 {
                    return Err(TpmCryptoError::InvalidKeyBits(0));
                }
                format_asym("rsa", &key_bits.to_string(), &name_alg_str, template)
            }
            TpmuPublicParms::Ecc(parms) => {
                let curve = parms.curve_id;
                let curve_str = TpmEllipticCurve::try_from(curve)?.to_string();
                format_asym("ecc", &curve_str, &name_alg_str, template)
            }
            TpmuPublicParms::KeyedHash(parms) => match parms.scheme.scheme {
                TpmAlgId::Null => Ok(format!("keyedhash-null:{name_alg_str}")),
                TpmAlgId::Xor => Ok(format!("keyedhash-xor:{name_alg_str}")),
                TpmAlgId::Hmac => Ok(format!("keyedhash-hmac:{name_alg_str}")),
                _ => Err(TpmCryptoError::InvalidObjectType),
            },
            _ => Err(TpmCryptoError::InvalidObjectType),
        }
    }
}

impl FromStr for TpmPublicTemplate {
    type Err = TpmCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("rsa-") {
            parse_rsa(rest)
        } else if let Some(rest) = s.strip_prefix("ecc-") {
            parse_ecc(rest)
        } else if let Some(name_alg_str) = s.strip_prefix("keyedhash-null:") {
            parse_keyedhash(name_alg_str, TpmAlgId::Null)
        } else if let Some(name_alg_str) = s.strip_prefix("keyedhash-xor:") {
            parse_keyedhash(name_alg_str, TpmAlgId::Xor)
        } else if let Some(name_alg_str) = s.strip_prefix("keyedhash-hmac:") {
            parse_keyedhash(name_alg_str, TpmAlgId::Hmac)
        } else {
            Err(TpmCryptoError::InvalidObjectType)
        }
    }
}

fn parse_rsa(suffix: &str) -> Result<TpmPublicTemplate, TpmCryptoError> {
    let (bits_str, rest) = suffix
        .split_once(':')
        .ok_or(TpmCryptoError::InvalidObjectType)?;
    let (name_alg_str, scheme_str) = split_name_and_scheme(rest)?;
    let key_bits: u16 = bits_str
        .parse()
        .map_err(|_| TpmCryptoError::InvalidObjectType)?;
    let name_alg =
        TpmHash::from_str(name_alg_str).map_err(|_| TpmCryptoError::InvalidObjectType)?;
    let (scheme, usage) = parse_asym_form(scheme_str)?;
    if !is_rsa_scheme(scheme) {
        return Err(TpmCryptoError::InvalidObjectType);
    }
    let (scheme, details) = asym_scheme(scheme, name_alg.into())?;

    let parms = TpmuPublicParms::Rsa(TpmsRsaParms {
        symmetric: TpmtSymDefObject::default(),
        scheme: TpmtRsaScheme { scheme, details },
        key_bits: TpmUint16::new(key_bits),
        exponent: TpmUint32::new(0),
    });
    let unique = TpmuPublicId::Rsa(TpmBuffer::default());

    TpmPublicTemplate::new()
        .with_public(unique, parms)
        .map(|t| t.with_name_alg(name_alg).with_object_attributes(usage))
}

fn parse_ecc(suffix: &str) -> Result<TpmPublicTemplate, TpmCryptoError> {
    let (curve_str, rest) = suffix
        .split_once(':')
        .ok_or(TpmCryptoError::InvalidObjectType)?;
    let (name_alg_str, scheme_str) = split_name_and_scheme(rest)?;
    let curve_id: TpmEccCurve = TpmEllipticCurve::from_str(curve_str)
        .map_err(|_| TpmCryptoError::InvalidObjectType)?
        .into();
    let name_alg =
        TpmHash::from_str(name_alg_str).map_err(|_| TpmCryptoError::InvalidObjectType)?;
    let (scheme, usage) = parse_asym_form(scheme_str)?;
    if !is_ecc_scheme(scheme) {
        return Err(TpmCryptoError::InvalidObjectType);
    }
    let (scheme, details) = asym_scheme(scheme, name_alg.into())?;

    let parms = TpmuPublicParms::Ecc(TpmsEccParms {
        symmetric: TpmtSymDefObject::default(),
        scheme: TpmtEccScheme { scheme, details },
        curve_id,
        kdf: TpmtKdfScheme::default(),
    });
    let unique = TpmuPublicId::Ecc(tpm2_protocol::data::TpmsEccPoint::default());

    TpmPublicTemplate::new()
        .with_public(unique, parms)
        .map(|t| t.with_name_alg(name_alg).with_object_attributes(usage))
}

fn parse_keyedhash(hash_alg: &str, scheme: TpmAlgId) -> Result<TpmPublicTemplate, TpmCryptoError> {
    let name_alg = TpmHash::from_str(hash_alg).map_err(|_| TpmCryptoError::InvalidObjectType)?;
    let name_alg_id = name_alg.into();

    let details = match scheme {
        TpmAlgId::Null => TpmuKeyedhashScheme::Null,
        TpmAlgId::Xor => TpmuKeyedhashScheme::Xor(TpmsSchemeXor {
            hash_alg: name_alg_id,
            kdf: TpmtKdfScheme {
                scheme: TpmAlgId::Kdf1Sp800_108,
                details: TpmuKdfScheme::Null,
            },
        }),
        TpmAlgId::Hmac => TpmuKeyedhashScheme::Hmac(TpmsSchemeHash {
            hash_alg: name_alg_id,
        }),
        _ => return Err(TpmCryptoError::InvalidObjectType),
    };

    let parms = TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
        scheme: TpmtKeyedhashScheme { scheme, details },
    });
    let unique = TpmuPublicId::KeyedHash(TpmBuffer::default());

    TpmPublicTemplate::new()
        .with_public(unique, parms)
        .map(|t| {
            t.with_name_alg(name_alg)
                .with_object_attributes(TpmaObject::SIGN_ENCRYPT)
        })
}

fn split_name_and_scheme(rest: &str) -> Result<(&str, Option<&str>), TpmCryptoError> {
    match rest.split_once(':') {
        None => Ok((rest, None)),
        Some((name_alg_str, scheme_str)) => {
            if name_alg_str.is_empty() || scheme_str.is_empty() || scheme_str.contains(':') {
                return Err(TpmCryptoError::InvalidObjectType);
            }
            Ok((name_alg_str, Some(scheme_str)))
        }
    }
}

fn parse_asym_form(scheme_str: Option<&str>) -> Result<(TpmAlgId, TpmaObject), TpmCryptoError> {
    match scheme_str {
        None => Ok((TpmAlgId::Null, TpmaObject::DECRYPT | TpmaObject::RESTRICTED)),
        Some(s) => {
            let scheme = parse_scheme(s)?;
            let usage = match scheme {
                TpmAlgId::Null => TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
                scheme if is_sign_scheme(scheme) => TpmaObject::SIGN_ENCRYPT,
                scheme if is_decrypt_scheme(scheme) => TpmaObject::DECRYPT,
                _ => return Err(TpmCryptoError::InvalidObjectType),
            };
            Ok((scheme, usage))
        }
    }
}

fn parse_scheme(s: &str) -> Result<TpmAlgId, TpmCryptoError> {
    match s {
        "null" => Ok(TpmAlgId::Null),
        "rsassa" => Ok(TpmAlgId::Rsassa),
        "rsapss" => Ok(TpmAlgId::Rsapss),
        "rsaes" => Ok(TpmAlgId::Rsaes),
        "oaep" => Ok(TpmAlgId::Oaep),
        "ecdsa" => Ok(TpmAlgId::Ecdsa),
        "ecdh" => Ok(TpmAlgId::Ecdh),
        "ecdaa" => Ok(TpmAlgId::Ecdaa),
        "ecschnorr" => Ok(TpmAlgId::Ecschnorr),
        "sm2" => Ok(TpmAlgId::Sm2),
        "ecmqv" => Ok(TpmAlgId::Ecmqv),
        _ => Err(TpmCryptoError::InvalidObjectType),
    }
}

fn scheme_name(scheme: TpmAlgId) -> Result<&'static str, TpmCryptoError> {
    match scheme {
        TpmAlgId::Null => Ok("null"),
        TpmAlgId::Rsassa => Ok("rsassa"),
        TpmAlgId::Rsapss => Ok("rsapss"),
        TpmAlgId::Rsaes => Ok("rsaes"),
        TpmAlgId::Oaep => Ok("oaep"),
        TpmAlgId::Ecdsa => Ok("ecdsa"),
        TpmAlgId::Ecdh => Ok("ecdh"),
        TpmAlgId::Ecdaa => Ok("ecdaa"),
        TpmAlgId::Ecschnorr => Ok("ecschnorr"),
        TpmAlgId::Sm2 => Ok("sm2"),
        TpmAlgId::Ecmqv => Ok("ecmqv"),
        _ => Err(TpmCryptoError::InvalidObjectType),
    }
}

fn format_asym(
    kind: &str,
    selector: &str,
    name_alg_str: &str,
    template: &TpmPublicTemplate,
) -> Result<String, TpmCryptoError> {
    if template.is_storage_parent() {
        return Ok(format!("{kind}-{selector}:{name_alg_str}"));
    }
    let scheme = template.scheme().ok_or(TpmCryptoError::InvalidObjectType)?;
    let scheme_str = scheme_name(scheme)?;
    Ok(format!("{kind}-{selector}:{name_alg_str}:{scheme_str}"))
}

const fn is_sign_scheme(scheme: TpmAlgId) -> bool {
    matches!(
        scheme,
        TpmAlgId::Rsassa
            | TpmAlgId::Rsapss
            | TpmAlgId::Ecdsa
            | TpmAlgId::Ecdaa
            | TpmAlgId::Ecschnorr
            | TpmAlgId::Sm2
    )
}

const fn is_decrypt_scheme(scheme: TpmAlgId) -> bool {
    matches!(
        scheme,
        TpmAlgId::Oaep | TpmAlgId::Rsaes | TpmAlgId::Ecdh | TpmAlgId::Ecmqv
    )
}

const fn is_rsa_scheme(scheme: TpmAlgId) -> bool {
    matches!(
        scheme,
        TpmAlgId::Null | TpmAlgId::Rsassa | TpmAlgId::Rsapss | TpmAlgId::Rsaes | TpmAlgId::Oaep
    )
}

const fn is_ecc_scheme(scheme: TpmAlgId) -> bool {
    matches!(
        scheme,
        TpmAlgId::Null
            | TpmAlgId::Ecdsa
            | TpmAlgId::Ecdh
            | TpmAlgId::Ecdaa
            | TpmAlgId::Ecschnorr
            | TpmAlgId::Sm2
            | TpmAlgId::Ecmqv
    )
}

fn asym_scheme(
    scheme: TpmAlgId,
    name_alg: TpmAlgId,
) -> Result<(TpmAlgId, TpmuAsymScheme), TpmCryptoError> {
    match scheme {
        TpmAlgId::Null | TpmAlgId::Rsaes => Ok((scheme, TpmuAsymScheme::Null)),
        TpmAlgId::Rsassa
        | TpmAlgId::Rsapss
        | TpmAlgId::Oaep
        | TpmAlgId::Ecdsa
        | TpmAlgId::Ecdh
        | TpmAlgId::Ecdaa
        | TpmAlgId::Ecschnorr
        | TpmAlgId::Sm2
        | TpmAlgId::Ecmqv => Ok((
            scheme,
            TpmuAsymScheme::Hash(TpmsSchemeHash { hash_alg: name_alg }),
        )),
        _ => Err(TpmCryptoError::InvalidObjectType),
    }
}

fn fill_scheme_hash(
    scheme: TpmAlgId,
    details: TpmuAsymScheme,
    name_alg: TpmAlgId,
) -> (TpmAlgId, TpmuAsymScheme) {
    match details {
        TpmuAsymScheme::Hash(mut hash) if hash.hash_alg == TpmAlgId::Null => {
            hash.hash_alg = name_alg;
            (scheme, TpmuAsymScheme::Hash(hash))
        }
        details => (scheme, details),
    }
}
