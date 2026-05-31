//! X.509 extension parsing and role-based validation.
//!
//! Provides functions to parse and validate standard X.509v3 extensions
//! from certificates, and to verify that a certificate's extensions are
//! appropriate for its role in the PKI (end entity, intermediate CA,
//! CRL signer, OCSP responder).
//!
//! # Supported Extensions
//!
//! | Extension | OID | Function |
//! |-----------|-----|----------|
//! | Basic Constraints | `2.5.29.19` | [`check_basic_constraints`] |
//! | Key Usage | `2.5.29.15` | [`check_key_usage`] |
//! | Extended Key Usage | `2.5.29.37` | [`check_extended_key_usage`] |
//! | (any) | — | [`has_extension`] |
//!
//! # Role Validation
//!
//! [`validate_extensions_for_role`] checks that a certificate's extensions
//! match the expected profile for the given [`CertRole`]:
//!
//! - **EndEntity**: must NOT have `CA:TRUE`; should have `digitalSignature` key usage
//! - **IntermediateCa**: must have `CA:TRUE` + `keyCertSign` key usage
//! - **CrlSigner**: must have `cRLSign` key usage
//! - **OcspResponder**: must have `id-kp-OCSPSigning` EKU

use crate::der_utils;
use crate::error::LtvError;
use x509_cert::Certificate;

// ── OID constants ─────────────────────────────────────────────────

/// Basic Constraints extension OID: 2.5.29.19
const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";

/// Key Usage extension OID: 2.5.29.15
const KEY_USAGE_OID: &str = "2.5.29.15";

/// Extended Key Usage extension OID: 2.5.29.37
const EKU_OID: &str = "2.5.29.37";

/// OCSP Signing EKU OID: 1.3.6.1.5.5.7.3.9
const OCSP_SIGNING_EKU_OID: &str = "1.3.6.1.5.5.7.3.9";

// ── Public types ──────────────────────────────────────────────────

/// Key usage bits from the keyUsage extension (RFC 5280 §4.2.1.3).
///
/// The keyUsage extension is a BIT STRING with the following bits:
///
/// ```text
///   KeyUsage ::= BIT STRING {
///       digitalSignature        (0),
///       nonRepudiation          (1),  -- also called contentCommitment
///       keyEncipherment         (2),
///       dataEncipherment        (3),
///       keyAgreement            (4),
///       keyCertSign             (5),
///       cRLSign                 (6),
///       encipherOnly            (7),
///       decipherOnly            (8)
///   }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUsageBits {
    pub digital_signature: bool,
    pub content_commitment: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

impl KeyUsageBits {
    /// Create a KeyUsageBits with all bits set to false.
    pub fn none() -> Self {
        Self {
            digital_signature: false,
            content_commitment: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        }
    }
}

impl std::fmt::Display for KeyUsageBits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bits = Vec::new();
        if self.digital_signature {
            bits.push("digitalSignature");
        }
        if self.content_commitment {
            bits.push("contentCommitment");
        }
        if self.key_encipherment {
            bits.push("keyEncipherment");
        }
        if self.data_encipherment {
            bits.push("dataEncipherment");
        }
        if self.key_agreement {
            bits.push("keyAgreement");
        }
        if self.key_cert_sign {
            bits.push("keyCertSign");
        }
        if self.crl_sign {
            bits.push("cRLSign");
        }
        if self.encipher_only {
            bits.push("encipherOnly");
        }
        if self.decipher_only {
            bits.push("decipherOnly");
        }
        if bits.is_empty() {
            write!(f, "(none)")
        } else {
            write!(f, "{}", bits.join(", "))
        }
    }
}

/// The role a certificate plays in the PKI.
///
/// Used by [`validate_extensions_for_role`] to check that extensions
/// match the expected profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRole {
    /// End-entity certificate (e.g., document signer).
    EndEntity,
    /// Intermediate CA certificate.
    IntermediateCa,
    /// CRL issuer certificate.
    CrlSigner,
    /// OCSP responder certificate.
    OcspResponder,
}

impl std::fmt::Display for CertRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertRole::EndEntity => write!(f, "EndEntity"),
            CertRole::IntermediateCa => write!(f, "IntermediateCa"),
            CertRole::CrlSigner => write!(f, "CrlSigner"),
            CertRole::OcspResponder => write!(f, "OcspResponder"),
        }
    }
}

// ── Public functions ──────────────────────────────────────────────

/// Parse the Basic Constraints extension from a certificate.
///
/// Returns `(is_ca, path_len_constraint)`:
/// - `is_ca`: whether the `cA` boolean is TRUE
/// - `path_len_constraint`: optional `pathLenConstraint` integer
///
/// If the certificate has no Basic Constraints extension, returns `(false, None)`.
///
/// # ASN.1 Structure
///
/// ```text
/// BasicConstraints ::= SEQUENCE {
///     cA                      BOOLEAN DEFAULT FALSE,
///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
/// }
/// ```
pub fn check_basic_constraints(cert: &Certificate) -> Result<(bool, Option<u32>), LtvError> {
    let bc_oid = const_oid::ObjectIdentifier::new_unwrap(BASIC_CONSTRAINTS_OID);

    let ext_value = match find_extension_value(cert, &bc_oid) {
        Some(v) => v,
        None => return Ok((false, None)),
    };

    // Delegate to the shared, feature-independent byte parser so trust-chain
    // pathLen enforcement and ltv extension validation share one implementation.
    let (is_ca, path_len) =
        der_utils::parse_basic_constraints(ext_value).map_err(LtvError::X509Extension)?;
    // This helper's public API is `u32`; reject (rather than silently truncate)
    // a pathLenConstraint that does not fit.
    let path_len = match path_len {
        Some(p) => Some(u32::try_from(p).map_err(|_| {
            LtvError::X509Extension(format!("pathLenConstraint {p} exceeds u32 range"))
        })?),
        None => None,
    };
    Ok((is_ca, path_len))
}

/// Parse the Key Usage extension from a certificate.
///
/// Returns `Some(KeyUsageBits)` if the extension is present, `None` otherwise.
///
/// # ASN.1 Structure
///
/// ```text
/// KeyUsage ::= BIT STRING
/// ```
///
/// The BIT STRING value is encoded with a leading byte indicating the
/// number of unused bits in the last byte.
pub fn check_key_usage(cert: &Certificate) -> Result<Option<KeyUsageBits>, LtvError> {
    let ku_oid = const_oid::ObjectIdentifier::new_unwrap(KEY_USAGE_OID);

    let ext_value = match find_extension_value(cert, &ku_oid) {
        Some(v) => v,
        None => return Ok(None),
    };

    // Parse BIT STRING (tag 0x03)
    let (tag, bs_body) = der_utils::parse_tlv(ext_value)
        .map_err(|e| LtvError::X509Extension(format!("keyUsage: {e}")))?;
    if tag != 0x03 {
        return Err(LtvError::X509Extension(format!(
            "keyUsage: expected BIT STRING (0x03), got 0x{tag:02x}"
        )));
    }

    if bs_body.is_empty() {
        return Err(LtvError::X509Extension("keyUsage: empty BIT STRING".into()));
    }

    // First byte = number of unused bits in the last content byte
    let _unused_bits = bs_body[0];
    let bit_bytes = &bs_body[1..];

    // Helper: check if bit N is set (MSB-first within each byte)
    let bit_set = |n: usize| -> bool {
        let byte_idx = n / 8;
        let bit_idx = 7 - (n % 8);
        if byte_idx < bit_bytes.len() {
            (bit_bytes[byte_idx] >> bit_idx) & 1 == 1
        } else {
            false
        }
    };

    Ok(Some(KeyUsageBits {
        digital_signature: bit_set(0),
        content_commitment: bit_set(1),
        key_encipherment: bit_set(2),
        data_encipherment: bit_set(3),
        key_agreement: bit_set(4),
        key_cert_sign: bit_set(5),
        crl_sign: bit_set(6),
        encipher_only: bit_set(7),
        decipher_only: bit_set(8),
    }))
}

/// Parse the Extended Key Usage extension from a certificate.
///
/// Returns a list of EKU OIDs. Returns an empty list if the extension
/// is not present.
///
/// # ASN.1 Structure
///
/// ```text
/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
/// KeyPurposeId ::= OBJECT IDENTIFIER
/// ```
pub fn check_extended_key_usage(
    cert: &Certificate,
) -> Result<Vec<const_oid::ObjectIdentifier>, LtvError> {
    let eku_oid = const_oid::ObjectIdentifier::new_unwrap(EKU_OID);

    let ext_value = match find_extension_value(cert, &eku_oid) {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };

    // Parse SEQUENCE
    let (tag, seq_body) = der_utils::parse_tlv(ext_value)
        .map_err(|e| LtvError::X509Extension(format!("extKeyUsage: {e}")))?;
    if tag != 0x30 {
        return Err(LtvError::X509Extension(format!(
            "extKeyUsage: expected SEQUENCE (0x30), got 0x{tag:02x}"
        )));
    }

    let mut oids = Vec::new();
    let mut pos = &seq_body[..];
    while !pos.is_empty() {
        let (oid_tag, oid_body, rest) = der_utils::parse_tlv_with_rest(pos)
            .map_err(|e| LtvError::X509Extension(format!("extKeyUsage OID: {e}")))?;
        if oid_tag != 0x06 {
            return Err(LtvError::X509Extension(format!(
                "extKeyUsage: expected OID (0x06), got 0x{oid_tag:02x}"
            )));
        }

        // Reconstruct the full DER OID encoding to use ObjectIdentifier::from_bytes
        let oid = const_oid::ObjectIdentifier::from_bytes(oid_body).map_err(|e| {
            LtvError::X509Extension(format!("extKeyUsage: invalid OID encoding: {e}"))
        })?;
        oids.push(oid);
        pos = rest;
    }

    Ok(oids)
}

/// Check whether a certificate has a specific extension by OID.
///
/// This only checks for the extension's presence — it does not parse
/// or validate the extension's value.
pub fn has_extension(cert: &Certificate, oid: &const_oid::ObjectIdentifier) -> bool {
    find_extension_value(cert, oid).is_some()
}

/// Validate that a certificate's extensions match the expected profile
/// for the given role.
///
/// # Role Requirements
///
/// | Role | Basic Constraints | Key Usage | EKU |
/// |------|-------------------|-----------|-----|
/// | EndEntity | CA must be FALSE | digitalSignature (warning if missing) | — |
/// | IntermediateCa | CA must be TRUE | keyCertSign required | — |
/// | CrlSigner | — | cRLSign required | — |
/// | OcspResponder | — | — | id-kp-OCSPSigning required |
///
/// # Errors
///
/// Returns `LtvError::X509Extension` if:
/// - A required extension is missing or has wrong value
/// - Extension parsing fails
pub fn validate_extensions_for_role(cert: &Certificate, role: CertRole) -> Result<(), LtvError> {
    match role {
        CertRole::EndEntity => validate_end_entity(cert),
        CertRole::IntermediateCa => validate_intermediate_ca(cert),
        CertRole::CrlSigner => validate_crl_signer(cert),
        CertRole::OcspResponder => validate_ocsp_responder(cert),
    }
}

// ── Private helpers ───────────────────────────────────────────────

/// Find the raw extension value (extnValue OCTET STRING content) for
/// the given OID. Returns `None` if not found.
fn find_extension_value<'a>(
    cert: &'a Certificate,
    oid: &const_oid::ObjectIdentifier,
) -> Option<&'a [u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|ext| ext.extn_id == *oid)
        .map(|ext| ext.extn_value.as_bytes())
}

/// Validate end-entity certificate extensions.
fn validate_end_entity(cert: &Certificate) -> Result<(), LtvError> {
    // Check basicConstraints: CA must NOT be TRUE
    let (is_ca, _) = check_basic_constraints(cert)?;
    if is_ca {
        return Err(LtvError::X509Extension(
            "EndEntity certificate has basicConstraints CA:TRUE".into(),
        ));
    }

    // Key usage: digitalSignature should be present if keyUsage extension exists
    if let Some(ku) = check_key_usage(cert)? {
        if !ku.digital_signature && !ku.content_commitment {
            return Err(LtvError::X509Extension(format!(
                "EndEntity certificate missing digitalSignature or contentCommitment \
                 key usage (has: {ku})"
            )));
        }
    }

    Ok(())
}

/// Validate intermediate CA certificate extensions.
fn validate_intermediate_ca(cert: &Certificate) -> Result<(), LtvError> {
    // Check basicConstraints: CA must be TRUE
    let (is_ca, _) = check_basic_constraints(cert)?;
    if !is_ca {
        return Err(LtvError::X509Extension(
            "IntermediateCa certificate missing basicConstraints CA:TRUE".into(),
        ));
    }

    // Key usage: keyCertSign must be set
    match check_key_usage(cert)? {
        Some(ku) => {
            if !ku.key_cert_sign {
                return Err(LtvError::X509Extension(format!(
                    "IntermediateCa certificate missing keyCertSign key usage (has: {ku})"
                )));
            }
        }
        None => {
            return Err(LtvError::X509Extension(
                "IntermediateCa certificate missing keyUsage extension".into(),
            ));
        }
    }

    Ok(())
}

/// Validate CRL signer certificate extensions.
fn validate_crl_signer(cert: &Certificate) -> Result<(), LtvError> {
    // Key usage: cRLSign must be set
    match check_key_usage(cert)? {
        Some(ku) => {
            if !ku.crl_sign {
                return Err(LtvError::X509Extension(format!(
                    "CrlSigner certificate missing cRLSign key usage (has: {ku})"
                )));
            }
        }
        None => {
            return Err(LtvError::X509Extension(
                "CrlSigner certificate missing keyUsage extension".into(),
            ));
        }
    }

    Ok(())
}

/// Validate OCSP responder certificate extensions.
fn validate_ocsp_responder(cert: &Certificate) -> Result<(), LtvError> {
    // EKU: must have id-kp-OCSPSigning
    let ekus = check_extended_key_usage(cert)?;
    let ocsp_signing = const_oid::ObjectIdentifier::new_unwrap(OCSP_SIGNING_EKU_OID);

    if !ekus.contains(&ocsp_signing) {
        return Err(LtvError::X509Extension(format!(
            "OcspResponder certificate missing id-kp-OCSPSigning EKU (has: {})",
            if ekus.is_empty() {
                "(none)".to_string()
            } else {
                ekus.iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        )));
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    fn load_test_cert(pem_str: &str) -> Certificate {
        let (_, der) = pem_rfc7468::decode_vec(pem_str.as_bytes()).unwrap();
        Certificate::from_der(&der).unwrap()
    }

    fn ca_cert() -> Certificate {
        let pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        load_test_cert(pem)
    }

    fn intermediate_cert() -> Certificate {
        let pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_cert.pem"
        ));
        load_test_cert(pem)
    }

    fn signer_cert() -> Certificate {
        let pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        load_test_cert(pem)
    }

    // ── check_basic_constraints ───────────────────────────────────

    #[test]
    fn test_basic_constraints_intermediate_ca() {
        let cert = intermediate_cert();
        let (is_ca, path_len) = check_basic_constraints(&cert).unwrap();
        assert!(is_ca, "intermediate CA should have CA:TRUE");
        assert_eq!(path_len, Some(0), "intermediate CA should have pathlen:0");
    }

    #[test]
    fn test_basic_constraints_end_entity() {
        let cert = signer_cert();
        let (is_ca, path_len) = check_basic_constraints(&cert).unwrap();
        assert!(!is_ca, "signer cert should have CA:FALSE");
        assert_eq!(path_len, None, "signer cert should have no pathlen");
    }

    #[test]
    fn test_basic_constraints_root_ca() {
        // Root CA generated by openssl without explicit basicConstraints
        // in the req but is self-signed. Depending on generation, it may
        // or may not have basicConstraints.
        let cert = ca_cert();
        let result = check_basic_constraints(&cert);
        assert!(
            result.is_ok(),
            "parsing root CA basic constraints should succeed"
        );
    }

    // ── check_key_usage ───────────────────────────────────────────

    #[test]
    fn test_key_usage_intermediate_ca() {
        let cert = intermediate_cert();
        let ku = check_key_usage(&cert).unwrap();
        assert!(ku.is_some(), "intermediate CA should have keyUsage");
        let ku = ku.unwrap();
        assert!(ku.key_cert_sign, "intermediate CA should have keyCertSign");
        assert!(ku.crl_sign, "intermediate CA should have cRLSign");
        assert!(
            !ku.digital_signature,
            "intermediate CA should not have digitalSignature"
        );
    }

    #[test]
    fn test_key_usage_signer() {
        let cert = signer_cert();
        let ku = check_key_usage(&cert).unwrap();
        assert!(ku.is_some(), "signer cert should have keyUsage");
        let ku = ku.unwrap();
        assert!(ku.digital_signature, "signer should have digitalSignature");
        assert!(
            ku.content_commitment,
            "signer should have nonRepudiation/contentCommitment"
        );
        assert!(!ku.key_cert_sign, "signer should not have keyCertSign");
    }

    // ── check_extended_key_usage ──────────────────────────────────

    #[test]
    fn test_eku_absent() {
        // Our test intermediate CA has no EKU extension
        let cert = intermediate_cert();
        let ekus = check_extended_key_usage(&cert).unwrap();
        assert!(ekus.is_empty(), "intermediate CA should have no EKU");
    }

    // ── has_extension ─────────────────────────────────────────────

    #[test]
    fn test_has_extension() {
        let cert = intermediate_cert();
        let bc_oid = const_oid::ObjectIdentifier::new_unwrap(BASIC_CONSTRAINTS_OID);
        let ku_oid = const_oid::ObjectIdentifier::new_unwrap(KEY_USAGE_OID);
        let eku_oid = const_oid::ObjectIdentifier::new_unwrap(EKU_OID);

        assert!(
            has_extension(&cert, &bc_oid),
            "intermediate CA should have basicConstraints"
        );
        assert!(
            has_extension(&cert, &ku_oid),
            "intermediate CA should have keyUsage"
        );
        assert!(
            !has_extension(&cert, &eku_oid),
            "intermediate CA should not have EKU"
        );
    }

    // ── validate_extensions_for_role ──────────────────────────────

    #[test]
    fn test_validate_end_entity() {
        let cert = signer_cert();
        let result = validate_extensions_for_role(&cert, CertRole::EndEntity);
        assert!(
            result.is_ok(),
            "signer cert should pass EndEntity validation: {result:?}"
        );
    }

    #[test]
    fn test_validate_end_entity_rejects_ca() {
        let cert = intermediate_cert();
        let result = validate_extensions_for_role(&cert, CertRole::EndEntity);
        assert!(
            result.is_err(),
            "intermediate CA should fail EndEntity validation"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("CA:TRUE"),
            "error should mention CA:TRUE: {err}"
        );
    }

    #[test]
    fn test_validate_intermediate_ca() {
        let cert = intermediate_cert();
        let result = validate_extensions_for_role(&cert, CertRole::IntermediateCa);
        assert!(
            result.is_ok(),
            "intermediate CA cert should pass IntermediateCa validation: {result:?}"
        );
    }

    #[test]
    fn test_validate_intermediate_ca_rejects_end_entity() {
        let cert = signer_cert();
        let result = validate_extensions_for_role(&cert, CertRole::IntermediateCa);
        assert!(
            result.is_err(),
            "signer cert should fail IntermediateCa validation"
        );
    }

    #[test]
    fn test_validate_crl_signer() {
        let cert = intermediate_cert();
        let result = validate_extensions_for_role(&cert, CertRole::CrlSigner);
        assert!(
            result.is_ok(),
            "intermediate CA (with cRLSign) should pass CrlSigner validation: {result:?}"
        );
    }

    #[test]
    fn test_validate_crl_signer_rejects_missing() {
        let cert = signer_cert();
        let result = validate_extensions_for_role(&cert, CertRole::CrlSigner);
        assert!(
            result.is_err(),
            "signer cert (no cRLSign) should fail CrlSigner validation"
        );
    }

    #[test]
    fn test_validate_ocsp_responder_rejects_no_eku() {
        let cert = signer_cert();
        let result = validate_extensions_for_role(&cert, CertRole::OcspResponder);
        assert!(
            result.is_err(),
            "signer cert should fail OcspResponder validation"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("OCSPSigning"),
            "error should mention OCSPSigning: {err}"
        );
    }

    // ── KeyUsageBits Display ──────────────────────────────────────

    #[test]
    fn test_key_usage_display() {
        let ku = KeyUsageBits {
            digital_signature: true,
            content_commitment: true,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        };
        let s = format!("{ku}");
        assert!(s.contains("digitalSignature"));
        assert!(s.contains("contentCommitment"));
        assert!(!s.contains("keyCertSign"));

        let empty = KeyUsageBits::none();
        assert_eq!(format!("{empty}"), "(none)");
    }
}
