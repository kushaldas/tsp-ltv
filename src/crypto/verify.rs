//! Shared signature verification functions.
//!
//! Extracted from `trust/store.rs` so that CRL, OCSP, and chain
//! verification can all reuse the same cryptographic primitives.
//!
//! Supports:
//! - RSA PKCS#1 v1.5 with MD5 (legacy), SHA-1 (legacy), SHA-224, SHA-256, SHA-384, SHA-512
//! - RSA-PSS (RSASSA-PSS) with SHA-256, SHA-384, SHA-512
//! - ECDSA P-256/P-384 with SHA-1 (legacy)
//! - ECDSA P-256 with SHA-256
//! - ECDSA P-384 with SHA-384
//! - ECDSA P-521 with SHA-512
//! - Ed25519

use crate::crypto::algorithm::{
    DigestAlgorithm, OID_ECDSA_WITH_SHA1, OID_ED25519, OID_MD5_WITH_RSA, OID_RSASSA_PSS,
    OID_SHA1_WITH_RSA, OID_SHA224_WITH_RSA,
};
use crate::error::TrustError;

/// id-mgf1 (1.2.840.113549.1.1.8) — the mask generation function for PSS.
const OID_MGF1: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");

/// Verify a raw signature over `tbs_bytes` using the signer's SPKI (DER)
/// and the given signature algorithm OID.
///
/// This is the primary entry point — it dispatches to the correct
/// algorithm based on the OID.
///
/// # Supported algorithms
///
/// | OID | Algorithm |
/// |-----|-----------|
/// | `1.2.840.113549.1.1.4`  | MD5 with RSA (legacy) |
/// | `1.2.840.113549.1.1.5`  | SHA-1 with RSA (legacy) |
/// | `1.2.840.113549.1.1.11` | SHA-256 with RSA |
/// | `1.2.840.113549.1.1.12` | SHA-384 with RSA |
/// | `1.2.840.113549.1.1.13` | SHA-512 with RSA |
/// | `1.2.840.113549.1.1.14` | SHA-224 with RSA |
/// | `1.2.840.113549.1.1.10` | RSASSA-PSS (tries SHA-256/384/512) |
/// | `1.2.840.10045.4.1`     | ECDSA with SHA-1 (legacy) |
/// | `1.2.840.10045.4.3.2`   | ECDSA with SHA-256 |
/// | `1.2.840.10045.4.3.3`   | ECDSA with SHA-384 |
/// | `1.2.840.10045.4.3.4`   | ECDSA with SHA-512 |
/// | `1.3.101.112`           | Ed25519 |
pub fn verify_signature_by_oid(
    tbs_bytes: &[u8],
    signature_bytes: &[u8],
    spki_der: &[u8],
    sig_alg_oid: &const_oid::ObjectIdentifier,
) -> Result<(), TrustError> {
    use const_oid::db;

    // --- Legacy RSA algorithms ---
    if *sig_alg_oid == OID_MD5_WITH_RSA {
        verify_rsa_signature::<md5::Md5>(tbs_bytes, signature_bytes, spki_der)
    } else if *sig_alg_oid == OID_SHA1_WITH_RSA {
        verify_rsa_signature::<sha1::Sha1>(tbs_bytes, signature_bytes, spki_der)
    } else if *sig_alg_oid == OID_SHA224_WITH_RSA {
        verify_rsa_signature::<sha2::Sha224>(tbs_bytes, signature_bytes, spki_der)
    }
    // --- Modern RSA PKCS#1 v1.5 ---
    else if *sig_alg_oid == db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        verify_rsa_signature::<sha2::Sha256>(tbs_bytes, signature_bytes, spki_der)
    } else if *sig_alg_oid == db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION {
        verify_rsa_signature::<sha2::Sha384>(tbs_bytes, signature_bytes, spki_der)
    } else if *sig_alg_oid == db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION {
        verify_rsa_signature::<sha2::Sha512>(tbs_bytes, signature_bytes, spki_der)
    } else if *sig_alg_oid == OID_RSASSA_PSS {
        // RSA-PSS: AlgorithmIdentifier parameters should specify the hash,
        // but here we only have the OID. Try SHA-256 first, then SHA-384, SHA-512.
        verify_rsa_pss_signature::<sha2::Sha256>(tbs_bytes, signature_bytes, spki_der)
            .or_else(|_| {
                verify_rsa_pss_signature::<sha2::Sha384>(tbs_bytes, signature_bytes, spki_der)
            })
            .or_else(|_| {
                verify_rsa_pss_signature::<sha2::Sha512>(tbs_bytes, signature_bytes, spki_der)
            })
    }
    // --- Legacy ECDSA ---
    else if *sig_alg_oid == OID_ECDSA_WITH_SHA1 {
        // ECDSA-SHA1: try P-256 first, then P-384, then P-521
        verify_ecdsa_p256_sha1_signature(tbs_bytes, signature_bytes, spki_der)
            .or_else(|_| verify_ecdsa_p384_sha1_signature(tbs_bytes, signature_bytes, spki_der))
    }
    // --- Modern ECDSA ---
    else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_256 {
        // ECDSA-SHA256: try P-256 first, then P-384, then P-521
        // P-521 with SHA-256 is unusual but occurs with self-signed certs
        verify_ecdsa_p256_signature(tbs_bytes, signature_bytes, spki_der)
            .or_else(|_| verify_ecdsa_p384_signature(tbs_bytes, signature_bytes, spki_der))
            .or_else(|_| verify_ecdsa_p521_sha256_signature(tbs_bytes, signature_bytes, spki_der))
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_384 {
        // ECDSA-SHA384: try P-384 first, then P-256, then P-521
        verify_ecdsa_p384_signature(tbs_bytes, signature_bytes, spki_der)
            .or_else(|_| verify_ecdsa_p256_signature(tbs_bytes, signature_bytes, spki_der))
            .or_else(|_| verify_ecdsa_p521_sha384_signature(tbs_bytes, signature_bytes, spki_der))
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_512 {
        // ECDSA-SHA512: try P-521 first, then P-384
        verify_ecdsa_p521_signature(tbs_bytes, signature_bytes, spki_der)
            .or_else(|_| verify_ecdsa_p384_signature(tbs_bytes, signature_bytes, spki_der))
    } else if *sig_alg_oid == OID_ED25519 {
        verify_ed25519_signature(tbs_bytes, signature_bytes, spki_der)
    } else {
        Err(TrustError::UnsupportedAlgorithm(format!(
            "signature algorithm OID: {sig_alg_oid}"
        )))
    }
}

/// Verify a signature given the full signature `AlgorithmIdentifier`.
///
/// This is the parameter-aware entry point and should be preferred over
/// [`verify_signature_by_oid`] whenever the caller has the algorithm's
/// parameters. For RSASSA-PSS it decodes the `RSASSA-PSS-params` and verifies
/// strictly (hash, MGF1 hash, salt length) per RFC 4055; for every other
/// algorithm the hash is implied by the OID, so it delegates to
/// [`verify_signature_by_oid`].
pub fn verify_signature_by_algid(
    tbs_bytes: &[u8],
    signature_bytes: &[u8],
    spki_der: &[u8],
    sig_alg: &spki::AlgorithmIdentifierOwned,
) -> Result<(), TrustError> {
    if sig_alg.oid == OID_RSASSA_PSS {
        verify_rsa_pss_signature_strict(
            tbs_bytes,
            signature_bytes,
            spki_der,
            sig_alg.parameters.as_ref(),
        )
        .map(|_| ())
    } else {
        verify_signature_by_oid(tbs_bytes, signature_bytes, spki_der, &sig_alg.oid)
    }
}

/// Verify an RSASSA-PSS signature strictly according to its `RSASSA-PSS-params`
/// (RFC 4055), returning the digest the parameters selected.
///
/// For PSS the hash, MGF1 hash, salt length, and trailer field are part of the
/// algorithm definition and live in the signature `AlgorithmIdentifier`
/// parameters, not in the OID. This enforces:
/// - the parameters are present (a bare PSS OID is rejected),
/// - the `hashAlgorithm` is one we support,
/// - `maskGenAlgorithm` is MGF1 keyed to that same hash (the only form RFC 4055
///   recommends and the underlying verifier supports),
/// - the declared `saltLength` is used (PSS verification is salt-length
///   sensitive).
///
/// `trailerField` can only decode to its single defined value (`0xBC`), so
/// `RsaPssParams` decoding already rejects anything else.
pub fn verify_rsa_pss_signature_strict(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
    parameters: Option<&der::Any>,
) -> Result<DigestAlgorithm, TrustError> {
    use der::Encode;
    use rsa::pkcs1::RsaPssParams;

    let params_any = parameters.ok_or_else(|| {
        TrustError::UnsupportedAlgorithm(
            "RSASSA-PSS signatureAlgorithm is missing its required parameters".into(),
        )
    })?;
    let params_der = params_any.to_der().map_err(|e| {
        TrustError::SignatureVerification(format!("failed to re-encode RSASSA-PSS parameters: {e}"))
    })?;
    let params = RsaPssParams::try_from(params_der.as_slice()).map_err(|e| {
        TrustError::SignatureVerification(format!("failed to decode RSASSA-PSS parameters: {e}"))
    })?;

    let hash = DigestAlgorithm::from_oid(&params.hash.oid).ok_or_else(|| {
        TrustError::UnsupportedAlgorithm(format!(
            "unsupported RSASSA-PSS hashAlgorithm OID: {}",
            params.hash.oid
        ))
    })?;

    if params.mask_gen.oid != OID_MGF1 {
        return Err(TrustError::UnsupportedAlgorithm(format!(
            "unsupported RSASSA-PSS maskGenAlgorithm OID: {}",
            params.mask_gen.oid
        )));
    }
    let mgf1_hash_oid = params.mask_gen.parameters.as_ref().map(|h| h.oid);
    if mgf1_hash_oid != Some(params.hash.oid) {
        return Err(TrustError::UnsupportedAlgorithm(format!(
            "RSASSA-PSS MGF1 hash ({}) differs from the message hash ({}); not supported",
            mgf1_hash_oid
                .map(|o| o.to_string())
                .unwrap_or_else(|| "absent".into()),
            params.hash.oid,
        )));
    }

    let salt_len = params.salt_len as usize;
    match hash {
        DigestAlgorithm::Sha256 => {
            verify_rsa_pss_signature_with_salt::<sha2::Sha256>(tbs, sig, spki_der, salt_len)?
        }
        DigestAlgorithm::Sha384 => {
            verify_rsa_pss_signature_with_salt::<sha2::Sha384>(tbs, sig, spki_der, salt_len)?
        }
        DigestAlgorithm::Sha512 => {
            verify_rsa_pss_signature_with_salt::<sha2::Sha512>(tbs, sig, spki_der, salt_len)?
        }
        other => {
            return Err(TrustError::UnsupportedAlgorithm(format!(
                "RSASSA-PSS with digest {other:?}"
            )))
        }
    }
    Ok(hash)
}

/// Verify a certificate's signature against its issuer's public key.
///
/// Encodes the TBS portion and checks the outer signature using
/// [`verify_signature_by_algid`] so that RSASSA-PSS parameters are honoured.
pub fn verify_certificate_signature(
    cert: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
) -> Result<(), TrustError> {
    use der::Encode;

    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;

    let tbs_bytes = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| TrustError::SignatureVerification(format!("TBS encoding failed: {e}")))?;
    let signature_bytes = cert.signature.raw_bytes();

    let spki_der = issuer_spki
        .to_der()
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI encoding failed: {e}")))?;

    verify_signature_by_algid(
        &tbs_bytes,
        signature_bytes,
        &spki_der,
        &cert.signature_algorithm,
    )
}

/// Verify an RSA PKCS#1 v1.5 signature over `tbs` using the given SPKI.
pub fn verify_rsa_signature<D: digest::Digest + const_oid::AssociatedOid>(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::RsaPublicKey;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let pub_key = RsaPublicKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("RSA key decode failed: {e}")))?;

    let hash = D::digest(tbs);
    let scheme = Pkcs1v15Sign::new::<D>();
    pub_key
        .verify(scheme, &hash, sig)
        .map_err(|e| TrustError::SignatureVerification(format!("RSA signature invalid: {e}")))
}

/// Verify an RSA-PSS (RSASSA-PSS) signature over `tbs` using the given SPKI.
///
/// Uses the default salt length (the digest output size). Callers that have
/// decoded the `RSASSA-PSS-params` saltLength should use
/// [`verify_rsa_pss_signature_with_salt`] instead, since PSS verification is
/// salt-length sensitive.
pub fn verify_rsa_pss_signature<
    D: digest::Digest + digest::FixedOutputReset + Default + Clone + Send + Sync + 'static,
>(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    verify_rsa_pss_signature_with_salt::<D>(tbs, sig, spki_der, <D as digest::Digest>::output_size())
}

/// Verify an RSA-PSS (RSASSA-PSS) signature over `tbs` with an explicit salt
/// length.
///
/// PSS verification is sensitive to the salt length: the value recovered from
/// the signature must equal `salt_len`. RFC 4055 carries the salt length in the
/// `RSASSA-PSS-params` of the signature `AlgorithmIdentifier`, so a compliant
/// verifier must use that value rather than assuming the default. The mask
/// generation function is MGF1 keyed to the same hash `D` (the only form this
/// verifier and the underlying `rsa` crate support); callers are responsible
/// for rejecting parameters that disagree.
pub fn verify_rsa_pss_signature_with_salt<
    D: digest::Digest + digest::FixedOutputReset + Default + Clone + Send + Sync + 'static,
>(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
    salt_len: usize,
) -> Result<(), TrustError> {
    use der::Decode;
    use rsa::pss::Pss;
    use rsa::RsaPublicKey;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let pub_key = RsaPublicKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("RSA key decode failed: {e}")))?;

    let hash = D::digest(tbs);
    let scheme = Pss::new_with_salt::<D>(salt_len);
    pub_key
        .verify(scheme, &hash, sig)
        .map_err(|e| TrustError::SignatureVerification(format!("RSA-PSS signature invalid: {e}")))
}

/// Verify an ECDSA P-256 (SHA-256) signature.
pub fn verify_ecdsa_p256_signature(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = VerifyingKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-256 key decode failed: {e}")))?;
    let signature = Signature::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-256 sig decode failed: {e}")))?;

    vk.verify(tbs, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-256 invalid: {e}")))
}

/// Verify an ECDSA P-384 (SHA-384) signature.
pub fn verify_ecdsa_p384_signature(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = VerifyingKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-384 key decode failed: {e}")))?;
    let signature = Signature::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-384 sig decode failed: {e}")))?;

    vk.verify(tbs, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-384 invalid: {e}")))
}

/// Verify an ECDSA P-521 (SHA-512) signature.
pub fn verify_ecdsa_p521_signature(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest as _;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = ecdsa::VerifyingKey::<p521::NistP521>::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-521 key decode failed: {e}")))?;
    let signature = ecdsa::Signature::<p521::NistP521>::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-521 sig decode failed: {e}")))?;

    // P-521 doesn't implement DigestPrimitive, so we prehash with SHA-512
    let hash = sha2::Sha512::digest(tbs);
    vk.verify_prehash(&hash, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-521 invalid: {e}")))
}

/// Verify an ECDSA P-521 signature where the *signing algorithm* specified SHA-256
/// (e.g., a self-signed cert with `ecdsa-with-SHA256` but a P-521 key).
///
/// Note: The `ecdsa` crate's `bits2field` requires the hash to be at least
/// half the field size (33 bytes for P-521). Since SHA-256 produces 32 bytes,
/// we left-pad with a zero byte to satisfy this constraint.
pub fn verify_ecdsa_p521_sha256_signature(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest as _;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = ecdsa::VerifyingKey::<p521::NistP521>::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-521 key decode failed: {e}")))?;
    let signature = ecdsa::Signature::<p521::NistP521>::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-521 sig decode failed: {e}")))?;

    let hash = sha2::Sha256::digest(tbs);
    // SHA-256 produces 32 bytes, but ecdsa crate's bits2field requires >= 33 bytes
    // (half of P-521's 66-byte field size). Left-pad to 66 bytes (field size).
    let mut padded = vec![0u8; 66];
    padded[66 - 32..].copy_from_slice(&hash);
    vk.verify_prehash(&padded, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-521/SHA-256 invalid: {e}")))
}

/// Verify an ECDSA P-521 signature where the *signing algorithm* specified SHA-384.
pub fn verify_ecdsa_p521_sha384_signature(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest as _;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = ecdsa::VerifyingKey::<p521::NistP521>::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-521 key decode failed: {e}")))?;
    let signature = ecdsa::Signature::<p521::NistP521>::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-521 sig decode failed: {e}")))?;

    let hash = sha2::Sha384::digest(tbs);
    vk.verify_prehash(&hash, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-521/SHA-384 invalid: {e}")))
}

/// Verify an ECDSA P-256 (SHA-1) signature (legacy).
pub fn verify_ecdsa_p256_sha1_signature(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha1::Digest as _;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = p256::ecdsa::VerifyingKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-256 key decode failed: {e}")))?;
    let signature = p256::ecdsa::Signature::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-256 sig decode failed: {e}")))?;

    let hash = sha1::Sha1::digest(tbs);
    // SHA-1 produces 20 bytes; P-256 prehash verification accepts it
    vk.verify_prehash(&hash, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-256/SHA-1 invalid: {e}")))
}

/// Verify an ECDSA P-384 (SHA-1) signature (legacy).
pub fn verify_ecdsa_p384_sha1_signature(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha1::Digest as _;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = p384::ecdsa::VerifyingKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-384 key decode failed: {e}")))?;
    let signature = p384::ecdsa::Signature::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-384 sig decode failed: {e}")))?;

    let hash = sha1::Sha1::digest(tbs);
    vk.verify_prehash(&hash, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-384/SHA-1 invalid: {e}")))
}

/// Verify an Ed25519 signature.
pub fn verify_ed25519_signature(tbs: &[u8], sig: &[u8], spki_der: &[u8]) -> Result<(), TrustError> {
    use der::Decode;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let spki = spki::SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let key_bytes = spki.subject_public_key.raw_bytes();
    let vk = VerifyingKey::try_from(key_bytes)
        .map_err(|e| TrustError::SignatureVerification(format!("Ed25519 key decode: {e}")))?;
    let signature = Signature::from_slice(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("Ed25519 sig decode: {e}")))?;

    vk.verify(tbs, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("Ed25519 invalid: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use x509_cert::Certificate;

    fn load_test_cert(pem_str: &str) -> Certificate {
        let (_, der) = pem_rfc7468::decode_vec(pem_str.as_bytes()).unwrap();
        Certificate::from_der(&der).unwrap()
    }

    #[test]
    fn test_verify_certificate_signature_ca_self_signed() {
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        let ca = load_test_cert(ca_pem);
        // Self-signed: issuer == subject
        let result = verify_certificate_signature(&ca, &ca);
        assert!(
            result.is_ok(),
            "CA self-signature should verify: {result:?}"
        );
    }

    #[test]
    fn test_verify_certificate_signature_chain() {
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        let intermediate_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_cert.pem"
        ));
        let signer_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let ca = load_test_cert(ca_pem);
        let intermediate = load_test_cert(intermediate_pem);
        let signer = load_test_cert(signer_pem);

        // Signer is issued by intermediate
        let result = verify_certificate_signature(&signer, &intermediate);
        assert!(
            result.is_ok(),
            "signer cert should verify against intermediate: {result:?}"
        );

        // Intermediate is issued by CA
        let result = verify_certificate_signature(&intermediate, &ca);
        assert!(
            result.is_ok(),
            "intermediate cert should verify against CA: {result:?}"
        );
    }

    #[test]
    fn test_verify_certificate_signature_wrong_issuer() {
        let signer_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let signer = load_test_cert(signer_pem);

        // Self-verify should fail (signer is not self-signed)
        let result = verify_certificate_signature(&signer, &signer);
        assert!(result.is_err(), "wrong issuer should fail verification");
    }

    #[test]
    fn test_unsupported_algorithm_oid() {
        let fake_oid = const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.9");
        let result = verify_signature_by_oid(b"tbs", b"sig", b"spki", &fake_oid);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("unsupported"),
            "error should mention unsupported: {err_msg}"
        );
    }

    #[test]
    fn test_rsassa_pss_oid_dispatches() {
        // Even with bad data, the RSA-PSS branch should be reached (not "unsupported")
        let pss_oid = OID_RSASSA_PSS;
        let result = verify_signature_by_oid(b"tbs", b"sig", b"bad_spki", &pss_oid);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        // Should fail at SPKI decode, not "unsupported algorithm"
        assert!(
            !err_msg.contains("unsupported"),
            "RSA-PSS should be dispatched, not unsupported: {err_msg}"
        );
    }

    /// Build an RSASSA-PSS signature `AlgorithmIdentifier` (OID + params) for a
    /// given hash and salt length.
    fn pss_algid<D>(salt_len: u8) -> spki::AlgorithmIdentifierOwned
    where
        D: const_oid::AssociatedOid,
    {
        use der::Encode;
        use rsa::pkcs1::RsaPssParams;
        let params = RsaPssParams::new::<D>(salt_len);
        let params_der = params.to_der().unwrap();
        spki::AlgorithmIdentifierOwned {
            oid: OID_RSASSA_PSS,
            parameters: Some(der::Any::from_der(&params_der).unwrap()),
        }
    }

    #[test]
    fn test_pss_algid_uses_declared_salt_length() {
        // verify_signature_by_algid must honour the saltLength carried in
        // RSASSA-PSS-params (cert/CRL/OCSP paths), not assume the default.
        use rsa::pkcs8::EncodePublicKey;
        use rsa::pss::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        use sha2::Sha256;

        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let spki_der = rsa::RsaPublicKey::from(&key)
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        let msg = b"tbs bytes to be signed with PSS";
        let signing = SigningKey::<Sha256>::new_with_salt_len(key, 48);
        let sig = signing
            .sign_with_rng(&mut rand::thread_rng(), msg)
            .to_vec();

        // Correct salt length declared -> verifies.
        verify_signature_by_algid(msg, &sig, &spki_der, &pss_algid::<Sha256>(48))
            .expect("PSS with declared salt 48 must verify");

        // Wrong (default) salt length declared -> fails.
        assert!(
            verify_signature_by_algid(msg, &sig, &spki_der, &pss_algid::<Sha256>(32)).is_err(),
            "PSS with mismatched declared salt length must fail"
        );
    }

    #[test]
    fn test_pss_strict_requires_parameters() {
        // A bare RSASSA-PSS algid (no params) is rejected as unsupported.
        let bare = spki::AlgorithmIdentifierOwned {
            oid: OID_RSASSA_PSS,
            parameters: None,
        };
        let err = verify_signature_by_algid(b"tbs", b"sig", b"spki", &bare).unwrap_err();
        assert!(
            matches!(err, TrustError::UnsupportedAlgorithm(_)),
            "PSS without parameters must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_ed25519_oid_dispatches() {
        let ed_oid = OID_ED25519;
        let result = verify_signature_by_oid(b"tbs", b"sig", b"bad_spki", &ed_oid);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            !err_msg.contains("unsupported"),
            "Ed25519 should be dispatched, not unsupported: {err_msg}"
        );
    }
}
