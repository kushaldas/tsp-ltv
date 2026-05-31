//! Shared signature verification functions.
//!
//! Extracted from `trust/store.rs` so that CRL, OCSP, and chain
//! verification can all reuse the same cryptographic primitives.
//!
//! Supports:
//! - RSA PKCS#1 v1.5 with MD5 (legacy), SHA-1 (legacy), SHA-224 (legacy), SHA-256, SHA-384, SHA-512
//! - RSA-PSS (RSASSA-PSS) with SHA-256, SHA-384, SHA-512
//! - ECDSA P-256/P-384 with SHA-1 (legacy)
//! - ECDSA P-256 with SHA-256
//! - ECDSA P-384 with SHA-384
//! - ECDSA P-521 with SHA-512
//! - Ed25519
//!
//! ## Weak-algorithm policy (H-1)
//!
//! Signatures built on a broken/deprecated digest — MD5, SHA-1, or SHA-224 —
//! are **rejected by default**: the strict [`SignaturePolicy`] (the default for
//! every public entry point) refuses them before any cryptographic work, so the
//! whole crate is fail-closed against weak hashes. Such a digest must never
//! underpin a *fresh* trust decision.
//!
//! Callers that must validate genuinely historical material (e.g. a legacy
//! XML-DSig interop certificate signed with SHA-1/MD5) can opt in explicitly.
//! The opt-in is reachable from the public API, not just these low-level
//! primitives:
//!
//! - [`crate::trust::TrustStore::allow_legacy_signatures`] — certificate-chain
//!   verification (including the TSA certificate chain reached by
//!   [`crate::tsp::verify_timestamp_token`]).
//! - [`crate::ltv::RevocationConfig::allow_legacy_signatures`] — OCSP response
//!   and CRL signatures.
//! - The `*_with_policy` free functions here — for direct callers.
//!
//! The RFC 3161 token's own CMS `SignerInfo` signature is always verified
//! strictly: a timestamp token must not itself be freshly signed with a weak
//! digest (and a SHA-1 `digestAlgorithm` is not representable in
//! [`DigestAlgorithm`] anyway). Legacy TSA *certificate chains* are still
//! accepted via the trust store's policy above.

use crate::crypto::algorithm::{
    DigestAlgorithm, OID_ECDSA_WITH_SHA1, OID_ED25519, OID_MD5_WITH_RSA, OID_RSASSA_PSS,
    OID_SHA1_WITH_RSA, OID_SHA224_WITH_RSA,
};
use crate::error::TrustError;

/// id-mgf1 (1.2.840.113549.1.1.8) — the mask generation function for PSS.
const OID_MGF1: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");

/// id-ecPublicKey (1.2.840.10045.2.1) — the SPKI algorithm OID for EC keys.
const OID_EC_PUBLIC_KEY: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// secp256r1 / P-256 named-curve OID (1.2.840.10045.3.1.7).
const OID_CURVE_P256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// secp384r1 / P-384 named-curve OID (1.3.132.0.34).
const OID_CURVE_P384: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// secp521r1 / P-521 named-curve OID (1.3.132.0.35).
const OID_CURVE_P521: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// The NIST prime curve a verifying key is defined over, read from its SPKI
/// named-curve parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EcCurve {
    P256,
    P384,
    P521,
}

/// The hash a declared ECDSA signature-algorithm OID selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EcdsaHash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// Determine the NIST curve a public key is defined over from its already-parsed
/// SPKI `AlgorithmIdentifier`. Requires `id-ecPublicKey` with a recognized
/// named-curve OID parameter; anything else is rejected.
///
/// Takes the parsed [`spki::SubjectPublicKeyInfoRef`] (rather than raw DER) so
/// the dispatcher can decode the SPKI exactly once and reuse it for both curve
/// detection and key construction, instead of decoding it twice per signature.
fn ec_named_curve(spki: &spki::SubjectPublicKeyInfoRef<'_>) -> Result<EcCurve, TrustError> {
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(TrustError::SignatureVerification(format!(
            "ECDSA signature but SPKI algorithm is not id-ecPublicKey (got {})",
            spki.algorithm.oid
        )));
    }
    let params = spki.algorithm.parameters.ok_or_else(|| {
        TrustError::SignatureVerification("EC SPKI is missing its namedCurve parameter".into())
    })?;
    let curve_oid: const_oid::ObjectIdentifier = params.decode_as().map_err(|e| {
        TrustError::SignatureVerification(format!("EC namedCurve parameter is not an OID: {e}"))
    })?;

    if curve_oid == OID_CURVE_P256 {
        Ok(EcCurve::P256)
    } else if curve_oid == OID_CURVE_P384 {
        Ok(EcCurve::P384)
    } else if curve_oid == OID_CURVE_P521 {
        Ok(EcCurve::P521)
    } else {
        Err(TrustError::SignatureVerification(format!(
            "unsupported EC named curve OID: {curve_oid}"
        )))
    }
}

/// Verify an ECDSA signature, binding the verifying key's curve (read from the
/// SPKI) to the hash the signature-algorithm OID declared (finding L-8).
///
/// Previously the dispatcher tried each curve in turn via `or_else`, so e.g. a
/// P-521 key could satisfy an `ecdsa-with-SHA256` OID — a curve/hash strength
/// mismatch. Here the curve is taken from the key and only the conformant
/// (curve, hash) pairings are accepted; the unusual-but-real P-521-with-SHA-256
/// and P-521-with-SHA-384 combinations seen on some self-signed certificates are
/// kept, but cross-curve guesses are rejected.
fn verify_ecdsa_bound(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
    hash: EcdsaHash,
) -> Result<(), TrustError> {
    use der::Decode;
    use spki::SubjectPublicKeyInfoRef;

    // Decode the SPKI once and reuse it for both curve detection and key
    // construction; the per-curve helpers below take the parsed ref so a
    // successful verification performs a single SPKI decode, not two.
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let curve = ec_named_curve(&spki)?;
    match (curve, hash) {
        (EcCurve::P256, EcdsaHash::Sha256) => verify_ecdsa_p256_spki(spki, tbs, sig),
        (EcCurve::P384, EcdsaHash::Sha384) => verify_ecdsa_p384_spki(spki, tbs, sig),
        (EcCurve::P521, EcdsaHash::Sha512) => verify_ecdsa_p521_spki(spki, tbs, sig),
        (EcCurve::P521, EcdsaHash::Sha256) => verify_ecdsa_p521_sha256_spki(spki, tbs, sig),
        (EcCurve::P521, EcdsaHash::Sha384) => verify_ecdsa_p521_sha384_spki(spki, tbs, sig),
        (EcCurve::P256, EcdsaHash::Sha1) => verify_ecdsa_p256_sha1_spki(spki, tbs, sig),
        (EcCurve::P384, EcdsaHash::Sha1) => verify_ecdsa_p384_sha1_spki(spki, tbs, sig),
        (curve, hash) => Err(TrustError::SignatureVerification(format!(
            "ECDSA curve {curve:?} is not a supported pairing with the declared {hash:?} hash"
        ))),
    }
}

/// Policy controlling whether signatures over weak/deprecated digests are
/// accepted (finding H-1).
///
/// The default ([`SignaturePolicy::strict`]) refuses signatures built on MD5,
/// SHA-1, or SHA-224: MD5 chosen-prefix collisions are trivial, SHA-1 has been
/// broken since SHAttered (2017), and SHA-224 falls below the modern 128-bit
/// security floor. Strong SHA-2 / SHA-3 based RSA, RSASSA-PSS, ECDSA (incl.
/// P-521) and Ed25519 signatures are always accepted.
///
/// [`SignaturePolicy::allow_legacy`] re-enables the weak algorithms. Use it
/// only for explicit backward-compatibility scenarios (validating archival or
/// interop material whose risk you have accepted); never for fresh trust
/// decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignaturePolicy {
    allow_legacy: bool,
}

impl SignaturePolicy {
    /// Fail-closed policy: signatures over MD5 / SHA-1 / SHA-224 are rejected.
    pub const fn strict() -> Self {
        Self {
            allow_legacy: false,
        }
    }

    /// Permissive policy that additionally accepts MD5 / SHA-1 / SHA-224
    /// signatures. Use only for explicit backward-compatibility scenarios.
    pub const fn allow_legacy() -> Self {
        Self { allow_legacy: true }
    }

    /// Whether legacy weak-digest signatures are permitted under this policy.
    pub const fn legacy_allowed(&self) -> bool {
        self.allow_legacy
    }
}

impl Default for SignaturePolicy {
    /// The default policy is [`SignaturePolicy::strict`] (fail-closed).
    fn default() -> Self {
        Self::strict()
    }
}

/// True if `oid` names a signature algorithm built on a broken or deprecated
/// message digest (MD5, SHA-1, or SHA-224) that the strict policy refuses.
///
/// Unknown OIDs return `false` so they fall through to the regular
/// `UnsupportedAlgorithm` handling rather than being misreported as "weak".
pub fn is_weak_signature_oid(oid: &const_oid::ObjectIdentifier) -> bool {
    *oid == OID_MD5_WITH_RSA
        || *oid == OID_SHA1_WITH_RSA
        || *oid == OID_SHA224_WITH_RSA
        || *oid == OID_ECDSA_WITH_SHA1
}

/// Verify a raw signature over `tbs_bytes` using the signer's SPKI (DER) and the
/// given signature algorithm OID, under the strict (default) [`SignaturePolicy`].
///
/// Equivalent to [`verify_signature_by_oid_with_policy`] with
/// [`SignaturePolicy::strict`]; weak-digest signatures are rejected.
///
/// # Supported algorithms
///
/// | OID | Algorithm | Strict policy |
/// |-----|-----------|---------------|
/// | `1.2.840.113549.1.1.4`  | MD5 with RSA (legacy) | rejected |
/// | `1.2.840.113549.1.1.5`  | SHA-1 with RSA (legacy) | rejected |
/// | `1.2.840.113549.1.1.14` | SHA-224 with RSA (legacy) | rejected |
/// | `1.2.840.10045.4.1`     | ECDSA with SHA-1 (legacy) | rejected |
/// | `1.2.840.113549.1.1.11` | SHA-256 with RSA | accepted |
/// | `1.2.840.113549.1.1.12` | SHA-384 with RSA | accepted |
/// | `1.2.840.113549.1.1.13` | SHA-512 with RSA | accepted |
/// | `1.2.840.113549.1.1.10` | RSASSA-PSS (tries SHA-256/384/512) | accepted |
/// | `1.2.840.10045.4.3.2`   | ECDSA with SHA-256 | accepted |
/// | `1.2.840.10045.4.3.3`   | ECDSA with SHA-384 | accepted |
/// | `1.2.840.10045.4.3.4`   | ECDSA with SHA-512 | accepted |
/// | `1.3.101.112`           | Ed25519 | accepted |
pub fn verify_signature_by_oid(
    tbs_bytes: &[u8],
    signature_bytes: &[u8],
    spki_der: &[u8],
    sig_alg_oid: &const_oid::ObjectIdentifier,
) -> Result<(), TrustError> {
    verify_signature_by_oid_with_policy(
        tbs_bytes,
        signature_bytes,
        spki_der,
        sig_alg_oid,
        &SignaturePolicy::default(),
    )
}

/// Like [`verify_signature_by_oid`] but with an explicit [`SignaturePolicy`].
///
/// Under the strict policy, signatures built on MD5 / SHA-1 / SHA-224 are
/// rejected **before any cryptographic work** with [`TrustError::WeakAlgorithm`].
/// This is the single chokepoint every in-tree path flows through
/// (certificate-chain, CRL, OCSP, and CMS/RFC 3161 token verification all reach
/// it directly or via [`verify_signature_by_algid`]).
pub fn verify_signature_by_oid_with_policy(
    tbs_bytes: &[u8],
    signature_bytes: &[u8],
    spki_der: &[u8],
    sig_alg_oid: &const_oid::ObjectIdentifier,
    policy: &SignaturePolicy,
) -> Result<(), TrustError> {
    use const_oid::db;

    // Algorithm policy (H-1): refuse signatures over broken/deprecated digests
    // before touching any key material, unless the caller has explicitly opted
    // into legacy verification. Unknown OIDs are not "weak" — they fall through
    // to the UnsupportedAlgorithm arm below.
    if !policy.allow_legacy && is_weak_signature_oid(sig_alg_oid) {
        return Err(TrustError::WeakAlgorithm(format!(
            "signature algorithm OID {sig_alg_oid} relies on a weak digest \
             (MD5/SHA-1/SHA-224); pass SignaturePolicy::allow_legacy() to accept it"
        )));
    }

    // --- Legacy RSA algorithms (only reachable under allow_legacy) ---
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
    // --- Legacy ECDSA (only reachable under allow_legacy) ---
    else if *sig_alg_oid == OID_ECDSA_WITH_SHA1 {
        verify_ecdsa_bound(tbs_bytes, signature_bytes, spki_der, EcdsaHash::Sha1)
    }
    // --- Modern ECDSA — the curve is taken from the key (L-8) ---
    else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_256 {
        verify_ecdsa_bound(tbs_bytes, signature_bytes, spki_der, EcdsaHash::Sha256)
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_384 {
        verify_ecdsa_bound(tbs_bytes, signature_bytes, spki_der, EcdsaHash::Sha384)
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_512 {
        verify_ecdsa_bound(tbs_bytes, signature_bytes, spki_der, EcdsaHash::Sha512)
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
    verify_signature_by_algid_with_policy(
        tbs_bytes,
        signature_bytes,
        spki_der,
        sig_alg,
        &SignaturePolicy::default(),
    )
}

/// Like [`verify_signature_by_algid`] but with an explicit [`SignaturePolicy`].
///
/// RSASSA-PSS is always strong here — the strict PSS decoder only accepts
/// SHA-256/384/512 — so the weak-digest gate is enforced on the delegated
/// [`verify_signature_by_oid_with_policy`] path for every other algorithm.
pub fn verify_signature_by_algid_with_policy(
    tbs_bytes: &[u8],
    signature_bytes: &[u8],
    spki_der: &[u8],
    sig_alg: &spki::AlgorithmIdentifierOwned,
    policy: &SignaturePolicy,
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
        verify_signature_by_oid_with_policy(
            tbs_bytes,
            signature_bytes,
            spki_der,
            &sig_alg.oid,
            policy,
        )
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
    verify_certificate_signature_with_policy(cert, issuer, &SignaturePolicy::default())
}

/// Like [`verify_certificate_signature`] but with an explicit
/// [`SignaturePolicy`]. The default rejects certificates signed with
/// MD5/SHA-1/SHA-224; pass [`SignaturePolicy::allow_legacy`] to accept them
/// (e.g. for historical interop fixtures).
pub fn verify_certificate_signature_with_policy(
    cert: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
    policy: &SignaturePolicy,
) -> Result<(), TrustError> {
    use der::Encode;

    // RFC 5280 §4.1.1.2: the outer `signatureAlgorithm` field MUST contain the
    // same algorithm identifier as the `signature` field inside the (signed)
    // `tbsCertificate`. Only the inner one is covered by the signature; a
    // mismatch means the unauthenticated outer field was altered (e.g. an
    // algorithm-substitution attempt), so reject before any crypto (L-5).
    if cert.signature_algorithm != cert.tbs_certificate.signature {
        // The equality above covers the full AlgorithmIdentifier (OID *and*
        // parameters), so the diagnostic must surface both — printing only the
        // OIDs would misleadingly show the same value twice when the mismatch is
        // purely in the parameters (e.g. differing RSASSA-PSS parameters).
        return Err(TrustError::SignatureVerification(format!(
            "certificate outer signatureAlgorithm (oid={}, params={:?}) does not match \
             the signed tbsCertificate.signature (oid={}, params={:?})",
            cert.signature_algorithm.oid,
            cert.signature_algorithm.parameters,
            cert.tbs_certificate.signature.oid,
            cert.tbs_certificate.signature.parameters
        )));
    }

    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;

    let tbs_bytes = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| TrustError::SignatureVerification(format!("TBS encoding failed: {e}")))?;
    let signature_bytes = cert.signature.raw_bytes();

    let spki_der = issuer_spki
        .to_der()
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI encoding failed: {e}")))?;

    verify_signature_by_algid_with_policy(
        &tbs_bytes,
        signature_bytes,
        &spki_der,
        &cert.signature_algorithm,
        policy,
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
    verify_rsa_pss_signature_with_salt::<D>(
        tbs,
        sig,
        spki_der,
        <D as digest::Digest>::output_size(),
    )
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

/// Decode an SPKI from raw DER for the public single-shot ECDSA verifiers.
fn decode_spki(spki_der: &[u8]) -> Result<spki::SubjectPublicKeyInfoRef<'_>, TrustError> {
    use der::Decode;
    spki::SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))
}

/// Verify an ECDSA P-256 (SHA-256) signature.
pub fn verify_ecdsa_p256_signature(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    verify_ecdsa_p256_spki(decode_spki(spki_der)?, tbs, sig)
}

fn verify_ecdsa_p256_spki(
    spki: spki::SubjectPublicKeyInfoRef<'_>,
    tbs: &[u8],
    sig: &[u8],
) -> Result<(), TrustError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

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
    verify_ecdsa_p384_spki(decode_spki(spki_der)?, tbs, sig)
}

fn verify_ecdsa_p384_spki(
    spki: spki::SubjectPublicKeyInfoRef<'_>,
    tbs: &[u8],
    sig: &[u8],
) -> Result<(), TrustError> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

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
    verify_ecdsa_p521_spki(decode_spki(spki_der)?, tbs, sig)
}

fn verify_ecdsa_p521_spki(
    spki: spki::SubjectPublicKeyInfoRef<'_>,
    tbs: &[u8],
    sig: &[u8],
) -> Result<(), TrustError> {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest as _;

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
    verify_ecdsa_p521_sha256_spki(decode_spki(spki_der)?, tbs, sig)
}

fn verify_ecdsa_p521_sha256_spki(
    spki: spki::SubjectPublicKeyInfoRef<'_>,
    tbs: &[u8],
    sig: &[u8],
) -> Result<(), TrustError> {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest as _;

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
    verify_ecdsa_p521_sha384_spki(decode_spki(spki_der)?, tbs, sig)
}

fn verify_ecdsa_p521_sha384_spki(
    spki: spki::SubjectPublicKeyInfoRef<'_>,
    tbs: &[u8],
    sig: &[u8],
) -> Result<(), TrustError> {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest as _;

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
    verify_ecdsa_p256_sha1_spki(decode_spki(spki_der)?, tbs, sig)
}

fn verify_ecdsa_p256_sha1_spki(
    spki: spki::SubjectPublicKeyInfoRef<'_>,
    tbs: &[u8],
    sig: &[u8],
) -> Result<(), TrustError> {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha1::Digest as _;

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
    verify_ecdsa_p384_sha1_spki(decode_spki(spki_der)?, tbs, sig)
}

fn verify_ecdsa_p384_sha1_spki(
    spki: spki::SubjectPublicKeyInfoRef<'_>,
    tbs: &[u8],
    sig: &[u8],
) -> Result<(), TrustError> {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha1::Digest as _;

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
        let sig = signing.sign_with_rng(&mut rand::thread_rng(), msg).to_vec();

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
    fn test_weak_signature_oids_rejected_by_default() {
        // H-1: MD5/SHA-1/SHA-224 based signatures must be refused before any
        // crypto, under the strict default policy.
        for oid in [
            OID_MD5_WITH_RSA,
            OID_SHA1_WITH_RSA,
            OID_SHA224_WITH_RSA,
            OID_ECDSA_WITH_SHA1,
        ] {
            let err = verify_signature_by_oid(b"tbs", b"sig", b"spki", &oid).unwrap_err();
            assert!(
                matches!(err, TrustError::WeakAlgorithm(_)),
                "{oid} should be rejected as weak, got {err:?}"
            );
        }
    }

    #[test]
    fn test_weak_signature_oids_accepted_with_legacy_policy() {
        // With an explicit legacy opt-in the gate is lifted: verification then
        // proceeds and fails at SPKI decode, not at the policy gate.
        let legacy = SignaturePolicy::allow_legacy();
        for oid in [OID_MD5_WITH_RSA, OID_SHA1_WITH_RSA, OID_SHA224_WITH_RSA] {
            let err =
                verify_signature_by_oid_with_policy(b"tbs", b"sig", b"bad_spki", &oid, &legacy)
                    .unwrap_err();
            assert!(
                !matches!(err, TrustError::WeakAlgorithm(_)),
                "{oid} should pass the gate under allow_legacy, got {err:?}"
            );
        }
    }

    #[test]
    fn test_unknown_oid_is_unsupported_not_weak() {
        // An unrecognized OID must remain UnsupportedAlgorithm, never WeakAlgorithm.
        let fake = const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.9");
        let err = verify_signature_by_oid(b"tbs", b"sig", b"spki", &fake).unwrap_err();
        assert!(
            matches!(err, TrustError::UnsupportedAlgorithm(_)),
            "unknown OID should be unsupported, got {err:?}"
        );
    }

    #[test]
    fn test_signature_policy_default_is_strict() {
        assert_eq!(SignaturePolicy::default(), SignaturePolicy::strict());
        assert!(!SignaturePolicy::default().legacy_allowed());
        assert!(SignaturePolicy::allow_legacy().legacy_allowed());
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

    #[test]
    fn test_outer_inner_signature_algorithm_mismatch_rejected() {
        // L-5: a certificate whose outer signatureAlgorithm differs from the
        // signed tbsCertificate.signature must be rejected (RFC 5280 §4.1.1.2)
        // before any signature math.
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        let ca = load_test_cert(ca_pem);

        // Sanity: untampered self-signed CA verifies.
        verify_certificate_signature(&ca, &ca).expect("untampered CA must verify");

        // Tamper only the (unauthenticated) outer signatureAlgorithm.
        let mut tampered = ca.clone();
        tampered.signature_algorithm = spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION,
            parameters: None,
        };
        let err = verify_certificate_signature(&tampered, &ca).unwrap_err();
        assert!(
            matches!(err, TrustError::SignatureVerification(ref m) if m.contains("does not match")),
            "outer/inner signatureAlgorithm mismatch must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_ecdsa_curve_is_bound_to_declared_hash() {
        // L-8: ECDSA verification dispatches on the SPKI named curve. A P-256
        // key + ecdsa-with-SHA256 verifies; the same key under a SHA-512-declared
        // OID is rejected as an unsupported curve/hash pairing (no cross-curve
        // trial-and-error).
        use const_oid::db;
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use rsa::pkcs8::EncodePublicKey;

        let sk = SigningKey::random(&mut rand::thread_rng());
        let spki_der = sk
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        // ec_named_curve recognizes the P-256 SPKI.
        let spki = decode_spki(&spki_der).unwrap();
        assert_eq!(ec_named_curve(&spki).unwrap(), EcCurve::P256);

        let msg = b"message bound to a P-256 ECDSA signature";
        let sig: Signature = sk.sign(msg);
        let sig_der = sig.to_der().as_bytes().to_vec();

        // Correct pairing verifies.
        verify_signature_by_oid(msg, &sig_der, &spki_der, &db::rfc5912::ECDSA_WITH_SHA_256)
            .expect("P-256 + ecdsa-with-SHA256 must verify");

        // Mismatched declared hash for a P-256 key is rejected (not silently
        // retried against another curve).
        let err =
            verify_signature_by_oid(msg, &sig_der, &spki_der, &db::rfc5912::ECDSA_WITH_SHA_512)
                .unwrap_err();
        assert!(
            matches!(err, TrustError::SignatureVerification(_)),
            "P-256 key under a SHA-512 ECDSA OID must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_ec_named_curve_rejects_non_ec_key() {
        // An RSA SPKI under the ECDSA path must be rejected, not misdispatched.
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        let ca = load_test_cert(ca_pem);
        let spki_der = der::Encode::to_der(&ca.tbs_certificate.subject_public_key_info).unwrap();
        let spki = decode_spki(&spki_der).unwrap();
        let err = ec_named_curve(&spki).unwrap_err();
        assert!(
            matches!(err, TrustError::SignatureVerification(ref m) if m.contains("id-ecPublicKey")),
            "RSA SPKI must be rejected by ec_named_curve, got {err:?}"
        );
    }
}
