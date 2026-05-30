//! Digest and signature algorithm enumerations.
//!
//! Provides the core algorithm types used throughout underskrift for
//! signing, verification, and hashing operations.
//!
//! ## Supported digest algorithms
//!
//! | Algorithm | OID |
//! |-----------|-----|
//! | SHA-256 | `2.16.840.1.101.3.4.2.1` |
//! | SHA-384 | `2.16.840.1.101.3.4.2.2` |
//! | SHA-512 | `2.16.840.1.101.3.4.2.3` |
//! | SHA3-256 | `2.16.840.1.101.3.4.2.8` |
//! | SHA3-384 | `2.16.840.1.101.3.4.2.9` |
//! | SHA3-512 | `2.16.840.1.101.3.4.2.10` |
//!
//! ## Supported signature algorithms
//!
//! | Algorithm | OID |
//! |-----------|-----|
//! | RSA PKCS#1 v1.5 + SHA-256 | `1.2.840.113549.1.1.11` |
//! | RSA PKCS#1 v1.5 + SHA-384 | `1.2.840.113549.1.1.12` |
//! | RSA PKCS#1 v1.5 + SHA-512 | `1.2.840.113549.1.1.13` |
//! | RSA-PSS (parameterized) | `1.2.840.113549.1.1.10` |
//! | ECDSA P-256 + SHA-256 | `1.2.840.10045.4.3.2` |
//! | ECDSA P-384 + SHA-384 | `1.2.840.10045.4.3.3` |
//! | Ed25519 | `1.3.101.112` |

use const_oid::ObjectIdentifier;

// ── Digest Algorithm OID Constants ──────────────────────────────────────

/// OID for SHA3-256: `2.16.840.1.101.3.4.2.8`
pub const OID_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");

/// OID for SHA3-384: `2.16.840.1.101.3.4.2.9`
pub const OID_SHA3_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9");

/// OID for SHA3-512: `2.16.840.1.101.3.4.2.10`
pub const OID_SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10");

// ── Signature Algorithm OID Constants ───────────────────────────────────

/// OID for RSASSA-PSS: `1.2.840.113549.1.1.10`
pub const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// OID for Ed25519: `1.3.101.112`
pub const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// OID for ECDSA with SHA-512: `1.2.840.10045.4.3.4`
pub const OID_ECDSA_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

// ── Legacy / compatibility OIDs ─────────────────────────────────────────

/// OID for MD5 with RSA Encryption: `1.2.840.113549.1.1.4`
pub const OID_MD5_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.4");

/// OID for SHA-1 with RSA Encryption: `1.2.840.113549.1.1.5`
pub const OID_SHA1_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");

/// OID for SHA-224 with RSA Encryption: `1.2.840.113549.1.1.14`
pub const OID_SHA224_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.14");

/// OID for ECDSA with SHA-1: `1.2.840.10045.4.1`
pub const OID_ECDSA_WITH_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");

// ── DigestAlgorithm ─────────────────────────────────────────────────────

/// Supported digest (hash) algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl DigestAlgorithm {
    /// OID for this digest algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            DigestAlgorithm::Sha256 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            DigestAlgorithm::Sha384 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2"),
            DigestAlgorithm::Sha512 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3"),
            DigestAlgorithm::Sha3_256 => OID_SHA3_256,
            DigestAlgorithm::Sha3_384 => OID_SHA3_384,
            DigestAlgorithm::Sha3_512 => OID_SHA3_512,
        }
    }

    /// Try to construct a `DigestAlgorithm` from an OID.
    ///
    /// Returns `None` for unrecognized OIDs.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        // SHA-2 family
        if *oid == DigestAlgorithm::Sha256.oid() {
            Some(DigestAlgorithm::Sha256)
        } else if *oid == DigestAlgorithm::Sha384.oid() {
            Some(DigestAlgorithm::Sha384)
        } else if *oid == DigestAlgorithm::Sha512.oid() {
            Some(DigestAlgorithm::Sha512)
        }
        // SHA-3 family
        else if *oid == OID_SHA3_256 {
            Some(DigestAlgorithm::Sha3_256)
        } else if *oid == OID_SHA3_384 {
            Some(DigestAlgorithm::Sha3_384)
        } else if *oid == OID_SHA3_512 {
            Some(DigestAlgorithm::Sha3_512)
        } else {
            None
        }
    }

    /// Compute the digest of the given data.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        use digest::Digest;
        match self {
            DigestAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
            DigestAlgorithm::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
            DigestAlgorithm::Sha3_384 => sha3::Sha3_384::digest(data).to_vec(),
            DigestAlgorithm::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
        }
    }

    /// Create a streaming hasher for this algorithm.
    ///
    /// Use this when you need to hash data in multiple chunks (e.g., the two
    /// ByteRange segments for PDF signing).
    pub fn new_hasher(&self) -> DigestHasher {
        use digest::Digest;
        match self {
            DigestAlgorithm::Sha256 => DigestHasher::Sha256(sha2::Sha256::new()),
            DigestAlgorithm::Sha384 => DigestHasher::Sha384(sha2::Sha384::new()),
            DigestAlgorithm::Sha512 => DigestHasher::Sha512(sha2::Sha512::new()),
            DigestAlgorithm::Sha3_256 => DigestHasher::Sha3_256(sha3::Sha3_256::new()),
            DigestAlgorithm::Sha3_384 => DigestHasher::Sha3_384(sha3::Sha3_384::new()),
            DigestAlgorithm::Sha3_512 => DigestHasher::Sha3_512(sha3::Sha3_512::new()),
        }
    }

    /// Output size of the digest in bytes.
    pub fn output_size(&self) -> usize {
        match self {
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha3_256 => 32,
            DigestAlgorithm::Sha384 | DigestAlgorithm::Sha3_384 => 48,
            DigestAlgorithm::Sha512 | DigestAlgorithm::Sha3_512 => 64,
        }
    }

    /// Human-readable name of this algorithm.
    pub fn name(&self) -> &'static str {
        match self {
            DigestAlgorithm::Sha256 => "SHA-256",
            DigestAlgorithm::Sha384 => "SHA-384",
            DigestAlgorithm::Sha512 => "SHA-512",
            DigestAlgorithm::Sha3_256 => "SHA3-256",
            DigestAlgorithm::Sha3_384 => "SHA3-384",
            DigestAlgorithm::Sha3_512 => "SHA3-512",
        }
    }

    /// Whether this is a SHA-3 family algorithm.
    pub fn is_sha3(&self) -> bool {
        matches!(
            self,
            DigestAlgorithm::Sha3_256 | DigestAlgorithm::Sha3_384 | DigestAlgorithm::Sha3_512
        )
    }

    /// Return all known digest algorithms.
    pub fn all() -> &'static [DigestAlgorithm] {
        &[
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
            DigestAlgorithm::Sha3_256,
            DigestAlgorithm::Sha3_384,
            DigestAlgorithm::Sha3_512,
        ]
    }
}

impl Default for DigestAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

impl std::fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ── DigestHasher ────────────────────────────────────────────────────────

/// Streaming hasher that supports incremental updates.
pub enum DigestHasher {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha3_256(sha3::Sha3_256),
    Sha3_384(sha3::Sha3_384),
    Sha3_512(sha3::Sha3_512),
}

impl DigestHasher {
    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        use digest::Digest;
        match self {
            DigestHasher::Sha256(h) => h.update(data),
            DigestHasher::Sha384(h) => h.update(data),
            DigestHasher::Sha512(h) => h.update(data),
            DigestHasher::Sha3_256(h) => h.update(data),
            DigestHasher::Sha3_384(h) => h.update(data),
            DigestHasher::Sha3_512(h) => h.update(data),
        }
    }

    /// Finalize the hash and return the digest bytes.
    pub fn finalize(self) -> Vec<u8> {
        use digest::Digest;
        match self {
            DigestHasher::Sha256(h) => h.finalize().to_vec(),
            DigestHasher::Sha384(h) => h.finalize().to_vec(),
            DigestHasher::Sha512(h) => h.finalize().to_vec(),
            DigestHasher::Sha3_256(h) => h.finalize().to_vec(),
            DigestHasher::Sha3_384(h) => h.finalize().to_vec(),
            DigestHasher::Sha3_512(h) => h.finalize().to_vec(),
        }
    }
}

// ── SignatureAlgorithm ──────────────────────────────────────────────────

/// Supported signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// RSA with PKCS#1 v1.5 padding.
    ///
    /// The concrete OID depends on the digest algorithm:
    /// - SHA-256: `1.2.840.113549.1.1.11`
    /// - SHA-384: `1.2.840.113549.1.1.12`
    /// - SHA-512: `1.2.840.113549.1.1.13`
    RsaPkcs1v15,

    /// RSA with PSS padding (RSASSA-PSS).
    ///
    /// Uses a single OID (`1.2.840.113549.1.1.10`) with AlgorithmIdentifier
    /// parameters encoding the hash function, MGF, and salt length.
    RsaPss,

    /// ECDSA with P-256 curve (uses SHA-256).
    EcdsaP256,

    /// ECDSA with P-384 curve (uses SHA-384).
    EcdsaP384,

    /// EdDSA with Ed25519 curve.
    Ed25519,
}

impl SignatureAlgorithm {
    /// Human-readable name of this algorithm.
    pub fn name(&self) -> &'static str {
        match self {
            SignatureAlgorithm::RsaPkcs1v15 => "RSA-PKCS1-v1.5",
            SignatureAlgorithm::RsaPss => "RSA-PSS",
            SignatureAlgorithm::EcdsaP256 => "ECDSA-P256",
            SignatureAlgorithm::EcdsaP384 => "ECDSA-P384",
            SignatureAlgorithm::Ed25519 => "Ed25519",
        }
    }

    /// Return all known signature algorithms.
    pub fn all() -> &'static [SignatureAlgorithm] {
        &[
            SignatureAlgorithm::RsaPkcs1v15,
            SignatureAlgorithm::RsaPss,
            SignatureAlgorithm::EcdsaP256,
            SignatureAlgorithm::EcdsaP384,
            SignatureAlgorithm::Ed25519,
        ]
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ── Algorithm Registry ──────────────────────────────────────────────────

/// A registry of allowed algorithms for PDF signing operations.
///
/// By default, the registry allows all supported algorithms. Use the builder
/// methods to restrict or customize the allowed set.
///
/// Note: this registry is a *signing-profile* allowlist and is **not** the
/// mechanism that rejects weak signature hashes during verification. Weak
/// digests (MD5/SHA-1/SHA-224) are refused by the
/// [`crate::crypto::verify::SignaturePolicy`] gate in the verification path;
/// the `DigestAlgorithm`/`SignatureAlgorithm` enums here cannot even represent
/// those digests, so `allow_all()` already excludes them by construction.
///
/// # Example
///
/// ```
/// use tsp_ltv::crypto::algorithm::{AlgorithmRegistry, DigestAlgorithm, SignatureAlgorithm};
///
/// // Allow only SHA-256/384/512 with RSA and ECDSA (no SHA-3, no Ed25519)
/// let registry = AlgorithmRegistry::new()
///     .allow_digest(DigestAlgorithm::Sha256)
///     .allow_digest(DigestAlgorithm::Sha384)
///     .allow_digest(DigestAlgorithm::Sha512)
///     .allow_signature(SignatureAlgorithm::RsaPkcs1v15)
///     .allow_signature(SignatureAlgorithm::RsaPss)
///     .allow_signature(SignatureAlgorithm::EcdsaP256)
///     .allow_signature(SignatureAlgorithm::EcdsaP384);
///
/// assert!(registry.is_digest_allowed(DigestAlgorithm::Sha256));
/// assert!(!registry.is_digest_allowed(DigestAlgorithm::Sha3_256));
/// ```
#[derive(Debug, Clone)]
pub struct AlgorithmRegistry {
    /// Allowed digest algorithms. If empty after explicit configuration,
    /// nothing is allowed.
    allowed_digests: Vec<DigestAlgorithm>,
    /// Allowed signature algorithms. If empty after explicit configuration,
    /// nothing is allowed.
    allowed_signatures: Vec<SignatureAlgorithm>,
    /// Whether the registry was explicitly configured (vs default "allow all").
    configured: bool,
}

impl AlgorithmRegistry {
    /// Create a new empty registry (nothing allowed yet).
    ///
    /// Use `allow_digest()` and `allow_signature()` to add algorithms,
    /// or `default()` to start with everything allowed.
    pub fn new() -> Self {
        Self {
            allowed_digests: Vec::new(),
            allowed_signatures: Vec::new(),
            configured: true,
        }
    }

    /// Create a registry that allows all supported algorithms.
    pub fn allow_all() -> Self {
        Self {
            allowed_digests: DigestAlgorithm::all().to_vec(),
            allowed_signatures: SignatureAlgorithm::all().to_vec(),
            configured: true,
        }
    }

    /// Create a standard registry suitable for production PDF signing.
    ///
    /// Allows SHA-256/384/512 (SHA-2 family) with RSA PKCS#1v1.5, RSA-PSS,
    /// ECDSA P-256, and ECDSA P-384. Does not include SHA-3 or Ed25519 since
    /// these are not yet widely supported by PDF readers.
    pub fn standard() -> Self {
        Self {
            allowed_digests: vec![
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
            ],
            allowed_signatures: vec![
                SignatureAlgorithm::RsaPkcs1v15,
                SignatureAlgorithm::RsaPss,
                SignatureAlgorithm::EcdsaP256,
                SignatureAlgorithm::EcdsaP384,
            ],
            configured: true,
        }
    }

    /// Add a digest algorithm to the allowed set.
    pub fn allow_digest(mut self, alg: DigestAlgorithm) -> Self {
        if !self.allowed_digests.contains(&alg) {
            self.allowed_digests.push(alg);
        }
        self
    }

    /// Add a signature algorithm to the allowed set.
    pub fn allow_signature(mut self, alg: SignatureAlgorithm) -> Self {
        if !self.allowed_signatures.contains(&alg) {
            self.allowed_signatures.push(alg);
        }
        self
    }

    /// Check whether a digest algorithm is allowed.
    pub fn is_digest_allowed(&self, alg: DigestAlgorithm) -> bool {
        if !self.configured {
            return true;
        }
        self.allowed_digests.contains(&alg)
    }

    /// Check whether a signature algorithm is allowed.
    pub fn is_signature_allowed(&self, alg: SignatureAlgorithm) -> bool {
        if !self.configured {
            return true;
        }
        self.allowed_signatures.contains(&alg)
    }

    /// Validate that a (signature algorithm, digest algorithm) combination is allowed.
    ///
    /// Returns `Ok(())` if both are allowed, or an error message describing what's rejected.
    pub fn validate(
        &self,
        sig_alg: SignatureAlgorithm,
        digest_alg: DigestAlgorithm,
    ) -> Result<(), String> {
        if !self.is_signature_allowed(sig_alg) {
            return Err(format!(
                "signature algorithm {} is not allowed by the algorithm registry",
                sig_alg
            ));
        }
        if !self.is_digest_allowed(digest_alg) {
            return Err(format!(
                "digest algorithm {} is not allowed by the algorithm registry",
                digest_alg
            ));
        }
        Ok(())
    }

    /// Return the list of allowed digest algorithms.
    pub fn allowed_digests(&self) -> &[DigestAlgorithm] {
        &self.allowed_digests
    }

    /// Return the list of allowed signature algorithms.
    pub fn allowed_signatures(&self) -> &[SignatureAlgorithm] {
        &self.allowed_signatures
    }
}

impl Default for AlgorithmRegistry {
    /// Default registry allows all supported algorithms.
    ///
    /// This is *not* a weak-hash vector: the `DigestAlgorithm` /
    /// `SignatureAlgorithm` enums cannot represent MD5/SHA-1/SHA-224, so
    /// `allow_all()` already excludes them. Weak hashes are refused separately
    /// by [`crate::crypto::verify::SignaturePolicy`] in the verification path.
    fn default() -> Self {
        Self::allow_all()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_algorithm_oid_roundtrip() {
        for &alg in DigestAlgorithm::all() {
            let oid = alg.oid();
            let roundtrip = DigestAlgorithm::from_oid(&oid);
            assert_eq!(roundtrip, Some(alg), "roundtrip failed for {alg:?}");
        }
    }

    #[test]
    fn test_digest_algorithm_from_unknown_oid() {
        let unknown = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.9");
        assert_eq!(DigestAlgorithm::from_oid(&unknown), None);
    }

    #[test]
    fn test_sha3_digests() {
        let data = b"hello world";

        let sha3_256 = DigestAlgorithm::Sha3_256.digest(data);
        assert_eq!(sha3_256.len(), 32);

        let sha3_384 = DigestAlgorithm::Sha3_384.digest(data);
        assert_eq!(sha3_384.len(), 48);

        let sha3_512 = DigestAlgorithm::Sha3_512.digest(data);
        assert_eq!(sha3_512.len(), 64);

        // SHA-2 and SHA-3 should produce different results
        let sha2_256 = DigestAlgorithm::Sha256.digest(data);
        assert_ne!(sha2_256, sha3_256, "SHA-256 and SHA3-256 should differ");
    }

    #[test]
    fn test_sha3_streaming_hasher() {
        let data = b"hello world";

        // One-shot digest should match streaming
        for &alg in DigestAlgorithm::all() {
            let one_shot = alg.digest(data);
            let mut hasher = alg.new_hasher();
            hasher.update(b"hello ");
            hasher.update(b"world");
            let streaming = hasher.finalize();
            assert_eq!(one_shot, streaming, "mismatch for {alg:?}");
        }
    }

    #[test]
    fn test_output_size() {
        assert_eq!(DigestAlgorithm::Sha256.output_size(), 32);
        assert_eq!(DigestAlgorithm::Sha384.output_size(), 48);
        assert_eq!(DigestAlgorithm::Sha512.output_size(), 64);
        assert_eq!(DigestAlgorithm::Sha3_256.output_size(), 32);
        assert_eq!(DigestAlgorithm::Sha3_384.output_size(), 48);
        assert_eq!(DigestAlgorithm::Sha3_512.output_size(), 64);
    }

    #[test]
    fn test_is_sha3() {
        assert!(!DigestAlgorithm::Sha256.is_sha3());
        assert!(!DigestAlgorithm::Sha384.is_sha3());
        assert!(!DigestAlgorithm::Sha512.is_sha3());
        assert!(DigestAlgorithm::Sha3_256.is_sha3());
        assert!(DigestAlgorithm::Sha3_384.is_sha3());
        assert!(DigestAlgorithm::Sha3_512.is_sha3());
    }

    #[test]
    fn test_display() {
        assert_eq!(DigestAlgorithm::Sha256.to_string(), "SHA-256");
        assert_eq!(DigestAlgorithm::Sha3_256.to_string(), "SHA3-256");
        assert_eq!(SignatureAlgorithm::RsaPss.to_string(), "RSA-PSS");
        assert_eq!(SignatureAlgorithm::Ed25519.to_string(), "Ed25519");
    }

    // --- AlgorithmRegistry tests ---

    #[test]
    fn test_default_registry_allows_all() {
        let reg = AlgorithmRegistry::default();
        for &alg in DigestAlgorithm::all() {
            assert!(reg.is_digest_allowed(alg), "{alg:?} should be allowed");
        }
        for &alg in SignatureAlgorithm::all() {
            assert!(reg.is_signature_allowed(alg), "{alg:?} should be allowed");
        }
    }

    #[test]
    fn test_empty_registry_allows_nothing() {
        let reg = AlgorithmRegistry::new();
        assert!(!reg.is_digest_allowed(DigestAlgorithm::Sha256));
        assert!(!reg.is_signature_allowed(SignatureAlgorithm::RsaPkcs1v15));
    }

    #[test]
    fn test_standard_registry() {
        let reg = AlgorithmRegistry::standard();
        // SHA-2 family allowed
        assert!(reg.is_digest_allowed(DigestAlgorithm::Sha256));
        assert!(reg.is_digest_allowed(DigestAlgorithm::Sha384));
        assert!(reg.is_digest_allowed(DigestAlgorithm::Sha512));
        // SHA-3 family NOT allowed
        assert!(!reg.is_digest_allowed(DigestAlgorithm::Sha3_256));
        assert!(!reg.is_digest_allowed(DigestAlgorithm::Sha3_384));
        assert!(!reg.is_digest_allowed(DigestAlgorithm::Sha3_512));
        // Standard signature algorithms
        assert!(reg.is_signature_allowed(SignatureAlgorithm::RsaPkcs1v15));
        assert!(reg.is_signature_allowed(SignatureAlgorithm::RsaPss));
        assert!(reg.is_signature_allowed(SignatureAlgorithm::EcdsaP256));
        assert!(reg.is_signature_allowed(SignatureAlgorithm::EcdsaP384));
        // Ed25519 not in standard
        assert!(!reg.is_signature_allowed(SignatureAlgorithm::Ed25519));
    }

    #[test]
    fn test_custom_registry() {
        let reg = AlgorithmRegistry::new()
            .allow_digest(DigestAlgorithm::Sha3_256)
            .allow_signature(SignatureAlgorithm::RsaPss);

        assert!(reg.is_digest_allowed(DigestAlgorithm::Sha3_256));
        assert!(!reg.is_digest_allowed(DigestAlgorithm::Sha256));
        assert!(reg.is_signature_allowed(SignatureAlgorithm::RsaPss));
        assert!(!reg.is_signature_allowed(SignatureAlgorithm::RsaPkcs1v15));
    }

    #[test]
    fn test_validate_combination() {
        let reg = AlgorithmRegistry::standard();

        assert!(reg
            .validate(SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha256)
            .is_ok());
        assert!(reg
            .validate(SignatureAlgorithm::RsaPss, DigestAlgorithm::Sha384)
            .is_ok());

        // Ed25519 not allowed
        let err = reg
            .validate(SignatureAlgorithm::Ed25519, DigestAlgorithm::Sha256)
            .unwrap_err();
        assert!(err.contains("Ed25519"));
        assert!(err.contains("not allowed"));

        // SHA3-256 not allowed in standard
        let err = reg
            .validate(SignatureAlgorithm::RsaPss, DigestAlgorithm::Sha3_256)
            .unwrap_err();
        assert!(err.contains("SHA3-256"));
        assert!(err.contains("not allowed"));
    }

    #[test]
    fn test_no_duplicate_allow() {
        let reg = AlgorithmRegistry::new()
            .allow_digest(DigestAlgorithm::Sha256)
            .allow_digest(DigestAlgorithm::Sha256)
            .allow_digest(DigestAlgorithm::Sha256);

        assert_eq!(reg.allowed_digests().len(), 1);
    }

    #[test]
    fn test_sha3_oids_correct() {
        // Per NIST / RFC 8702
        assert_eq!(OID_SHA3_256.to_string(), "2.16.840.1.101.3.4.2.8");
        assert_eq!(OID_SHA3_384.to_string(), "2.16.840.1.101.3.4.2.9");
        assert_eq!(OID_SHA3_512.to_string(), "2.16.840.1.101.3.4.2.10");
    }

    #[test]
    fn test_rsassa_pss_oid() {
        assert_eq!(OID_RSASSA_PSS.to_string(), "1.2.840.113549.1.1.10");
    }

    #[test]
    fn test_ed25519_oid() {
        assert_eq!(OID_ED25519.to_string(), "1.3.101.112");
    }
}
