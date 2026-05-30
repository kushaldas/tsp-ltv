//! Error types for the tsp-ltv crate.

use thiserror::Error;

/// Errors from RFC 3161 timestamping operations.
#[derive(Debug, Error)]
pub enum TspError {
    #[error("TSA HTTP request failed: {0}")]
    HttpError(String),

    #[error("TSA returned error status: {0}")]
    TsaError(String),

    #[error("invalid timestamp response: {0}")]
    InvalidResponse(String),

    #[error("timestamp token verification failed: {0}")]
    VerificationFailed(String),
}

/// Errors from long-term validation operations (OCSP, CRL, chain building).
#[cfg(feature = "ltv")]
#[derive(Debug, Error)]
pub enum LtvError {
    #[error("OCSP error: {0}")]
    Ocsp(String),

    /// The OCSP responder returned a non-successful `responseStatus`
    /// (malformedRequest, internalError, tryLater, sigRequired, unauthorized).
    ///
    /// This is a responder-side or transient condition — **not** proof that the
    /// response was malformed or forged — so it is non-determinative. Callers
    /// must treat it as `Unknown` (status could not be determined), never as a
    /// definitive `Invalid`.
    #[error("OCSP responder returned non-successful status: {0}")]
    OcspResponderStatus(String),

    #[error("CRL error: {0}")]
    Crl(String),

    #[error("certificate chain error: {0}")]
    Chain(String),

    #[error("DSS construction error: {0}")]
    Dss(String),

    #[error("revocation check error: {0}")]
    Revocation(String),

    #[error("X.509 extension validation error: {0}")]
    X509Extension(String),
}

/// Errors from trust store management.
#[derive(Debug, Error)]
pub enum TrustError {
    #[error("certificate parse error: {0}")]
    CertificateParse(String),

    #[error("path is not a directory: {0}")]
    NotADirectory(String),

    #[error("certificate chain is empty")]
    EmptyChain,

    #[error("chain broken at index {index}: expected issuer {expected_issuer}, found subject {found_subject}")]
    ChainBroken {
        index: usize,
        expected_issuer: String,
        found_subject: String,
    },

    #[error("certificate at index {index} is not yet valid (not_before: {not_before})")]
    NotYetValid {
        index: usize,
        not_before: der::DateTime,
    },

    #[error("certificate at index {index} is expired (not_after: {not_after})")]
    Expired {
        index: usize,
        not_after: der::DateTime,
    },

    #[error("untrusted root: no trust anchor found for issuer {issuer}")]
    UntrustedRoot { issuer: String },

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("weak/disabled signature algorithm rejected by policy: {0}")]
    WeakAlgorithm(String),

    #[error("trust store not configured for {0}")]
    StoreNotConfigured(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
