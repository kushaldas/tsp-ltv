//! Long-term validation (LTV) support.
//!
//! Provides OCSP, CRL, and certificate chain infrastructure for
//! long-term signature validation across all AdES formats.
//!
//! # Architecture
//!
//! - [`OcspClient`] — Fetches OCSP responses from responders
//! - [`CrlClient`] — Fetches and caches CRLs from distribution points
//! - [`ChainBuilder`] — Discovers intermediate certs via AIA extensions
//! - [`RevocationConfig`] — Configuration for concurrent OCSP + CRL checking
//!
//! # AdES Conformance Levels
//!
//! | Level | LTV Data |
//! |-------|----------|
//! | B-B   | None |
//! | B-T   | Timestamp only |
//! | B-LT  | Certs + OCSP + CRLs |
//! | B-LTA | Above + archive timestamp |

pub mod chain;
pub mod crl;
pub mod ocsp;
pub mod revocation;
pub mod status;
pub mod x509_ext;

// Re-exports
pub use chain::ChainBuilder;
pub use crl::CrlClient;
pub use ocsp::{
    OcspClient, AiaAccessMethod, extract_aia_urls,
    CertStatus, SingleResponse, ParsedBasicOcspResponse, ResponderId, OcspFreshness,
    build_ocsp_request_with_nonce, has_ocsp_nocheck_extension,
    parse_ocsp_response, check_revocation as ocsp_check_revocation,
};
pub use revocation::{RevocationConfig, check_certificate_revocation};
#[cfg(feature = "blocking")]
pub use revocation::check_certificate_revocation_blocking;
pub use status::{ValidationStatus, RevocationSource, RevocationReason, resolve_priority};
pub use x509_ext::{
    KeyUsageBits, CertRole,
    check_basic_constraints, check_key_usage, check_extended_key_usage,
    has_extension, validate_extensions_for_role,
};
