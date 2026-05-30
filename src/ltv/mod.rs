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
    build_ocsp_request_with_nonce, check_revocation as ocsp_check_revocation, extract_aia_urls,
    has_ocsp_nocheck_extension, parse_ocsp_response, AiaAccessMethod, CertStatus, OcspClient,
    OcspFreshness, ParsedBasicOcspResponse, ResponderId, SingleResponse,
};
#[cfg(feature = "blocking")]
pub use revocation::check_certificate_revocation_blocking;
pub use revocation::{check_certificate_revocation, RevocationConfig};
pub use status::{resolve_priority, RevocationReason, RevocationSource, ValidationStatus};
pub use x509_ext::{
    check_basic_constraints, check_extended_key_usage, check_key_usage, has_extension,
    validate_extensions_for_role, CertRole, KeyUsageBits,
};
