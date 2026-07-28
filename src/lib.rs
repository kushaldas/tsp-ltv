//! # tsp-ltv
//!
//! Shared timestamping (RFC 3161) and long-term validation infrastructure
//! for Advanced Electronic Signature (AdES) formats.
//!
//! This crate provides the core types and network clients for:
//! - **TSP**: RFC 3161 timestamp requests, responses, and validation
//! - **OCSP**: Online Certificate Status Protocol client (RFC 6960)
//! - **CRL**: Certificate Revocation List fetching and caching (RFC 5280)
//! - **Trust**: Certificate trust stores, chain building, and validation
//!
//! It is format-agnostic — it does not know about PDF, XML, or JSON.
//! Each AdES crate (underskrift for PAdES/CAdES, bergshamra for XAdES,
//! jades for JAdES) builds its own format-specific embedding on top
//! of these shared clients.

#[cfg(not(any(feature = "rustcrypto", feature = "aws-lc")))]
compile_error!("select exactly one document provider: rustcrypto or aws-lc");
#[cfg(all(feature = "rustcrypto", feature = "aws-lc"))]
compile_error!("document provider features are mutually exclusive: select exactly one");
#[cfg(all(
    feature = "tsp",
    not(any(feature = "tls-ring", feature = "tls-aws-lc"))
))]
compile_error!("networking requires exactly one TLS provider: tls-ring or tls-aws-lc");
#[cfg(all(feature = "tls-ring", feature = "tls-aws-lc"))]
compile_error!("TLS provider features are mutually exclusive: select exactly one");

pub use kryptering::{
    backend_info, capabilities, initialize_backend, supports, BackendId, BackendInfo, Capability,
    FipsStatus, Operation, TlsBackendId,
};

// Always-compiled modules
pub mod crypto;
pub mod der_utils;
pub mod error;
pub mod trust;

// Feature-gated modules
#[cfg(feature = "tsp")]
pub mod net;

#[cfg(feature = "tsp")]
pub mod tsp;

#[cfg(feature = "ltv")]
pub mod ltv;
