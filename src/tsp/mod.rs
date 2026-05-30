//! RFC 3161 timestamp client.
//!
//! Provides a TSA (Time Stamping Authority) client for obtaining
//! RFC 3161 timestamp tokens, used for AdES B-T and higher profiles.
//!
//! # Architecture
//!
//! - [`TsaClient`] — Single TSA endpoint client with configurable digest algorithm,
//!   policy OID, and timeout
//! - [`TsaClientPool`] — Fallback chain of multiple TSA clients for resilience
//! - [`token`] — Low-level TimeStampReq/Resp ASN.1 building and parsing
//!
//! # Example
//!
//! ```no_run
//! use tsp_ltv::tsp::{TsaClient, TsaClientPool};
//!
//! # async fn example() -> Result<(), tsp_ltv::error::TspError> {
//! // Single TSA
//! let client = TsaClient::new("http://timestamp.digicert.com");
//! let hash = vec![0u8; 32]; // SHA-256 hash of signature value
//! let token = client.timestamp(&hash).await?;
//!
//! // Multiple TSAs with fallback
//! let pool = TsaClientPool::from_urls(&[
//!     "http://timestamp.digicert.com",
//!     "http://timestamp.globalsign.com/tsa/r6advanced1",
//! ]);
//! let token = pool.timestamp(&hash).await?;
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod token;

// Re-exports
pub use client::{TsaClient, TsaClientPool};
pub use token::{
    build_timestamp_request, extract_tst_info, generate_nonce, parse_timestamp_response,
    validate_timestamp_response, verify_timestamp_token, PkiStatus, TimeStampResp, TstInfo,
};
