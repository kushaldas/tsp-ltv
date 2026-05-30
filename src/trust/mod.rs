//! Trust store management for certificate chain validation.
//!
//! This module provides [`TrustStore`] for holding trusted CA certificates
//! (trust anchors) and [`TrustStoreSet`] for managing separate stores for
//! different purposes: signature validation, timestamp authority validation,
//! and SVT issuer validation.
//!
//! # Loading trust anchors
//!
//! Trust anchors can be loaded from:
//! - Individual PEM files (one or more certificates per file)
//! - Directories of PEM files
//! - DER-encoded bytes
//! - `x509_cert::Certificate` objects directly
//!
//! # Example
//!
//! ```no_run
//! use tsp_ltv::trust::{TrustStore, TrustStoreSet};
//!
//! # fn example() -> Result<(), tsp_ltv::error::TrustError> {
//! // Load a trust store from a PEM file
//! let sig_store = TrustStore::from_pem_file("ca-certs.pem")?;
//!
//! // Or from a directory of PEM files
//! let tsa_store = TrustStore::from_pem_directory("/etc/ssl/certs")?;
//!
//! // Combine into a typed set
//! let stores = TrustStoreSet::new()
//!     .with_sig_store(sig_store)
//!     .with_tsa_store(tsa_store);
//! # Ok(())
//! # }
//! ```

mod chain_build;
mod store;
mod store_set;

pub use chain_build::{
    build_chain_from_pool, build_chain_from_pool_with_policy, trust_anchor_subjects,
};
pub use store::TrustStore;
pub use store_set::{StoreKind, TrustStoreSet};
