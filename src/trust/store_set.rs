//! [`TrustStoreSet`] — typed collection of trust stores for different purposes.

use super::TrustStore;

/// Identifies which trust store to use for a given operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreKind {
    /// Trust anchors for validating signing certificates.
    Signature,
    /// Trust anchors for validating TSA (timestamp authority) certificates.
    Timestamp,
    /// Trust anchors for validating SVT issuer certificates.
    Svt,
}

impl std::fmt::Display for StoreKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreKind::Signature => write!(f, "sig"),
            StoreKind::Timestamp => write!(f, "tsa"),
            StoreKind::Svt => write!(f, "svt"),
        }
    }
}

/// A set of trust stores for different validation purposes.
///
/// PDF signature validation may require up to three separate sets of trust
/// anchors:
/// - **Signature** (`sig`): for validating the signer's certificate chain
/// - **Timestamp** (`tsa`): for validating timestamp authority certificates
/// - **SVT** (`svt`): for validating Signature Validation Token issuers
///
/// Each store is optional. If a store is not configured, operations that
/// require it will fail with an appropriate error.
///
/// # Example
///
/// ```no_run
/// use tsp_ltv::trust::{TrustStore, TrustStoreSet};
///
/// # fn example() -> Result<(), tsp_ltv::error::TrustError> {
/// let stores = TrustStoreSet::new()
///     .with_sig_store(TrustStore::from_pem_file("ca-bundle.pem")?)
///     .with_tsa_store(TrustStore::from_pem_file("tsa-roots.pem")?);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TrustStoreSet {
    sig: Option<TrustStore>,
    tsa: Option<TrustStore>,
    svt: Option<TrustStore>,
}

impl TrustStoreSet {
    /// Create an empty store set (no stores configured).
    pub fn new() -> Self {
        Self {
            sig: None,
            tsa: None,
            svt: None,
        }
    }

    /// Set the signature validation trust store.
    pub fn with_sig_store(mut self, store: TrustStore) -> Self {
        self.sig = Some(store);
        self
    }

    /// Set the timestamp authority trust store.
    pub fn with_tsa_store(mut self, store: TrustStore) -> Self {
        self.tsa = Some(store);
        self
    }

    /// Set the SVT issuer trust store.
    pub fn with_svt_store(mut self, store: TrustStore) -> Self {
        self.svt = Some(store);
        self
    }

    /// Get the trust store for the given kind.
    pub fn get(&self, kind: StoreKind) -> Option<&TrustStore> {
        match kind {
            StoreKind::Signature => self.sig.as_ref(),
            StoreKind::Timestamp => self.tsa.as_ref(),
            StoreKind::Svt => self.svt.as_ref(),
        }
    }

    /// Get a mutable reference to the trust store for the given kind.
    pub fn get_mut(&mut self, kind: StoreKind) -> Option<&mut TrustStore> {
        match kind {
            StoreKind::Signature => self.sig.as_mut(),
            StoreKind::Timestamp => self.tsa.as_mut(),
            StoreKind::Svt => self.svt.as_mut(),
        }
    }

    /// Get the signature trust store.
    pub fn sig(&self) -> Option<&TrustStore> {
        self.sig.as_ref()
    }

    /// Get the timestamp authority trust store.
    pub fn tsa(&self) -> Option<&TrustStore> {
        self.tsa.as_ref()
    }

    /// Get the SVT trust store.
    pub fn svt(&self) -> Option<&TrustStore> {
        self.svt.as_ref()
    }

    /// Check if any stores are configured.
    pub fn has_any(&self) -> bool {
        self.sig.is_some() || self.tsa.is_some() || self.svt.is_some()
    }

    /// Set a store by kind.
    pub fn set(&mut self, kind: StoreKind, store: TrustStore) {
        match kind {
            StoreKind::Signature => self.sig = Some(store),
            StoreKind::Timestamp => self.tsa = Some(store),
            StoreKind::Svt => self.svt = Some(store),
        }
    }
}

impl Default for TrustStoreSet {
    fn default() -> Self {
        Self::new()
    }
}
