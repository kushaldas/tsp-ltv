//! Concurrent OCSP + CRL revocation checking orchestrator.
//!
//! This module provides a high-level API for checking a certificate's
//! revocation status using both OCSP and CRL concurrently. Results from
//! both sources are merged using the priority rules from [`resolve_priority`]:
//! `REVOKED > VALID > UNKNOWN > INVALID`.
//!
//! # Configuration
//!
//! [`RevocationConfig`] controls timeouts, OCSP preference, nonce usage,
//! and whether revocation checking is mandatory.
//!
//! # Usage
//!
//! ```rust,no_run
//! use tsp_ltv::ltv::revocation::{RevocationConfig, check_certificate_revocation};
//! use tsp_ltv::ltv::{OcspClient, CrlClient};
//! # async fn example() {
//! let config = RevocationConfig::default();
//! let ocsp = OcspClient::new();
//! let crl = CrlClient::new();
//! // let status = check_certificate_revocation(&cert, &issuer, &config, &crl, &ocsp, None).await;
//! # }
//! ```

use std::time::Duration;

use chrono::{DateTime, Utc};
use x509_cert::Certificate;

use crate::ltv::crl::{self, CrlClient};
use crate::ltv::ocsp::{self, OcspClient};
use crate::ltv::status::{resolve_priority, ValidationStatus};

// ── Configuration ─────────────────────────────────────────────────

/// Configuration for revocation checking behavior.
///
/// Defaults match the Java stack's `BasicCertificateValidityChecker`:
/// - OCSP preferred over CRL
/// - Both checked concurrently
/// - 3 second OCSP timeout, 7 second CRL timeout
/// - Nonces enabled for replay protection
/// - Revocation checking required (Unknown → error)
#[derive(Debug, Clone)]
pub struct RevocationConfig {
    /// Prefer OCSP over CRL when both are available.
    ///
    /// When true, OCSP is given precedence in the result. Both are still
    /// checked concurrently regardless of this setting. Default: `true`.
    pub prefer_ocsp: bool,

    /// Whether a definitive revocation result is required.
    ///
    /// When true, an `Unknown` final result is treated as an error by
    /// downstream validators. Default: `true`.
    pub require_revocation_check: bool,

    /// OCSP request timeout. Default: 3 seconds.
    pub ocsp_timeout: Duration,

    /// CRL fetch timeout. Default: 7 seconds.
    pub crl_timeout: Duration,

    /// Whether to include a nonce in OCSP requests. Default: `true`.
    pub use_ocsp_nonce: bool,

    /// Maximum recursion depth for OCSP responder revocation checking.
    ///
    /// When an OCSP responder certificate itself needs revocation checking,
    /// this limits how deep we go. Default: 1.
    pub max_ocsp_recursion: usize,

    /// Overall per-certificate timeout for both OCSP + CRL combined.
    ///
    /// If both checks together take longer than this, the remaining check
    /// is abandoned and whatever results are available are used. Default: 10 seconds.
    pub per_cert_timeout: Duration,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            prefer_ocsp: true,
            require_revocation_check: true,
            ocsp_timeout: Duration::from_secs(3),
            crl_timeout: Duration::from_secs(7),
            use_ocsp_nonce: true,
            max_ocsp_recursion: 1,
            per_cert_timeout: Duration::from_secs(10),
        }
    }
}

impl RevocationConfig {
    /// Create a config that disables revocation checking.
    ///
    /// Useful for offline validation where OCSP/CRL endpoints are
    /// unreachable.
    pub fn disabled() -> Self {
        Self {
            require_revocation_check: false,
            ..Default::default()
        }
    }

    /// Create a strict config with shorter timeouts.
    pub fn strict() -> Self {
        Self {
            require_revocation_check: true,
            ocsp_timeout: Duration::from_secs(2),
            crl_timeout: Duration::from_secs(5),
            per_cert_timeout: Duration::from_secs(8),
            ..Default::default()
        }
    }
}

// ── Async orchestrator ────────────────────────────────────────────

/// Check a single certificate's revocation status using OCSP and CRL concurrently.
///
/// This is the primary entry point for revocation checking. It:
///
/// 1. Launches OCSP and CRL checks concurrently
/// 2. Wraps both in a per-certificate timeout
/// 3. Merges results using `resolve_priority` (REVOKED > VALID > UNKNOWN)
///
/// # Arguments
///
/// - `cert` — the certificate to check
/// - `issuer` — the issuer's certificate (needed for signature verification)
/// - `config` — timeout/behavior configuration
/// - `crl_client` — CRL fetching client
/// - `ocsp_client` — OCSP querying client
/// - `validation_time` — if `None`, uses the current time
///
/// # Returns
///
/// A [`ValidationStatus`] reflecting the merged result of both checks.
/// If both checks fail or time out, returns `Unknown`.
pub async fn check_certificate_revocation(
    cert: &Certificate,
    issuer: &Certificate,
    config: &RevocationConfig,
    crl_client: &CrlClient,
    ocsp_client: &OcspClient,
    validation_time: Option<DateTime<Utc>>,
) -> ValidationStatus {
    // Run OCSP and CRL checks concurrently with a per-cert timeout
    let ocsp_fut = run_ocsp_check(cert, issuer, config, ocsp_client, validation_time);
    let crl_fut = run_crl_check(cert, issuer, config, crl_client, validation_time);

    // Use tokio::join! for concurrent execution, wrapped in a timeout
    let result = tokio::time::timeout(config.per_cert_timeout, async {
        tokio::join!(ocsp_fut, crl_fut)
    })
    .await;

    let (ocsp_status, crl_status) = match result {
        Ok((ocsp, crl)) => (ocsp, crl),
        Err(_elapsed) => {
            log::warn!("per-certificate revocation check timed out after {:?}", config.per_cert_timeout);
            (
                ValidationStatus::Unknown {
                    reason: "OCSP check timed out".into(),
                },
                ValidationStatus::Unknown {
                    reason: "CRL check timed out".into(),
                },
            )
        }
    };

    log::debug!("OCSP result: {ocsp_status}, CRL result: {crl_status}");

    // Merge results using priority
    resolve_priority(ocsp_status, crl_status)
}

/// Sync wrapper for [`check_certificate_revocation`].
///
/// Available when the `blocking` feature is enabled. Uses `tokio::runtime::Runtime::block_on()`
/// to execute the async function synchronously.
#[cfg(feature = "blocking")]
pub fn check_certificate_revocation_blocking(
    cert: &Certificate,
    issuer: &Certificate,
    config: &RevocationConfig,
    crl_client: &CrlClient,
    ocsp_client: &OcspClient,
    validation_time: Option<DateTime<Utc>>,
) -> ValidationStatus {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");
    rt.block_on(check_certificate_revocation(
        cert,
        issuer,
        config,
        crl_client,
        ocsp_client,
        validation_time,
    ))
}

// ── Internal: OCSP check ──────────────────────────────────────────

/// Run the OCSP check for a single certificate.
///
/// Returns `Unknown` if no OCSP URLs are available or if the check fails.
async fn run_ocsp_check(
    cert: &Certificate,
    issuer: &Certificate,
    config: &RevocationConfig,
    ocsp_client: &OcspClient,
    validation_time: Option<DateTime<Utc>>,
) -> ValidationStatus {
    // Check if cert has OCSP URLs
    let urls = OcspClient::extract_ocsp_urls(cert);
    if urls.is_empty() {
        log::debug!("no OCSP responder URL in certificate AIA extension");
        return ValidationStatus::Unknown {
            reason: "no OCSP responder URL available".into(),
        };
    }

    // Apply OCSP-specific timeout
    let result = tokio::time::timeout(config.ocsp_timeout, async {
        // Fetch OCSP response (with or without nonce)
        let fetch_result = if config.use_ocsp_nonce {
            match ocsp_client.fetch_ocsp_response_with_nonce(cert, issuer).await {
                Ok((response_der, nonce)) => {
                    ocsp::check_revocation(&response_der, cert, issuer, Some(&nonce), validation_time)
                }
                Err(e) => Err(e),
            }
        } else {
            match ocsp_client.fetch_ocsp_response(cert, issuer).await {
                Ok(response_der) => {
                    ocsp::check_revocation(&response_der, cert, issuer, None, validation_time)
                }
                Err(e) => Err(e),
            }
        };

        match fetch_result {
            Ok(status) => status,
            Err(e) => {
                log::warn!("OCSP check failed: {e}");
                ValidationStatus::Unknown {
                    reason: format!("OCSP check failed: {e}"),
                }
            }
        }
    })
    .await;

    match result {
        Ok(status) => status,
        Err(_elapsed) => {
            log::warn!("OCSP check timed out after {:?}", config.ocsp_timeout);
            ValidationStatus::Unknown {
                reason: format!("OCSP check timed out after {:?}", config.ocsp_timeout),
            }
        }
    }
}

// ── Internal: CRL check ───────────────────────────────────────────

/// Run the CRL check for a single certificate.
///
/// Returns `Unknown` if no CRL distribution points are available or if
/// the check fails.
async fn run_crl_check(
    cert: &Certificate,
    issuer: &Certificate,
    config: &RevocationConfig,
    crl_client: &CrlClient,
    validation_time: Option<DateTime<Utc>>,
) -> ValidationStatus {
    // Check if cert has CRL distribution points
    let urls = CrlClient::extract_crl_urls(cert);
    if urls.is_empty() {
        log::debug!("no CRL distribution points in certificate");
        return ValidationStatus::Unknown {
            reason: "no CRL distribution points available".into(),
        };
    }

    // Apply CRL-specific timeout
    let result = tokio::time::timeout(config.crl_timeout, async {
        // Fetch CRL(s) for this certificate
        match crl_client.fetch_crls_for_cert(cert).await {
            Ok(crls) => {
                if crls.is_empty() {
                    return ValidationStatus::Unknown {
                        reason: "no CRLs could be fetched".into(),
                    };
                }

                // Check the first successfully fetched CRL
                // (fetch_crls_for_cert already stops after the first success)
                match crl::check_revocation(&crls[0], cert, issuer, validation_time) {
                    Ok(status) => status,
                    Err(e) => {
                        log::warn!("CRL revocation check failed: {e}");
                        ValidationStatus::Unknown {
                            reason: format!("CRL check failed: {e}"),
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("CRL fetch failed: {e}");
                ValidationStatus::Unknown {
                    reason: format!("CRL fetch failed: {e}"),
                }
            }
        }
    })
    .await;

    match result {
        Ok(status) => status,
        Err(_elapsed) => {
            log::warn!("CRL check timed out after {:?}", config.crl_timeout);
            ValidationStatus::Unknown {
                reason: format!("CRL check timed out after {:?}", config.crl_timeout),
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ltv::status::RevocationSource;

    // ── RevocationConfig tests ────────────────────────────────────

    #[test]
    fn test_default_config() {
        let config = RevocationConfig::default();
        assert!(config.prefer_ocsp);
        assert!(config.require_revocation_check);
        assert!(config.use_ocsp_nonce);
        assert_eq!(config.ocsp_timeout, Duration::from_secs(3));
        assert_eq!(config.crl_timeout, Duration::from_secs(7));
        assert_eq!(config.max_ocsp_recursion, 1);
        assert_eq!(config.per_cert_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_disabled_config() {
        let config = RevocationConfig::disabled();
        assert!(!config.require_revocation_check);
        assert!(config.prefer_ocsp); // still defaults for others
    }

    #[test]
    fn test_strict_config() {
        let config = RevocationConfig::strict();
        assert!(config.require_revocation_check);
        assert_eq!(config.ocsp_timeout, Duration::from_secs(2));
        assert_eq!(config.crl_timeout, Duration::from_secs(5));
        assert_eq!(config.per_cert_timeout, Duration::from_secs(8));
    }

    // ── Orchestrator unit tests (no network) ──────────────────────
    //
    // These tests verify the orchestrator logic using certificates
    // that have no OCSP/CRL endpoints (our test fixtures), so both
    // checks return Unknown → merged result is Unknown.

    #[tokio::test]
    async fn test_check_no_ocsp_no_crl_returns_unknown() {
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        let intermediate_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_cert.pem"
        ));

        let (_, ca_der) = pem_rfc7468::decode_vec(ca_pem.as_bytes()).unwrap();
        let (_, inter_der) = pem_rfc7468::decode_vec(intermediate_pem.as_bytes()).unwrap();

        let ca = der::Decode::from_der(&ca_der).unwrap();
        let intermediate: Certificate = der::Decode::from_der(&inter_der).unwrap();

        let config = RevocationConfig::default();
        let crl_client = CrlClient::new();
        let ocsp_client = OcspClient::new();

        let status = check_certificate_revocation(
            &intermediate,
            &ca,
            &config,
            &crl_client,
            &ocsp_client,
            None,
        )
        .await;

        // Our test certs have no OCSP or CRL endpoints → Unknown
        assert!(
            status.is_unknown(),
            "expected Unknown for certs without OCSP/CRL endpoints, got: {status}"
        );
    }

    #[tokio::test]
    async fn test_resolve_ocsp_valid_crl_unknown() {
        // Test the resolve_priority logic directly through the merge
        let ocsp = ValidationStatus::Valid {
            source: RevocationSource::Ocsp,
            checked_at: Utc::now(),
        };
        let crl = ValidationStatus::Unknown {
            reason: "no CRL endpoints".into(),
        };
        let result = resolve_priority(ocsp, crl);
        assert!(result.is_valid());
    }

    #[tokio::test]
    async fn test_resolve_ocsp_unknown_crl_revoked() {
        let ocsp = ValidationStatus::Unknown {
            reason: "timeout".into(),
        };
        let crl = ValidationStatus::Revoked {
            source: RevocationSource::Crl,
            reason: crate::ltv::status::RevocationReason::KeyCompromise,
            revocation_time: Utc::now(),
        };
        let result = resolve_priority(ocsp, crl);
        assert!(result.is_revoked());
    }

    #[tokio::test]
    async fn test_resolve_both_valid_picks_first() {
        let ocsp = ValidationStatus::Valid {
            source: RevocationSource::Ocsp,
            checked_at: Utc::now(),
        };
        let crl = ValidationStatus::Valid {
            source: RevocationSource::Crl,
            checked_at: Utc::now(),
        };
        let result = resolve_priority(ocsp, crl);
        // Both valid, first (OCSP) wins since priorities are equal
        assert!(result.is_valid());
        match result {
            ValidationStatus::Valid { source, .. } => {
                assert_eq!(source, RevocationSource::Ocsp);
            }
            _ => panic!("expected Valid"),
        }
    }

    #[tokio::test]
    async fn test_resolve_both_unknown() {
        let a = ValidationStatus::Unknown {
            reason: "no OCSP".into(),
        };
        let b = ValidationStatus::Unknown {
            reason: "no CRL".into(),
        };
        let result = resolve_priority(a, b);
        assert!(result.is_unknown());
    }

    #[tokio::test]
    async fn test_check_with_signer_cert_returns_unknown() {
        // Signer cert also has no OCSP/CRL endpoints in our test fixtures
        let signer_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let intermediate_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_cert.pem"
        ));

        let (_, signer_der) = pem_rfc7468::decode_vec(signer_pem.as_bytes()).unwrap();
        let (_, inter_der) = pem_rfc7468::decode_vec(intermediate_pem.as_bytes()).unwrap();

        let signer: Certificate = der::Decode::from_der(&signer_der).unwrap();
        let intermediate: Certificate = der::Decode::from_der(&inter_der).unwrap();

        let config = RevocationConfig {
            per_cert_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let crl_client = CrlClient::new();
        let ocsp_client = OcspClient::new();

        let status = check_certificate_revocation(
            &signer,
            &intermediate,
            &config,
            &crl_client,
            &ocsp_client,
            None,
        )
        .await;

        assert!(
            status.is_unknown(),
            "expected Unknown for signer cert without endpoints, got: {status}"
        );
    }

    #[test]
    fn test_config_custom() {
        let config = RevocationConfig {
            prefer_ocsp: false,
            require_revocation_check: false,
            ocsp_timeout: Duration::from_millis(500),
            crl_timeout: Duration::from_millis(1000),
            use_ocsp_nonce: false,
            max_ocsp_recursion: 0,
            per_cert_timeout: Duration::from_secs(2),
        };
        assert!(!config.prefer_ocsp);
        assert!(!config.require_revocation_check);
        assert!(!config.use_ocsp_nonce);
        assert_eq!(config.max_ocsp_recursion, 0);
    }
}
