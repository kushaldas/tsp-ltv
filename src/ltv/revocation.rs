//! Concurrent OCSP + CRL revocation checking orchestrator.
//!
//! This module provides a high-level API for checking a certificate's
//! revocation status using both OCSP and CRL concurrently. Results from
//! both sources are merged using the priority rules from [`resolve_priority`]:
//! `REVOKED > VALID > INVALID > UNKNOWN`.
//!
//! # Fail-closed policy
//!
//! When [`RevocationConfig::require_revocation_check`] is `true` (the default),
//! a merged result that is not a definitive `Valid` or `Revoked` is a hard
//! failure: an `Unknown` outcome is upgraded to `Invalid` so that an
//! unreachable, blocked, or forged revocation source can never be mistaken for
//! "fine to proceed". Set `require_revocation_check = false`
//! ([`RevocationConfig::disabled`]) for best-effort/offline validation where
//! `Unknown` is acceptable.
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

use crate::error::LtvError;
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
    /// When true (the default), [`check_certificate_revocation`] enforces a
    /// fail-closed policy: any non-definitive merged result (`Unknown`, or an
    /// `Invalid` from a malformed/forged source) blocks, and `Unknown` is
    /// upgraded to `Invalid` so callers cannot treat it as acceptable. When
    /// false, `Unknown` is returned unchanged for best-effort/offline use.
    /// Default: `true`.
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

    /// Signature-algorithm policy applied to OCSP responses and CRLs.
    ///
    /// Defaults to strict — an OCSP response or CRL signed with MD5/SHA-1/SHA-224
    /// fails validation (→ `Invalid`). Set via
    /// [`RevocationConfig::allow_legacy_signatures`] to accept such signatures
    /// when validating historical revocation material.
    pub signature_policy: crate::crypto::verify::SignaturePolicy,
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
            signature_policy: crate::crypto::verify::SignaturePolicy::default(),
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

    /// Accept OCSP responses and CRLs signed with weak/legacy digests
    /// (MD5/SHA-1/SHA-224).
    ///
    /// Off by default. Enable only to validate historical revocation material
    /// whose risk you have accepted; never for fresh trust decisions.
    pub fn allow_legacy_signatures(mut self) -> Self {
        self.signature_policy = crate::crypto::verify::SignaturePolicy::allow_legacy();
        self
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
/// A [`ValidationStatus`] reflecting the merged result of both checks, after
/// applying the `require_revocation_check` policy.
///
/// - With `require_revocation_check == true` (default), only a verified `Valid`
///   or a `Revoked` passes; any `Unknown` (both sources unreachable/blocked/
///   absent) or `Invalid` (a source served malformed/forged data) is a hard
///   failure, with `Unknown` upgraded to `Invalid`. This prevents an attacker
///   from getting a revoked certificate accepted by blocking or forging the
///   revocation sources.
/// - With `require_revocation_check == false`, the merged status is returned
///   unchanged, so `Unknown` is acceptable (best-effort/offline mode).
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

    // Merge results using priority, then apply the fail-closed policy.
    let merged = resolve_priority(ocsp_status, crl_status);
    enforce_revocation_policy(merged, config.require_revocation_check)
}

/// Apply the `require_revocation_check` policy to a merged revocation result.
///
/// Under a strict policy a result that is not a definitive `Valid` or `Revoked`
/// must block. An `Unknown` outcome — no usable revocation information, because
/// every source was absent, unreachable, blocked, or timed out — is upgraded to
/// `Invalid` so the returned status is unambiguously non-acceptable; a caller
/// can no longer mistake a blocked or absent revocation source for "fine to
/// proceed". An already-`Invalid` result (a source served malformed/forged
/// data) is left as-is — it already blocks. When the policy is relaxed
/// (`require_revocation_check == false`), the merged status is returned
/// unchanged so `Unknown` remains acceptable for offline/best-effort use.
fn enforce_revocation_policy(
    status: ValidationStatus,
    require_revocation_check: bool,
) -> ValidationStatus {
    if !require_revocation_check {
        return status;
    }
    match status {
        ValidationStatus::Unknown { reason } => ValidationStatus::Invalid {
            reason: format!(
                "revocation check required but status could not be established: {reason}"
            ),
        },
        other => other,
    }
}

/// Classify an error from [`ocsp::check_revocation`] into a [`ValidationStatus`].
///
/// Only **definitive integrity failures** — bad signature, malformed/expired
/// response, nonce mismatch, untrusted responder — become `Invalid` (a hard,
/// dominating, attack-indicating result). A **responder-side / transient
/// status** (`tryLater`, `internalError`, `unauthorized`, ...) is reported by
/// the responder, not proof of a forged or malformed response, so it stays
/// `Unknown` (non-determinative). This keeps a temporary OCSP outage as
/// best-effort `Unknown` rather than escalating it to a hard failure that would
/// dominate a CRL `Unknown` even under a relaxed policy.
fn ocsp_check_error_to_status(e: LtvError) -> ValidationStatus {
    match e {
        LtvError::OcspResponderStatus(_) => {
            log::warn!("OCSP responder returned a non-successful status: {e}");
            ValidationStatus::Unknown {
                reason: format!("OCSP responder unavailable: {e}"),
            }
        }
        other => {
            log::warn!("OCSP response failed validation: {other}");
            ValidationStatus::Invalid {
                reason: format!("OCSP response failed validation: {other}"),
            }
        }
    }
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
/// Returns `Unknown` if no OCSP URLs are available, the fetch fails, the request
/// times out, or the responder returns a non-successful status (tryLater,
/// internalError, unauthorized, ...) — all non-determinative. Returns `Invalid`
/// only for a definitive integrity failure on a received response (bad
/// signature, malformed, nonce mismatch, untrusted responder).
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
        // Fetch the OCSP response. A fetch failure (network, no endpoint, HTTP
        // error) is non-determinative → Unknown.
        let fetched = if config.use_ocsp_nonce {
            ocsp_client
                .fetch_ocsp_response_with_nonce(cert, issuer)
                .await
                .map(|(der, nonce)| (der, Some(nonce)))
        } else {
            ocsp_client
                .fetch_ocsp_response(cert, issuer)
                .await
                .map(|der| (der, None))
        };
        let (response_der, nonce) = match fetched {
            Ok(v) => v,
            Err(e) => {
                log::warn!("OCSP fetch failed: {e}");
                return ValidationStatus::Unknown {
                    reason: format!("OCSP fetch failed: {e}"),
                };
            }
        };

        // We received a response. Classify the outcome: a definitive integrity
        // failure (bad signature, malformed/expired response, nonce mismatch,
        // untrusted responder) is Invalid, but a responder-side / transient
        // status (tryLater, internalError, unauthorized, ...) is non-
        // determinative and stays Unknown — so a temporary responder outage
        // does not become a hard failure under best-effort/offline policy.
        match ocsp::check_revocation_with_policy(
            &response_der,
            cert,
            issuer,
            nonce.as_deref(),
            validation_time,
            &config.signature_policy,
        ) {
            Ok(status) => status,
            Err(e) => ocsp_check_error_to_status(e),
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
/// Returns `Unknown` if no CRL distribution points are available, no CRL could
/// be fetched, or the fetch times out. Returns `Invalid` if a CRL was fetched
/// but failed validation (bad signature, malformed structure).
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
                // (fetch_crls_for_cert already stops after the first success).
                // A validation failure on a CRL we actually received (bad
                // signature, malformed structure) is a definitive negative
                // result → Invalid, not Unknown, so a forged CRL cannot fail
                // open by masquerading as "status undetermined".
                match crl::check_revocation_with_policy(
                    &crls[0],
                    cert,
                    issuer,
                    validation_time,
                    &config.signature_policy,
                ) {
                    Ok(status) => status,
                    Err(e) => {
                        log::warn!("CRL revocation check failed: {e}");
                        ValidationStatus::Invalid {
                            reason: format!("CRL validation failed: {e}"),
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

    fn load_ca_and_intermediate() -> (Certificate, Certificate) {
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
        (ca, intermediate)
    }

    #[tokio::test]
    async fn test_check_no_endpoints_strict_hard_fails() {
        // C-2 regression: with the default (strict) policy, a certificate that
        // offers no usable revocation source must NOT fail open as Unknown — it
        // must hard-fail (Invalid) so callers cannot proceed.
        let (ca, intermediate) = load_ca_and_intermediate();

        let config = RevocationConfig::default();
        assert!(config.require_revocation_check);
        let crl_client = CrlClient::new();
        let ocsp_client = OcspClient::new();

        let status =
            check_certificate_revocation(&intermediate, &ca, &config, &crl_client, &ocsp_client, None)
                .await;

        assert!(
            status.is_invalid(),
            "strict policy must hard-fail when no revocation source is usable, got: {status}"
        );
        assert!(
            !status.is_unknown(),
            "strict policy must not return Unknown (fail-open), got: {status}"
        );
    }

    #[tokio::test]
    async fn test_check_no_endpoints_disabled_returns_unknown() {
        // With revocation checking disabled, the same certs return Unknown
        // (best-effort/offline mode) rather than hard-failing.
        let (ca, intermediate) = load_ca_and_intermediate();

        let config = RevocationConfig::disabled();
        assert!(!config.require_revocation_check);
        let crl_client = CrlClient::new();
        let ocsp_client = OcspClient::new();

        let status =
            check_certificate_revocation(&intermediate, &ca, &config, &crl_client, &ocsp_client, None)
                .await;

        assert!(
            status.is_unknown(),
            "disabled policy should return Unknown for certs without endpoints, got: {status}"
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
    async fn test_check_with_signer_cert_strict_hard_fails() {
        // Signer cert also has no OCSP/CRL endpoints in our test fixtures, so
        // the strict default policy hard-fails (Invalid) rather than Unknown.
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
            status.is_invalid(),
            "expected hard fail (Invalid) for signer cert without endpoints under strict policy, got: {status}"
        );
    }

    // ── Policy enforcement unit tests ─────────────────────────────

    #[test]
    fn test_enforce_policy_upgrades_unknown_to_invalid_when_required() {
        let unknown = ValidationStatus::Unknown {
            reason: "both sources unreachable".into(),
        };
        let enforced = enforce_revocation_policy(unknown, true);
        assert!(
            enforced.is_invalid(),
            "strict policy must upgrade Unknown to Invalid, got: {enforced}"
        );
    }

    #[test]
    fn test_enforce_policy_keeps_unknown_when_not_required() {
        let unknown = ValidationStatus::Unknown {
            reason: "offline".into(),
        };
        assert!(enforce_revocation_policy(unknown, false).is_unknown());
    }

    #[test]
    fn test_enforce_policy_passes_valid_and_revoked_through() {
        let valid = ValidationStatus::Valid {
            source: RevocationSource::Ocsp,
            checked_at: Utc::now(),
        };
        assert!(enforce_revocation_policy(valid, true).is_valid());

        let revoked = ValidationStatus::Revoked {
            source: RevocationSource::Crl,
            reason: crate::ltv::status::RevocationReason::KeyCompromise,
            revocation_time: Utc::now(),
        };
        assert!(enforce_revocation_policy(revoked, true).is_revoked());
    }

    #[test]
    fn test_enforce_policy_keeps_invalid_blocking() {
        // An Invalid (forged/malformed source) already blocks and is left as-is.
        let invalid = ValidationStatus::Invalid {
            reason: "forged CRL".into(),
        };
        assert!(enforce_revocation_policy(invalid, true).is_invalid());
    }

    #[test]
    fn test_ocsp_responder_status_maps_to_unknown_not_invalid() {
        // Responder-side / transient statuses (tryLater, internalError, ...) are
        // non-determinative and must NOT escalate to Invalid.
        for msg in ["tryLater (3)", "internalError (2)", "unauthorized (6)"] {
            let status = ocsp_check_error_to_status(LtvError::OcspResponderStatus(msg.into()));
            assert!(
                status.is_unknown(),
                "responder status {msg} must map to Unknown, got: {status}"
            );
        }
    }

    #[test]
    fn test_ocsp_integrity_failure_maps_to_invalid() {
        // Definitive integrity failures (bad signature, malformed, nonce
        // mismatch, untrusted responder) must map to Invalid.
        for e in [
            LtvError::Ocsp("OCSP signature verification failed".into()),
            LtvError::Ocsp("nonce mismatch".into()),
            LtvError::Ocsp("responder certificate not trusted".into()),
        ] {
            let status = ocsp_check_error_to_status(e);
            assert!(
                status.is_invalid(),
                "integrity failure must map to Invalid, got: {status}"
            );
        }
    }

    #[tokio::test]
    async fn test_ocsp_outage_does_not_dominate_under_relaxed_policy() {
        // Regression: a transient OCSP responder status (Unknown) must not, when
        // merged with a CRL Unknown, become a dominating Invalid. Under a
        // relaxed policy the merged result stays Unknown (best-effort).
        let ocsp = ocsp_check_error_to_status(LtvError::OcspResponderStatus("tryLater (3)".into()));
        let crl = ValidationStatus::Unknown {
            reason: "no CRL distribution points".into(),
        };
        let merged = resolve_priority(ocsp, crl);
        assert!(merged.is_unknown(), "transient OCSP outage must not become Invalid");
        assert!(enforce_revocation_policy(merged, false).is_unknown());
    }

    #[test]
    fn test_forged_source_plus_unreachable_hard_fails_under_strict() {
        // Attack scenario: one source is forged (→ Invalid), the other is
        // blocked (→ Unknown). Merge yields Invalid (dominates Unknown), and
        // the strict policy keeps it blocking. The revoked cert is not accepted.
        let forged = ValidationStatus::Invalid {
            reason: "forged CRL signature".into(),
        };
        let blocked = ValidationStatus::Unknown {
            reason: "OCSP egress blocked".into(),
        };
        let merged = resolve_priority(forged, blocked);
        assert!(merged.is_invalid());
        assert!(enforce_revocation_policy(merged, true).is_invalid());
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
            signature_policy: crate::crypto::verify::SignaturePolicy::default(),
        };
        assert!(!config.prefer_ocsp);
        assert!(!config.require_revocation_check);
        assert!(!config.use_ocsp_nonce);
        assert_eq!(config.max_ocsp_recursion, 0);
    }
}
