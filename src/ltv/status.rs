//! Four-valued certificate validation status model.
//!
//! This module defines the core types for representing certificate revocation
//! check results, following the Java stack's `ValidationStatus` pattern.
//! The four-valued model (Valid, Revoked, Invalid, Unknown) drives the entire
//! certificate validation pipeline and policy framework.

use chrono::{DateTime, Utc};

/// Source of a revocation check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationSource {
    /// Certificate Revocation List (RFC 5280).
    Crl,
    /// Online Certificate Status Protocol (RFC 6960).
    Ocsp,
}

impl std::fmt::Display for RevocationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crl => write!(f, "CRL"),
            Self::Ocsp => write!(f, "OCSP"),
        }
    }
}

/// Revocation reason code per RFC 5280 §5.3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    /// 0 — unspecified
    Unspecified,
    /// 1 — keyCompromise
    KeyCompromise,
    /// 2 — cACompromise
    CaCompromise,
    /// 3 — affiliationChanged
    AffiliationChanged,
    /// 4 — superseded
    Superseded,
    /// 5 — cessationOfOperation
    CessationOfOperation,
    /// 6 — certificateHold
    CertificateHold,
    // 7 is unused
    /// 8 — removeFromCRL
    RemoveFromCrl,
    /// 9 — privilegeWithdrawn
    PrivilegeWithdrawn,
    /// 10 — aACompromise
    AaCompromise,
    /// Unknown reason code.
    Unknown(u8),
}

impl RevocationReason {
    /// Parse a reason code from its integer value.
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Unspecified,
            1 => Self::KeyCompromise,
            2 => Self::CaCompromise,
            3 => Self::AffiliationChanged,
            4 => Self::Superseded,
            5 => Self::CessationOfOperation,
            6 => Self::CertificateHold,
            8 => Self::RemoveFromCrl,
            9 => Self::PrivilegeWithdrawn,
            10 => Self::AaCompromise,
            other => Self::Unknown(other),
        }
    }

    /// Return the integer code for this reason.
    pub fn code(&self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
            Self::Unknown(v) => *v,
        }
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "unspecified"),
            Self::KeyCompromise => write!(f, "keyCompromise"),
            Self::CaCompromise => write!(f, "cACompromise"),
            Self::AffiliationChanged => write!(f, "affiliationChanged"),
            Self::Superseded => write!(f, "superseded"),
            Self::CessationOfOperation => write!(f, "cessationOfOperation"),
            Self::CertificateHold => write!(f, "certificateHold"),
            Self::RemoveFromCrl => write!(f, "removeFromCRL"),
            Self::PrivilegeWithdrawn => write!(f, "privilegeWithdrawn"),
            Self::AaCompromise => write!(f, "aACompromise"),
            Self::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

/// Four-valued certificate validation status.
///
/// This is the core result type for revocation checking. Each certificate
/// in a chain gets a `ValidationStatus` from both CRL and OCSP checks,
/// and these are resolved using priority rules.
#[derive(Debug, Clone)]
pub enum ValidationStatus {
    /// Certificate is confirmed not revoked.
    Valid {
        /// Which method confirmed validity.
        source: RevocationSource,
        /// When the check was performed.
        checked_at: DateTime<Utc>,
    },

    /// Certificate has been revoked.
    Revoked {
        /// Which method reported revocation.
        source: RevocationSource,
        /// Why the certificate was revoked.
        reason: RevocationReason,
        /// When the certificate was revoked.
        revocation_time: DateTime<Utc>,
    },

    /// Certificate validation failed (structural/crypto error).
    ///
    /// Distinct from `Unknown` — this means we got a definitive negative
    /// result (e.g., CRL signature invalid, OCSP response malformed).
    Invalid {
        /// What went wrong.
        reason: String,
    },

    /// Revocation status could not be determined.
    ///
    /// This could mean the OCSP responder returned "unknown", no
    /// CRL/OCSP endpoint was available, or the check timed out.
    Unknown {
        /// Why status is unknown.
        reason: String,
    },
}

impl ValidationStatus {
    /// Returns true if this status is `Valid`.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    /// Returns true if this status is `Revoked`.
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }

    /// Returns true if this status is `Invalid`.
    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid { .. })
    }

    /// Returns true if this status is `Unknown`.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }

    /// Priority value for conflict resolution (higher = takes precedence).
    ///
    /// Order: `Revoked(3) > Valid(2) > Invalid(1) > Unknown(0)`
    ///
    /// `Invalid` (a definitive cryptographic/structural rejection — e.g. a
    /// forged CRL or a malformed OCSP response) deliberately dominates
    /// `Unknown` (status simply could not be determined). An attacker who
    /// serves garbage from one revocation source must not be able to hide that
    /// behind the other source's `Unknown`. `Valid` still dominates `Invalid`,
    /// because a genuine, cryptographically verified "good" from one source
    /// cannot be forged, so a bogus result from the other source should not turn
    /// a genuinely valid certificate into a hard failure.
    fn priority(&self) -> u8 {
        match self {
            Self::Revoked { .. } => 3,
            Self::Valid { .. } => 2,
            Self::Invalid { .. } => 1,
            Self::Unknown { .. } => 0,
        }
    }
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid { source, checked_at } => {
                write!(f, "VALID (via {source}, checked at {checked_at})")
            }
            Self::Revoked {
                source,
                reason,
                revocation_time,
            } => {
                write!(
                    f,
                    "REVOKED (via {source}, reason={reason}, time={revocation_time})"
                )
            }
            Self::Invalid { reason } => write!(f, "INVALID ({reason})"),
            Self::Unknown { reason } => write!(f, "UNKNOWN ({reason})"),
        }
    }
}

/// Resolve two validation statuses using priority rules.
///
/// Priority order: `REVOKED > VALID > INVALID > UNKNOWN`
///
/// - If either check returns `Revoked`, the final result is `Revoked`
/// - If either check returns `Valid` (and neither is `Revoked`), result is `Valid`
/// - Otherwise a definitive `Invalid` (e.g. a forged CRL or malformed OCSP
///   response) dominates a non-determinative `Unknown`, so a bogus revocation
///   source cannot be masked behind the other source's `Unknown`
/// - If both are `Unknown`, result is `Unknown`
pub fn resolve_priority(a: ValidationStatus, b: ValidationStatus) -> ValidationStatus {
    if a.priority() >= b.priority() {
        a
    } else {
        b
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_reason_roundtrip() {
        for code in [0, 1, 2, 3, 4, 5, 6, 8, 9, 10] {
            let reason = RevocationReason::from_code(code);
            assert_eq!(reason.code(), code);
        }
        // Unknown
        let reason = RevocationReason::from_code(7);
        assert_eq!(reason.code(), 7);
        assert!(matches!(reason, RevocationReason::Unknown(7)));
    }

    #[test]
    fn test_validation_status_predicates() {
        let valid = ValidationStatus::Valid {
            source: RevocationSource::Ocsp,
            checked_at: Utc::now(),
        };
        assert!(valid.is_valid());
        assert!(!valid.is_revoked());

        let revoked = ValidationStatus::Revoked {
            source: RevocationSource::Crl,
            reason: RevocationReason::KeyCompromise,
            revocation_time: Utc::now(),
        };
        assert!(revoked.is_revoked());
        assert!(!revoked.is_valid());

        let invalid = ValidationStatus::Invalid {
            reason: "bad signature".into(),
        };
        assert!(invalid.is_invalid());

        let unknown = ValidationStatus::Unknown {
            reason: "no OCSP responder".into(),
        };
        assert!(unknown.is_unknown());
    }

    #[test]
    fn test_resolve_priority_revoked_wins() {
        let valid = ValidationStatus::Valid {
            source: RevocationSource::Ocsp,
            checked_at: Utc::now(),
        };
        let revoked = ValidationStatus::Revoked {
            source: RevocationSource::Crl,
            reason: RevocationReason::KeyCompromise,
            revocation_time: Utc::now(),
        };

        let result = resolve_priority(valid, revoked);
        assert!(result.is_revoked());
    }

    #[test]
    fn test_resolve_priority_valid_over_unknown() {
        let valid = ValidationStatus::Valid {
            source: RevocationSource::Crl,
            checked_at: Utc::now(),
        };
        let unknown = ValidationStatus::Unknown {
            reason: "timeout".into(),
        };

        let result = resolve_priority(unknown, valid);
        assert!(result.is_valid());
    }

    #[test]
    fn test_resolve_priority_invalid_over_unknown() {
        // A definitive Invalid (e.g. a forged/malformed revocation source) must
        // dominate a non-determinative Unknown from the other source, so the
        // bogus source is surfaced rather than masked.
        let invalid = ValidationStatus::Invalid {
            reason: "bad CRL".into(),
        };
        let unknown = ValidationStatus::Unknown {
            reason: "no OCSP".into(),
        };

        // Order of arguments must not matter.
        assert!(resolve_priority(invalid.clone(), unknown.clone()).is_invalid());
        assert!(resolve_priority(unknown, invalid).is_invalid());
    }

    #[test]
    fn test_resolve_priority_valid_over_invalid() {
        // A genuine, verified Valid cannot be forged, so it should not be
        // turned into a hard failure by a bogus result from the other source.
        let valid = ValidationStatus::Valid {
            source: RevocationSource::Ocsp,
            checked_at: Utc::now(),
        };
        let invalid = ValidationStatus::Invalid {
            reason: "forged CRL".into(),
        };
        assert!(resolve_priority(valid.clone(), invalid.clone()).is_valid());
        assert!(resolve_priority(invalid, valid).is_valid());
    }

    #[test]
    fn test_display() {
        let valid = ValidationStatus::Valid {
            source: RevocationSource::Ocsp,
            checked_at: Utc::now(),
        };
        let s = format!("{valid}");
        assert!(s.starts_with("VALID (via OCSP"));

        let reason = RevocationReason::KeyCompromise;
        assert_eq!(format!("{reason}"), "keyCompromise");
    }
}
