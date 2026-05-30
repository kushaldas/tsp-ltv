//! CRL fetching, caching, and revocation checking.
//!
//! Fetches Certificate Revocation Lists from distribution points found in
//! X.509 certificates, with both in-memory and optional disk caching.
//! Also provides CRL content parsing and signature verification for
//! offline revocation status checking.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::Client;
use x509_cert::Certificate;

use crate::der_utils::{
    find_tagged_value, integer_bodies_equal, parse_integer_body, parse_tlv,
    parse_tlv_with_rest, parse_x509_time,
};
use crate::error::LtvError;
use crate::ltv::status::{RevocationReason, RevocationSource, ValidationStatus};

/// A cached CRL entry.
#[derive(Debug, Clone)]
struct CrlCacheEntry {
    /// Raw DER-encoded CRL bytes.
    der: Vec<u8>,
    /// When this entry was fetched.
    fetched_at: Instant,
}

/// CRL client with in-memory caching.
///
/// Fetches CRLs from distribution points and caches them to avoid
/// redundant network requests.
#[derive(Debug, Clone)]
pub struct CrlClient {
    http_client: Client,
    timeout: Duration,
    /// In-memory cache: URL -> CRL entry
    cache: Arc<Mutex<HashMap<String, CrlCacheEntry>>>,
    /// How long cached CRLs remain valid.
    grace_period: Duration,
}

impl CrlClient {
    /// Create a new CRL client with default settings.
    ///
    /// Default grace period: 1 hour.
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
            timeout: Duration::from_secs(30),
            cache: Arc::new(Mutex::new(HashMap::new())),
            grace_period: Duration::from_secs(3600),
        }
    }

    /// Set the HTTP client.
    pub fn http_client(mut self, client: Client) -> Self {
        self.http_client = client;
        self
    }

    /// Set the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the cache grace period.
    pub fn grace_period(mut self, grace: Duration) -> Self {
        self.grace_period = grace;
        self
    }

    /// Extract CRL distribution point URLs from a certificate.
    pub fn extract_crl_urls(cert: &Certificate) -> Vec<String> {
        let mut urls = Vec::new();

        // CRL Distribution Points extension OID: 2.5.29.31
        let crl_dp_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.31");

        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == crl_dp_oid {
                    // Parse the CRL Distribution Points extension value
                    // It's a SEQUENCE OF DistributionPoint
                    if let Ok(urls_from_ext) = parse_crl_dp_extension(ext.extn_value.as_bytes()) {
                        urls.extend(urls_from_ext);
                    }
                }
            }
        }

        urls
    }

    /// Fetch a CRL from the given URL, using cache if available.
    pub async fn fetch_crl(&self, url: &str) -> Result<Vec<u8>, LtvError> {
        // Check cache first
        {
            let cache = self.cache.lock().map_err(|e| {
                LtvError::Crl(format!("cache lock poisoned: {e}"))
            })?;
            if let Some(entry) = cache.get(url) {
                if entry.fetched_at.elapsed() < self.grace_period {
                    log::debug!("CRL cache hit for {url}");
                    return Ok(entry.der.clone());
                }
            }
        }

        log::debug!("Fetching CRL from {url}");

        let response = self
            .http_client
            .get(url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| LtvError::Crl(format!("CRL fetch from {url} failed: {e}")))?;

        if !response.status().is_success() {
            return Err(LtvError::Crl(format!(
                "CRL fetch from {url} returned HTTP {}",
                response.status()
            )));
        }

        let crl_bytes = response
            .bytes()
            .await
            .map_err(|e| LtvError::Crl(format!("failed to read CRL response body: {e}")))?
            .to_vec();

        // Validate that it looks like a DER-encoded CRL (starts with SEQUENCE tag)
        if crl_bytes.is_empty() || crl_bytes[0] != 0x30 {
            return Err(LtvError::Crl(format!(
                "CRL from {url} does not appear to be DER-encoded"
            )));
        }

        log::debug!("CRL from {url}: {} bytes", crl_bytes.len());

        // Update cache
        {
            let mut cache = self.cache.lock().map_err(|e| {
                LtvError::Crl(format!("cache lock poisoned: {e}"))
            })?;
            cache.insert(
                url.to_string(),
                CrlCacheEntry {
                    der: crl_bytes.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }

        Ok(crl_bytes)
    }

    /// Fetch all CRLs for a certificate (from all distribution points).
    pub async fn fetch_crls_for_cert(
        &self,
        cert: &Certificate,
    ) -> Result<Vec<Vec<u8>>, LtvError> {
        let urls = Self::extract_crl_urls(cert);
        let mut crls = Vec::new();

        for url in &urls {
            match self.fetch_crl(url).await {
                Ok(crl) => {
                    crls.push(crl);
                    // One CRL is sufficient for most validation scenarios
                    break;
                }
                Err(e) => {
                    log::warn!("Failed to fetch CRL from {url}: {e}");
                    // Try next URL
                }
            }
        }

        Ok(crls)
    }

    /// Clear the in-memory cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }
}

impl Default for CrlClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the CRL Distribution Points extension value.
///
/// ```text
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
/// DistributionPoint ::= SEQUENCE {
///     distributionPoint  [0] DistributionPointName OPTIONAL,
///     reasons            [1] ReasonFlags OPTIONAL,
///     cRLIssuer          [2] GeneralNames OPTIONAL
/// }
/// DistributionPointName ::= CHOICE {
///     fullName           [0] GeneralNames,
///     nameRelativeToCRLIssuer [1] RelativeDistinguishedName
/// }
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// GeneralName ::= CHOICE {
///     uniformResourceIdentifier [6] IA5String,
///     ...
/// }
/// ```
fn parse_crl_dp_extension(der_bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut urls = Vec::new();

    // SEQUENCE OF DistributionPoint
    let (tag, body) = parse_tlv(der_bytes)?;
    if tag != 0x30 {
        return Err(format!("expected SEQUENCE, got 0x{tag:02x}"));
    }

    let mut pos = &body[..];
    while !pos.is_empty() {
        let (dp_tag, dp_body, rest) = parse_tlv_with_rest(pos)?;
        if dp_tag == 0x30 {
            // DistributionPoint SEQUENCE
            // Look for distributionPoint [0]
            if !dp_body.is_empty() {
                if let Ok((inner_tag, inner_body, _)) = parse_tlv_with_rest(&dp_body) {
                    if inner_tag == 0xA0 {
                        // DistributionPointName — look for fullName [0]
                        if let Ok((fn_tag, fn_body, _)) = parse_tlv_with_rest(&inner_body) {
                            if fn_tag == 0xA0 {
                                // GeneralNames — look for URI [6]
                                let mut gn_pos = &fn_body[..];
                                while !gn_pos.is_empty() {
                                    if let Ok((gn_tag, gn_body, gn_rest)) =
                                        parse_tlv_with_rest(gn_pos)
                                    {
                                        if gn_tag == 0x86 {
                                            // uniformResourceIdentifier [6] IMPLICIT IA5String
                                            if let Ok(uri) = std::str::from_utf8(&gn_body) {
                                                urls.push(uri.to_string());
                                            }
                                        }
                                        gn_pos = gn_rest;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        pos = rest;
    }

    Ok(urls)
}

// ── CRL content parsing and revocation checking ─────────────────────────────

/// A parsed revoked certificate entry from a CRL.
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    /// Serial number of the revoked certificate (leading-zero-stripped).
    pub serial_number: Vec<u8>,
    /// When the certificate was revoked.
    pub revocation_time: chrono::DateTime<chrono::Utc>,
    /// Reason for revocation, if present in CRL entry extensions.
    pub reason: RevocationReason,
}

/// Parsed contents of a CRL's TBSCertList.
#[derive(Debug)]
pub struct ParsedCrl {
    /// Raw TBS bytes (for signature verification).
    pub tbs_bytes: Vec<u8>,
    /// Signature algorithm (OID plus any parameters, e.g. RSASSA-PSS-params).
    pub signature_algorithm: spki::AlgorithmIdentifierOwned,
    /// Raw signature bytes (BIT STRING contents, without the unused-bits byte).
    pub signature_bytes: Vec<u8>,
    /// CRL issuer distinguished name (raw DER of the Name SEQUENCE).
    pub issuer_der: Vec<u8>,
    /// thisUpdate timestamp.
    pub this_update: chrono::DateTime<chrono::Utc>,
    /// nextUpdate timestamp, if present.
    pub next_update: Option<chrono::DateTime<chrono::Utc>>,
    /// Revoked certificate entries.
    pub revoked_entries: Vec<RevokedEntry>,
}

/// Parse a DER-encoded CRL into its structural components.
///
/// ```text
/// CertificateList ::= SEQUENCE {
///     tbsCertList          TBSCertList,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
///
/// TBSCertList ::= SEQUENCE {
///     version              Version OPTIONAL (v2 = INTEGER 1),
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     thisUpdate           Time,
///     nextUpdate           Time OPTIONAL,
///     revokedCertificates  SEQUENCE OF SEQUENCE { ... } OPTIONAL,
///     crlExtensions    [0] Extensions OPTIONAL
/// }
/// ```
pub fn parse_crl(crl_der: &[u8]) -> Result<ParsedCrl, LtvError> {
    // Outer SEQUENCE: CertificateList
    let (outer_tag, outer_body) =
        parse_tlv(crl_der).map_err(|e| LtvError::Crl(format!("CRL outer SEQUENCE: {e}")))?;
    if outer_tag != 0x30 {
        return Err(LtvError::Crl(format!(
            "expected CRL SEQUENCE (0x30), got 0x{outer_tag:02x}"
        )));
    }

    // Parse the three children: tbsCertList, signatureAlgorithm, signatureValue
    let (tbs_tag, tbs_value, rest) = parse_tlv_with_rest(&outer_body)
        .map_err(|e| LtvError::Crl(format!("CRL tbsCertList: {e}")))?;
    if tbs_tag != 0x30 {
        return Err(LtvError::Crl(format!(
            "expected tbsCertList SEQUENCE, got 0x{tbs_tag:02x}"
        )));
    }
    // Reconstruct full TBS DER (tag + length + value) for signature verification
    let tbs_start = crl_der.len() - outer_body.len();
    let tbs_end = crl_der.len() - outer_body.len() + (outer_body.len() - rest.len());
    let tbs_bytes = crl_der[tbs_start..tbs_end].to_vec();

    // signatureAlgorithm AlgorithmIdentifier (SEQUENCE). Keep the full
    // structure (OID + parameters) so RSASSA-PSS-params are available when the
    // signature is verified, rather than discarding everything but the OID.
    use der::Decode as _;
    let sig_alg_input = rest;
    let (sig_alg_tag, _sig_alg_body, rest) = parse_tlv_with_rest(sig_alg_input)
        .map_err(|e| LtvError::Crl(format!("CRL sigAlg: {e}")))?;
    if sig_alg_tag != 0x30 {
        return Err(LtvError::Crl(format!(
            "expected signatureAlgorithm SEQUENCE, got 0x{sig_alg_tag:02x}"
        )));
    }
    let sig_alg_der = &sig_alg_input[..sig_alg_input.len() - rest.len()];
    let signature_algorithm = spki::AlgorithmIdentifierOwned::from_der(sig_alg_der)
        .map_err(|e| LtvError::Crl(format!("CRL signatureAlgorithm decode: {e}")))?;

    // signatureValue BIT STRING
    let (sig_val_tag, sig_val_body, _) =
        parse_tlv_with_rest(rest).map_err(|e| LtvError::Crl(format!("CRL sigValue: {e}")))?;
    if sig_val_tag != 0x03 {
        return Err(LtvError::Crl(format!(
            "expected signatureValue BIT STRING (0x03), got 0x{sig_val_tag:02x}"
        )));
    }
    // BIT STRING: first byte is unused-bits count (should be 0)
    if sig_val_body.is_empty() {
        return Err(LtvError::Crl("empty signature BIT STRING".into()));
    }
    let signature_bytes = sig_val_body[1..].to_vec();

    // Parse TBSCertList body
    let mut tbs_pos = &tbs_value[..];

    // Optional: version [0] EXPLICIT INTEGER (v2 = 1)
    if !tbs_pos.is_empty() && tbs_pos[0] == 0x02 {
        // Check if first field is an INTEGER — could be version if small,
        // or could be the AlgorithmIdentifier. Actually version is optional
        // and v1 CRLs might omit it. The next field after optional version
        // is a SEQUENCE (AlgorithmIdentifier). Let's peek:
        // If we see INTEGER, skip it as version.
        let (_, _, r) = parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Crl(format!("CRL version: {e}")))?;
        tbs_pos = r;
    }

    // signature AlgorithmIdentifier (SEQUENCE) — skip, we got it from outer
    if !tbs_pos.is_empty() {
        let (tag, _, r) = parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Crl(format!("CRL inner sigAlg: {e}")))?;
        if tag == 0x30 {
            tbs_pos = r;
        }
    }

    // issuer Name (SEQUENCE)
    let (issuer_tag, _issuer_body, rest_after_issuer) = parse_tlv_with_rest(tbs_pos)
        .map_err(|e| LtvError::Crl(format!("CRL issuer: {e}")))?;
    if issuer_tag != 0x30 {
        return Err(LtvError::Crl(format!(
            "expected issuer SEQUENCE, got 0x{issuer_tag:02x}"
        )));
    }
    // Capture raw issuer DER (full TLV)
    let issuer_len = tbs_pos.len() - rest_after_issuer.len();
    let issuer_der = tbs_pos[..issuer_len].to_vec();
    tbs_pos = rest_after_issuer;

    // thisUpdate Time (UTCTime 0x17 or GeneralizedTime 0x18)
    let (time_tag, time_body, rest_after_this) = parse_tlv_with_rest(tbs_pos)
        .map_err(|e| LtvError::Crl(format!("CRL thisUpdate: {e}")))?;
    let this_update = parse_x509_time(time_tag, time_body)
        .map_err(|e| LtvError::Crl(format!("CRL thisUpdate parse: {e}")))?;
    tbs_pos = rest_after_this;

    // nextUpdate Time OPTIONAL
    let mut next_update = None;
    if !tbs_pos.is_empty() && (tbs_pos[0] == 0x17 || tbs_pos[0] == 0x18) {
        let (nt_tag, nt_body, r) = parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Crl(format!("CRL nextUpdate: {e}")))?;
        next_update = Some(
            parse_x509_time(nt_tag, nt_body)
                .map_err(|e| LtvError::Crl(format!("CRL nextUpdate parse: {e}")))?,
        );
        tbs_pos = r;
    }

    // revokedCertificates SEQUENCE OF OPTIONAL
    let mut revoked_entries = Vec::new();
    if !tbs_pos.is_empty() && tbs_pos[0] == 0x30 {
        let (rc_tag, rc_body, r) = parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Crl(format!("CRL revokedCertificates: {e}")))?;
        if rc_tag == 0x30 {
            parse_revoked_certificates(rc_body, &mut revoked_entries)?;
        }
        tbs_pos = r;
    }
    // Remaining: optional [0] crlExtensions — we skip for now
    let _ = tbs_pos;

    Ok(ParsedCrl {
        tbs_bytes,
        signature_algorithm,
        signature_bytes,
        issuer_der,
        this_update,
        next_update,
        revoked_entries,
    })
}

/// Parse the revokedCertificates SEQUENCE body.
///
/// ```text
/// revokedCertificates ::= SEQUENCE OF SEQUENCE {
///     userCertificate    CertificateSerialNumber (INTEGER),
///     revocationDate     Time,
///     crlEntryExtensions Extensions OPTIONAL
/// }
/// ```
fn parse_revoked_certificates(
    body: &[u8],
    entries: &mut Vec<RevokedEntry>,
) -> Result<(), LtvError> {
    let mut pos = body;
    while !pos.is_empty() {
        let (entry_tag, entry_body, rest) = parse_tlv_with_rest(pos)
            .map_err(|e| LtvError::Crl(format!("revoked entry: {e}")))?;
        if entry_tag != 0x30 {
            return Err(LtvError::Crl(format!(
                "expected revoked entry SEQUENCE, got 0x{entry_tag:02x}"
            )));
        }

        // userCertificate INTEGER
        let (serial_tag, serial_body, entry_rest) = parse_tlv_with_rest(entry_body)
            .map_err(|e| LtvError::Crl(format!("revoked serial: {e}")))?;
        if serial_tag != 0x02 {
            return Err(LtvError::Crl(format!(
                "expected serial INTEGER (0x02), got 0x{serial_tag:02x}"
            )));
        }
        let serial_number = parse_integer_body(serial_body);

        // revocationDate Time
        let (time_tag, time_body, entry_rest2) = parse_tlv_with_rest(entry_rest)
            .map_err(|e| LtvError::Crl(format!("revocation date: {e}")))?;
        let revocation_time = parse_x509_time(time_tag, time_body)
            .map_err(|e| LtvError::Crl(format!("revocation date parse: {e}")))?;

        // crlEntryExtensions OPTIONAL — look for reason code
        let reason = parse_revocation_reason(entry_rest2);

        entries.push(RevokedEntry {
            serial_number,
            revocation_time,
            reason,
        });

        pos = rest;
    }
    Ok(())
}

/// Parse optional CRL entry extensions to find a reason code.
///
/// The reason code extension (OID 2.5.29.21) contains an ENUMERATED value.
fn parse_revocation_reason(extensions_area: &[u8]) -> RevocationReason {
    if extensions_area.is_empty() {
        return RevocationReason::Unspecified;
    }

    // Extensions is a SEQUENCE OF Extension
    let Ok((tag, ext_body, _)) = parse_tlv_with_rest(extensions_area) else {
        return RevocationReason::Unspecified;
    };
    if tag != 0x30 {
        return RevocationReason::Unspecified;
    }

    // CRL reason code OID: 2.5.29.21
    let reason_oid_bytes: &[u8] = &[0x55, 0x1D, 0x15]; // 2.5.29.21

    // Walk through extensions
    let mut pos = &ext_body[..];
    while !pos.is_empty() {
        let Ok((ext_tag, ext_value, rest)) = parse_tlv_with_rest(pos) else {
            break;
        };
        if ext_tag == 0x30 {
            // Extension SEQUENCE: OID + optional critical BOOLEAN + value OCTET STRING
            if let Some(oid_body) = find_tagged_value(ext_value, 0x06) {
                if oid_body == reason_oid_bytes {
                    // Found reason code extension — value is in OCTET STRING
                    if let Some(octet_body) = find_tagged_value(ext_value, 0x04) {
                        // Inside the OCTET STRING is an ENUMERATED value
                        if let Some(enum_body) = find_tagged_value(octet_body, 0x0A) {
                            if !enum_body.is_empty() {
                                return RevocationReason::from_code(enum_body[0]);
                            }
                        }
                    }
                }
            }
        }
        pos = rest;
    }

    RevocationReason::Unspecified
}

/// Verify a CRL's signature against the issuer's public key.
///
/// Extracts the issuer's SPKI, then delegates to
/// [`crate::crypto::verify::verify_signature_by_algid`] so RSASSA-PSS
/// parameters are honoured.
pub fn verify_crl_signature(
    parsed_crl: &ParsedCrl,
    issuer: &Certificate,
) -> Result<(), LtvError> {
    verify_crl_signature_with_policy(
        parsed_crl,
        issuer,
        &crate::crypto::verify::SignaturePolicy::default(),
    )
}

/// Like [`verify_crl_signature`] but with an explicit
/// [`SignaturePolicy`](crate::crypto::verify::SignaturePolicy). The default
/// rejects CRLs signed with MD5/SHA-1/SHA-224.
pub fn verify_crl_signature_with_policy(
    parsed_crl: &ParsedCrl,
    issuer: &Certificate,
    policy: &crate::crypto::verify::SignaturePolicy,
) -> Result<(), LtvError> {
    use der::Encode;

    let spki_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| LtvError::Crl(format!("issuer SPKI encode failed: {e}")))?;

    crate::crypto::verify::verify_signature_by_algid_with_policy(
        &parsed_crl.tbs_bytes,
        &parsed_crl.signature_bytes,
        &spki_der,
        &parsed_crl.signature_algorithm,
        policy,
    )
    .map_err(|e| LtvError::Crl(format!("CRL signature verification failed: {e}")))
}

/// Check whether a certificate is revoked according to a CRL.
///
/// Performs the full CRL validation pipeline:
/// 1. Parse CRL structure
/// 2. Verify CRL signature against issuer's public key
/// 3. Check CRL freshness (thisUpdate/nextUpdate vs validation_time)
/// 4. Verify CRL issuer DN matches the certificate's issuer
/// 5. Search for the certificate's serial number in revoked entries
/// 6. Time-aware: if `revocationDate > validation_time` → `Valid`
///
/// Returns a [`ValidationStatus`] indicating the result.
pub fn check_revocation(
    crl_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<ValidationStatus, LtvError> {
    check_revocation_with_policy(
        crl_der,
        cert,
        issuer,
        validation_time,
        &crate::crypto::verify::SignaturePolicy::default(),
    )
}

/// Like [`check_revocation`] but with an explicit
/// [`SignaturePolicy`](crate::crypto::verify::SignaturePolicy) for the CRL
/// signature check. The default rejects CRLs signed with MD5/SHA-1/SHA-224.
pub fn check_revocation_with_policy(
    crl_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
) -> Result<ValidationStatus, LtvError> {
    let now = validation_time.unwrap_or_else(chrono::Utc::now);

    // 1. Parse CRL
    let parsed = parse_crl(crl_der)?;

    // 2. Verify CRL signature
    verify_crl_signature_with_policy(&parsed, issuer, policy)?;

    // 3. Check CRL freshness: nextUpdate should be in the future
    if let Some(next_update) = parsed.next_update {
        if now > next_update {
            log::warn!("CRL is stale: nextUpdate={next_update}, validation_time={now}");
            // Stale CRL — we still process it but log a warning.
            // The Java stack treats stale CRLs as valid for revocation
            // checking but flags it in diagnostics.
        }
    }

    // 4. Verify CRL issuer matches cert's issuer
    // We compare raw DER issuer names
    let cert_issuer_der = get_cert_issuer_der(cert)?;
    if parsed.issuer_der != cert_issuer_der {
        return Err(LtvError::Crl(
            "CRL issuer does not match certificate issuer".into(),
        ));
    }

    // 5. Get the certificate's serial number for lookup
    let cert_serial = get_cert_serial_body(cert);

    // 6. Search for serial number in revoked entries
    for entry in &parsed.revoked_entries {
        if integer_bodies_equal(&entry.serial_number, &cert_serial) {
            // Found! Time-aware check: if revocationDate > validation_time → Valid
            if entry.revocation_time > now {
                log::debug!(
                    "cert serial found in CRL but revocation_time ({}) is in the future relative to validation_time ({})",
                    entry.revocation_time, now
                );
                return Ok(ValidationStatus::Valid {
                    source: RevocationSource::Crl,
                    checked_at: now,
                });
            }

            return Ok(ValidationStatus::Revoked {
                source: RevocationSource::Crl,
                reason: entry.reason,
                revocation_time: entry.revocation_time,
            });
        }
    }

    // Serial not found in revoked list → Valid
    Ok(ValidationStatus::Valid {
        source: RevocationSource::Crl,
        checked_at: now,
    })
}

/// Extract the raw DER encoding of a certificate's issuer Name.
fn get_cert_issuer_der(cert: &Certificate) -> Result<Vec<u8>, LtvError> {
    use der::Encode;
    cert.tbs_certificate
        .issuer
        .to_der()
        .map_err(|e| LtvError::Crl(format!("cert issuer DER encode failed: {e}")))
}

/// Extract the serial number body from a certificate (stripped of leading zero padding).
fn get_cert_serial_body(cert: &Certificate) -> Vec<u8> {
    let serial = &cert.tbs_certificate.serial_number;
    let bytes = serial.as_bytes();
    parse_integer_body(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der_utils::{encode_integer_u64, encode_sequence_from_parts, encode_sequence_raw, encode_tlv};
    use der::{Decode, Encode};

    #[test]
    fn test_crl_client_default() {
        let client = CrlClient::new();
        assert_eq!(client.grace_period, Duration::from_secs(3600));
    }

    #[test]
    fn test_crl_client_builder() {
        let client = CrlClient::new()
            .timeout(Duration::from_secs(10))
            .grace_period(Duration::from_secs(7200));
        assert_eq!(client.grace_period, Duration::from_secs(7200));
    }

    #[test]
    fn test_extract_crl_urls_no_extensions() {
        // A certificate without CRL DP extensions should return empty
        let cert_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        // Root CAs typically don't have CRL DPs
        let pem_data = pem_rfc7468::decode_vec(cert_pem.as_bytes());
        if let Ok((_label, der)) = pem_data {
            if let Ok(cert) = Certificate::from_der(&der) {
                let urls = CrlClient::extract_crl_urls(&cert);
                // Root CA may or may not have CRL DPs, just ensure no panic
                let _ = urls;
            }
        }
    }

    // ── CRL content parsing tests ─────────────────────────────────────

    /// Build a synthetic DER-encoded CRL signed by the test intermediate CA.
    ///
    /// This constructs a minimal CRL by hand:
    /// - TBSCertList with version, AlgId, issuer, thisUpdate, revokedCerts
    /// - Signs it with the intermediate CA key
    fn build_test_crl(
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
        revoked_serials: &[(Vec<u8>, &str)], // (serial_bytes, "YYMMDDHHMMSSZ")
    ) -> Vec<u8> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Signer;
        use rsa::signature::SignatureEncoding;
        use rsa::pkcs8::DecodePrivateKey;
        use sha2::Sha256;

        // Build TBSCertList body
        let mut tbs_body = Vec::new();

        // version INTEGER 1 (v2)
        tbs_body.extend_from_slice(&encode_integer_u64(1));

        // signature AlgorithmIdentifier: sha256WithRSAEncryption
        let sha256_rsa_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        let alg_id = encode_sequence_from_parts(&[sha256_rsa_oid, &[0x05, 0x00]]);
        tbs_body.extend_from_slice(&alg_id);

        // issuer Name — use the issuer cert's subject DER
        let issuer_name_der = issuer_cert
            .tbs_certificate
            .subject
            .to_der()
            .unwrap();
        tbs_body.extend_from_slice(&issuer_name_der);

        // thisUpdate UTCTime
        let this_update_utc = encode_tlv(0x17, b"260101000000Z");
        tbs_body.extend_from_slice(&this_update_utc);

        // nextUpdate UTCTime
        let next_update_utc = encode_tlv(0x17, b"270101000000Z");
        tbs_body.extend_from_slice(&next_update_utc);

        // revokedCertificates SEQUENCE OF
        if !revoked_serials.is_empty() {
            let mut revoked_body = Vec::new();
            for (serial, time_str) in revoked_serials {
                // Each entry: SEQUENCE { INTEGER serial, UTCTime revocationDate }
                let serial_tlv = encode_tlv(0x02, serial);
                let time_tlv = encode_tlv(0x17, time_str.as_bytes());
                let entry = encode_sequence_from_parts(&[&serial_tlv, &time_tlv]);
                revoked_body.extend_from_slice(&entry);
            }
            let revoked_seq = encode_sequence_raw(&revoked_body);
            tbs_body.extend_from_slice(&revoked_seq);
        }

        // Wrap as TBSCertList SEQUENCE
        let tbs_der = encode_sequence_raw(&tbs_body);

        // Sign TBS with issuer's RSA key
        let key_der = pem_rfc7468::decode_vec(issuer_key_pem.as_bytes())
            .unwrap()
            .1;
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_der(&key_der).unwrap();
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature: rsa::pkcs1v15::Signature = signing_key.sign(&tbs_der);
        let sig_bytes = signature.to_vec();

        // Build outer CertificateList SEQUENCE
        let outer_alg_id = alg_id.clone();
        // BIT STRING: 0x00 unused bits prefix + signature bytes
        let mut bit_string_value = vec![0x00];
        bit_string_value.extend_from_slice(&sig_bytes);
        let sig_bit_string = encode_tlv(0x03, &bit_string_value);

        let cert_list =
            encode_sequence_from_parts(&[&tbs_der, &outer_alg_id, &sig_bit_string]);
        cert_list
    }

    fn load_test_cert(pem_str: &str) -> Certificate {
        let (_, der) = pem_rfc7468::decode_vec(pem_str.as_bytes()).unwrap();
        Certificate::from_der(&der).unwrap()
    }

    fn intermediate_ca_cert() -> Certificate {
        let pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_cert.pem"
        ));
        load_test_cert(pem)
    }

    fn intermediate_ca_key_pem() -> &'static str {
        // This is generated by gen-test-fixtures.sh and is gitignored.
        // Tests that need it should check for its existence.
        // For CI, the fixture script must be run first.
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_key.pem"
        )
    }

    fn signer_cert() -> Certificate {
        let pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        load_test_cert(pem)
    }

    #[test]
    fn test_parse_crl_empty_revoked_list() {
        // We need the intermediate CA key to sign. If it doesn't exist, skip.
        let key_path = intermediate_ca_key_pem();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found (run gen-test-fixtures.sh)");
            return;
        };

        let issuer = intermediate_ca_cert();
        let crl_der = build_test_crl(&issuer, &key_pem, &[]);
        let parsed = parse_crl(&crl_der).unwrap();

        assert!(parsed.revoked_entries.is_empty());
        assert!(parsed.next_update.is_some());
        assert_eq!(
            parsed.this_update.to_rfc3339(),
            "2026-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn test_parse_crl_with_revoked_entries() {
        let key_path = intermediate_ca_key_pem();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let revoked = vec![
            (vec![0x01], "250601120000Z"),
            (vec![0x00, 0xFF], "250701120000Z"),
        ];
        let crl_der = build_test_crl(&issuer, &key_pem, &revoked);
        let parsed = parse_crl(&crl_der).unwrap();

        assert_eq!(parsed.revoked_entries.len(), 2);
        assert_eq!(parsed.revoked_entries[0].serial_number, vec![0x01]);
        assert_eq!(parsed.revoked_entries[1].serial_number, vec![0xFF]);
    }

    #[test]
    fn test_verify_crl_signature() {
        let key_path = intermediate_ca_key_pem();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let crl_der = build_test_crl(&issuer, &key_pem, &[]);
        let parsed = parse_crl(&crl_der).unwrap();

        let result = verify_crl_signature(&parsed, &issuer);
        assert!(result.is_ok(), "CRL signature should verify: {result:?}");
    }

    #[test]
    fn test_verify_crl_signature_wrong_issuer() {
        let key_path = intermediate_ca_key_pem();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let crl_der = build_test_crl(&issuer, &key_pem, &[]);
        let parsed = parse_crl(&crl_der).unwrap();

        // Use a different cert (signer) as "issuer" — should fail
        let wrong_issuer = signer_cert();
        let result = verify_crl_signature(&parsed, &wrong_issuer);
        assert!(result.is_err(), "wrong issuer should fail verification");
    }

    #[test]
    fn test_check_revocation_not_revoked() {
        let key_path = intermediate_ca_key_pem();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        // CRL with no revoked entries
        let crl_der = build_test_crl(&issuer, &key_pem, &[]);
        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status = check_revocation(&crl_der, &cert, &issuer, Some(validation_time)).unwrap();
        assert!(status.is_valid(), "should be valid: {status}");
    }

    #[test]
    fn test_check_revocation_cert_is_revoked() {
        let key_path = intermediate_ca_key_pem();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        // Get the signer cert's serial number
        let serial = get_cert_serial_body(&cert);

        // CRL with the signer's serial revoked
        let revoked = vec![(serial, "250601120000Z")];
        let crl_der = build_test_crl(&issuer, &key_pem, &revoked);
        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status = check_revocation(&crl_der, &cert, &issuer, Some(validation_time)).unwrap();
        assert!(status.is_revoked(), "should be revoked: {status}");
    }

    #[test]
    fn test_check_revocation_time_aware_future_revocation() {
        let key_path = intermediate_ca_key_pem();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let serial = get_cert_serial_body(&cert);

        // Revocation date is 2027-01-01 but validation_time is 2026-06-01
        // → cert should be VALID at validation_time
        let revoked = vec![(serial, "270101120000Z")];
        let crl_der = build_test_crl(&issuer, &key_pem, &revoked);
        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status = check_revocation(&crl_der, &cert, &issuer, Some(validation_time)).unwrap();
        assert!(
            status.is_valid(),
            "should be valid (revocation in future): {status}"
        );
    }

    #[test]
    fn test_parse_crl_invalid_data() {
        let result = parse_crl(&[0x04, 0x00]); // OCTET STRING, not SEQUENCE
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("SEQUENCE"));
    }

    #[test]
    fn test_parse_revocation_reason_unspecified() {
        // No extensions → Unspecified
        let reason = parse_revocation_reason(&[]);
        assert_eq!(reason, RevocationReason::Unspecified);
    }
}
