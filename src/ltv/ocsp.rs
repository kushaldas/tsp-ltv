//! OCSP client, response parsing, and revocation checking.
//!
//! Builds OCSP requests (with optional nonce), sends them to OCSP responders
//! discovered from certificate AIA extensions, parses responses per RFC 6960,
//! verifies responder signatures, and checks revocation status.
//!
//! # RFC 6960 Structure (simplified)
//!
//! ```text
//! OCSPResponse ::= SEQUENCE {
//!     responseStatus   OCSPResponseStatus (ENUMERATED),
//!     responseBytes    [0] EXPLICIT ResponseBytes OPTIONAL
//! }
//! ResponseBytes ::= SEQUENCE {
//!     responseType     OID (id-pkix-ocsp-basic),
//!     response         OCTET STRING (DER BasicOCSPResponse)
//! }
//! BasicOCSPResponse ::= SEQUENCE {
//!     tbsResponseData  ResponseData,
//!     signatureAlgorithm AlgorithmIdentifier,
//!     signature         BIT STRING,
//!     certs        [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
//! }
//! ResponseData ::= SEQUENCE {
//!     version          [0] EXPLICIT Version DEFAULT v1,
//!     responderID      ResponderID,
//!     producedAt       GeneralizedTime,
//!     responses        SEQUENCE OF SingleResponse,
//!     responseExtensions [1] EXPLICIT Extensions OPTIONAL
//! }
//! SingleResponse ::= SEQUENCE {
//!     certID           CertID,
//!     certStatus       CertStatus,
//!     thisUpdate       GeneralizedTime,
//!     nextUpdate   [0] EXPLICIT GeneralizedTime OPTIONAL,
//!     singleExtensions [1] EXPLICIT Extensions OPTIONAL
//! }
//! CertStatus ::= CHOICE {
//!     good    [0] IMPLICIT NULL,
//!     revoked [1] IMPLICIT RevokedInfo,
//!     unknown [2] IMPLICIT UnknownInfo
//! }
//! RevokedInfo ::= SEQUENCE {
//!     revocationTime    GeneralizedTime,
//!     revocationReason  [0] EXPLICIT CRLReason OPTIONAL
//! }
//! ```

use std::time::Duration;

use der::Encode;
use reqwest::Client;
use x509_cert::Certificate;

use crate::der_utils;
use crate::error::LtvError;
use crate::ltv::status::{RevocationReason, RevocationSource, ValidationStatus};

/// OCSP request Content-Type.
const OCSP_REQUEST_CONTENT_TYPE: &str = "application/ocsp-request";

/// OCSP good response status.
const OCSP_RESPONSE_SUCCESSFUL: u8 = 0;

/// OID for id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1).
const OCSP_BASIC_RESPONSE_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

/// OID for id-pkix-ocsp-nonce (1.3.6.1.5.5.7.48.1.2) — raw OID bytes.
const OCSP_NONCE_OID_BYTES: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

/// OID for id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9) — raw OID bytes.
const OCSP_SIGNING_EKU_OID_BYTES: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];

/// Nonce size in bytes (matches Java stack: 30 bytes).
const NONCE_SIZE: usize = 30;

// ── Parsed OCSP response types ─────────────────────────────────────

/// Cert status from an OCSP SingleResponse.
#[derive(Debug, Clone)]
pub enum CertStatus {
    /// Certificate is not revoked.
    Good,
    /// Certificate has been revoked.
    Revoked {
        /// When the certificate was revoked.
        revocation_time: chrono::DateTime<chrono::Utc>,
        /// Reason for revocation, if provided.
        reason: RevocationReason,
    },
    /// Responder doesn't know about this certificate.
    Unknown,
}

/// A parsed SingleResponse from an OCSP BasicOCSPResponse.
#[derive(Debug, Clone)]
pub struct SingleResponse {
    /// CertID hash algorithm OID bytes (raw, without tag/length).
    pub hash_algorithm_oid: Vec<u8>,
    /// Issuer name hash (from CertID).
    pub issuer_name_hash: Vec<u8>,
    /// Issuer key hash (from CertID).
    pub issuer_key_hash: Vec<u8>,
    /// Serial number of the certificate (leading-zero-stripped).
    pub serial_number: Vec<u8>,
    /// The revocation status.
    pub cert_status: CertStatus,
    /// thisUpdate for this response.
    pub this_update: chrono::DateTime<chrono::Utc>,
    /// nextUpdate (optional).
    pub next_update: Option<chrono::DateTime<chrono::Utc>>,
}

/// A parsed BasicOCSPResponse.
#[derive(Debug)]
pub struct ParsedBasicOcspResponse {
    /// Raw tbsResponseData bytes (for signature verification).
    pub tbs_response_data: Vec<u8>,
    /// Signature algorithm (OID plus any parameters, e.g. RSASSA-PSS-params).
    pub signature_algorithm: spki::AlgorithmIdentifierOwned,
    /// Raw signature bytes (BIT STRING contents, without unused-bits byte).
    pub signature_bytes: Vec<u8>,
    /// Responder ID — either byName (DER Name) or byKeyHash (OCTET STRING body).
    pub responder_id: ResponderId,
    /// producedAt timestamp.
    pub produced_at: chrono::DateTime<chrono::Utc>,
    /// Individual certificate responses.
    pub responses: Vec<SingleResponse>,
    /// Nonce from response extensions, if present.
    pub nonce: Option<Vec<u8>>,
    /// Embedded certificates (from [0] EXPLICIT SEQUENCE OF Certificate).
    pub embedded_certs_der: Vec<Vec<u8>>,
}

/// Responder identification.
#[derive(Debug, Clone)]
pub enum ResponderId {
    /// byName [1] — DER-encoded Name (the responder's DN).
    ByName(Vec<u8>),
    /// byKeyHash [2] — SHA-1 hash of responder's public key.
    ByKeyHash(Vec<u8>),
}

// ── OCSP client ────────────────────────────────────────────────────

/// OCSP client for querying certificate revocation status.
#[derive(Debug, Clone)]
pub struct OcspClient {
    http_client: Client,
    timeout: Duration,
}

impl OcspClient {
    /// Create a new OCSP client with default settings.
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
            timeout: Duration::from_secs(30),
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

    /// Extract OCSP responder URLs from a certificate's AIA extension.
    pub fn extract_ocsp_urls(cert: &Certificate) -> Vec<String> {
        extract_aia_urls(cert, AiaAccessMethod::Ocsp)
    }

    /// Fetch an OCSP response for a certificate.
    ///
    /// Builds an OCSP request for `cert` issued by `issuer`, sends it
    /// to the OCSP responder URL found in the certificate's AIA extension,
    /// and returns the raw DER-encoded OCSP response.
    pub async fn fetch_ocsp_response(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<Vec<u8>, LtvError> {
        let urls = Self::extract_ocsp_urls(cert);
        if urls.is_empty() {
            return Err(LtvError::Ocsp(
                "no OCSP responder URL in certificate AIA extension".into(),
            ));
        }

        // Build the OCSP request
        let ocsp_request = build_ocsp_request(cert, issuer)?;

        let mut last_error = None;

        for url in &urls {
            match self.send_ocsp_request(url, &ocsp_request).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::warn!("OCSP request to {url} failed: {e}");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LtvError::Ocsp("all OCSP responder URLs failed".into())))
    }

    /// Fetch an OCSP response with a nonce for replay protection.
    ///
    /// Returns `(response_der, nonce_bytes)` — the nonce must be passed
    /// to [`check_revocation`] for validation.
    pub async fn fetch_ocsp_response_with_nonce(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<(Vec<u8>, Vec<u8>), LtvError> {
        let urls = Self::extract_ocsp_urls(cert);
        if urls.is_empty() {
            return Err(LtvError::Ocsp(
                "no OCSP responder URL in certificate AIA extension".into(),
            ));
        }

        let (ocsp_request, nonce) = build_ocsp_request_with_nonce(cert, issuer)?;

        let mut last_error = None;

        for url in &urls {
            match self.send_ocsp_request(url, &ocsp_request).await {
                Ok(response) => return Ok((response, nonce)),
                Err(e) => {
                    log::warn!("OCSP request to {url} failed: {e}");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LtvError::Ocsp("all OCSP responder URLs failed".into())))
    }

    /// Send an OCSP request to the given URL.
    async fn send_ocsp_request(&self, url: &str, request_der: &[u8]) -> Result<Vec<u8>, LtvError> {
        log::debug!(
            "Sending OCSP request to {url} ({} bytes)",
            request_der.len()
        );

        let response = self
            .http_client
            .post(url)
            .header("Content-Type", OCSP_REQUEST_CONTENT_TYPE)
            .timeout(self.timeout)
            .body(request_der.to_vec())
            .send()
            .await
            .map_err(|e| LtvError::Ocsp(format!("OCSP request to {url} failed: {e}")))?;

        // Handle redirects — some responders redirect HTTP to HTTPS
        let status = response.status();
        if !status.is_success() {
            return Err(LtvError::Ocsp(format!(
                "OCSP responder {url} returned HTTP {status}"
            )));
        }

        let resp_bytes = response
            .bytes()
            .await
            .map_err(|e| LtvError::Ocsp(format!("failed to read OCSP response body: {e}")))?
            .to_vec();

        if resp_bytes.is_empty() {
            return Err(LtvError::Ocsp(format!(
                "OCSP responder {url} returned empty response"
            )));
        }

        // Basic validation: check it's a SEQUENCE (DER-encoded OCSPResponse)
        if resp_bytes[0] != 0x30 {
            return Err(LtvError::Ocsp(format!(
                "OCSP response from {url} does not appear to be DER-encoded"
            )));
        }

        // Validate the response status
        validate_ocsp_response_status(&resp_bytes)?;

        log::debug!("OCSP response from {url}: {} bytes", resp_bytes.len());

        Ok(resp_bytes)
    }
}

impl Default for OcspClient {
    fn default() -> Self {
        Self::new()
    }
}

// ── AIA extension parsing ──────────────────────────────────────────

/// AIA access method type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiaAccessMethod {
    /// OCSP (1.3.6.1.5.5.7.48.1)
    Ocsp,
    /// CA Issuers (1.3.6.1.5.5.7.48.2)
    CaIssuers,
}

/// Extract URLs from a certificate's Authority Information Access extension.
pub fn extract_aia_urls(cert: &Certificate, method: AiaAccessMethod) -> Vec<String> {
    let mut urls = Vec::new();

    // AIA extension OID: 1.3.6.1.5.5.7.1.1
    let aia_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

    let method_oid = match method {
        AiaAccessMethod::Ocsp => const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1"),
        AiaAccessMethod::CaIssuers => const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2"),
    };

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == aia_oid {
                if let Ok(parsed) = parse_aia_extension(ext.extn_value.as_bytes(), &method_oid) {
                    urls.extend(parsed);
                }
            }
        }
    }

    urls
}

/// Parse AIA extension value to extract URLs for a specific access method.
///
/// ```text
/// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
/// AccessDescription ::= SEQUENCE {
///     accessMethod    OBJECT IDENTIFIER,
///     accessLocation  GeneralName
/// }
/// ```
fn parse_aia_extension(
    der_bytes: &[u8],
    target_method_oid: &const_oid::ObjectIdentifier,
) -> Result<Vec<String>, LtvError> {
    let mut urls = Vec::new();

    let (tag, body) = der_utils::parse_tlv(der_bytes)
        .map_err(|e| LtvError::Ocsp(format!("AIA parse error: {e}")))?;
    if tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "AIA: expected SEQUENCE, got 0x{tag:02x}"
        )));
    }

    let target_oid_der = target_method_oid
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode target OID: {e}")))?;

    let mut pos = &body[..];
    while !pos.is_empty() {
        let (ad_tag, ad_body, rest) = der_utils::parse_tlv_with_rest(pos)
            .map_err(|e| LtvError::Ocsp(format!("AIA parse error: {e}")))?;
        if ad_tag == 0x30 {
            // AccessDescription SEQUENCE
            // First: accessMethod OID
            let (oid_tag, oid_body, ad_rest) = der_utils::parse_tlv_with_rest(ad_body)
                .map_err(|e| LtvError::Ocsp(format!("AIA parse error: {e}")))?;
            if oid_tag == 0x06 {
                let oid_tlv = der_utils::encode_tlv(0x06, oid_body);
                if oid_tlv == target_oid_der {
                    // Match — extract accessLocation GeneralName
                    // Look for uniformResourceIdentifier [6]
                    if !ad_rest.is_empty() {
                        let (gn_tag, gn_body, _) = der_utils::parse_tlv_with_rest(ad_rest)
                            .map_err(|e| LtvError::Ocsp(format!("AIA parse error: {e}")))?;
                        if gn_tag == 0x86 {
                            // [6] IMPLICIT IA5String — URI
                            if let Ok(uri) = std::str::from_utf8(gn_body) {
                                urls.push(uri.to_string());
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

// ── OCSP request building ──────────────────────────────────────────

/// Build an OCSP request for a certificate (without nonce).
///
/// ```text
/// OCSPRequest ::= SEQUENCE {
///     tbsRequest    TBSRequest,
///     optionalSignature [0] EXPLICIT Signature OPTIONAL
/// }
/// TBSRequest ::= SEQUENCE {
///     version           [0] EXPLICIT Version DEFAULT v1,
///     requestorName     [1] EXPLICIT GeneralName OPTIONAL,
///     requestList       SEQUENCE OF Request,
///     requestExtensions [2] EXPLICIT Extensions OPTIONAL
/// }
/// Request ::= SEQUENCE {
///     reqCert    CertID,
///     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
/// }
/// CertID ::= SEQUENCE {
///     hashAlgorithm     AlgorithmIdentifier,
///     issuerNameHash    OCTET STRING,
///     issuerKeyHash     OCTET STRING,
///     serialNumber      CertificateSerialNumber
/// }
/// ```
fn build_ocsp_request(cert: &Certificate, issuer: &Certificate) -> Result<Vec<u8>, LtvError> {
    let cert_id = build_cert_id(cert, issuer)?;

    // Request SEQUENCE { reqCert CertID }
    let request = der_utils::encode_sequence_from_parts(&[&cert_id]);

    // requestList SEQUENCE OF Request
    let request_list = der_utils::encode_sequence_from_parts(&[&request]);

    // TBSRequest SEQUENCE { requestList }
    let tbs_request = der_utils::encode_sequence_from_parts(&[&request_list]);

    // OCSPRequest SEQUENCE { tbsRequest }
    let ocsp_request = der_utils::encode_sequence_from_parts(&[&tbs_request]);

    Ok(ocsp_request)
}

/// Build an OCSP request with a random nonce extension.
///
/// Returns `(request_der, nonce_bytes)`.
pub fn build_ocsp_request_with_nonce(
    cert: &Certificate,
    issuer: &Certificate,
) -> Result<(Vec<u8>, Vec<u8>), LtvError> {
    let cert_id = build_cert_id(cert, issuer)?;

    // Request SEQUENCE { reqCert CertID }
    let request = der_utils::encode_sequence_from_parts(&[&cert_id]);

    // requestList SEQUENCE OF Request
    let request_list = der_utils::encode_sequence_from_parts(&[&request]);

    // Generate a 30-byte random nonce (matches Java stack)
    let nonce = generate_nonce();

    // Build nonce extension:
    // Extension ::= SEQUENCE {
    //     extnID    OID (id-pkix-ocsp-nonce),
    //     extnValue OCTET STRING (wrapping the nonce OCTET STRING)
    // }
    let nonce_oid_tlv = der_utils::encode_tlv(0x06, OCSP_NONCE_OID_BYTES);
    let nonce_inner = der_utils::encode_tlv(0x04, &nonce); // inner OCTET STRING
    let nonce_outer = der_utils::encode_tlv(0x04, &nonce_inner); // wrapped in extnValue OCTET STRING
    let nonce_ext = der_utils::encode_sequence_from_parts(&[&nonce_oid_tlv, &nonce_outer]);

    // Extensions SEQUENCE
    let extensions_seq = der_utils::encode_sequence_from_parts(&[&nonce_ext]);

    // requestExtensions [2] EXPLICIT Extensions
    let request_extensions = der_utils::encode_tlv(0xA2, &extensions_seq);

    // TBSRequest SEQUENCE { requestList, requestExtensions }
    let tbs_request = der_utils::encode_sequence_from_parts(&[&request_list, &request_extensions]);

    // OCSPRequest SEQUENCE { tbsRequest }
    let ocsp_request = der_utils::encode_sequence_from_parts(&[&tbs_request]);

    Ok((ocsp_request, nonce))
}

/// Build a CertID SEQUENCE for an OCSP request.
fn build_cert_id(cert: &Certificate, issuer: &Certificate) -> Result<Vec<u8>, LtvError> {
    // Hash the issuer's distinguished name
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode issuer name: {e}")))?;
    let issuer_name_hash = sha1_hash(&issuer_name_der);

    // Hash the issuer's public key
    let issuer_key_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec();
    let issuer_key_hash = sha1_hash(&issuer_key_der);

    // Serial number of the cert being checked
    let serial_der = cert
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode serial number: {e}")))?;

    // Build CertID
    let sha1_alg_id = build_sha1_algorithm_identifier()?;
    let issuer_name_hash_oct = der_utils::encode_tlv(0x04, &issuer_name_hash);
    let issuer_key_hash_oct = der_utils::encode_tlv(0x04, &issuer_key_hash);

    Ok(der_utils::encode_sequence_from_parts(&[
        &sha1_alg_id,
        &issuer_name_hash_oct,
        &issuer_key_hash_oct,
        &serial_der,
    ]))
}

/// Generate a cryptographically random nonce of NONCE_SIZE bytes.
fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce).expect("OS random number generator");
    nonce
}

/// Build SHA-1 AlgorithmIdentifier (SEQUENCE { OID, NULL }).
fn build_sha1_algorithm_identifier() -> Result<Vec<u8>, LtvError> {
    let sha1_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    let oid_der = sha1_oid
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("failed to encode SHA-1 OID: {e}")))?;
    let null_der = vec![0x05, 0x00]; // NULL
    Ok(der_utils::encode_sequence_from_parts(&[
        &oid_der, &null_der,
    ]))
}

// ── OCSP response parsing ──────────────────────────────────────────

/// Validate the OCSPResponse status field.
///
/// ```text
/// OCSPResponse ::= SEQUENCE {
///     responseStatus  OCSPResponseStatus,
///     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
/// }
/// OCSPResponseStatus ::= ENUMERATED { successful(0), ... }
/// ```
fn validate_ocsp_response_status(der_bytes: &[u8]) -> Result<(), LtvError> {
    let (tag, body) = der_utils::parse_tlv(der_bytes)
        .map_err(|e| LtvError::Ocsp(format!("OCSP response parse error: {e}")))?;
    if tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "OCSP response: expected SEQUENCE, got 0x{tag:02x}"
        )));
    }

    // First element: responseStatus ENUMERATED
    let (status_tag, status_body, _) = der_utils::parse_tlv_with_rest(&body)
        .map_err(|e| LtvError::Ocsp(format!("OCSP response parse error: {e}")))?;
    if status_tag != 0x0A {
        return Err(LtvError::Ocsp(format!(
            "OCSP response: expected ENUMERATED status, got 0x{status_tag:02x}"
        )));
    }

    if status_body.is_empty() {
        return Err(LtvError::Ocsp("OCSP response: empty status".into()));
    }

    let status = status_body[0];
    if status != OCSP_RESPONSE_SUCCESSFUL {
        return Err(LtvError::OcspResponderStatus(format!(
            "{} ({status})",
            ocsp_response_status_name(status)
        )));
    }

    Ok(())
}

/// Human-readable name for an OCSP `OCSPResponseStatus` code (RFC 6960 §4.2.1).
fn ocsp_response_status_name(status: u8) -> &'static str {
    match status {
        0 => "successful",
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "sigRequired",
        6 => "unauthorized",
        _ => "unknown",
    }
}

/// Parse a DER-encoded OCSPResponse into a BasicOCSPResponse.
///
/// Validates the response status and extracts the BasicOCSPResponse body.
pub fn parse_ocsp_response(response_der: &[u8]) -> Result<ParsedBasicOcspResponse, LtvError> {
    // OCSPResponse SEQUENCE
    let (outer_tag, outer_body) = der_utils::parse_tlv(response_der)
        .map_err(|e| LtvError::Ocsp(format!("OCSPResponse outer: {e}")))?;
    if outer_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected OCSPResponse SEQUENCE, got 0x{outer_tag:02x}"
        )));
    }

    // responseStatus ENUMERATED
    let (status_tag, status_body, rest) = der_utils::parse_tlv_with_rest(&outer_body)
        .map_err(|e| LtvError::Ocsp(format!("responseStatus: {e}")))?;
    if status_tag != 0x0A || status_body.is_empty() {
        return Err(LtvError::Ocsp("invalid responseStatus".into()));
    }
    if status_body[0] != OCSP_RESPONSE_SUCCESSFUL {
        // Responder-side / transient status (tryLater, internalError, ...) —
        // non-determinative, not an integrity failure. Typed distinctly so the
        // revocation orchestrator maps it to Unknown, not Invalid.
        return Err(LtvError::OcspResponderStatus(format!(
            "{} ({})",
            ocsp_response_status_name(status_body[0]),
            status_body[0]
        )));
    }

    // responseBytes [0] EXPLICIT ResponseBytes
    if rest.is_empty() {
        return Err(LtvError::Ocsp(
            "OCSP response successful but no responseBytes".into(),
        ));
    }
    let (rb_tag, rb_body, _) = der_utils::parse_tlv_with_rest(rest)
        .map_err(|e| LtvError::Ocsp(format!("responseBytes: {e}")))?;
    if rb_tag != 0xA0 {
        return Err(LtvError::Ocsp(format!(
            "expected responseBytes [0], got 0x{rb_tag:02x}"
        )));
    }

    // ResponseBytes SEQUENCE { responseType OID, response OCTET STRING }
    let (rb_seq_tag, rb_seq_body) = der_utils::parse_tlv(rb_body)
        .map_err(|e| LtvError::Ocsp(format!("ResponseBytes SEQUENCE: {e}")))?;
    if rb_seq_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected ResponseBytes SEQUENCE, got 0x{rb_seq_tag:02x}"
        )));
    }

    // responseType OID
    let (oid_tag, oid_body, rb_rest) = der_utils::parse_tlv_with_rest(&rb_seq_body)
        .map_err(|e| LtvError::Ocsp(format!("responseType OID: {e}")))?;
    if oid_tag != 0x06 {
        return Err(LtvError::Ocsp("expected responseType OID".into()));
    }
    if oid_body != OCSP_BASIC_RESPONSE_OID {
        return Err(LtvError::Ocsp(
            "responseType is not id-pkix-ocsp-basic".into(),
        ));
    }

    // response OCTET STRING (contains DER BasicOCSPResponse)
    let (oct_tag, oct_body, _) = der_utils::parse_tlv_with_rest(rb_rest)
        .map_err(|e| LtvError::Ocsp(format!("response OCTET STRING: {e}")))?;
    if oct_tag != 0x04 {
        return Err(LtvError::Ocsp("expected response OCTET STRING".into()));
    }

    // Parse BasicOCSPResponse
    parse_basic_ocsp_response(oct_body)
}

/// Parse a DER-encoded BasicOCSPResponse.
fn parse_basic_ocsp_response(der: &[u8]) -> Result<ParsedBasicOcspResponse, LtvError> {
    // BasicOCSPResponse SEQUENCE
    let (tag, body) =
        der_utils::parse_tlv(der).map_err(|e| LtvError::Ocsp(format!("BasicOCSPResponse: {e}")))?;
    if tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected BasicOCSPResponse SEQUENCE, got 0x{tag:02x}"
        )));
    }

    // tbsResponseData SEQUENCE
    let (tbs_tag, tbs_value, rest) = der_utils::parse_tlv_with_rest(&body)
        .map_err(|e| LtvError::Ocsp(format!("tbsResponseData: {e}")))?;
    if tbs_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected tbsResponseData SEQUENCE, got 0x{tbs_tag:02x}"
        )));
    }

    // Reconstruct TBS DER (tag + length + value) for signature verification
    let tbs_consumed = body.len() - rest.len();
    let tbs_response_data = body[..tbs_consumed].to_vec();

    // signatureAlgorithm AlgorithmIdentifier SEQUENCE. Keep the full structure
    // (OID + parameters) so RSASSA-PSS-params are available when the signature
    // is verified, rather than discarding everything but the OID.
    let sig_alg_input = rest;
    let (sig_alg_tag, _sig_alg_body, rest) = der_utils::parse_tlv_with_rest(sig_alg_input)
        .map_err(|e| LtvError::Ocsp(format!("signatureAlgorithm: {e}")))?;
    if sig_alg_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected signatureAlgorithm SEQUENCE, got 0x{sig_alg_tag:02x}"
        )));
    }
    let sig_alg_der = &sig_alg_input[..sig_alg_input.len() - rest.len()];
    let signature_algorithm = {
        use der::Decode as _;
        spki::AlgorithmIdentifierOwned::from_der(sig_alg_der)
            .map_err(|e| LtvError::Ocsp(format!("signatureAlgorithm decode: {e}")))?
    };

    // signature BIT STRING
    let (sig_tag, sig_body, rest) = der_utils::parse_tlv_with_rest(rest)
        .map_err(|e| LtvError::Ocsp(format!("signature BIT STRING: {e}")))?;
    if sig_tag != 0x03 {
        return Err(LtvError::Ocsp(format!(
            "expected signature BIT STRING, got 0x{sig_tag:02x}"
        )));
    }
    if sig_body.is_empty() {
        return Err(LtvError::Ocsp("empty signature BIT STRING".into()));
    }
    let signature_bytes = sig_body[1..].to_vec(); // skip unused-bits byte

    // certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
    let mut embedded_certs_der = Vec::new();
    if !rest.is_empty() {
        let (certs_tag, certs_body, _) = der_utils::parse_tlv_with_rest(rest)
            .map_err(|e| LtvError::Ocsp(format!("certs [0]: {e}")))?;
        if certs_tag == 0xA0 {
            // SEQUENCE OF Certificate
            let (seq_tag, seq_body) = der_utils::parse_tlv(certs_body)
                .map_err(|e| LtvError::Ocsp(format!("certs SEQUENCE: {e}")))?;
            if seq_tag == 0x30 {
                // Walk through certificates
                let mut cert_pos = &seq_body[..];
                while !cert_pos.is_empty() {
                    let (cert_tag, _cert_value, cert_rest) =
                        der_utils::parse_tlv_with_rest(cert_pos)
                            .map_err(|e| LtvError::Ocsp(format!("embedded cert: {e}")))?;
                    if cert_tag == 0x30 {
                        let cert_len = cert_pos.len() - cert_rest.len();
                        embedded_certs_der.push(cert_pos[..cert_len].to_vec());
                    }
                    cert_pos = cert_rest;
                }
            }
        }
    }

    // Parse tbsResponseData body
    let mut tbs_pos = tbs_value;

    // version [0] EXPLICIT INTEGER — optional, default v1
    if !tbs_pos.is_empty() && tbs_pos[0] == 0xA0 {
        let (_, _, r) = der_utils::parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Ocsp(format!("version: {e}")))?;
        tbs_pos = r;
    }

    // responderID: CHOICE {
    //   byName [1] EXPLICIT Name,
    //   byKeyHash [2] EXPLICIT OCTET STRING
    // }
    let responder_id = if !tbs_pos.is_empty() && tbs_pos[0] == 0xA1 {
        // byName [1]
        let (_, name_body, r) = der_utils::parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Ocsp(format!("responderID byName: {e}")))?;
        tbs_pos = r;
        ResponderId::ByName(name_body.to_vec())
    } else if !tbs_pos.is_empty() && tbs_pos[0] == 0xA2 {
        // byKeyHash [2]
        let (_, hash_wrapper, r) = der_utils::parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Ocsp(format!("responderID byKeyHash: {e}")))?;
        tbs_pos = r;
        // Inside [2]: OCTET STRING
        let (oct_tag, oct_body, _) = der_utils::parse_tlv_with_rest(hash_wrapper)
            .map_err(|e| LtvError::Ocsp(format!("responderID keyHash OCTET STRING: {e}")))?;
        if oct_tag != 0x04 {
            return Err(LtvError::Ocsp(format!(
                "expected OCTET STRING in byKeyHash, got 0x{oct_tag:02x}"
            )));
        }
        ResponderId::ByKeyHash(oct_body.to_vec())
    } else {
        return Err(LtvError::Ocsp("missing or unknown responderID".into()));
    };

    // producedAt GeneralizedTime
    let (pa_tag, pa_body, rest_after_pa) = der_utils::parse_tlv_with_rest(tbs_pos)
        .map_err(|e| LtvError::Ocsp(format!("producedAt: {e}")))?;
    if pa_tag != 0x18 {
        return Err(LtvError::Ocsp(format!(
            "expected producedAt GeneralizedTime (0x18), got 0x{pa_tag:02x}"
        )));
    }
    let produced_at = der_utils::parse_generalized_time(pa_body)
        .map_err(|e| LtvError::Ocsp(format!("producedAt parse: {e}")))?;
    tbs_pos = rest_after_pa;

    // responses SEQUENCE OF SingleResponse
    let (resp_seq_tag, resp_seq_body, rest_after_responses) =
        der_utils::parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Ocsp(format!("responses SEQUENCE: {e}")))?;
    if resp_seq_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected responses SEQUENCE, got 0x{resp_seq_tag:02x}"
        )));
    }

    let mut responses = Vec::new();
    let mut sr_pos = resp_seq_body;
    while !sr_pos.is_empty() {
        let (sr_tag, sr_body, sr_rest) = der_utils::parse_tlv_with_rest(sr_pos)
            .map_err(|e| LtvError::Ocsp(format!("SingleResponse: {e}")))?;
        if sr_tag == 0x30 {
            responses.push(parse_single_response(sr_body)?);
        }
        sr_pos = sr_rest;
    }

    tbs_pos = rest_after_responses;

    // responseExtensions [1] EXPLICIT Extensions OPTIONAL
    let mut nonce = None;
    if !tbs_pos.is_empty() && tbs_pos[0] == 0xA1 {
        let (_, ext_wrapper, _) = der_utils::parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Ocsp(format!("responseExtensions: {e}")))?;
        nonce = extract_nonce_from_extensions(ext_wrapper);
    }

    Ok(ParsedBasicOcspResponse {
        tbs_response_data,
        signature_algorithm,
        signature_bytes,
        responder_id,
        produced_at,
        responses,
        nonce,
        embedded_certs_der,
    })
}

/// Parse a SingleResponse from its SEQUENCE body.
fn parse_single_response(body: &[u8]) -> Result<SingleResponse, LtvError> {
    let mut pos = body;

    // certID SEQUENCE
    let (cid_tag, cid_body, rest) =
        der_utils::parse_tlv_with_rest(pos).map_err(|e| LtvError::Ocsp(format!("CertID: {e}")))?;
    if cid_tag != 0x30 {
        return Err(LtvError::Ocsp(format!(
            "expected CertID SEQUENCE, got 0x{cid_tag:02x}"
        )));
    }
    pos = rest;

    // Parse CertID body: hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber
    let (alg_tag, alg_body, cid_rest) = der_utils::parse_tlv_with_rest(cid_body)
        .map_err(|e| LtvError::Ocsp(format!("CertID hashAlgorithm: {e}")))?;
    if alg_tag != 0x30 {
        return Err(LtvError::Ocsp("expected hashAlgorithm SEQUENCE".into()));
    }
    // Extract OID from AlgorithmIdentifier
    let (oid_tag, oid_body, _) = der_utils::parse_tlv_with_rest(alg_body)
        .map_err(|e| LtvError::Ocsp(format!("hashAlgorithm OID: {e}")))?;
    if oid_tag != 0x06 {
        return Err(LtvError::Ocsp("expected OID in hashAlgorithm".into()));
    }
    let hash_algorithm_oid = oid_body.to_vec();

    // issuerNameHash OCTET STRING
    let (inh_tag, inh_body, cid_rest) = der_utils::parse_tlv_with_rest(cid_rest)
        .map_err(|e| LtvError::Ocsp(format!("issuerNameHash: {e}")))?;
    if inh_tag != 0x04 {
        return Err(LtvError::Ocsp(
            "expected issuerNameHash OCTET STRING".into(),
        ));
    }
    let issuer_name_hash = inh_body.to_vec();

    // issuerKeyHash OCTET STRING
    let (ikh_tag, ikh_body, cid_rest) = der_utils::parse_tlv_with_rest(cid_rest)
        .map_err(|e| LtvError::Ocsp(format!("issuerKeyHash: {e}")))?;
    if ikh_tag != 0x04 {
        return Err(LtvError::Ocsp("expected issuerKeyHash OCTET STRING".into()));
    }
    let issuer_key_hash = ikh_body.to_vec();

    // serialNumber INTEGER
    let (sn_tag, sn_body, _) = der_utils::parse_tlv_with_rest(cid_rest)
        .map_err(|e| LtvError::Ocsp(format!("serialNumber: {e}")))?;
    if sn_tag != 0x02 {
        return Err(LtvError::Ocsp("expected serialNumber INTEGER".into()));
    }
    let serial_number = der_utils::parse_integer_body(sn_body);

    // certStatus: CHOICE { good [0], revoked [1], unknown [2] }
    let (cs_tag, cs_body, rest_after_status) = der_utils::parse_tlv_with_rest(pos)
        .map_err(|e| LtvError::Ocsp(format!("certStatus: {e}")))?;
    pos = rest_after_status;

    let cert_status = match cs_tag {
        0x80 => {
            // good [0] IMPLICIT NULL
            CertStatus::Good
        }
        0xA1 => {
            // revoked [1] IMPLICIT RevokedInfo
            // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime,
            //                            revocationReason [0] EXPLICIT CRLReason OPTIONAL }
            parse_revoked_info(cs_body)?
        }
        0x82 => {
            // unknown [2] IMPLICIT UnknownInfo (NULL)
            CertStatus::Unknown
        }
        _ => {
            return Err(LtvError::Ocsp(format!(
                "unknown certStatus tag: 0x{cs_tag:02x}"
            )));
        }
    };

    // thisUpdate GeneralizedTime
    let (tu_tag, tu_body, rest_after_tu) = der_utils::parse_tlv_with_rest(pos)
        .map_err(|e| LtvError::Ocsp(format!("thisUpdate: {e}")))?;
    if tu_tag != 0x18 {
        return Err(LtvError::Ocsp(format!(
            "expected thisUpdate GeneralizedTime, got 0x{tu_tag:02x}"
        )));
    }
    let this_update = der_utils::parse_generalized_time(tu_body)
        .map_err(|e| LtvError::Ocsp(format!("thisUpdate parse: {e}")))?;
    pos = rest_after_tu;

    // nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
    let mut next_update = None;
    if !pos.is_empty() && pos[0] == 0xA0 {
        let (_, nu_inner, rest_after_nu) = der_utils::parse_tlv_with_rest(pos)
            .map_err(|e| LtvError::Ocsp(format!("nextUpdate [0]: {e}")))?;
        let (nu_tag, nu_body, _) = der_utils::parse_tlv_with_rest(nu_inner)
            .map_err(|e| LtvError::Ocsp(format!("nextUpdate GeneralizedTime: {e}")))?;
        if nu_tag == 0x18 {
            next_update = Some(
                der_utils::parse_generalized_time(nu_body)
                    .map_err(|e| LtvError::Ocsp(format!("nextUpdate parse: {e}")))?,
            );
        }
        pos = rest_after_nu;
    }

    // singleExtensions [1] — skip for now
    let _ = pos;

    Ok(SingleResponse {
        hash_algorithm_oid,
        issuer_name_hash,
        issuer_key_hash,
        serial_number,
        cert_status,
        this_update,
        next_update,
    })
}

/// Parse RevokedInfo from the [1] body.
fn parse_revoked_info(body: &[u8]) -> Result<CertStatus, LtvError> {
    // revocationTime GeneralizedTime
    let (rt_tag, rt_body, rest) = der_utils::parse_tlv_with_rest(body)
        .map_err(|e| LtvError::Ocsp(format!("revocationTime: {e}")))?;
    if rt_tag != 0x18 {
        return Err(LtvError::Ocsp(format!(
            "expected revocationTime GeneralizedTime, got 0x{rt_tag:02x}"
        )));
    }
    let revocation_time = der_utils::parse_generalized_time(rt_body)
        .map_err(|e| LtvError::Ocsp(format!("revocationTime parse: {e}")))?;

    // revocationReason [0] EXPLICIT CRLReason OPTIONAL
    let mut reason = RevocationReason::Unspecified;
    if !rest.is_empty() && rest[0] == 0xA0 {
        let (_, reason_inner, _) = der_utils::parse_tlv_with_rest(rest)
            .map_err(|e| LtvError::Ocsp(format!("revocationReason: {e}")))?;
        // CRLReason is ENUMERATED
        if let Some(enum_body) = der_utils::find_tagged_value(reason_inner, 0x0A) {
            if !enum_body.is_empty() {
                reason = RevocationReason::from_code(enum_body[0]);
            }
        }
    }

    Ok(CertStatus::Revoked {
        revocation_time,
        reason,
    })
}

/// Extract nonce value from response extensions.
///
/// The nonce extension (OID 1.3.6.1.5.5.7.48.1.2) may contain the nonce
/// as raw bytes or wrapped in a DER OCTET STRING. We handle both formats.
fn extract_nonce_from_extensions(ext_area: &[u8]) -> Option<Vec<u8>> {
    // Extensions is a SEQUENCE OF Extension
    let (tag, ext_body) = der_utils::parse_tlv(ext_area).ok()?;
    if tag != 0x30 {
        return None;
    }

    let mut pos = &ext_body[..];
    while !pos.is_empty() {
        let (ext_tag, ext_value, rest) = der_utils::parse_tlv_with_rest(pos).ok()?;
        if ext_tag == 0x30 {
            // Extension: { OID, [critical BOOLEAN,] extnValue OCTET STRING }
            if let Some(oid_body) = der_utils::find_tagged_value(ext_value, 0x06) {
                if oid_body == OCSP_NONCE_OID_BYTES {
                    // Found nonce extension — extract value
                    if let Some(octet_body) = der_utils::find_tagged_value(ext_value, 0x04) {
                        // The value may be:
                        // 1. Raw nonce bytes directly in the OCTET STRING
                        // 2. DER OCTET STRING wrapping the actual nonce
                        // Try to unwrap one layer of OCTET STRING
                        if !octet_body.is_empty() && octet_body[0] == 0x04 {
                            if let Ok((inner_tag, inner_body)) = der_utils::parse_tlv(octet_body) {
                                if inner_tag == 0x04 {
                                    return Some(inner_body);
                                }
                            }
                        }
                        // Raw nonce bytes
                        return Some(octet_body.to_vec());
                    }
                }
            }
        }
        pos = rest;
    }

    None
}

// ── Responder signature verification ───────────────────────────────

/// Verify the OCSP response signature.
///
/// Tries embedded certificates first, then falls back to the issuer certificate.
fn verify_ocsp_response_signature(
    parsed: &ParsedBasicOcspResponse,
    issuer: &Certificate,
    policy: &crate::crypto::verify::SignaturePolicy,
) -> Result<Certificate, LtvError> {
    use der::Decode;

    // Strategy: try embedded certs first, then issuer
    let mut candidates: Vec<Certificate> = Vec::new();

    // Embedded certs
    for cert_der in &parsed.embedded_certs_der {
        if let Ok(cert) = Certificate::from_der(cert_der) {
            candidates.push(cert);
        }
    }

    // Add issuer as fallback
    candidates.push(issuer.clone());

    // Try each candidate
    for candidate in &candidates {
        let spki_der = match candidate.tbs_certificate.subject_public_key_info.to_der() {
            Ok(d) => d,
            Err(_) => continue,
        };

        let result = crate::crypto::verify::verify_signature_by_algid_with_policy(
            &parsed.tbs_response_data,
            &parsed.signature_bytes,
            &spki_der,
            &parsed.signature_algorithm,
            policy,
        );

        if result.is_ok() {
            return Ok(candidate.clone());
        }
    }

    Err(LtvError::Ocsp(
        "OCSP response signature could not be verified against any candidate certificate".into(),
    ))
}

// ── Responder trust validation ─────────────────────────────────────

/// Validate that the OCSP responder is trusted.
///
/// Per RFC 6960 §4.2.2.2, the response signer must be one of:
/// 1. The CA that issued the certificate being checked (issuer == responder)
/// 2. A responder whose certificate is issued by the CA and has the
///    id-kp-OCSPSigning extended key usage
///
/// The responder certificate's own validity period is checked against `now`.
/// Additionally, if the responder certificate has the id-pkix-ocsp-nocheck
/// extension, the responder's own revocation status need not be checked
/// (not implemented here — both cases just return Ok).
fn validate_responder_trust(
    responder_cert: &Certificate,
    issuer: &Certificate,
    policy: &crate::crypto::verify::SignaturePolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), LtvError> {
    // Check the responder certificate's own validity period (M-6).
    let validity = &responder_cert.tbs_certificate.validity;
    let not_before = validity.not_before.to_date_time();
    let not_after = validity.not_after.to_date_time();
    // Convert der::DateTime to chrono for comparison
    let nb = chrono::DateTime::parse_from_rfc3339(&format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        not_before.year(),
        { not_before.month() },
        { not_before.day() },
        { not_before.hour() },
        { not_before.minutes() },
        { not_before.seconds() }
    ))
    .map_err(|e| LtvError::Ocsp(format!("invalid responder notBefore: {e}")))?
    .with_timezone(&chrono::Utc);
    let na = chrono::DateTime::parse_from_rfc3339(&format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        not_after.year(),
        { not_after.month() },
        { not_after.day() },
        { not_after.hour() },
        { not_after.minutes() },
        { not_after.seconds() }
    ))
    .map_err(|e| LtvError::Ocsp(format!("invalid responder notAfter: {e}")))?
    .with_timezone(&chrono::Utc);

    if now < nb {
        return Err(LtvError::Ocsp(format!(
            "OCSP responder certificate is not yet valid (notBefore: {nb})"
        )));
    }
    if now > na {
        return Err(LtvError::Ocsp(format!(
            "OCSP responder certificate is expired (notAfter: {na})"
        )));
    }

    // Case 1: responder IS the issuer
    if certs_have_same_subject(responder_cert, issuer) {
        return Ok(());
    }

    // Case 2: responder is a delegated OCSP signer
    // Must be issued by the same CA (issuer)
    let issuer_signed = crate::crypto::verify::verify_certificate_signature_with_policy(
        responder_cert,
        issuer,
        policy,
    );
    if issuer_signed.is_err() {
        return Err(LtvError::Ocsp(
            "OCSP responder certificate is not issued by the expected CA".into(),
        ));
    }

    // Must have id-kp-OCSPSigning EKU
    if !has_ocsp_signing_eku(responder_cert) {
        return Err(LtvError::Ocsp(
            "OCSP responder certificate lacks id-kp-OCSPSigning EKU".into(),
        ));
    }

    Ok(())
}

/// Check if two certificates have the same subject DN (by DER comparison).
fn certs_have_same_subject(a: &Certificate, b: &Certificate) -> bool {
    let a_der = a.tbs_certificate.subject.to_der();
    let b_der = b.tbs_certificate.subject.to_der();
    match (a_der, b_der) {
        (Ok(ad), Ok(bd)) => ad == bd,
        _ => false,
    }
}

/// Check if a certificate has the id-kp-OCSPSigning extended key usage.
fn has_ocsp_signing_eku(cert: &Certificate) -> bool {
    let eku_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.37");

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == eku_oid {
                // EKU value is SEQUENCE OF OID
                return eku_contains_oid(ext.extn_value.as_bytes(), OCSP_SIGNING_EKU_OID_BYTES);
            }
        }
    }
    false
}

/// Check if an EKU extension value contains a specific OID.
fn eku_contains_oid(eku_der: &[u8], target_oid_bytes: &[u8]) -> bool {
    let Ok((tag, body)) = der_utils::parse_tlv(eku_der) else {
        return false;
    };
    if tag != 0x30 {
        return false;
    }

    let mut pos = &body[..];
    while !pos.is_empty() {
        let Ok((oid_tag, oid_body, rest)) = der_utils::parse_tlv_with_rest(pos) else {
            break;
        };
        if oid_tag == 0x06 && oid_body == target_oid_bytes {
            return true;
        }
        pos = rest;
    }
    false
}

/// Check if a certificate has the id-pkix-ocsp-nocheck extension.
///
/// When present, the responder's own revocation status need not be checked.
pub fn has_ocsp_nocheck_extension(cert: &Certificate) -> bool {
    let nocheck_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5");

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == nocheck_oid {
                return true;
            }
        }
    }
    false
}

// ── Nonce validation ───────────────────────────────────────────────

/// Validate the OCSP response nonce against the request nonce.
///
/// Supports dual-format comparison per the Java stack:
/// - Direct comparison of raw nonce bytes
/// - Comparison with DER OCTET STRING wrapped nonce
fn validate_nonce(request_nonce: &[u8], response_nonce: &[u8]) -> Result<(), LtvError> {
    // Direct comparison
    if response_nonce == request_nonce {
        return Ok(());
    }

    // DER-wrapped comparison: response may contain raw bytes that match
    // when we wrap our nonce in OCTET STRING
    let wrapped_nonce = der_utils::encode_tlv(0x04, request_nonce);
    if response_nonce == wrapped_nonce.as_slice() {
        return Ok(());
    }

    // Or the response nonce may be DER-wrapped and our request nonce is raw
    if !response_nonce.is_empty() && response_nonce[0] == 0x04 {
        if let Ok((_, inner)) = der_utils::parse_tlv(response_nonce) {
            if inner == request_nonce {
                return Ok(());
            }
        }
    }

    Err(LtvError::Ocsp("OCSP response nonce mismatch".into()))
}

// ── Freshness policy ───────────────────────────────────────────────

/// Freshness policy for OCSP responses (RFC 6960 §4.2.2.1).
///
/// An OCSP response carries a validity window: the status is asserted as of
/// `thisUpdate` and the responder promises fresher information by `nextUpdate`.
/// A response must not be relied upon once the validation time is past
/// `nextUpdate` (widened by an allowed clock skew); without this check a
/// legitimately-issued "good" response can be replayed forever — including
/// after the certificate has been compromised and revoked.
///
/// All comparisons are made against the *validation time* (`now`), which for
/// long-term validation is the historical instant being validated, not the
/// wall clock. A response produced *after* that instant (later-collected
/// archival evidence) is accepted; only staleness relative to `now` is a
/// failure.
#[derive(Debug, Clone)]
pub struct OcspFreshness {
    /// Clock skew tolerance applied to staleness/max-age comparisons.
    /// Accommodates small differences between the responder's and the
    /// validator's clocks. Default: 5 minutes.
    pub clock_skew: chrono::Duration,

    /// Maximum age (measured from `thisUpdate`) tolerated for a response that
    /// omits the optional `nextUpdate` field. RFC 6960 allows `nextUpdate` to be
    /// absent ("fresher information is always available"); rather than treat
    /// such a response as eternally fresh, it is rejected once it is older than
    /// this bound. Default: 24 hours.
    pub max_age_without_next_update: chrono::Duration,
}

impl Default for OcspFreshness {
    fn default() -> Self {
        Self {
            clock_skew: chrono::Duration::minutes(5),
            max_age_without_next_update: chrono::Duration::hours(24),
        }
    }
}

/// Validate that an OCSP response is fresh enough to be relied upon at `now`.
///
/// The anti-replay guarantee (RFC 6960 §4.2.2.1) is that a response must not be
/// **stale** as of the validation time: the validation instant must not be past
/// `nextUpdate`. When `nextUpdate` is absent, the response is instead bounded by
/// [`OcspFreshness::max_age_without_next_update`] measured from `thisUpdate`.
///
/// A response produced *after* the validation instant is explicitly **accepted**:
/// in archival / long-term validation, `validation_time` is the historical
/// instant being validated (e.g. signing or timestamp `genTime`) and the
/// revocation evidence is normally collected shortly afterwards, so its
/// `thisUpdate`/`producedAt` legitimately fall after `validation_time`.
/// `producedAt` is the time the responder signed the response — not a status
/// assertion time — so it is not used to gate freshness at all.
///
/// Fails closed: an out-of-range (stale) response returns an `Err`, which the
/// orchestrator classifies as a definitive `Invalid` (a received-but-unusable
/// response), never the fail-open `Unknown`.
fn validate_response_freshness(
    sr: &SingleResponse,
    now: chrono::DateTime<chrono::Utc>,
    freshness: &OcspFreshness,
) -> Result<(), LtvError> {
    let skew = freshness.clock_skew;

    match sr.next_update {
        Some(next_update) => {
            // Sanity: a window that ends before it starts is malformed.
            if next_update < sr.this_update {
                return Err(LtvError::Ocsp(format!(
                    "OCSP response has nextUpdate ({next_update}) before thisUpdate ({})",
                    sr.this_update
                )));
            }
            // Anti-replay: reject once the validation instant is past nextUpdate.
            // (A response whose window lies at/after the validation instant —
            // later-collected archival evidence — is not stale and is kept.)
            if now > next_update + skew {
                return Err(LtvError::Ocsp(format!(
                    "OCSP response is stale: nextUpdate ({next_update}) is before validation time ({now})"
                )));
            }
        }
        None => {
            // No nextUpdate: bound the response's age from thisUpdate so an old
            // response cannot be relied on indefinitely. A response whose window
            // starts at/after the validation time is always within bound.
            let max_valid = sr.this_update + freshness.max_age_without_next_update + skew;
            if now > max_valid {
                return Err(LtvError::Ocsp(format!(
                    "OCSP response without nextUpdate is too old: thisUpdate ({}), validation time ({now}), max age {}",
                    sr.this_update, freshness.max_age_without_next_update
                )));
            }
        }
    }

    Ok(())
}

// ── Main revocation check function ─────────────────────────────────

/// Check whether a certificate is revoked according to an OCSP response.
///
/// Performs the full OCSP validation pipeline:
/// 1. Parse the OCSP response (BasicOCSPResponse)
/// 2. Verify the response signature (try embedded certs, then issuer)
/// 3. Validate responder trust (issuer match or delegated signer with EKU)
/// 4. If nonce provided, validate it matches the response
/// 5. Match the certificate's CertID in the response
/// 6. Time-aware: if `revocationTime > validation_time` → `Valid`
///
/// Returns a [`ValidationStatus`] indicating the result.
pub fn check_revocation(
    response_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    nonce: Option<&[u8]>,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<ValidationStatus, LtvError> {
    check_revocation_with_policy(
        response_der,
        cert,
        issuer,
        nonce,
        validation_time,
        &crate::crypto::verify::SignaturePolicy::default(),
    )
}

/// Like [`check_revocation`] but with an explicit
/// [`SignaturePolicy`](crate::crypto::verify::SignaturePolicy) for the response
/// and responder-certificate signature checks. The default rejects OCSP
/// material signed with MD5/SHA-1/SHA-224.
///
/// Freshness is validated with [`OcspFreshness::default`]; use
/// [`check_revocation_with_options`] to supply a custom freshness policy.
#[allow(clippy::too_many_arguments)]
pub fn check_revocation_with_policy(
    response_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    nonce: Option<&[u8]>,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
) -> Result<ValidationStatus, LtvError> {
    check_revocation_with_options(
        response_der,
        cert,
        issuer,
        nonce,
        validation_time,
        policy,
        &OcspFreshness::default(),
    )
}

/// Like [`check_revocation_with_policy`] but with an explicit [`OcspFreshness`]
/// policy controlling the RFC 6960 §4.2.2.1 time-window check.
///
/// A response that is stale as of `validation_time` (the validation instant is
/// past `nextUpdate`, or — lacking `nextUpdate` — the response is older than the
/// configured maximum age) fails closed with an `Err`, classified by the
/// orchestrator as `Invalid` (a received-but-unusable response), never the
/// fail-open `Unknown`. Later-collected evidence (window at/after the validation
/// instant) is accepted.
#[allow(clippy::too_many_arguments)]
pub fn check_revocation_with_options(
    response_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    nonce: Option<&[u8]>,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
    freshness: &OcspFreshness,
) -> Result<ValidationStatus, LtvError> {
    let now = validation_time.unwrap_or_else(chrono::Utc::now);

    // 1. Parse OCSP response
    let parsed = parse_ocsp_response(response_der)?;

    // 2. Verify signature — returns the responder certificate
    let responder_cert = verify_ocsp_response_signature(&parsed, issuer, policy)?;

    // 3. Validate responder trust (including cert validity vs. now)
    validate_responder_trust(&responder_cert, issuer, policy, now)?;

    // 4. Validate nonce (if provided)
    if let Some(request_nonce) = nonce {
        match &parsed.nonce {
            Some(response_nonce) => {
                validate_nonce(request_nonce, response_nonce)?;
            }
            None => {
                // Some responders don't support nonces — log warning but continue
                log::warn!("OCSP response does not contain a nonce (nonce was requested)");
            }
        }
    }

    // 5. Find the matching SingleResponse for our certificate
    // Build the expected CertID components
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| LtvError::Ocsp(format!("issuer name encode: {e}")))?;
    let expected_name_hash = sha1_hash(&issuer_name_der);

    let issuer_key_bytes = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec();
    let expected_key_hash = sha1_hash(&issuer_key_bytes);

    let cert_serial = der_utils::parse_integer_body(cert.tbs_certificate.serial_number.as_bytes());

    let matching_response = parsed.responses.iter().find(|sr| {
        sr.issuer_name_hash == expected_name_hash
            && sr.issuer_key_hash == expected_key_hash
            && der_utils::integer_bodies_equal(&sr.serial_number, &cert_serial)
    });

    let sr = match matching_response {
        Some(sr) => sr,
        None => {
            return Ok(ValidationStatus::Unknown {
                reason: "certificate not found in OCSP response".into(),
            });
        }
    };

    // 6. Validate response freshness (RFC 6960 §4.2.2.1). A response that is
    //    stale as of `now` (validation instant past nextUpdate) is rejected —
    //    fail closed — so a stale "good" response cannot be replayed
    //    indefinitely. Later-collected evidence (window at/after `now`) is kept.
    validate_response_freshness(sr, now, freshness)?;

    // 7. Map CertStatus to ValidationStatus
    match &sr.cert_status {
        CertStatus::Good => Ok(ValidationStatus::Valid {
            source: RevocationSource::Ocsp,
            checked_at: now,
        }),
        CertStatus::Revoked {
            revocation_time,
            reason,
        } => {
            // Time-aware: if revocationTime > validation_time → Valid
            if *revocation_time > now {
                log::debug!(
                    "cert found revoked in OCSP but revocation_time ({}) is after validation_time ({})",
                    revocation_time, now
                );
                Ok(ValidationStatus::Valid {
                    source: RevocationSource::Ocsp,
                    checked_at: now,
                })
            } else {
                Ok(ValidationStatus::Revoked {
                    source: RevocationSource::Ocsp,
                    reason: *reason,
                    revocation_time: *revocation_time,
                })
            }
        }
        CertStatus::Unknown => Ok(ValidationStatus::Unknown {
            reason: "OCSP responder reported certificate status as unknown".into(),
        }),
    }
}

/// Compute SHA-1 hash of data.
fn sha1_hash(data: &[u8]) -> Vec<u8> {
    use sha1::Digest;
    sha1::Sha1::digest(data).to_vec()
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    #[test]
    fn test_ocsp_client_default() {
        let client = OcspClient::new();
        assert_eq!(client.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_sha1_hash() {
        let hash = sha1_hash(b"test");
        assert_eq!(hash.len(), 20); // SHA-1 is 20 bytes
    }

    #[test]
    fn test_build_sha1_algorithm_identifier() {
        let alg_id = build_sha1_algorithm_identifier().unwrap();
        assert_eq!(alg_id[0], 0x30); // SEQUENCE
    }

    #[test]
    fn test_extract_ocsp_urls_from_fixture_cert() {
        let cert_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let pem_data = pem_rfc7468::decode_vec(cert_pem.as_bytes());
        if let Ok((_label, der)) = pem_data {
            if let Ok(cert) = Certificate::from_der(&der) {
                let urls = OcspClient::extract_ocsp_urls(&cert);
                let _ = urls;
            }
        }
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        assert_eq!(nonce1.len(), NONCE_SIZE);

        // Two nonces generated at the same time should still differ
        // (because of wrapping_add with index)
        let nonce2 = generate_nonce();
        assert_eq!(nonce2.len(), NONCE_SIZE);
    }

    #[test]
    fn test_build_ocsp_request_with_nonce() {
        let cert_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let issuer_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_cert.pem"
        ));
        let (_, cert_der) = pem_rfc7468::decode_vec(cert_pem.as_bytes()).unwrap();
        let (_, issuer_der) = pem_rfc7468::decode_vec(issuer_pem.as_bytes()).unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();
        let issuer = Certificate::from_der(&issuer_der).unwrap();

        let (request, nonce) = build_ocsp_request_with_nonce(&cert, &issuer).unwrap();
        assert!(!request.is_empty());
        assert_eq!(request[0], 0x30); // SEQUENCE
        assert_eq!(nonce.len(), NONCE_SIZE);
    }

    #[test]
    fn test_validate_nonce_direct_match() {
        let nonce = b"test-nonce-12345678901234567890";
        assert!(validate_nonce(nonce, nonce).is_ok());
    }

    #[test]
    fn test_validate_nonce_der_wrapped() {
        let nonce = b"test-nonce-data-here";
        let wrapped = der_utils::encode_tlv(0x04, nonce);
        // Response has DER-wrapped nonce, request has raw nonce
        assert!(validate_nonce(nonce, &wrapped).is_ok());
    }

    #[test]
    fn test_validate_nonce_mismatch() {
        let nonce1 = b"nonce-one-aaaaaaaaaaaaaaaaaaa";
        let nonce2 = b"nonce-two-bbbbbbbbbbbbbbbbbbb";
        assert!(validate_nonce(nonce1, nonce2).is_err());
    }

    // ── Synthetic OCSP response tests ────────────────────────────────

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

    fn intermediate_ca_key_pem_path() -> &'static str {
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

    /// Build a synthetic OCSP response signed by the intermediate CA key.
    ///
    /// Constructs a minimal OCSPResponse → BasicOCSPResponse by hand:
    /// - responseStatus: successful
    /// - tbsResponseData with responderID byName, producedAt, single response
    /// - Signed with the intermediate CA's RSA key
    fn build_test_ocsp_response(
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
        cert: &Certificate,
        status: &CertStatus,
        nonce: Option<&[u8]>,
    ) -> Vec<u8> {
        // Default window: produced/thisUpdate 2026-06-01T12:00Z,
        // nextUpdate 2026-06-08T12:00Z.
        build_test_ocsp_response_with_times(
            issuer_cert,
            issuer_key_pem,
            cert,
            status,
            nonce,
            "20260601120000Z",
            "20260601120000Z",
            Some("20260608120000Z"),
        )
    }

    /// Like [`build_test_ocsp_response`] but with explicit `producedAt`,
    /// `thisUpdate`, and optional `nextUpdate` GeneralizedTime strings.
    #[allow(clippy::too_many_arguments)]
    fn build_test_ocsp_response_with_times(
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
        cert: &Certificate,
        status: &CertStatus,
        nonce: Option<&[u8]>,
        produced_at_str: &str,
        this_update_str: &str,
        next_update_str: Option<&str>,
    ) -> Vec<u8> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Sha256;

        // Build tbsResponseData body
        let mut tbs_body = Vec::new();

        // responderID: byName [1] — use issuer's subject
        let issuer_subject_der = issuer_cert.tbs_certificate.subject.to_der().unwrap();
        let responder_id = der_utils::encode_tlv(0xA1, &issuer_subject_der);
        tbs_body.extend_from_slice(&responder_id);

        // producedAt GeneralizedTime
        let produced_at = der_utils::encode_tlv(0x18, produced_at_str.as_bytes());
        tbs_body.extend_from_slice(&produced_at);

        // Build SingleResponse
        let single_response = build_test_single_response_with_times(
            issuer_cert,
            cert,
            status,
            this_update_str,
            next_update_str,
        );

        // responses SEQUENCE OF SingleResponse
        let responses_seq = der_utils::encode_sequence_from_parts(&[&single_response]);
        tbs_body.extend_from_slice(&responses_seq);

        // responseExtensions [1] with nonce if provided
        if let Some(nonce_bytes) = nonce {
            let nonce_oid_tlv = der_utils::encode_tlv(0x06, OCSP_NONCE_OID_BYTES);
            let nonce_inner = der_utils::encode_tlv(0x04, nonce_bytes);
            let nonce_outer = der_utils::encode_tlv(0x04, &nonce_inner);
            let nonce_ext = der_utils::encode_sequence_from_parts(&[&nonce_oid_tlv, &nonce_outer]);
            let extensions_seq = der_utils::encode_sequence_from_parts(&[&nonce_ext]);
            let response_extensions = der_utils::encode_tlv(0xA1, &extensions_seq);
            tbs_body.extend_from_slice(&response_extensions);
        }

        // Wrap as tbsResponseData SEQUENCE
        let tbs_der = der_utils::encode_sequence_raw(&tbs_body);

        // Sign TBS
        let key_der = pem_rfc7468::decode_vec(issuer_key_pem.as_bytes())
            .unwrap()
            .1;
        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&key_der).unwrap();
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature: rsa::pkcs1v15::Signature = signing_key.sign(&tbs_der);
        let sig_bytes = signature.to_vec();

        // signatureAlgorithm: sha256WithRSAEncryption
        let sha256_rsa_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        let alg_id = der_utils::encode_sequence_from_parts(&[sha256_rsa_oid, &[0x05, 0x00]]);

        // signature BIT STRING
        let mut bit_string_value = vec![0x00];
        bit_string_value.extend_from_slice(&sig_bytes);
        let sig_bit_string = der_utils::encode_tlv(0x03, &bit_string_value);

        // BasicOCSPResponse SEQUENCE { tbs, alg, sig }
        let basic_response =
            der_utils::encode_sequence_from_parts(&[&tbs_der, &alg_id, &sig_bit_string]);

        // ResponseBytes SEQUENCE { responseType OID, response OCTET STRING }
        let basic_oid_tlv = der_utils::encode_tlv(0x06, OCSP_BASIC_RESPONSE_OID);
        let basic_octet = der_utils::encode_tlv(0x04, &basic_response);
        let response_bytes_seq =
            der_utils::encode_sequence_from_parts(&[&basic_oid_tlv, &basic_octet]);

        // responseBytes [0] EXPLICIT
        let response_bytes_tagged = der_utils::encode_tlv(0xA0, &response_bytes_seq);

        // responseStatus ENUMERATED successful (0)
        let response_status = der_utils::encode_tlv(0x0A, &[0x00]);

        // OCSPResponse SEQUENCE
        der_utils::encode_sequence_from_parts(&[&response_status, &response_bytes_tagged])
    }

    /// Build a synthetic SingleResponse for a certificate with explicit
    /// `thisUpdate` and optional `nextUpdate` GeneralizedTime strings.
    fn build_test_single_response_with_times(
        issuer_cert: &Certificate,
        cert: &Certificate,
        status: &CertStatus,
        this_update_str: &str,
        next_update_str: Option<&str>,
    ) -> Vec<u8> {
        // CertID
        let issuer_name_der = issuer_cert.tbs_certificate.subject.to_der().unwrap();
        let issuer_name_hash = sha1_hash(&issuer_name_der);
        let issuer_key_bytes = issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        let issuer_key_hash = sha1_hash(&issuer_key_bytes);

        let serial = cert.tbs_certificate.serial_number.to_der().unwrap();

        let sha1_alg_id = build_sha1_algorithm_identifier().unwrap();
        let name_hash_oct = der_utils::encode_tlv(0x04, &issuer_name_hash);
        let key_hash_oct = der_utils::encode_tlv(0x04, &issuer_key_hash);
        let cert_id = der_utils::encode_sequence_from_parts(&[
            &sha1_alg_id,
            &name_hash_oct,
            &key_hash_oct,
            &serial,
        ]);

        // certStatus
        let cert_status_der = match status {
            CertStatus::Good => {
                // good [0] IMPLICIT NULL
                der_utils::encode_tlv(0x80, &[])
            }
            CertStatus::Revoked {
                revocation_time,
                reason,
            } => {
                // revoked [1] IMPLICIT RevokedInfo
                let rt_str = revocation_time.format("%Y%m%d%H%M%SZ").to_string();
                let mut revoked_body = der_utils::encode_tlv(0x18, rt_str.as_bytes());
                if *reason != RevocationReason::Unspecified {
                    let reason_enum = der_utils::encode_tlv(0x0A, &[reason.code()]);
                    let reason_explicit = der_utils::encode_tlv(0xA0, &reason_enum);
                    revoked_body.extend_from_slice(&reason_explicit);
                }
                der_utils::encode_tlv(0xA1, &revoked_body)
            }
            CertStatus::Unknown => {
                // unknown [2] IMPLICIT NULL
                der_utils::encode_tlv(0x82, &[])
            }
        };

        // thisUpdate GeneralizedTime
        let this_update = der_utils::encode_tlv(0x18, this_update_str.as_bytes());

        // SingleResponse SEQUENCE { certID, certStatus, thisUpdate[, nextUpdate] }
        let mut parts: Vec<&[u8]> = vec![&cert_id, &cert_status_der, &this_update];

        // nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
        let next_update;
        if let Some(nu_str) = next_update_str {
            let next_update_gt = der_utils::encode_tlv(0x18, nu_str.as_bytes());
            next_update = der_utils::encode_tlv(0xA0, &next_update_gt);
            parts.push(&next_update);
        }

        der_utils::encode_sequence_from_parts(&parts)
    }

    #[test]
    fn test_parse_ocsp_response_good() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);

        let parsed = parse_ocsp_response(&response_der).unwrap();
        assert_eq!(parsed.responses.len(), 1);
        assert!(matches!(parsed.responses[0].cert_status, CertStatus::Good));
        assert!(parsed.nonce.is_none());
        assert!(parsed.embedded_certs_der.is_empty());
    }

    #[test]
    fn test_parse_ocsp_response_revoked() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let revocation_time = chrono::DateTime::parse_from_rfc3339("2026-03-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let status = CertStatus::Revoked {
            revocation_time,
            reason: RevocationReason::KeyCompromise,
        };

        let response_der = build_test_ocsp_response(&issuer, &key_pem, &cert, &status, None);

        let parsed = parse_ocsp_response(&response_der).unwrap();
        assert_eq!(parsed.responses.len(), 1);
        match &parsed.responses[0].cert_status {
            CertStatus::Revoked { reason, .. } => {
                assert_eq!(*reason, RevocationReason::KeyCompromise);
            }
            other => panic!("expected Revoked, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_ocsp_response_with_nonce() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let nonce = b"test-nonce-1234567890abcdef1234";

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, Some(nonce));

        let parsed = parse_ocsp_response(&response_der).unwrap();
        assert!(parsed.nonce.is_some());
        assert_eq!(parsed.nonce.as_deref(), Some(nonce.as_slice()));
    }

    #[test]
    fn test_check_revocation_good() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(status.is_valid(), "should be valid: {status}");
    }

    #[test]
    fn test_check_revocation_revoked() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let revocation_time = chrono::DateTime::parse_from_rfc3339("2026-03-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let cert_status = CertStatus::Revoked {
            revocation_time,
            reason: RevocationReason::Superseded,
        };

        let response_der = build_test_ocsp_response(&issuer, &key_pem, &cert, &cert_status, None);

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(status.is_revoked(), "should be revoked: {status}");
    }

    #[test]
    fn test_check_revocation_time_aware_future_revocation() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        // Revocation time is 2027-01-01, validation time is 2026-06-01
        // → should be VALID at validation_time
        let revocation_time = chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let cert_status = CertStatus::Revoked {
            revocation_time,
            reason: RevocationReason::Unspecified,
        };

        let response_der = build_test_ocsp_response(&issuer, &key_pem, &cert, &cert_status, None);

        // Validation time (2026-06-01T00:00Z) is the historical instant; the
        // response was produced shortly after (thisUpdate 2026-06-01T12:00Z,
        // nextUpdate 2026-06-08T12:00Z). Later-collected evidence is accepted,
        // and the 2027 revocation is in the future, so the result is Valid.
        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(
            status.is_valid(),
            "should be valid (revocation in future): {status}"
        );
    }

    // ── H-2: OCSP response freshness (RFC 6960 §4.2.2.1) ─────────────

    #[test]
    fn test_check_revocation_rejects_stale_good() {
        // A legitimately-signed "good" response is replayed long after its
        // nextUpdate (2026-06-08T12:00Z). It must NOT be accepted as Valid.
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);

        // Far past nextUpdate (the replay window the old code accepted forever).
        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-09-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let err = check_revocation(&response_der, &cert, &issuer, None, Some(validation_time))
            .expect_err("stale OCSP response must be rejected");
        assert!(
            matches!(err, LtvError::Ocsp(ref m) if m.contains("stale")),
            "expected stale error, got: {err}"
        );
    }

    #[test]
    fn test_check_revocation_accepts_later_produced_evidence() {
        // Archival/LTV: the response is produced *after* the historical
        // validation instant. With thisUpdate <= validation_time < producedAt
        // <= nextUpdate, the response is valid evidence and must be accepted —
        // producedAt being after the validation instant is not a freshness
        // failure (producedAt is the responder's signing time, not a status
        // assertion time).
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        // thisUpdate 12:00, producedAt 14:00, nextUpdate 2026-06-08; the
        // validation instant 13:00 sits between thisUpdate and producedAt.
        let response_der = build_test_ocsp_response_with_times(
            &issuer,
            &key_pem,
            &cert,
            &CertStatus::Good,
            None,
            "20260601140000Z",       // producedAt (after validation_time)
            "20260601120000Z",       // thisUpdate (<= validation_time)
            Some("20260608120000Z"), // nextUpdate
        );

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T13:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(
            status.is_valid(),
            "later-produced OCSP evidence must remain acceptable: {status}"
        );
    }

    #[test]
    fn test_check_revocation_accepts_stale_within_skew() {
        // Just past nextUpdate (2026-06-08T12:00Z) but within the default 5m
        // clock skew — still accepted.
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);

        // 3 minutes after nextUpdate — inside the 5-minute skew.
        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-08T12:03:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(status.is_valid(), "should be valid within skew: {status}");
    }

    #[test]
    fn test_validate_response_freshness_no_next_update_max_age() {
        // With nextUpdate absent, the response is fresh up to max_age from
        // thisUpdate and stale beyond it.
        let this_update = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let sr = SingleResponse {
            hash_algorithm_oid: vec![],
            issuer_name_hash: vec![],
            issuer_key_hash: vec![],
            serial_number: vec![],
            cert_status: CertStatus::Good,
            this_update,
            next_update: None,
        };
        let freshness = OcspFreshness::default(); // 24h max age, 5m skew

        // 12 hours later — within the 24h bound.
        let within = this_update + chrono::Duration::hours(12);
        assert!(validate_response_freshness(&sr, within, &freshness).is_ok());

        // Validation instant *before* thisUpdate (later-collected evidence) is
        // always within bound.
        let before = this_update - chrono::Duration::hours(6);
        assert!(validate_response_freshness(&sr, before, &freshness).is_ok());

        // 25 hours later — beyond the 24h bound (+ skew).
        let beyond = this_update + chrono::Duration::hours(25);
        let err = validate_response_freshness(&sr, beyond, &freshness)
            .expect_err("response older than max age must be rejected");
        assert!(
            matches!(err, LtvError::Ocsp(ref m) if m.contains("too old")),
            "got: {err}"
        );
    }

    #[test]
    fn test_check_revocation_unknown_status() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Unknown, None);

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status =
            check_revocation(&response_der, &cert, &issuer, None, Some(validation_time)).unwrap();
        assert!(status.is_unknown(), "should be unknown: {status}");
    }

    #[test]
    fn test_check_revocation_with_valid_nonce() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();
        let nonce = b"test-nonce-1234567890abcdef1234";

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, Some(nonce));

        let validation_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let status = check_revocation(
            &response_der,
            &cert,
            &issuer,
            Some(nonce),
            Some(validation_time),
        )
        .unwrap();
        assert!(status.is_valid(), "should be valid with nonce: {status}");
    }

    #[test]
    fn test_parse_ocsp_response_invalid_data() {
        // Not a valid OCSP response
        let result = parse_ocsp_response(&[0x04, 0x00]); // OCTET STRING
        assert!(result.is_err());
    }

    #[test]
    fn test_has_ocsp_nocheck_extension() {
        // Our test certs don't have this extension, so this tests the negative case
        let cert = signer_cert();
        assert!(!has_ocsp_nocheck_extension(&cert));
    }

    #[test]
    fn test_responder_id_variants() {
        let key_path = intermediate_ca_key_pem_path();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        let response_der =
            build_test_ocsp_response(&issuer, &key_pem, &cert, &CertStatus::Good, None);

        let parsed = parse_ocsp_response(&response_der).unwrap();
        // Our synthetic response uses byName
        assert!(matches!(parsed.responder_id, ResponderId::ByName(_)));
    }
}
