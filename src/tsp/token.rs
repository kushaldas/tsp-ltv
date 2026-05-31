//! TimeStampReq/Resp ASN.1 parsing and validation per RFC 3161.
//!
//! This module handles:
//! - Building `TimeStampReq` messages
//! - Parsing `TimeStampResp` responses
//! - Extracting and validating `TSTInfo` from the embedded `TimeStampToken`
//! - Nonce generation and verification

use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::crypto::algorithm::DigestAlgorithm;
use crate::der_utils;
use crate::error::{TrustError, TspError};
use crate::trust::TrustStore;

// ---------------------------------------------------------------------------
// OIDs
// ---------------------------------------------------------------------------

/// id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)
pub const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// id-signedData (1.2.840.113549.1.7.2)
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// id-contentType signed attribute (1.2.840.113549.1.9.3)
const ID_CONTENT_TYPE_ATTR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// id-messageDigest signed attribute (1.2.840.113549.1.9.4)
const ID_MESSAGE_DIGEST_ATTR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// Extended Key Usage extension (2.5.29.37)
const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// id-kp-timeStamping extended key usage (1.3.6.1.5.5.7.3.8).
///
/// RFC 3161 §2.3 requires the TSA signing certificate to carry this EKU,
/// and that the extension be marked **critical**.
const ID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// rsaEncryption (1.2.840.113549.1.1.1) — bare RSA key algorithm.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// id-ecPublicKey (1.2.840.10045.2.1) — bare EC key algorithm.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// id-RSASSA-PSS (1.2.840.113549.1.1.10).
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

// ---------------------------------------------------------------------------
// PKI status codes per RFC 3161 §2.4.2
// ---------------------------------------------------------------------------

/// PKIStatus values per RFC 3161.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiStatus {
    /// 0 — granted
    Granted,
    /// 1 — grantedWithMods
    GrantedWithMods,
    /// 2 — rejection
    Rejection,
    /// 3 — waiting
    Waiting,
    /// 4 — revocationWarning
    RevocationWarning,
    /// 5 — revocationNotification
    RevocationNotification,
    /// Unknown status value
    Unknown(u64),
}

impl PkiStatus {
    fn from_u64(v: u64) -> Self {
        match v {
            0 => Self::Granted,
            1 => Self::GrantedWithMods,
            2 => Self::Rejection,
            3 => Self::Waiting,
            4 => Self::RevocationWarning,
            5 => Self::RevocationNotification,
            _ => Self::Unknown(v),
        }
    }

    /// Returns true if the status indicates success (token was issued).
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Granted | Self::GrantedWithMods)
    }
}

impl std::fmt::Display for PkiStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Granted => write!(f, "granted (0)"),
            Self::GrantedWithMods => write!(f, "grantedWithMods (1)"),
            Self::Rejection => write!(f, "rejection (2)"),
            Self::Waiting => write!(f, "waiting (3)"),
            Self::RevocationWarning => write!(f, "revocationWarning (4)"),
            Self::RevocationNotification => write!(f, "revocationNotification (5)"),
            Self::Unknown(v) => write!(f, "unknown ({v})"),
        }
    }
}

// ---------------------------------------------------------------------------
// TimeStampReq builder
// ---------------------------------------------------------------------------

/// Build a DER-encoded RFC 3161 `TimeStampReq`.
///
/// ```text
/// TimeStampReq ::= SEQUENCE  {
///    version               INTEGER  { v1(1) },
///    messageImprint        MessageImprint,
///    reqPolicy             TSAPolicyId              OPTIONAL,
///    nonce                 INTEGER                  OPTIONAL,
///    certReq               BOOLEAN                  DEFAULT FALSE,
///    extensions        [0] IMPLICIT Extensions      OPTIONAL
/// }
///
/// MessageImprint ::= SEQUENCE  {
///    hashAlgorithm         AlgorithmIdentifier,
///    hashedMessage         OCTET STRING
/// }
/// ```
pub fn build_timestamp_request(
    digest_algorithm: DigestAlgorithm,
    message_hash: &[u8],
    policy_oid: Option<&ObjectIdentifier>,
    nonce: Option<u64>,
    cert_req: bool,
) -> Result<Vec<u8>, TspError> {
    let mut parts: Vec<Vec<u8>> = Vec::new();

    // version INTEGER { v1(1) }
    parts.push(der_utils::encode_integer_u64(1));

    // messageImprint
    let hash_alg = digest_algorithm_identifier(digest_algorithm);
    let hash_alg_der = hash_alg
        .to_der()
        .map_err(|e| TspError::InvalidResponse(format!("failed to encode hash algorithm: {e}")))?;
    let hashed_message = OctetString::new(message_hash.to_vec()).map_err(|e| {
        TspError::InvalidResponse(format!("failed to create hash octet string: {e}"))
    })?;
    let hashed_message_der = hashed_message
        .to_der()
        .map_err(|e| TspError::InvalidResponse(format!("failed to encode hash: {e}")))?;
    let msg_imprint = der_utils::encode_sequence_from_parts(&[&hash_alg_der, &hashed_message_der]);
    parts.push(msg_imprint);

    // reqPolicy OPTIONAL
    if let Some(oid) = policy_oid {
        let oid_der = oid
            .to_der()
            .map_err(|e| TspError::InvalidResponse(format!("failed to encode policy OID: {e}")))?;
        parts.push(oid_der);
    }

    // nonce OPTIONAL
    if let Some(n) = nonce {
        parts.push(der_utils::encode_integer_u64(n));
    }

    // certReq BOOLEAN DEFAULT FALSE — only encode when TRUE
    if cert_req {
        parts.push(der_utils::encode_boolean(true));
    }

    // Assemble SEQUENCE
    let body: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    Ok(der_utils::encode_sequence_raw(&body))
}

// ---------------------------------------------------------------------------
// TimeStampResp parsing
// ---------------------------------------------------------------------------

/// Parsed RFC 3161 TimeStampResp.
///
/// ```text
/// TimeStampResp ::= SEQUENCE  {
///    status                PKIStatusInfo,
///    timeStampToken        TimeStampToken     OPTIONAL
/// }
/// ```
#[derive(Debug)]
pub struct TimeStampResp {
    /// The PKI status information.
    pub status: PkiStatus,
    /// Free text status string (if any).
    pub status_string: Option<String>,
    /// Failure info bitstring (if any).
    pub failure_info: Option<Vec<u8>>,
    /// The raw DER-encoded TimeStampToken (a CMS ContentInfo).
    /// Present only when status is Granted or GrantedWithMods.
    pub token_der: Option<Vec<u8>>,
}

/// Parse a DER-encoded RFC 3161 `TimeStampResp`.
pub fn parse_timestamp_response(der_bytes: &[u8]) -> Result<TimeStampResp, TspError> {
    // TimeStampResp is a SEQUENCE
    let (tag, resp_body) = der_utils::parse_tlv(der_bytes)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse TimeStampResp: {e}")))?;
    if tag != 0x30 {
        return Err(TspError::InvalidResponse(format!(
            "expected SEQUENCE tag 0x30, got 0x{tag:02x}"
        )));
    }

    // First element: PKIStatusInfo SEQUENCE
    let (status_tag, status_body, rest) = der_utils::parse_tlv_with_rest(&resp_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse PKIStatusInfo: {e}")))?;
    if status_tag != 0x30 {
        return Err(TspError::InvalidResponse(format!(
            "expected PKIStatusInfo SEQUENCE, got 0x{status_tag:02x}"
        )));
    }

    // PKIStatusInfo: first element is PKIStatus INTEGER
    let (int_tag, int_body, status_rest) = der_utils::parse_tlv_with_rest(status_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse PKIStatus: {e}")))?;
    if int_tag != 0x02 {
        return Err(TspError::InvalidResponse(format!(
            "expected INTEGER tag 0x02 for PKIStatus, got 0x{int_tag:02x}"
        )));
    }
    let status_val = der_utils::decode_integer_u64(int_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to decode PKIStatus: {e}")))?;
    let status = PkiStatus::from_u64(status_val);

    // Parse optional statusString and failureInfo from status_rest
    let mut status_string = None;
    let mut failure_info = None;
    let mut remaining = status_rest;

    // Each remaining element of PKIStatusInfo is a well-formed TLV. A structural
    // parse failure here means the response is malformed, so fail hard rather
    // than silently truncating the optional statusString/failureInfo (L-6).
    while !remaining.is_empty() {
        let (stag, sbody, srest) = der_utils::parse_tlv_with_rest(remaining).map_err(|e| {
            TspError::InvalidResponse(format!("malformed PKIStatusInfo field: {e}"))
        })?;
        match stag {
            // statusString PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
            0x30 => {
                // PKIFreeText is SIZE (1..MAX): a present-but-empty SEQUENCE
                // violates the constraint, so reject it rather than silently
                // accepting it and leaving `status_string` as None (L-6).
                if sbody.is_empty() {
                    return Err(TspError::InvalidResponse(
                        "statusString PKIFreeText SEQUENCE is empty (violates SIZE (1..MAX))"
                            .into(),
                    ));
                }
                // EVERY element MUST be a UTF8String (tag 0x0C) carrying valid
                // UTF-8 — not only the first. Reject any other ASN.1 type and
                // reject invalid UTF-8 rather than lossily normalizing it (L-6).
                // The first element is surfaced as `status_string`.
                let mut elems = sbody;
                while !elems.is_empty() {
                    let (inner_tag, inner_body, inner_rest) = der_utils::parse_tlv_with_rest(elems)
                        .map_err(|e| {
                            TspError::InvalidResponse(format!("malformed statusString: {e}"))
                        })?;
                    if inner_tag != 0x0C {
                        return Err(TspError::InvalidResponse(format!(
                            "statusString element is not a UTF8String (tag 0x0c), got 0x{inner_tag:02x}"
                        )));
                    }
                    let text = std::str::from_utf8(inner_body).map_err(|e| {
                        TspError::InvalidResponse(format!("statusString is not valid UTF-8: {e}"))
                    })?;
                    if status_string.is_none() {
                        status_string = Some(text.to_string());
                    }
                    elems = inner_rest;
                }
            }
            // BIT STRING (failureInfo)
            0x03 => {
                failure_info = Some(sbody.to_vec());
            }
            _ => {}
        }
        remaining = srest;
    }

    // Second element: TimeStampToken OPTIONAL
    let token_der = if !rest.is_empty() {
        // The token is a ContentInfo (SEQUENCE). It must be a structurally valid
        // SEQUENCE that consumes ALL remaining bytes of the TimeStampResp — any
        // trailing bytes after it are malformed and rejected rather than being
        // folded into token_der or ignored (L-6).
        let (token_tag, _, after) = der_utils::parse_tlv_with_rest(rest)
            .map_err(|e| TspError::InvalidResponse(format!("failed to parse token TLV: {e}")))?;
        if token_tag != 0x30 {
            return Err(TspError::InvalidResponse(format!(
                "expected TimeStampToken SEQUENCE (0x30), got 0x{token_tag:02x}"
            )));
        }
        if !after.is_empty() {
            return Err(TspError::InvalidResponse(
                "trailing data after TimeStampToken in TimeStampResp".into(),
            ));
        }
        // `rest` is now exactly the token TLV (tag + length + value).
        Some(rest.to_vec())
    } else {
        None
    };

    Ok(TimeStampResp {
        status,
        status_string,
        failure_info,
        token_der,
    })
}

/// Validate a TimeStampResp: check status, **cryptographically verify the
/// token signature**, and confirm the message imprint / nonce match the request.
///
/// This performs the full RFC 3161 / RFC 5652 verification of the embedded
/// `TimeStampToken`:
/// - the CMS `SignerInfo` signature is verified over the signed attributes;
/// - the `content-type` and `message-digest` signed attributes are checked to
///   bind the signature to the `TSTInfo` content;
/// - the signing certificate is required to carry a critical
///   `id-kp-timeStamping` extended key usage.
///
/// It does **not** chain the TSA certificate to a trust anchor — at request
/// time the caller has no trust store. Use [`verify_timestamp_token`] with a
/// [`TrustStore`] to perform full path validation at verification time.
///
/// `extra_certs` lets the caller supply the TSA signing certificate out-of-band
/// for tokens that omit the (optional) CMS `certificates` field — e.g. when the
/// request used `certReq=false`. Pass `&[]` when the request used `certReq=true`
/// (the default), since the certificate is then embedded.
///
/// Returns the raw DER-encoded TimeStampToken (CMS ContentInfo containing SignedData).
pub fn validate_timestamp_response(
    resp: &TimeStampResp,
    expected_hash: &[u8],
    expected_nonce: Option<u64>,
    digest_algorithm: DigestAlgorithm,
    extra_certs: &[Certificate],
) -> Result<Vec<u8>, TspError> {
    // Check status
    if !resp.status.is_success() {
        let msg = match &resp.status_string {
            Some(s) => format!("status={}, message={s}", resp.status),
            None => format!("status={}", resp.status),
        };
        return Err(TspError::TsaError(msg));
    }

    let token_der = resp.token_der.as_ref().ok_or_else(|| {
        TspError::InvalidResponse("no token in response despite success status".into())
    })?;

    // Cryptographically verify the CMS signature and bind it to the TSTInfo.
    let (_verified, tst_info) = verify_token_cms(token_der, extra_certs)?;

    // Validate message imprint hash / algorithm / nonce against the request.
    check_tst_info_matches(&tst_info, expected_hash, expected_nonce, digest_algorithm)?;

    Ok(token_der.clone())
}

/// Fully verify an RFC 3161 timestamp token, including chaining the TSA
/// signing certificate to a configured trust anchor.
///
/// This is the entry point a *verifier* (as opposed to the requester) should
/// use — e.g. when validating an AdES B-T signature's embedded timestamp.
///
/// Verification steps:
/// 1. Parse the CMS `ContentInfo`/`SignedData` and locate the signing certificate.
/// 2. Verify the `SignerInfo` signature over the DER-encoded signed attributes.
/// 3. Check the `content-type` and `message-digest` signed attributes bind the
///    signature to the encapsulated `TSTInfo`.
/// 4. Require a critical `id-kp-timeStamping` EKU on the signing certificate.
/// 5. Confirm the message imprint hash/algorithm (and nonce, if supplied) match.
/// 6. If `trust_store` is provided: build the certificate chain from the
///    available certificates and verify it terminates at a trust anchor.
///
/// The CMS `certificates` field is optional (RFC 5652) and some TSAs omit it
/// (e.g. when `certReq` was false). `extra_certs` lets the caller supply the
/// TSA signing certificate (and any intermediates) out-of-band so such tokens
/// can still be verified; pass `&[]` when the token embeds its own certificates.
///
/// `validation_time` is the time at which certificate validity is assessed
/// (typically the timestamp's `genTime` for archival validation, or "now").
/// When `None` and a trust store is supplied, it defaults to the token's
/// authenticated `genTime`.
///
/// Returns the verified [`TstInfo`] on success.
pub fn verify_timestamp_token(
    token_der: &[u8],
    expected_hash: &[u8],
    digest_algorithm: DigestAlgorithm,
    expected_nonce: Option<u64>,
    trust_store: Option<&TrustStore>,
    validation_time: Option<der::DateTime>,
    extra_certs: &[Certificate],
) -> Result<TstInfo, TspError> {
    let (verified, tst_info) = verify_token_cms(token_der, extra_certs)?;

    check_tst_info_matches(&tst_info, expected_hash, expected_nonce, digest_algorithm)?;

    if let Some(store) = trust_store {
        // Build the chain [signer, intermediate, ...] from embedded certs and
        // verify it reaches a trust anchor. verify_chain performs the actual
        // signature checks on every link, so the ordering is safe. Order using
        // the store's signature policy so that, when legacy algorithms are
        // allowed, a weak-but-valid link is still preferred over a bare
        // same-subject name match (which would otherwise pick the wrong
        // re-issued intermediate and make verify_chain fail).
        let chain = order_chain(
            &verified.signer,
            &verified.embedded,
            store.signature_policy(),
        );

        // Default the chain validation time to the token's authenticated
        // genTime. verify_chain skips intermediate/anchor time-validity checks
        // when validation_time is None, so falling back to genTime ensures the
        // chain is assessed as of the moment the timestamp was created (the
        // correct instant for archival validation) rather than not at all.
        let effective_time = match validation_time {
            Some(t) => Some(t),
            None => Some(gen_time_datetime(&tst_info)?),
        };

        store.verify_chain(&chain, effective_time).map_err(|e| {
            TspError::VerificationFailed(format!(
                "TSA certificate does not chain to a trust anchor: {e}"
            ))
        })?;
    }

    Ok(tst_info)
}

/// A timestamp token whose CMS signature has been cryptographically verified.
struct VerifiedToken {
    /// The certificate whose key signed the token.
    signer: Certificate,
    /// All certificates embedded in the SignedData (signer + any intermediates).
    embedded: Vec<Certificate>,
}

/// Parse and cryptographically verify the CMS SignedData of a timestamp token.
///
/// Returns the verified signer/embedded certificates together with the parsed
/// `TSTInfo` taken from the (now-authenticated) encapsulated content.
fn verify_token_cms(
    token_der: &[u8],
    extra_certs: &[Certificate],
) -> Result<(VerifiedToken, TstInfo), TspError> {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;

    // ContentInfo { contentType, content [0] EXPLICIT }
    let ci = ContentInfo::from_der(token_der)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse ContentInfo: {e}")))?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(TspError::InvalidResponse(format!(
            "ContentInfo contentType is not id-signedData (got {})",
            ci.content_type
        )));
    }

    let signed_data: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse SignedData: {e}")))?;

    // encapContentInfo must wrap a TSTInfo.
    let eci = &signed_data.encap_content_info;
    if eci.econtent_type != ID_CT_TST_INFO {
        return Err(TspError::InvalidResponse(format!(
            "encapContentInfo eContentType is not id-ct-TSTInfo (got {})",
            eci.econtent_type
        )));
    }
    let econtent = eci.econtent.as_ref().ok_or_else(|| {
        TspError::InvalidResponse("SignedData has no encapsulated content".into())
    })?;
    // The eContent is an OCTET STRING; its value is the DER of TSTInfo.
    let tst_info_der = econtent.value().to_vec();

    // Exactly one SignerInfo is expected for an RFC 3161 token. More than one
    // makes verification ambiguous (which signer is authoritative?), so reject.
    let signer_infos = &signed_data.signer_infos.0;
    if signer_infos.len() != 1 {
        return Err(TspError::InvalidResponse(format!(
            "expected exactly one SignerInfo, found {}",
            signer_infos.len()
        )));
    }
    let signer_info = signer_infos.iter().next().expect("checked len == 1");

    // Signed attributes are mandatory: the signature is computed over them, and
    // they carry the message-digest binding to the eContent.
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| TspError::VerificationFailed("SignerInfo has no signedAttrs".into()))?;

    // Collect candidate certificates: those embedded in the token (CMS
    // `certificates` is optional and may be absent) plus any supplied
    // out-of-band by the caller via `extra_certs`.
    let mut embedded: Vec<Certificate> = Vec::new();
    if let Some(cert_set) = &signed_data.certificates {
        for choice in cert_set.0.iter() {
            if let CertificateChoices::Certificate(cert) = choice {
                embedded.push(cert.clone());
            }
        }
    }
    for cert in extra_certs {
        if !embedded
            .iter()
            .any(|c| c.tbs_certificate == cert.tbs_certificate)
        {
            embedded.push(cert.clone());
        }
    }

    // No certificates to verify against at all: the token omitted the (optional)
    // CMS `certificates` field and the caller supplied no `extra_certs`. This is
    // not a cryptographic failure — we simply lack the signer's public key — so
    // report it distinctly and point the caller at the two ways to provide it.
    if embedded.is_empty() {
        return Err(TspError::InvalidResponse(
            "timestamp token contains no certificates and no extra_certs were supplied; \
             request the token with certReq=true, or pass the TSA certificate via extra_certs"
                .into(),
        ));
    }

    // Locate the signing certificate identified by SignerInfo.sid.
    let signer = find_signer_cert(&signer_info.sid, &embedded).ok_or_else(|| {
        TspError::VerificationFailed(
            "signing certificate identified by SignerInfo not found in token or extra_certs".into(),
        )
    })?;

    // The digest algorithm used for the message-digest attribute and signature.
    let digest_alg = DigestAlgorithm::from_oid(&signer_info.digest_alg.oid).ok_or_else(|| {
        TspError::VerificationFailed(format!(
            "unsupported SignerInfo digestAlgorithm OID: {}",
            signer_info.digest_alg.oid
        ))
    })?;

    // --- content-type signed attribute must equal id-ct-TSTInfo ---
    let content_type_attr =
        find_attribute(signed_attrs, &ID_CONTENT_TYPE_ATTR)?.ok_or_else(|| {
            TspError::VerificationFailed("signedAttrs missing content-type attribute".into())
        })?;
    let signed_content_type: ObjectIdentifier = content_type_attr.decode_as().map_err(|e| {
        TspError::VerificationFailed(format!("invalid content-type attribute: {e}"))
    })?;
    if signed_content_type != ID_CT_TST_INFO {
        return Err(TspError::VerificationFailed(format!(
            "signed content-type is not id-ct-TSTInfo (got {signed_content_type})"
        )));
    }

    // --- message-digest signed attribute must equal digest(eContent) ---
    let message_digest_attr =
        find_attribute(signed_attrs, &ID_MESSAGE_DIGEST_ATTR)?.ok_or_else(|| {
            TspError::VerificationFailed("signedAttrs missing message-digest attribute".into())
        })?;
    // RFC 5652: the message-digest attribute value is an OCTET STRING. Decode it
    // as such rather than reading raw Any bytes, so a different ASN.1 type whose
    // content happens to match cannot be accepted.
    let signed_digest = message_digest_attr
        .decode_as::<OctetString>()
        .map_err(|e| {
            TspError::VerificationFailed(format!(
                "message-digest attribute is not an OCTET STRING: {e}"
            ))
        })?;
    let computed_digest = digest_alg.digest(&tst_info_der);
    if signed_digest.as_bytes() != computed_digest.as_slice() {
        return Err(TspError::VerificationFailed(
            "message-digest signed attribute does not match the TSTInfo content".into(),
        ));
    }

    // --- verify the SignerInfo signature over the DER-encoded signedAttrs ---
    // CMS signs the SET OF SignedAttributes (tag 0x31), not the [0] IMPLICIT form.
    let signed_attrs_der = signed_attrs.to_der().map_err(|e| {
        TspError::VerificationFailed(format!("failed to re-encode signedAttrs: {e}"))
    })?;
    let spki_der = signer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| TspError::VerificationFailed(format!("failed to encode signer SPKI: {e}")))?;
    verify_cms_signature(
        &signed_attrs_der,
        signer_info.signature.as_bytes(),
        &spki_der,
        &signer_info.signature_algorithm,
        digest_alg,
    )
    .map_err(|e| TspError::VerificationFailed(format!("TSA signature verification failed: {e}")))?;

    // --- require a critical id-kp-timeStamping EKU on the signer ---
    require_timestamping_eku(&signer)?;

    // The TSTInfo is now authenticated; parse its fields.
    let tst_info = parse_tst_info_body(&tst_info_der)?;

    // RFC 3161: genTime must fall within the signing certificate's validity.
    // This holds independently of any trust store, so enforce it on every
    // verification path (both the requester and the verifier entry points).
    check_gen_time_within_validity(&signer, &tst_info)?;

    Ok((VerifiedToken { signer, embedded }, tst_info))
}

/// Validate that a parsed [`TstInfo`] matches the request's expected hash,
/// algorithm, and (optionally) nonce.
fn check_tst_info_matches(
    tst_info: &TstInfo,
    expected_hash: &[u8],
    expected_nonce: Option<u64>,
    digest_algorithm: DigestAlgorithm,
) -> Result<(), TspError> {
    use subtle::ConstantTimeEq;

    // Compare the messageImprint hash in constant time (L-7). These are public,
    // locally-derived values so the risk is low, but a constant-time compare is
    // cheap defense-in-depth and avoids leaking a match-prefix length.
    let hash_matches = tst_info.message_hash.len() == expected_hash.len()
        && bool::from(tst_info.message_hash.ct_eq(expected_hash));
    if !hash_matches {
        return Err(TspError::InvalidResponse(
            "TSTInfo messageImprint hash does not match request".into(),
        ));
    }

    if tst_info.hash_algorithm != digest_algorithm {
        return Err(TspError::InvalidResponse(format!(
            "TSTInfo hash algorithm mismatch: expected {:?}, got {:?}",
            digest_algorithm, tst_info.hash_algorithm,
        )));
    }

    if let Some(expected) = expected_nonce {
        match tst_info.nonce {
            // Constant-time nonce comparison (L-7).
            Some(actual) if bool::from(actual.ct_eq(&expected)) => {}
            Some(actual) => {
                return Err(TspError::InvalidResponse(format!(
                    "nonce mismatch: expected {expected}, got {actual}"
                )));
            }
            None => {
                return Err(TspError::InvalidResponse(
                    "expected nonce in TSTInfo but none present".into(),
                ));
            }
        }
    }

    Ok(())
}

/// Find the certificate identified by a CMS `SignerIdentifier` among `certs`.
fn find_signer_cert(
    sid: &cms::signed_data::SignerIdentifier,
    certs: &[Certificate],
) -> Option<Certificate> {
    use cms::signed_data::SignerIdentifier;
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(iasn) => certs
            .iter()
            .find(|c| {
                c.tbs_certificate.issuer == iasn.issuer
                    && c.tbs_certificate.serial_number == iasn.serial_number
            })
            .cloned(),
        SignerIdentifier::SubjectKeyIdentifier(skid) => {
            let want = skid.0.as_bytes();
            certs
                .iter()
                .find(|c| cert_ski(c).as_deref() == Some(want))
                .cloned()
        }
    }
}

/// Extract the SubjectKeyIdentifier (2.5.29.14) octet contents from a cert.
fn cert_ski(cert: &Certificate) -> Option<Vec<u8>> {
    let ski_oid = ObjectIdentifier::new_unwrap("2.5.29.14");
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    let ext = exts.iter().find(|e| e.extn_id == ski_oid)?;
    // extnValue is an OCTET STRING wrapping the SKI OCTET STRING.
    let (tag, body) = der_utils::parse_tlv(ext.extn_value.as_bytes()).ok()?;
    if tag != 0x04 {
        return None;
    }
    Some(body)
}

/// Find a single-valued signed attribute by OID.
///
/// Returns `Ok(None)` if the attribute is absent. CMS signed attributes such as
/// `content-type` and `message-digest` must appear exactly once and carry a
/// single value (RFC 5652 §11); duplicate attributes or multi-valued attributes
/// are rejected with `Err` to avoid ambiguity.
fn find_attribute<'a>(
    attrs: &'a x509_cert::attr::Attributes,
    oid: &ObjectIdentifier,
) -> Result<Option<&'a der::Any>, TspError> {
    let mut matching = attrs.iter().filter(|attr| attr.oid == *oid);
    let attr = match matching.next() {
        Some(a) => a,
        None => return Ok(None),
    };
    if matching.next().is_some() {
        return Err(TspError::VerificationFailed(format!(
            "duplicate signed attribute {oid}"
        )));
    }
    if attr.values.len() != 1 {
        return Err(TspError::VerificationFailed(format!(
            "signed attribute {oid} must have exactly one value (has {})",
            attr.values.len()
        )));
    }
    Ok(attr.values.iter().next())
}

/// Verify the CMS `SignerInfo` signature over `signed_attrs_der`.
///
/// The CMS `SignerInfo.signatureAlgorithm` is frequently a *bare* key algorithm
/// (`rsaEncryption`, `id-ecPublicKey`, `rsassaPss`) rather than a combined
/// sig+hash OID. The authoritative hash is `SignerInfo.digestAlgorithm`
/// (`digest_alg`), so we bind verification to it:
/// - RSASSA-PSS is verified strictly according to its `RSASSA-PSS-params`
///   (hashAlgorithm, MGF1 hash, saltLength, trailerField), and those
///   parameters must agree with `digestAlgorithm`. See [`verify_pss_signature`].
/// - Bare `rsaEncryption` / `id-ecPublicKey` are mapped to the combined OID for
///   `digest_alg`.
/// - A combined OID (sha256WithRSAEncryption, ecdsa-with-SHA256, ...) is passed
///   through, but only after checking that the hash it encodes matches
///   `digestAlgorithm`; a mismatch is rejected rather than silently accepted.
fn verify_cms_signature(
    signed_attrs_der: &[u8],
    signature: &[u8],
    spki_der: &[u8],
    signature_algorithm: &AlgorithmIdentifierOwned,
    digest_alg: DigestAlgorithm,
) -> Result<(), TrustError> {
    use crate::crypto::verify::verify_signature_by_oid;
    use const_oid::db;

    let sig_alg_oid = &signature_algorithm.oid;

    if *sig_alg_oid == OID_RSASSA_PSS {
        return verify_pss_signature(
            signed_attrs_der,
            signature,
            spki_der,
            signature_algorithm,
            digest_alg,
        );
    }

    let resolved = if *sig_alg_oid == OID_RSA_ENCRYPTION {
        match digest_alg {
            DigestAlgorithm::Sha256 => db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            DigestAlgorithm::Sha384 => db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION,
            DigestAlgorithm::Sha512 => db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION,
            _ => *sig_alg_oid,
        }
    } else if *sig_alg_oid == OID_EC_PUBLIC_KEY {
        match digest_alg {
            DigestAlgorithm::Sha256 => db::rfc5912::ECDSA_WITH_SHA_256,
            DigestAlgorithm::Sha384 => db::rfc5912::ECDSA_WITH_SHA_384,
            DigestAlgorithm::Sha512 => db::rfc5912::ECDSA_WITH_SHA_512,
            _ => *sig_alg_oid,
        }
    } else {
        // Already a combined OID (sha256WithRSAEncryption, ecdsa-with-SHA256,
        // Ed25519, ...). For the RSA/ECDSA combined forms the hash is encoded in
        // the OID itself; reject any token whose signatureAlgorithm hash
        // disagrees with the SignerInfo.digestAlgorithm used for the
        // message-digest attribute, instead of trusting two inconsistent hashes.
        if let Some(embedded) = combined_oid_digest(sig_alg_oid) {
            if embedded != digest_alg {
                return Err(TrustError::SignatureVerification(format!(
                    "signatureAlgorithm hash ({}) disagrees with SignerInfo.digestAlgorithm ({})",
                    embedded.name(),
                    digest_alg.name(),
                )));
            }
        }
        *sig_alg_oid
    };

    verify_signature_by_oid(signed_attrs_der, signature, spki_der, &resolved)
}

/// Verify an RSASSA-PSS `SignerInfo` signature strictly per its
/// `RSASSA-PSS-params` (RFC 4055), then bind the PSS hash to
/// `SignerInfo.digestAlgorithm`.
///
/// The parameter handling (hashAlgorithm, MGF1 hash, saltLength, trailerField)
/// lives in [`crate::crypto::verify::verify_rsa_pss_signature_strict`], shared
/// with certificate/CRL/OCSP verification. On top of that, CMS requires the
/// PSS `hashAlgorithm` to equal the `digestAlgorithm` used for the
/// message-digest attribute, so a token that pairs a mismatched hash with PSS
/// is rejected here even though the signature itself is well-formed.
fn verify_pss_signature(
    signed_attrs_der: &[u8],
    signature: &[u8],
    spki_der: &[u8],
    signature_algorithm: &AlgorithmIdentifierOwned,
    digest_alg: DigestAlgorithm,
) -> Result<(), TrustError> {
    use crate::crypto::verify::verify_rsa_pss_signature_strict;

    let pss_hash = verify_rsa_pss_signature_strict(
        signed_attrs_der,
        signature,
        spki_der,
        signature_algorithm.parameters.as_ref(),
    )?;

    if pss_hash != digest_alg {
        return Err(TrustError::SignatureVerification(format!(
            "RSASSA-PSS hashAlgorithm ({}) disagrees with SignerInfo.digestAlgorithm ({})",
            pss_hash.name(),
            digest_alg.name(),
        )));
    }

    Ok(())
}

/// For a *combined* signature-algorithm OID (one that bakes in the hash, e.g.
/// `sha256WithRSAEncryption` or `ecdsa-with-SHA256`), return the digest it
/// encodes. Returns `None` for OIDs that carry no separate hash we model here
/// (Ed25519, or legacy SHA-1/MD5/SHA-224 forms outside our digest set).
fn combined_oid_digest(oid: &ObjectIdentifier) -> Option<DigestAlgorithm> {
    use const_oid::db;
    if *oid == db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION || *oid == db::rfc5912::ECDSA_WITH_SHA_256 {
        Some(DigestAlgorithm::Sha256)
    } else if *oid == db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION
        || *oid == db::rfc5912::ECDSA_WITH_SHA_384
    {
        Some(DigestAlgorithm::Sha384)
    } else if *oid == db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION
        || *oid == db::rfc5912::ECDSA_WITH_SHA_512
    {
        Some(DigestAlgorithm::Sha512)
    } else {
        None
    }
}

/// Require that `cert` carries the `id-kp-timeStamping` EKU, marked critical,
/// per RFC 3161 §2.3.
fn require_timestamping_eku(cert: &Certificate) -> Result<(), TspError> {
    let exts = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
        TspError::VerificationFailed("TSA certificate has no extensions (no EKU)".into())
    })?;
    let eku_ext = exts
        .iter()
        .find(|e| e.extn_id == ID_CE_EXT_KEY_USAGE)
        .ok_or_else(|| {
            TspError::VerificationFailed(
                "TSA certificate lacks an extendedKeyUsage extension".into(),
            )
        })?;

    if !eku_ext.critical {
        return Err(TspError::VerificationFailed(
            "TSA certificate extendedKeyUsage is not marked critical (RFC 3161 §2.3)".into(),
        ));
    }

    if !eku_contains(eku_ext.extn_value.as_bytes(), &ID_KP_TIME_STAMPING) {
        return Err(TspError::VerificationFailed(
            "TSA certificate extendedKeyUsage does not include id-kp-timeStamping".into(),
        ));
    }

    Ok(())
}

/// Return true if an EKU extension value (SEQUENCE OF OID) contains `target`.
fn eku_contains(eku_der: &[u8], target: &ObjectIdentifier) -> bool {
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
        if oid_tag == 0x06 {
            if let Ok(oid) = ObjectIdentifier::from_der(&der_utils::encode_tlv(0x06, oid_body)) {
                if oid == *target {
                    return true;
                }
            }
        }
        pos = rest;
    }
    false
}

/// Order embedded certificates into a chain `[signer, issuer, ...]`.
///
/// For each step, candidates are matched by subject==issuer name and then the
/// one whose public key actually verifies the current certificate's signature
/// is preferred. This avoids picking the wrong certificate when several
/// embedded certs share a subject name (e.g. re-issued intermediates), which
/// would otherwise make a valid chain fail in [`TrustStore::verify_chain`]. If
/// no candidate verifies, the first name match is used so verify_chain still
/// produces a meaningful error.
fn order_chain(
    signer: &Certificate,
    embedded: &[Certificate],
    policy: crate::crypto::verify::SignaturePolicy,
) -> Vec<Certificate> {
    let mut chain = vec![signer.clone()];
    // Bounded to avoid loops on adversarial inputs.
    for _ in 0..16 {
        let current = chain.last().unwrap().clone();
        if current.tbs_certificate.issuer == current.tbs_certificate.subject {
            break; // reached a self-signed cert
        }
        let candidates: Vec<&Certificate> = embedded
            .iter()
            .filter(|c| {
                c.tbs_certificate.subject == current.tbs_certificate.issuer
                    && !chain
                        .iter()
                        .any(|existing| existing.tbs_certificate == c.tbs_certificate)
            })
            .collect();

        // Prefer a candidate whose key actually signed `current`. Use the same
        // policy verify_chain will use, so a legacy-but-valid link is preferred
        // (under allow_legacy) instead of being skipped and falling back to a
        // possibly-wrong same-subject name match.
        let chosen = candidates
            .iter()
            .find(|c| {
                crate::crypto::verify::verify_certificate_signature_with_policy(
                    &current, c, &policy,
                )
                .is_ok()
            })
            .or_else(|| candidates.first());

        match chosen {
            Some(c) => chain.push((*c).clone()),
            None => break,
        }
    }
    chain
}

/// Decode the timestamp's `genTime` (GeneralizedTime) to a `der::DateTime`.
fn gen_time_datetime(tst_info: &TstInfo) -> Result<der::DateTime, TspError> {
    // gen_time_der holds the GeneralizedTime *contents*; re-wrap to decode.
    let gt_tlv = der_utils::encode_tlv(0x18, &tst_info.gen_time_der);
    Ok(der::asn1::GeneralizedTime::from_der(&gt_tlv)
        .map_err(|e| TspError::VerificationFailed(format!("invalid genTime: {e}")))?
        .to_date_time())
}

/// Confirm the timestamp's `genTime` falls within the signer certificate's
/// validity window (RFC 3161).
fn check_gen_time_within_validity(
    signer: &Certificate,
    tst_info: &TstInfo,
) -> Result<(), TspError> {
    let gen_time = gen_time_datetime(tst_info)?;

    let validity = &signer.tbs_certificate.validity;
    let not_before = validity.not_before.to_date_time();
    let not_after = validity.not_after.to_date_time();

    if gen_time < not_before || gen_time > not_after {
        return Err(TspError::VerificationFailed(format!(
            "timestamp genTime {gen_time} is outside the TSA certificate validity \
             ({not_before} .. {not_after})"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// TSTInfo extraction
// ---------------------------------------------------------------------------

/// Parsed TSTInfo from a TimeStampToken.
#[derive(Debug)]
pub struct TstInfo {
    /// The hash algorithm used in the message imprint.
    pub hash_algorithm: DigestAlgorithm,
    /// The message hash from the message imprint.
    pub message_hash: Vec<u8>,
    /// The serial number of the timestamp.
    pub serial_number: Vec<u8>,
    /// The generation time (raw DER bytes of GeneralizedTime).
    pub gen_time_der: Vec<u8>,
    /// Nonce from the response (if present).
    pub nonce: Option<u64>,
    /// The TSA policy OID.
    pub policy_oid: Option<String>,
}

/// Extract TSTInfo from a TimeStampToken (CMS ContentInfo).
///
/// The TimeStampToken is a CMS ContentInfo wrapping SignedData,
/// whose encapsulated content is id-ct-TSTInfo.
pub fn extract_tst_info(token_der: &[u8]) -> Result<TstInfo, TspError> {
    // Parse ContentInfo SEQUENCE
    let (tag, ci_body) = der_utils::parse_tlv(token_der)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse ContentInfo: {e}")))?;
    if tag != 0x30 {
        return Err(TspError::InvalidResponse(
            "ContentInfo: expected SEQUENCE".into(),
        ));
    }

    // contentType OID — should be id-signedData
    let (_oid_tag, _oid_body, ci_rest) = der_utils::parse_tlv_with_rest(&ci_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse contentType: {e}")))?;

    // content [0] EXPLICIT — the SignedData
    let (ctx_tag, sd_inner, _) = der_utils::parse_tlv_with_rest(ci_rest)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse content [0]: {e}")))?;
    if ctx_tag != 0xA0 {
        return Err(TspError::InvalidResponse(format!(
            "expected [0] EXPLICIT tag 0xA0, got 0x{ctx_tag:02x}"
        )));
    }

    // SignedData SEQUENCE
    let (sd_tag, sd_body) = der_utils::parse_tlv(sd_inner)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse SignedData: {e}")))?;
    if sd_tag != 0x30 {
        return Err(TspError::InvalidResponse(
            "SignedData: expected SEQUENCE".into(),
        ));
    }

    // SignedData fields: version, digestAlgorithms, encapContentInfo, [0] certs, [1] crls, signerInfos
    let (_ver_tag, _ver_body, sd_rest) = der_utils::parse_tlv_with_rest(&sd_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse SD version: {e}")))?;

    // digestAlgorithms SET OF
    let (_da_tag, _da_body, sd_rest2) = der_utils::parse_tlv_with_rest(sd_rest)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse digestAlgorithms: {e}")))?;

    // encapContentInfo SEQUENCE
    let (_eci_tag, eci_body, _sd_rest3) = der_utils::parse_tlv_with_rest(sd_rest2)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse encapContentInfo: {e}")))?;

    // eContentType OID
    let (_ect_tag, _ect_body, eci_rest) = der_utils::parse_tlv_with_rest(eci_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse eContentType: {e}")))?;

    // eContent [0] EXPLICIT
    let (ec_tag, ec_inner, _) = der_utils::parse_tlv_with_rest(eci_rest)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse eContent [0]: {e}")))?;
    if ec_tag != 0xA0 {
        return Err(TspError::InvalidResponse(format!(
            "expected eContent [0] tag 0xA0, got 0x{ec_tag:02x}"
        )));
    }

    // The eContent is an OCTET STRING containing TSTInfo
    let (os_tag, tst_info_der, _) = der_utils::parse_tlv_with_rest(ec_inner).map_err(|e| {
        TspError::InvalidResponse(format!("failed to parse eContent OCTET STRING: {e}"))
    })?;
    if os_tag != 0x04 {
        return Err(TspError::InvalidResponse(format!(
            "expected OCTET STRING 0x04 for eContent, got 0x{os_tag:02x}"
        )));
    }

    // Now parse TSTInfo SEQUENCE
    parse_tst_info_body(tst_info_der)
}

/// Parse the inner TSTInfo SEQUENCE body.
///
/// ```text
/// TSTInfo ::= SEQUENCE  {
///    version                      INTEGER  { v1(1) },
///    policy                       TSAPolicyId,
///    messageImprint               MessageImprint,
///    serialNumber                 INTEGER,
///    genTime                      GeneralizedTime,
///    accuracy                     Accuracy               OPTIONAL,
///    ordering                     BOOLEAN             DEFAULT FALSE,
///    nonce                        INTEGER                OPTIONAL,
///    tsa                     [0]  GeneralName            OPTIONAL,
///    extensions              [1]  IMPLICIT Extensions    OPTIONAL
/// }
/// ```
fn parse_tst_info_body(der_bytes: &[u8]) -> Result<TstInfo, TspError> {
    let (tag, body) = der_utils::parse_tlv(der_bytes).map_err(|e| {
        TspError::InvalidResponse(format!("TSTInfo: failed to parse SEQUENCE: {e}"))
    })?;
    if tag != 0x30 {
        return Err(TspError::InvalidResponse(
            "TSTInfo: expected SEQUENCE".into(),
        ));
    }

    let mut pos = &body[..];

    // version INTEGER
    let (_vtag, _vbody, rest) = der_utils::parse_tlv_with_rest(pos)
        .map_err(|e| TspError::InvalidResponse(format!("TSTInfo: failed to parse version: {e}")))?;
    pos = rest;

    // policy TSAPolicyId (OID)
    let (_ptag, pbody, rest) = der_utils::parse_tlv_with_rest(pos)
        .map_err(|e| TspError::InvalidResponse(format!("TSTInfo: failed to parse policy: {e}")))?;
    let policy_oid = ObjectIdentifier::from_der(&der_utils::encode_tlv(0x06, pbody))
        .ok()
        .map(|oid| oid.to_string());
    pos = rest;

    // messageImprint SEQUENCE { hashAlgorithm, hashedMessage }
    let (_mi_tag, mi_body, rest) = der_utils::parse_tlv_with_rest(pos).map_err(|e| {
        TspError::InvalidResponse(format!("TSTInfo: failed to parse messageImprint: {e}"))
    })?;
    pos = rest;

    let (hash_algorithm, message_hash) = parse_message_imprint(mi_body)?;

    // serialNumber INTEGER
    let (_sn_tag, sn_body, rest) = der_utils::parse_tlv_with_rest(pos).map_err(|e| {
        TspError::InvalidResponse(format!("TSTInfo: failed to parse serialNumber: {e}"))
    })?;
    let serial_number = sn_body.to_vec();
    pos = rest;

    // genTime GeneralizedTime
    let (_gt_tag, gt_body, rest) = der_utils::parse_tlv_with_rest(pos)
        .map_err(|e| TspError::InvalidResponse(format!("TSTInfo: failed to parse genTime: {e}")))?;
    let gen_time_der = gt_body.to_vec();
    pos = rest;

    // Now parse optional fields: accuracy, ordering, nonce, tsa, extensions
    let mut nonce = None;

    while !pos.is_empty() {
        if let Ok((ftag, fbody, frest)) = der_utils::parse_tlv_with_rest(pos) {
            match ftag {
                // accuracy is SEQUENCE
                0x30 => {
                    // Skip accuracy
                }
                // ordering BOOLEAN
                0x01 => {
                    // Skip ordering
                }
                // nonce INTEGER
                0x02 => {
                    nonce =
                        Some(der_utils::decode_integer_u64(fbody).map_err(|e| {
                            TspError::InvalidResponse(format!("TSTInfo nonce: {e}"))
                        })?);
                }
                // tsa [0] GeneralName
                0xA0 => {
                    // Skip TSA name
                }
                // extensions [1] IMPLICIT
                0xA1 => {
                    // Skip extensions
                }
                _ => {
                    // Unknown, skip
                }
            }
            pos = frest;
        } else {
            break;
        }
    }

    Ok(TstInfo {
        hash_algorithm,
        message_hash,
        serial_number,
        gen_time_der,
        nonce,
        policy_oid,
    })
}

/// Parse a MessageImprint: { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
fn parse_message_imprint(body: &[u8]) -> Result<(DigestAlgorithm, Vec<u8>), TspError> {
    // hashAlgorithm SEQUENCE
    let (_alg_tag, alg_body, rest) = der_utils::parse_tlv_with_rest(body).map_err(|e| {
        TspError::InvalidResponse(format!(
            "messageImprint: failed to parse hashAlgorithm: {e}"
        ))
    })?;

    // First element of AlgorithmIdentifier is the OID
    let (_oid_tag, oid_body, _) = der_utils::parse_tlv_with_rest(alg_body).map_err(|e| {
        TspError::InvalidResponse(format!(
            "messageImprint: failed to parse algorithm OID: {e}"
        ))
    })?;

    let alg_oid =
        ObjectIdentifier::from_der(&der_utils::encode_tlv(0x06, oid_body)).map_err(|e| {
            TspError::InvalidResponse(format!("messageImprint: invalid algorithm OID: {e}"))
        })?;

    let digest_alg = oid_to_digest_algorithm(&alg_oid)?;

    // hashedMessage OCTET STRING
    let (_hash_tag, hash_body, _) = der_utils::parse_tlv_with_rest(rest).map_err(|e| {
        TspError::InvalidResponse(format!(
            "messageImprint: failed to parse hashedMessage: {e}"
        ))
    })?;

    Ok((digest_alg, hash_body.to_vec()))
}

/// Map an OID to our DigestAlgorithm enum.
fn oid_to_digest_algorithm(oid: &ObjectIdentifier) -> Result<DigestAlgorithm, TspError> {
    DigestAlgorithm::from_oid(oid)
        .ok_or_else(|| TspError::InvalidResponse(format!("unsupported hash algorithm OID: {oid}")))
}

/// Build an AlgorithmIdentifier for a digest algorithm.
fn digest_algorithm_identifier(alg: DigestAlgorithm) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: alg.oid(),
        parameters: None,
    }
}

// ---------------------------------------------------------------------------
// Generate a nonce
// ---------------------------------------------------------------------------

/// Generate a cryptographically random 64-bit nonce for timestamp requests.
pub fn generate_nonce() -> u64 {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).expect("OS random number generator");
    u64::from_ne_bytes(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_timestamp_request_basic() {
        let hash = vec![0xAA; 32]; // SHA-256 sized
        let req =
            build_timestamp_request(DigestAlgorithm::Sha256, &hash, None, None, true).unwrap();

        // Should be a valid DER SEQUENCE
        assert_eq!(req[0], 0x30, "should start with SEQUENCE tag");

        // Parse it back
        let (tag, _body) = der_utils::parse_tlv(&req).unwrap();
        assert_eq!(tag, 0x30);
    }

    #[test]
    fn test_build_timestamp_request_with_nonce() {
        let hash = vec![0xBB; 32];
        let nonce = 12345678u64;
        let req = build_timestamp_request(DigestAlgorithm::Sha256, &hash, None, Some(nonce), true)
            .unwrap();

        let (tag, _body) = der_utils::parse_tlv(&req).unwrap();
        assert_eq!(tag, 0x30);
    }

    #[test]
    fn test_encode_integer_u64() {
        // Encode 1
        let encoded = der_utils::encode_integer_u64(1);
        assert_eq!(encoded, vec![0x02, 0x01, 0x01]);

        // Encode 128 (needs padding because high bit set)
        let encoded = der_utils::encode_integer_u64(128);
        assert_eq!(encoded, vec![0x02, 0x02, 0x00, 0x80]);

        // Encode 0
        let encoded = der_utils::encode_integer_u64(0);
        // Should be 0x02 0x01 0x00
        assert_eq!(encoded, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_pki_status_display() {
        assert_eq!(PkiStatus::Granted.to_string(), "granted (0)");
        assert_eq!(PkiStatus::Rejection.to_string(), "rejection (2)");
        assert!(PkiStatus::Granted.is_success());
        assert!(PkiStatus::GrantedWithMods.is_success());
        assert!(!PkiStatus::Rejection.is_success());
    }

    #[test]
    fn test_der_length_roundtrip() {
        for len in [0, 1, 127, 128, 255, 256, 65535, 65536] {
            let mut buf = Vec::new();
            der_utils::encode_der_length(&mut buf, len);
            let (parsed_len, consumed) = der_utils::parse_der_length(&buf).unwrap();
            assert_eq!(parsed_len, len, "length roundtrip failed for {len}");
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_parse_timestamp_response_error_status() {
        // Build a minimal TimeStampResp with rejection status
        // PKIStatusInfo SEQUENCE { PKIStatus INTEGER 2 }
        let status_info = der_utils::encode_sequence_raw(&der_utils::encode_integer_u64(2));
        let resp_der = der_utils::encode_sequence_raw(&status_info);

        let resp = parse_timestamp_response(&resp_der).unwrap();
        assert_eq!(resp.status, PkiStatus::Rejection);
        assert!(resp.token_der.is_none());
    }

    #[test]
    fn test_parse_timestamp_response_rejects_malformed_status_field() {
        // L-6: a structurally malformed element inside PKIStatusInfo must be a
        // hard error, not silently dropped. Status INTEGER 0 (granted) followed
        // by a SEQUENCE whose declared length overruns the buffer.
        let mut status_body = der_utils::encode_integer_u64(0);
        status_body.extend_from_slice(&[0x30, 0x05, 0x01]); // truncated SEQUENCE
        let status_info = der_utils::encode_sequence_raw(&status_body);
        let resp_der = der_utils::encode_sequence_raw(&status_info);

        let err = parse_timestamp_response(&resp_der)
            .expect_err("malformed PKIStatusInfo field must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(_)),
            "expected InvalidResponse, got {err:?}"
        );
    }

    /// Build a `TimeStampResp` whose PKIStatusInfo carries a rejection status
    /// and a `statusString` SEQUENCE wrapping a single element with `inner_tag`
    /// / `inner_body`, so tests can supply a non-UTF8String or invalid UTF-8.
    fn resp_with_status_string(inner_tag: u8, inner_body: &[u8]) -> Vec<u8> {
        let status_int = der_utils::encode_integer_u64(2); // rejection
        let free_text =
            der_utils::encode_sequence_raw(&der_utils::encode_tlv(inner_tag, inner_body));
        let mut status_body = status_int;
        status_body.extend_from_slice(&free_text);
        let status_info = der_utils::encode_sequence_raw(&status_body);
        der_utils::encode_sequence_raw(&status_info)
    }

    #[test]
    fn test_parse_timestamp_response_accepts_valid_status_string() {
        // A well-formed UTF8String statusString is decoded.
        let resp_der = resp_with_status_string(0x0C, "rejected: bad request".as_bytes());
        let resp = parse_timestamp_response(&resp_der).unwrap();
        assert_eq!(resp.status, PkiStatus::Rejection);
        assert_eq!(resp.status_string.as_deref(), Some("rejected: bad request"));
    }

    #[test]
    fn test_parse_timestamp_response_rejects_non_utf8string_status() {
        // L-6: PKIFreeText elements are UTF8String; an OCTET STRING (or any other
        // type) inside statusString must be rejected, not accepted blindly.
        let resp_der = resp_with_status_string(0x04, b"not a utf8string"); // OCTET STRING
        let err = parse_timestamp_response(&resp_der)
            .expect_err("non-UTF8String statusString must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(ref m) if m.contains("UTF8String")),
            "expected UTF8String tag rejection, got {err:?}"
        );
    }

    #[test]
    fn test_parse_timestamp_response_rejects_invalid_utf8_status() {
        // L-6: invalid UTF-8 inside a UTF8String must be rejected, not lossily
        // normalized.
        let resp_der = resp_with_status_string(0x0C, &[0xFF, 0xFE, 0xFD]);
        let err = parse_timestamp_response(&resp_der)
            .expect_err("invalid UTF-8 statusString must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(ref m) if m.contains("UTF-8")),
            "expected invalid-UTF-8 rejection, got {err:?}"
        );
    }

    #[test]
    fn test_parse_timestamp_response_rejects_malformed_trailing_status_element() {
        // L-6 (PR review): PKIFreeText is SEQUENCE OF UTF8String — EVERY element
        // must be validated, not just the first. A valid first UTF8String
        // followed by a non-UTF8String element must still be rejected.
        let status_int = der_utils::encode_integer_u64(2); // rejection
        let mut free_text_body = der_utils::encode_tlv(0x0C, b"ok");
        free_text_body.extend_from_slice(&der_utils::encode_tlv(0x04, b"bad")); // OCTET STRING
        let free_text = der_utils::encode_sequence_raw(&free_text_body);
        let mut status_body = status_int;
        status_body.extend_from_slice(&free_text);
        let status_info = der_utils::encode_sequence_raw(&status_body);
        let resp_der = der_utils::encode_sequence_raw(&status_info);

        let err = parse_timestamp_response(&resp_der)
            .expect_err("a trailing non-UTF8String statusString element must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(ref m) if m.contains("UTF8String")),
            "expected UTF8String rejection of the trailing element, got {err:?}"
        );
    }

    #[test]
    fn test_parse_timestamp_response_rejects_empty_status_string() {
        // L-6 (PR review): PKIFreeText is SEQUENCE SIZE (1..MAX) OF UTF8String.
        // A present-but-empty statusString SEQUENCE violates the size constraint
        // and must be rejected rather than silently leaving status_string None.
        let status_int = der_utils::encode_integer_u64(2); // rejection
        let free_text = der_utils::encode_sequence_raw(&[]); // empty SEQUENCE
        let mut status_body = status_int;
        status_body.extend_from_slice(&free_text);
        let status_info = der_utils::encode_sequence_raw(&status_body);
        let resp_der = der_utils::encode_sequence_raw(&status_info);

        let err = parse_timestamp_response(&resp_der)
            .expect_err("an empty statusString SEQUENCE must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(ref m) if m.contains("empty")),
            "expected empty-PKIFreeText rejection, got {err:?}"
        );
    }

    #[test]
    fn test_parse_timestamp_response_rejects_trailing_bytes_after_token() {
        // L-6 (PR review): the TimeStampToken must consume all remaining bytes of
        // the TimeStampResp; trailing bytes after it are malformed.
        let status_info = der_utils::encode_sequence_raw(&der_utils::encode_integer_u64(0));
        let token = der_utils::encode_sequence_raw(&der_utils::encode_integer_u64(1)); // dummy SEQUENCE
        let mut body = status_info;
        body.extend_from_slice(&token);
        body.extend_from_slice(&der_utils::encode_integer_u64(9)); // trailing junk
        let resp_der = der_utils::encode_sequence_raw(&body);

        let err = parse_timestamp_response(&resp_der)
            .expect_err("trailing bytes after the TimeStampToken must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(ref m) if m.contains("trailing")),
            "expected trailing-data rejection, got {err:?}"
        );
    }

    #[test]
    fn test_parse_timestamp_response_rejects_non_sequence_token() {
        // L-6: a non-SEQUENCE where the optional TimeStampToken is expected is
        // malformed and must be rejected rather than yielding token_der = None.
        let status_info = der_utils::encode_sequence_raw(&der_utils::encode_integer_u64(0));
        let mut body = status_info;
        // Append a bogus token: an INTEGER instead of a ContentInfo SEQUENCE.
        body.extend_from_slice(&der_utils::encode_integer_u64(7));
        let resp_der = der_utils::encode_sequence_raw(&body);

        let err = parse_timestamp_response(&resp_der)
            .expect_err("non-SEQUENCE TimeStampToken must be rejected");
        assert!(
            matches!(err, TspError::InvalidResponse(_)),
            "expected InvalidResponse, got {err:?}"
        );
    }

    #[test]
    fn test_generate_nonce() {
        let n1 = generate_nonce();
        // Brief pause to ensure different nonce
        std::thread::sleep(std::time::Duration::from_millis(1));
        let n2 = generate_nonce();
        // They should differ (with extremely high probability)
        assert_ne!(n1, n2, "nonces should be unique");
    }

    // ── RFC 3161 token signature verification (C-1 fix) ──────────────────

    use cms::cert::CertificateChoices;
    use cms::content_info::{CmsVersion, ContentInfo};
    use cms::signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignerIdentifier, SignerInfo, SignerInfos,
    };
    use der::asn1::{Any, SetOfVec};
    use der::{Decode, Tag};
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;
    use spki::AlgorithmIdentifierOwned;
    use std::sync::OnceLock;
    use x509_cert::attr::Attribute;
    use x509_cert::Certificate;

    const INTERMEDIATE_CERT_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/intermediate_ca_cert.pem"
    ));
    const INTERMEDIATE_KEY_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/intermediate_ca_key.pem"
    ));
    const ROOT_CERT_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ca_cert.pem"
    ));

    fn load_cert(pem: &str) -> Certificate {
        let (_, der) = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap();
        Certificate::from_der(&der).unwrap()
    }

    fn load_key(pem: &str) -> RsaPrivateKey {
        let der = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap().1;
        RsaPrivateKey::from_pkcs8_der(&der).unwrap()
    }

    fn intermediate_cert() -> Certificate {
        load_cert(INTERMEDIATE_CERT_PEM)
    }

    fn intermediate_key() -> RsaPrivateKey {
        load_key(INTERMEDIATE_KEY_PEM)
    }

    /// A TSA signing identity (certificate + private key) generated at runtime,
    /// so no private key is committed to the repository. The certificate carries
    /// a critical id-kp-timeStamping EKU and is issued by the committed
    /// intermediate CA, so it chains to the committed test root.
    struct TsaIdentity {
        cert: Certificate,
        key: RsaPrivateKey,
    }

    fn tsa_identity() -> &'static TsaIdentity {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Keypair;
        use sha2::Sha256;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::ext::pkix::ExtendedKeyUsage;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        static ID: OnceLock<TsaIdentity> = OnceLock::new();
        ID.get_or_init(|| {
            // Generate the TSA keypair at runtime.
            let mut rng = rand::thread_rng();
            let tsa_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
            let tsa_signing = SigningKey::<Sha256>::new(tsa_key.clone());
            let spki = SubjectPublicKeyInfoOwned::from_key(tsa_signing.verifying_key())
                .expect("SPKI from key");

            // Issue the TSA cert from the committed intermediate CA.
            let issuer = intermediate_cert();
            let ca_signer = SigningKey::<Sha256>::new(intermediate_key());
            let profile = Profile::Leaf {
                issuer: issuer.tbs_certificate.subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            };
            let serial = SerialNumber::new(&[0x2A]).unwrap();
            // Valid from "now" for ~10 years; clock-derived genTimes fall inside.
            let validity =
                Validity::from_now(std::time::Duration::from_secs(3650 * 24 * 3600)).unwrap();
            let subject: Name = "CN=Runtime Test TSA,O=tsp-ltv tests".parse().unwrap();

            let mut builder =
                CertificateBuilder::new(profile, serial, validity, subject, spki, &ca_signer)
                    .expect("cert builder");
            // Critical because the EKU set does not include anyExtendedKeyUsage.
            builder
                .add_extension(&ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]))
                .expect("add EKU");
            let cert = builder
                .build::<rsa::pkcs1v15::Signature>()
                .expect("sign cert");

            TsaIdentity { cert, key: tsa_key }
        })
    }

    fn tsa_cert() -> Certificate {
        tsa_identity().cert.clone()
    }

    fn tsa_key() -> RsaPrivateKey {
        tsa_identity().key.clone()
    }

    const SHA256_OID_DER: &[u8] = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];

    /// Format a chrono UTC instant as GeneralizedTime contents (YYYYMMDDHHMMSSZ).
    fn fmt_generalized(dt: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
        dt.format("%Y%m%d%H%M%SZ").to_string().into_bytes()
    }

    /// A genTime inside the runtime TSA cert validity. The cert is valid from
    /// "now" for ~10 years, so the current instant is always inside. Derived
    /// from the clock (not a hard-coded calendar date) so tests don't expire.
    fn gen_time_within() -> Vec<u8> {
        fmt_generalized(chrono::Utc::now())
    }

    /// A genTime past the runtime TSA cert's notAfter (~now + 10y).
    fn gen_time_after_validity() -> Vec<u8> {
        fmt_generalized(chrono::Utc::now() + chrono::Duration::days(365 * 20))
    }

    /// A `der::DateTime` for "now", used as the chain validation time.
    fn validation_time() -> der::DateTime {
        use chrono::{Datelike, Timelike};
        let n = chrono::Utc::now();
        der::DateTime::new(
            n.year() as u16,
            n.month() as u8,
            n.day() as u8,
            n.hour() as u8,
            n.minute() as u8,
            n.second() as u8,
        )
        .unwrap()
    }

    /// Build a DER-encoded TSTInfo with the given message imprint hash, nonce,
    /// and genTime (GeneralizedTime contents, i.e. b"YYYYMMDDHHMMSSZ").
    fn build_tst_info(hash: &[u8], nonce: u64, gen_time_bytes: &[u8]) -> Vec<u8> {
        let version = der_utils::encode_integer_u64(1);
        // policy OID (arbitrary but well-formed)
        let policy = der_utils::encode_tlv(0x06, &[0x2B, 0x06, 0x01, 0x04, 0x01]);
        // messageImprint { AlgorithmIdentifier{ sha256, NULL }, OCTET STRING hash }
        let alg = der_utils::encode_sequence_from_parts(&[SHA256_OID_DER, &[0x05, 0x00]]);
        let hashed = der_utils::encode_tlv(0x04, hash);
        let message_imprint = der_utils::encode_sequence_from_parts(&[&alg, &hashed]);
        let serial = der_utils::encode_integer_u64(42);
        let gen_time = der_utils::encode_tlv(0x18, gen_time_bytes);
        let nonce_int = der_utils::encode_integer_u64(nonce);
        let body = [
            version,
            policy,
            message_imprint,
            serial,
            gen_time,
            nonce_int,
        ]
        .concat();
        der_utils::encode_sequence_raw(&body)
    }

    fn null_params() -> Option<Any> {
        Some(Any::null())
    }

    /// Build a fully-formed CMS TimeStampToken (ContentInfo/SignedData) signed
    /// by `signer_key`, embedding `signer_cert` plus `extra_certs`.
    ///
    /// If `corrupt_sig` is true, the signature is computed over the wrong bytes
    /// so the token's signature will not verify.
    fn build_signed_token(
        signer_cert: &Certificate,
        signer_key: &RsaPrivateKey,
        extra_certs: &[Certificate],
        hash: &[u8],
        nonce: u64,
        corrupt_sig: bool,
    ) -> Vec<u8> {
        build_signed_token_gt(
            signer_cert,
            signer_key,
            extra_certs,
            hash,
            nonce,
            &gen_time_within(),
            true,
            corrupt_sig,
        )
    }

    /// Like [`build_signed_token`] but with an explicit genTime and control over
    /// whether the certificates are embedded (`embed_certs`), for testing the
    /// genTime-within-validity check and externally-supplied signer certs.
    #[allow(clippy::too_many_arguments)]
    fn build_signed_token_gt(
        signer_cert: &Certificate,
        signer_key: &RsaPrivateKey,
        extra_certs: &[Certificate],
        hash: &[u8],
        nonce: u64,
        gen_time_bytes: &[u8],
        embed_certs: bool,
        corrupt_sig: bool,
    ) -> Vec<u8> {
        use rsa::pkcs1v15::{Signature, SigningKey};
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::{Digest, Sha256};

        let tst_info_der = build_tst_info(hash, nonce, gen_time_bytes);

        // Signed attributes: content-type = id-ct-TSTInfo, message-digest = SHA256(eContent)
        let digest = Sha256::digest(&tst_info_der).to_vec();
        let ct_value = Any::encode_from(&ID_CT_TST_INFO).unwrap();
        let ct_attr = Attribute {
            oid: ID_CONTENT_TYPE_ATTR,
            values: SetOfVec::try_from(vec![ct_value]).unwrap(),
        };
        let md_value = Any::new(Tag::OctetString, digest).unwrap();
        let md_attr = Attribute {
            oid: ID_MESSAGE_DIGEST_ATTR,
            values: SetOfVec::try_from(vec![md_value]).unwrap(),
        };
        let signed_attrs: x509_cert::attr::Attributes =
            SetOfVec::try_from(vec![ct_attr, md_attr]).unwrap();

        // Sign the DER of the SET OF signed attributes (RFC 5652 §5.4).
        let signed_attrs_der = signed_attrs.to_der().unwrap();
        let signing_key = SigningKey::<Sha256>::new(signer_key.clone());
        let to_sign: &[u8] = if corrupt_sig {
            b"not the signed attributes"
        } else {
            &signed_attrs_der
        };
        let signature: Signature = signing_key.sign(to_sign);

        let sha256_alg = AlgorithmIdentifierOwned {
            oid: DigestAlgorithm::Sha256.oid(),
            parameters: null_params(),
        };
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
                issuer: signer_cert.tbs_certificate.issuer.clone(),
                serial_number: signer_cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: sha256_alg.clone(),
            signed_attrs: Some(signed_attrs),
            // bare rsaEncryption — exercises resolve_cms_signature_oid()
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: OID_RSA_ENCRYPTION,
                parameters: null_params(),
            },
            signature: OctetString::new(signature.to_vec()).unwrap(),
            unsigned_attrs: None,
        };

        // Embedded certificates (optional): signer first, then any extras.
        let certificates = if embed_certs {
            let mut cert_choices = vec![CertificateChoices::Certificate(signer_cert.clone())];
            for cert in extra_certs {
                cert_choices.push(CertificateChoices::Certificate(cert.clone()));
            }
            Some(CertificateSet::from(
                SetOfVec::try_from(cert_choices).unwrap(),
            ))
        } else {
            None
        };

        let signed_data = cms::signed_data::SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::try_from(vec![sha256_alg]).unwrap(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_CT_TST_INFO,
                econtent: Some(Any::new(Tag::OctetString, tst_info_der).unwrap()),
            },
            certificates,
            crls: None,
            signer_infos: SignerInfos::from(SetOfVec::try_from(vec![signer_info]).unwrap()),
        };

        let content_info = ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::encode_from(&signed_data).unwrap(),
        };
        content_info.to_der().unwrap()
    }

    #[test]
    fn test_verify_valid_token_no_trust_store() {
        let hash = vec![0xABu8; 32];
        let nonce = 0xDEAD_BEEFu64;
        let token = build_signed_token(&tsa_cert(), &tsa_key(), &[], &hash, nonce, false);

        let tst = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            Some(nonce),
            None,
            None,
            &[],
        )
        .expect("validly-signed token must verify");
        assert_eq!(tst.message_hash, hash);
        assert_eq!(tst.nonce, Some(nonce));
    }

    #[test]
    fn test_verify_valid_token_with_trust_store() {
        let hash = vec![0x11u8; 32];
        let nonce = 7u64;
        // Embed the intermediate so the chain reaches the root anchor.
        let token = build_signed_token(
            &tsa_cert(),
            &tsa_key(),
            &[intermediate_cert()],
            &hash,
            nonce,
            false,
        );

        let mut store = TrustStore::new();
        let (_, root_der) = pem_rfc7468::decode_vec(ROOT_CERT_PEM.as_bytes()).unwrap();
        store.add_der_certificate(&root_der).unwrap();

        let tst = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            Some(nonce),
            Some(&store),
            Some(validation_time()),
            &[],
        )
        .expect("token chaining to a trusted root must verify");
        assert_eq!(tst.message_hash, hash);
    }

    #[test]
    fn test_trust_store_validation_time_defaults_to_gen_time() {
        // With a trust store but validation_time = None, the chain must still be
        // verified using the token's genTime (not skipped). genTime is "now",
        // within every cert's validity, so this must succeed.
        let hash = vec![0x88u8; 32];
        let token = build_signed_token(
            &tsa_cert(),
            &tsa_key(),
            &[intermediate_cert()],
            &hash,
            1,
            false,
        );
        let mut store = TrustStore::new();
        let (_, root_der) = pem_rfc7468::decode_vec(ROOT_CERT_PEM.as_bytes()).unwrap();
        store.add_der_certificate(&root_der).unwrap();

        verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            Some(&store),
            None, // -> defaults to genTime
            &[],
        )
        .expect("chain must verify at genTime when validation_time is None");
    }

    #[test]
    fn test_reject_gen_time_outside_validity_without_trust_store() {
        // genTime ~20 years out is past the TSA cert's notAfter (~now + 10y).
        // This must be rejected even when no trust store is supplied (RFC 3161).
        let hash = vec![0x77u8; 32];
        let token = build_signed_token_gt(
            &tsa_cert(),
            &tsa_key(),
            &[],
            &hash,
            1,
            &gen_time_after_validity(),
            true,  // embed certs
            false, // valid signature
        );
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::VerificationFailed(_)),
            "genTime outside TSA cert validity must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_reject_tampered_signature() {
        let hash = vec![0x22u8; 32];
        let token = build_signed_token(&tsa_cert(), &tsa_key(), &[], &hash, 1, true);
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::VerificationFailed(_)),
            "tampered signature must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_reject_untrusted_root() {
        // Token is validly signed but the trust store does NOT contain the root.
        let hash = vec![0x33u8; 32];
        let token = build_signed_token(
            &tsa_cert(),
            &tsa_key(),
            &[intermediate_cert()],
            &hash,
            1,
            false,
        );
        let empty_store = TrustStore::new();
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            Some(&empty_store),
            Some(validation_time()),
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::VerificationFailed(_)),
            "token not chaining to a trust anchor must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_reject_signer_without_timestamping_eku() {
        // Sign with the intermediate CA key and present the intermediate CA cert
        // as the signer. The signature verifies, but the cert lacks the critical
        // id-kp-timeStamping EKU, so verification must fail.
        let hash = vec![0x44u8; 32];
        let token = build_signed_token(
            &intermediate_cert(),
            &intermediate_key(),
            &[],
            &hash,
            1,
            false,
        );
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::VerificationFailed(_)),
            "signer without timeStamping EKU must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_reject_unsigned_token_old_behavior() {
        // A token with no SignerInfo — the kind the old (vulnerable) code would
        // have accepted because it only parsed TSTInfo. Must now be rejected.
        let hash = vec![0x55u8; 32];
        let tst_info_der = build_tst_info(&hash, 1, &gen_time_within());
        let signed_data = cms::signed_data::SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::new(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_CT_TST_INFO,
                econtent: Some(Any::new(Tag::OctetString, tst_info_der).unwrap()),
            },
            certificates: None,
            crls: None,
            signer_infos: SignerInfos::from(SetOfVec::<SignerInfo>::new()),
        };
        let content_info = ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::encode_from(&signed_data).unwrap(),
        };
        let token = content_info.to_der().unwrap();

        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::InvalidResponse(_)),
            "unsigned token must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_reject_garbage_token() {
        let err = verify_timestamp_token(
            &[0x30, 0x03, 0x02, 0x01, 0x01],
            &[0u8; 32],
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, TspError::InvalidResponse(_)));
    }

    #[test]
    fn test_reject_wrong_message_imprint() {
        // Validly signed, but the caller expected a different hash than the one
        // in the (authenticated) TSTInfo.
        let real_hash = vec![0x66u8; 32];
        let token = build_signed_token(&tsa_cert(), &tsa_key(), &[], &real_hash, 1, false);
        let expected = vec![0x99u8; 32];
        let err = verify_timestamp_token(
            &token,
            &expected,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, TspError::InvalidResponse(_)));
    }

    /// Build an RSASSA-PSS `signatureAlgorithm` (OID + `RSASSA-PSS-params`) for
    /// the given hash and salt length, mirroring what a TSA emits.
    fn pss_algid<D>(salt_len: u8) -> AlgorithmIdentifierOwned
    where
        D: const_oid::AssociatedOid,
    {
        use rsa::pkcs1::RsaPssParams;
        let params = RsaPssParams::new::<D>(salt_len);
        let params_der = params.to_der().unwrap();
        AlgorithmIdentifierOwned {
            oid: OID_RSASSA_PSS,
            parameters: Some(der::Any::from_der(&params_der).unwrap()),
        }
    }

    #[test]
    fn test_pss_signature_bound_to_signerinfo_digest() {
        use rsa::pkcs8::EncodePublicKey;
        use rsa::pss::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        use sha2::Sha256;

        let key = tsa_key();
        let spki_der = rsa::RsaPublicKey::from(&key)
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        // Sign with RSA-PSS / SHA-256 using the default salt length (= 32).
        let signing = SigningKey::<Sha256>::new(key);
        let msg = b"the DER-encoded signed attributes";
        let mut rng = rand::thread_rng();
        let sig = signing.sign_with_rng(&mut rng, msg).to_vec();

        let algid = pss_algid::<Sha256>(32);

        // Verification bound to SHA-256 (matching SignerInfo.digestAlgorithm) succeeds.
        verify_cms_signature(msg, &sig, &spki_der, &algid, DigestAlgorithm::Sha256)
            .expect("PSS-SHA256 signature must verify when bound to SHA-256");

        // Verification bound to a different digest must NOT accept the signature
        // (previously the code tried multiple hashes and could mis-accept).
        assert!(
            verify_cms_signature(msg, &sig, &spki_der, &algid, DigestAlgorithm::Sha384).is_err(),
            "PSS signature must be rejected when the bound digest does not match"
        );
    }

    #[test]
    fn test_pss_signature_honours_nondefault_salt_length() {
        // Regression: PSS verification must use the saltLength from
        // RSASSA-PSS-params, not assume the default (= digest size). A token
        // signed with a non-default salt length must still verify.
        use rsa::pkcs8::EncodePublicKey;
        use rsa::pss::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        use sha2::Sha256;

        let key = tsa_key();
        let spki_der = rsa::RsaPublicKey::from(&key)
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        // Sign with a 48-byte salt (default for SHA-256 is 32).
        let signing = SigningKey::<Sha256>::new_with_salt_len(key, 48);
        let msg = b"the DER-encoded signed attributes";
        let mut rng = rand::thread_rng();
        let sig = signing.sign_with_rng(&mut rng, msg).to_vec();

        // With the matching saltLength in the params, verification succeeds.
        let algid = pss_algid::<Sha256>(48);
        verify_cms_signature(msg, &sig, &spki_der, &algid, DigestAlgorithm::Sha256)
            .expect("PSS signature with non-default salt must verify when params declare it");

        // Declaring the wrong (default) salt length must fail: the parameters
        // are authoritative and PSS verification is salt-length sensitive.
        let wrong = pss_algid::<Sha256>(32);
        assert!(
            verify_cms_signature(msg, &sig, &spki_der, &wrong, DigestAlgorithm::Sha256).is_err(),
            "PSS signature must not verify when the declared salt length is wrong"
        );
    }

    #[test]
    fn test_pss_signature_requires_parameters() {
        // A bare RSASSA-PSS OID with no parameters is non-compliant (RFC 4055):
        // the hash/MGF/salt are undefined, so reject rather than guess defaults.
        let bare = AlgorithmIdentifierOwned {
            oid: OID_RSASSA_PSS,
            parameters: None,
        };
        let err =
            verify_cms_signature(b"x", b"y", b"z", &bare, DigestAlgorithm::Sha256).unwrap_err();
        assert!(
            matches!(err, TrustError::UnsupportedAlgorithm(_)),
            "PSS without parameters must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_combined_sig_algorithm_hash_must_match_digest_algorithm() {
        // Regression: a token whose signatureAlgorithm encodes a different hash
        // than SignerInfo.digestAlgorithm must be rejected, even though both the
        // signature and the message-digest attribute would individually verify.
        use const_oid::db;
        use rsa::pkcs1v15::{Signature, SigningKey};
        use rsa::pkcs8::EncodePublicKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Sha256;

        let key = tsa_key();
        let spki_der = rsa::RsaPublicKey::from(&key)
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        // A genuine sha256WithRSAEncryption signature.
        let signing = SigningKey::<Sha256>::new(key);
        let msg = b"the DER-encoded signed attributes";
        let sig: Signature = signing.sign(msg);
        let sig = sig.to_vec();

        let algid = AlgorithmIdentifierOwned {
            oid: db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: None,
        };

        // Consistent: signatureAlgorithm hash == digestAlgorithm -> verifies.
        verify_cms_signature(msg, &sig, &spki_der, &algid, DigestAlgorithm::Sha256)
            .expect("sha256WithRSA must verify when digestAlgorithm is SHA-256");

        // Inconsistent: digestAlgorithm = SHA-512 but signatureAlgorithm encodes
        // SHA-256. Must be rejected up front, not silently accepted.
        let err = verify_cms_signature(msg, &sig, &spki_der, &algid, DigestAlgorithm::Sha512)
            .unwrap_err();
        assert!(
            matches!(err, TrustError::SignatureVerification(ref m) if m.contains("disagrees")),
            "mismatched signatureAlgorithm/digestAlgorithm must be rejected, got {err:?}"
        );
    }

    #[test]
    fn test_verify_token_without_embedded_certs_via_extra_certs() {
        // A token that omits the CMS certificates field (e.g. certReq=false).
        // It cannot be verified on its own, but succeeds when the signer cert is
        // supplied out-of-band through `extra_certs`.
        let hash = vec![0xC0u8; 32];
        let token = build_signed_token_gt(
            &tsa_cert(),
            &tsa_key(),
            &[],
            &hash,
            1,
            &gen_time_within(),
            false, // do NOT embed certificates
            false,
        );

        // Without the cert there is no key to check the signature; this is
        // reported as InvalidResponse (missing material), not a crypto failure.
        let err = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, TspError::InvalidResponse(_)),
            "token without certs and no extra_certs must fail as InvalidResponse, got {err:?}"
        );

        // Supplying the signer cert out-of-band lets it verify.
        let tst = verify_timestamp_token(
            &token,
            &hash,
            DigestAlgorithm::Sha256,
            None,
            None,
            None,
            &[tsa_cert()],
        )
        .expect("token must verify with externally-supplied signer cert");
        assert_eq!(tst.message_hash, hash);
    }

    /// Regression for the ambiguous-embedded-chain case: when several embedded
    /// certs share the issuer's subject, `order_chain` must prefer the one whose
    /// key actually signed the current cert. Under `allow_legacy` a SHA-1 link
    /// is valid and must win over a same-subject decoy that the strict precheck
    /// would otherwise let it fall back to.
    #[test]
    fn test_order_chain_prefers_legacy_valid_issuer_among_same_subject_candidates() {
        use crate::crypto::verify::SignaturePolicy;
        use der::asn1::BitString;
        use der::{Any, Decode, Encode};
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Keypair;
        use rsa::{Pkcs1v15Sign, RsaPrivateKey};
        use sha1::{Digest as _, Sha1};
        use sha2::Sha256;
        use spki::AlgorithmIdentifierOwned;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        let mut rng = rand::thread_rng();
        let validity =
            Validity::from_now(std::time::Duration::from_secs(3650 * 24 * 3600)).unwrap();
        let issuer_name: Name = "CN=Ambiguous Issuer,O=tsp-ltv tests".parse().unwrap();

        let self_signed = |name: &Name, key: &RsaPrivateKey, serial: u8| {
            let signer = SigningKey::<Sha256>::new(key.clone());
            let spki = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).unwrap();
            CertificateBuilder::new(
                Profile::Root,
                SerialNumber::new(&[serial]).unwrap(),
                validity,
                name.clone(),
                spki,
                &signer,
            )
            .unwrap()
            .build()
            .unwrap()
        };

        // Real issuer and a decoy sharing the same subject but a different key.
        let real_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let real_issuer = self_signed(&issuer_name, &real_key, 0x01);
        let decoy_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let decoy = self_signed(&issuer_name, &decoy_key, 0x02);

        // Leaf issued by the real issuer, re-signed with SHA-1.
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let leaf_spki = SubjectPublicKeyInfoOwned::from_key(
            SigningKey::<Sha256>::new(leaf_key).verifying_key(),
        )
        .unwrap();
        let real_signer = SigningKey::<Sha256>::new(real_key.clone());
        let base = CertificateBuilder::new(
            Profile::Leaf {
                issuer: issuer_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::new(&[0x03]).unwrap(),
            validity,
            "CN=Ambiguous Leaf,O=tsp-ltv tests".parse().unwrap(),
            leaf_spki,
            &real_signer,
        )
        .unwrap()
        .build()
        .unwrap();
        // Set the inner tbsCertificate.signature to SHA-1 too, so the leaf is
        // well-formed (outer == inner per RFC 5280 §4.1.1.2) and genuinely
        // SHA-1-signed — otherwise verify (under allow_legacy) would reject it on
        // the signatureAlgorithm-mismatch check (L-5) before reaching the curve.
        let sha1_algid = AlgorithmIdentifierOwned {
            oid: crate::crypto::algorithm::OID_SHA1_WITH_RSA,
            parameters: Some(Any::from_der(&[0x05, 0x00]).unwrap()),
        };
        let mut tbs = base.tbs_certificate.clone();
        tbs.signature = sha1_algid.clone();
        let tbs_der = tbs.to_der().unwrap();
        let hash = Sha1::digest(&tbs_der);
        let sig = real_key
            .sign(Pkcs1v15Sign::new::<Sha1>(), &hash)
            .expect("SHA-1 RSA sign");
        let leaf = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sha1_algid,
            signature: BitString::from_bytes(&sig).unwrap(),
        };

        // Decoy first, so the strict fallback (first name match) picks it.
        let embedded = vec![decoy.clone(), real_issuer.clone()];
        let real_spki = real_issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let decoy_spki = decoy
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();

        // Strict: the SHA-1 link can't be verified, so order_chain falls back to
        // the first same-subject match — the wrong (decoy) cert.
        let strict = order_chain(&leaf, &embedded, SignaturePolicy::strict());
        assert_eq!(strict.len(), 2);
        assert_eq!(
            strict[1]
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            decoy_spki,
            "strict precheck falls back to the wrong same-subject cert"
        );

        // allow_legacy: order_chain prefers the cryptographically-correct issuer.
        let legacy = order_chain(&leaf, &embedded, SignaturePolicy::allow_legacy());
        assert_eq!(legacy.len(), 2);
        assert_eq!(
            legacy[1]
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            real_spki,
            "allow_legacy prefers the issuer whose key actually signed the leaf"
        );
    }
}
