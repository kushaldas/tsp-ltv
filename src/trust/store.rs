//! [`TrustStore`] — a collection of trusted CA certificates (trust anchors).

use crate::error::TrustError;
use der::{Decode, Encode};
use std::path::Path;
use x509_cert::Certificate;

/// Read `(is_ca, pathLenConstraint)` from a certificate's `BasicConstraints`
/// extension. Available in all build configurations (independent of the `ltv`
/// feature) so `verify_chain` can enforce `pathLenConstraint` on the TSP-only
/// token-verification path as well as under `ltv`. A certificate without the
/// extension yields `(false, None)`.
fn basic_constraints(cert: &Certificate) -> Result<(bool, Option<u64>), TrustError> {
    let bc_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.19");
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Ok((false, None));
    };
    for ext in extensions.iter() {
        if ext.extn_id == bc_oid {
            return crate::der_utils::parse_basic_constraints(ext.extn_value.as_bytes())
                .map_err(TrustError::CertificateParse);
        }
    }
    Ok((false, None))
}

fn is_self_issued(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
}

/// Read the `keyCertSign` bit (bit 5) from a certificate's `keyUsage`
/// extension (2.5.29.15). Returns `Ok(None)` when the extension is absent and
/// `Ok(Some(bool))` otherwise. Available in all build configurations so
/// `verify_chain` can enforce CA key-usage even without the `ltv` feature
/// (finding L-3).
fn key_cert_sign(cert: &Certificate) -> Result<Option<bool>, TrustError> {
    let ku_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.15");
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Ok(None);
    };
    let Some(ext) = extensions.iter().find(|e| e.extn_id == ku_oid) else {
        return Ok(None);
    };
    parse_key_cert_sign_bit(ext.extn_value.as_bytes()).map(Some)
}

/// Parse a `keyUsage` extension value (a DER BIT STRING) and return whether the
/// `keyCertSign` bit (bit 5) is set.
///
/// The parse is strict — a malformed encoding is a hard error, kept distinct
/// from the semantic "keyCertSign not set" (`Ok(false)`): the value must be a
/// single BIT STRING with no trailing bytes, a valid unused-bits count (0..=7),
/// all unused bits in the final octet set to 0 (DER, X.690 §11.2.1), and at
/// least one content octet (RFC 5280 §4.2.1.3 requires keyUsage to assert at
/// least one bit, so a content-less BIT STRING is rejected).
fn parse_key_cert_sign_bit(extn_value: &[u8]) -> Result<bool, TrustError> {
    // keyUsage is a BIT STRING: first content byte is the unused-bit count,
    // followed by the bit bytes (MSB-first). keyCertSign is bit 5.
    let (tag, body, rest) = crate::der_utils::parse_tlv_with_rest(extn_value)
        .map_err(|e| TrustError::CertificateParse(format!("keyUsage: {e}")))?;
    if !rest.is_empty() {
        return Err(TrustError::CertificateParse(
            "keyUsage: trailing data after BIT STRING".into(),
        ));
    }
    if tag != 0x03 {
        return Err(TrustError::CertificateParse(format!(
            "keyUsage: expected BIT STRING (0x03), got 0x{tag:02x}"
        )));
    }
    if body.is_empty() {
        return Err(TrustError::CertificateParse(
            "keyUsage: BIT STRING missing the unused-bits octet".into(),
        ));
    }
    let unused_bits = body[0];
    if unused_bits > 7 {
        return Err(TrustError::CertificateParse(format!(
            "keyUsage: invalid unused-bits count {unused_bits} (must be 0..=7)"
        )));
    }
    let bit_bytes = &body[1..];
    if bit_bytes.is_empty() {
        return Err(TrustError::CertificateParse(
            "keyUsage: BIT STRING has no content octets (no key-usage bits set)".into(),
        ));
    }
    // DER (X.690 §11.2.1): every unused bit in the final octet MUST be 0.
    // A non-zero pad is a malformed encoding and is rejected rather than
    // silently masked, keeping encoding errors distinct from the semantic
    // "keyCertSign not set" case.
    if unused_bits > 0 {
        let last = bit_bytes[bit_bytes.len() - 1];
        let pad_mask = (1u8 << unused_bits) - 1;
        if last & pad_mask != 0 {
            return Err(TrustError::CertificateParse(format!(
                "keyUsage: BIT STRING has {unused_bits} non-zero unused bit(s) (not valid DER)"
            )));
        }
    }
    // bit 5 → byte 0, mask 0b0000_0100 (7 - 5 = 2).
    Ok((bit_bytes[0] >> 2) & 1 == 1)
}

/// Validate that an intermediate (issuer) certificate is permitted to sign
/// certificates: it must assert `basicConstraints` `cA:TRUE`, and — *if* it
/// carries a `keyUsage` extension — that extension must assert `keyCertSign`.
///
/// Per RFC 5280 §4.2.1.3 the `keyUsage` extension is **optional**: when absent
/// there is no key-usage restriction and `cA:TRUE` alone authorizes certificate
/// signing, so a missing `keyUsage` is accepted. Only a `keyUsage` that is
/// present *without* `keyCertSign` is rejected (the key must not then be used to
/// verify certificate signatures).
///
/// This is enforced in **every** build configuration (finding L-3): the
/// previous CA-extension check lived in the `ltv`-gated extension module, so a
/// `tsp`-only build skipped intermediate CA validation entirely. `verify_chain`
/// is reached by the RFC 3161 token path even without `ltv`, so the check must
/// not be feature-gated.
fn validate_intermediate_ca_extensions(cert: &Certificate, label: &str) -> Result<(), TrustError> {
    let (is_ca, _) = basic_constraints(cert)?;
    if !is_ca {
        return Err(TrustError::ProfileViolation(format!(
            "{label} is not a CA (basicConstraints cA is not TRUE)"
        )));
    }
    match key_cert_sign(cert)? {
        // keyUsage present and asserts keyCertSign, or keyUsage absent (no
        // restriction — RFC 5280 permits a CA certificate without keyUsage).
        Some(true) | None => Ok(()),
        // keyUsage present but does NOT assert keyCertSign — the key must not be
        // used to verify certificate signatures.
        Some(false) => Err(TrustError::ProfileViolation(format!(
            "{label} keyUsage is present but does not assert keyCertSign"
        ))),
    }
}

/// Enforce `issuer`'s `pathLenConstraint` against the CA certificates in
/// `below` (the certificates subordinate to it in the chain). `label`
/// identifies the issuer in error messages. A parse failure of any
/// `BasicConstraints` on the path is a hard error, not a silent skip.
fn enforce_path_len(
    issuer: &Certificate,
    below: &[Certificate],
    label: &str,
) -> Result<(), TrustError> {
    let (_is_ca, path_len) = basic_constraints(issuer).map_err(|e| {
        TrustError::ProfileViolation(format!("failed to parse basicConstraints for {label}: {e}"))
    })?;
    let Some(max_depth) = path_len else {
        return Ok(());
    };
    // RFC 5280 counts only non-self-issued CA certificates below the
    // constrained issuer. A CA leaf is counted when it is not self-issued (the
    // chain is generic leaf-to-anchor, so `below[0]` is not assumed to be an
    // end-entity); a self-issued rollover CA does not consume the budget.
    let mut subordinate_ca_count = 0u64;
    for cert in below {
        let (is_ca, _) = basic_constraints(cert).map_err(|e| {
            TrustError::ProfileViolation(format!(
                "failed to parse basicConstraints below {label}: {e}"
            ))
        })?;
        if is_ca && !is_self_issued(cert) {
            subordinate_ca_count += 1;
        }
    }
    if subordinate_ca_count > max_depth {
        return Err(TrustError::ProfileViolation(format!(
            "pathLenConstraint ({max_depth}) exceeded for {label}: {subordinate_ca_count} non-self-issued subordinate CA certs below"
        )));
    }
    Ok(())
}

/// Object identifiers (dotted strings) of the X.509v3 extensions this crate
/// recognises and processes during chain verification, regardless of which
/// features are compiled in. Per RFC 5280 §4.2 an unrecognised **critical**
/// extension MUST cause the certificate (and thus the chain) to be rejected —
/// see [`reject_unknown_critical_extensions`]. An extension is listed here only
/// if the crate actually understands it in *every* build configuration:
///
/// - `2.5.29.19` basicConstraints — processed by `basic_constraints` /
///   `enforce_path_len`.
/// - `2.5.29.15` keyUsage — processed by `key_cert_sign` /
///   `validate_extensions_for_role`.
/// - `2.5.29.37` extendedKeyUsage — processed in every build: a tsp-only build
///   requires a critical `id-kp-timeStamping` EKU on the TSA signer
///   (`tsp::token::require_timestamping_eku`, RFC 3161 §2.3), and the `ltv`
///   build additionally binds the leaf via `verify_chain_for_purpose`.
///
/// Extensions whose *only* processing path lives behind the `ltv` feature
/// (`subjectAltName`, `cRLDistributionPoints`, `authorityInfoAccess`,
/// `nameConstraints`) are NOT listed here. A tsp-only build does not process
/// them, so a certificate asserting any of them **critical** is rejected (fail
/// closed); they are recognised only via [`RECOGNIZED_CRITICAL_EXT_OIDS_LTV`]
/// when the code that processes them is compiled in.
///
/// `subjectKeyIdentifier` (`2.5.29.14`) and `authorityKeyIdentifier`
/// (`2.5.29.35`) are deliberately omitted from every list. RFC 5280 requires
/// them to be **non-critical**; a certificate that nonetheless marks one
/// critical therefore hits the critical check as an unrecognised OID and is
/// rejected (fail closed).
const RECOGNIZED_CRITICAL_EXT_OIDS: &[&str] = &[
    "2.5.29.19", // basicConstraints
    "2.5.29.15", // keyUsage
    "2.5.29.37", // extendedKeyUsage
];

/// PEM armor marker used to distinguish a PEM anchor file from raw DER.
const PEM_ARMOR: &[u8] = b"-----BEGIN";

/// Critical extensions recognised **only** when the `ltv` feature compiles in
/// the code that processes them. In a tsp-only build none of these have a
/// processing path, so a certificate asserting them critical is rejected by
/// [`reject_unknown_critical_extensions`] (RFC 5280 §4.2 — fail closed).
///
/// - `2.5.29.17` subjectAltName — consumed by name-constraints checking.
/// - `2.5.29.31` cRLDistributionPoints — consumed by the CRL fetch path.
/// - `1.3.6.1.5.5.7.1.1` authorityInfoAccess — consumed by the AIA/OCSP path.
/// - `2.5.29.30` nameConstraints — enforced by `enforce_name_constraints_path`.
#[cfg(feature = "ltv")]
const RECOGNIZED_CRITICAL_EXT_OIDS_LTV: &[&str] = &[
    "2.5.29.17",                                        // subjectAltName
    "2.5.29.31",                                        // cRLDistributionPoints
    "1.3.6.1.5.5.7.1.1",                                // authorityInfoAccess
    crate::ltv::name_constraints::NAME_CONSTRAINTS_OID, // 2.5.29.30 nameConstraints
];

/// Reject a certificate that asserts a **critical** extension this crate does
/// not recognise (RFC 5280 §4.2: "A certificate-using system MUST reject the
/// certificate if it encounters a critical extension it does not recognize or
/// cannot process").
///
/// This is feature-independent and runs for every certificate in the chain
/// (including the anchor) so a tsp-only build is held to the same MUST-reject
/// rule. The `ltv`-processed `nameConstraints` OID is accepted only when the
/// `ltv` feature is compiled in; otherwise a critical `nameConstraints` is
/// unrecognised and the chain is refused — fail closed rather than silently
/// ignoring a constraint the build cannot enforce.
fn reject_unknown_critical_extensions(cert: &Certificate, label: &str) -> Result<(), TrustError> {
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Ok(());
    };
    for ext in extensions.iter() {
        if !ext.critical {
            continue;
        }
        let oid = ext.extn_id.to_string();
        // `mut` is used only under `ltv` (the extra-OID branch below); tsp-only
        // builds never reassign it.
        #[allow(unused_mut)]
        let mut recognized = RECOGNIZED_CRITICAL_EXT_OIDS.contains(&oid.as_str());
        // subjectAltName / cRLDistributionPoints / authorityInfoAccess /
        // nameConstraints are only *processed* under the `ltv` feature;
        // recognise them as critical only when that code is compiled in.
        #[cfg(feature = "ltv")]
        {
            if !recognized && RECOGNIZED_CRITICAL_EXT_OIDS_LTV.contains(&oid.as_str()) {
                recognized = true;
            }
        }
        if !recognized {
            return Err(TrustError::ProfileViolation(format!(
                "{label} has an unrecognized critical extension {oid} (RFC 5280 §4.2 MUST reject)"
            )));
        }
    }
    Ok(())
}

/// Enforce RFC 5280 §4.2.1.10 name constraints over a fully-resolved path
/// `[leaf, intermediate..., anchor]` (the anchor appended last).
///
/// Constraints accumulate top-down: starting from the anchor, each CA's
/// `NameConstraints` extension is folded into the running state and applied to
/// every certificate **below** it. A subordinate certificate whose subject DN or
/// a subjectAltName entry falls in an excluded subtree — or outside every
/// permitted subtree of its type — is rejected. A `NameConstraints` extension
/// that constrains a GeneralName type this crate does not implement is rejected
/// as unsupported (fail closed).
///
/// Only compiled under `ltv`; a tsp-only build keeps a *critical* nameConstraints
/// fail-closed via [`reject_unknown_critical_extensions`] instead.
#[cfg(feature = "ltv")]
fn enforce_name_constraints_path(path: &[&Certificate]) -> Result<(), TrustError> {
    use crate::ltv::name_constraints::NameConstraintState;

    let mut state = NameConstraintState::default();
    // path[last] is the anchor; walk from the anchor (top) down to the leaf.
    // For each issuer CA, fold its constraints in, then check every certificate
    // strictly below it.
    let n = path.len();
    for top in (1..n).rev() {
        let issuer = path[top];
        state
            .add_from_cert(issuer)
            .map_err(|e| name_constraint_to_trust_error(issuer, e))?;
        if state.is_empty() {
            continue;
        }
        // Check every certificate below this issuer (indices 0..top).
        for sub in path.iter().take(top) {
            state
                .check_cert(sub)
                .map_err(|e| name_constraint_to_trust_error(sub, e))?;
        }
    }
    Ok(())
}

#[cfg(feature = "ltv")]
fn name_constraint_to_trust_error(
    cert: &Certificate,
    e: crate::ltv::name_constraints::NameConstraintError,
) -> TrustError {
    let subject = format!("{}", cert.tbs_certificate.subject);
    TrustError::ProfileViolation(format!("certificate '{subject}': {e}"))
}

/// A trust anchor: a parsed certificate paired with its DER encoding.
#[derive(Clone)]
struct TrustAnchor {
    cert: Certificate,
    der: Vec<u8>,
}

/// A collection of trusted CA certificates.
///
/// Used to validate that a certificate chain terminates at one of the
/// configured trust anchors.
#[derive(Clone)]
pub struct TrustStore {
    anchors: Vec<TrustAnchor>,
    /// Human-readable label for diagnostics (e.g., "sig", "tsa", "svt").
    label: Option<String>,
    /// Signature-algorithm policy applied during chain verification. Defaults
    /// to strict (weak digests MD5/SHA-1/SHA-224 rejected); opt into legacy via
    /// [`TrustStore::allow_legacy_signatures`].
    signature_policy: crate::crypto::verify::SignaturePolicy,
}

impl TrustStore {
    /// Create an empty trust store.
    pub fn new() -> Self {
        Self {
            anchors: Vec::new(),
            label: None,
            signature_policy: crate::crypto::verify::SignaturePolicy::default(),
        }
    }

    /// Set a diagnostic label for this store.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the signature-algorithm policy used by
    /// [`verify_chain`](Self::verify_chain).
    pub fn with_signature_policy(mut self, policy: crate::crypto::verify::SignaturePolicy) -> Self {
        self.signature_policy = policy;
        self
    }

    /// Accept certificates signed with weak/legacy digests (MD5/SHA-1/SHA-224)
    /// during chain verification.
    ///
    /// Off by default — weak digests are rejected. Enable this only to validate
    /// historical material (e.g. legacy XML-DSig interop certificates) whose
    /// risk you have accepted; never for fresh trust decisions.
    pub fn allow_legacy_signatures(mut self) -> Self {
        self.signature_policy = crate::crypto::verify::SignaturePolicy::allow_legacy();
        self
    }

    /// The signature-algorithm policy this store applies during verification.
    pub fn signature_policy(&self) -> crate::crypto::verify::SignaturePolicy {
        self.signature_policy
    }

    /// The diagnostic label, if set.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Number of trust anchors in this store.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    // ── Loading methods ──────────────────────────────────────────────

    /// Load trust anchors from a PEM file (may contain multiple certificates).
    pub fn from_pem_file(path: impl AsRef<Path>) -> Result<Self, TrustError> {
        let data = std::fs::read(path.as_ref()).map_err(TrustError::Io)?;
        let mut store = Self::new();
        store.add_pem_data(&data)?;
        Ok(store)
    }

    /// Load trust anchors from all certificate files (`*.pem`, `*.crt`, `*.cer`)
    /// in a directory, **failing closed** on any load or parse error (B-5). Each
    /// file may be PEM (one or more certificates) or a single DER-encoded
    /// certificate — `.crt`/`.cer` anchors are commonly raw DER.
    ///
    /// A trust store silently dropping a malformed anchor file is dangerous: the
    /// trust-anchor set shrinks without the operator noticing, so a chain that
    /// *should* be trusted is rejected — or, worse, a partially-loaded set is
    /// relied on as if complete. This method therefore returns an error as soon
    /// as any candidate file cannot be read or parsed, naming the offending file,
    /// rather than swallowing the failure.
    ///
    /// Files whose extension is not a recognised certificate extension are not
    /// candidates and are skipped without error. Use
    /// [`from_pem_directory_lenient`](Self::from_pem_directory_lenient) for the
    /// previous best-effort behaviour (still surfaced via a returned list of
    /// skipped files and reasons).
    pub fn from_pem_directory(dir: impl AsRef<Path>) -> Result<Self, TrustError> {
        let dir = dir.as_ref();
        if !dir.is_dir() {
            return Err(TrustError::NotADirectory(dir.display().to_string()));
        }

        let mut store = Self::new();
        // Fail closed on directory-entry I/O errors too: a transient FS fault or
        // a permission problem while enumerating must not silently shrink the
        // trust-anchor set.
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map_err(TrustError::Io)?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(TrustError::Io)?;
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_lowercase();
                if ext == "pem" || ext == "crt" || ext == "cer" {
                    let data = std::fs::read(&path).map_err(|e| {
                        TrustError::Io(std::io::Error::new(
                            e.kind(),
                            format!("failed to read trust anchor file {}: {e}", path.display()),
                        ))
                    })?;
                    store.add_anchor_file_data(&data).map_err(|e| {
                        // `add_anchor_file_data` already returns a TrustError;
                        // unwrap a CertificateParse to its inner message so the
                        // re-wrapped error is not double-prefixed
                        // ("certificate parse error: ...: certificate parse
                        // error: ..."), while still naming the offending file.
                        let detail = match e {
                            TrustError::CertificateParse(m) => m,
                            other => other.to_string(),
                        };
                        TrustError::CertificateParse(format!(
                            "failed to parse trust anchor file {}: {detail}",
                            path.display()
                        ))
                    })?;
                }
            }
        }

        Ok(store)
    }

    /// Best-effort variant of [`from_pem_directory`](Self::from_pem_directory):
    /// files that fail to read or parse are skipped, but the skipped file paths
    /// and per-file errors are **returned** (not silently dropped) so the caller
    /// can log or assert on them.
    ///
    /// Returns `(store, skipped)` where `skipped` lists `(path, reason)` for each
    /// candidate file that could not be loaded. A non-empty `skipped` means the
    /// trust-anchor set is smaller than the directory's contents — the caller
    /// MUST decide whether that is acceptable rather than have the decision made
    /// silently for them.
    ///
    /// One special case: if enumerating a directory *entry* itself fails (a
    /// transient FS fault or a permission error, so the file name is unknown),
    /// the skip is still reported, but with the **directory** path (not a file
    /// path) and a `reason` beginning `directory entry error:`. Callers that need
    /// to tell file-level skips apart can key off that prefix / the path being
    /// the directory.
    pub fn from_pem_directory_lenient(
        dir: impl AsRef<Path>,
    ) -> Result<(Self, Vec<(std::path::PathBuf, String)>), TrustError> {
        let dir = dir.as_ref();
        if !dir.is_dir() {
            return Err(TrustError::NotADirectory(dir.display().to_string()));
        }

        let mut store = Self::new();
        let mut skipped: Vec<(std::path::PathBuf, String)> = Vec::new();
        let mut entries: Vec<std::fs::DirEntry> = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(TrustError::Io)? {
            match entry {
                Ok(entry) => entries.push(entry),
                // Even in lenient mode, a dropped directory entry is reported
                // rather than silently swallowed, so the caller can see that the
                // enumeration was incomplete.
                Err(e) => {
                    log::warn!(
                        "skipping unreadable directory entry in {}: {e}",
                        dir.display()
                    );
                    skipped.push((dir.to_path_buf(), format!("directory entry error: {e}")));
                }
            }
        }
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_lowercase();
                if ext == "pem" || ext == "crt" || ext == "cer" {
                    match std::fs::read(&path) {
                        Ok(data) => {
                            if let Err(e) = store.add_anchor_file_data(&data) {
                                log::warn!(
                                    "skipping unparseable trust anchor {}: {e}",
                                    path.display()
                                );
                                skipped.push((path.clone(), e.to_string()));
                            }
                        }
                        Err(e) => {
                            log::warn!("skipping unreadable trust anchor {}: {e}", path.display());
                            skipped.push((path.clone(), e.to_string()));
                        }
                    }
                }
            }
        }

        Ok((store, skipped))
    }

    /// Load one anchor file's bytes, accepting either PEM (possibly a
    /// multi-certificate bundle) or a single DER-encoded certificate.
    ///
    /// `.crt`/`.cer` files are frequently raw DER, so a PEM-only parse would
    /// fail-close on perfectly valid anchors. PEM is recognised by its
    /// `-----BEGIN` armor; any other content is parsed as DER.
    fn add_anchor_file_data(&mut self, data: &[u8]) -> Result<(), TrustError> {
        // Recognise PEM by its armor at the *start* of the file (after optional
        // leading ASCII whitespace), not by a substring scan: a DER certificate
        // can legitimately contain the bytes "-----BEGIN" inside an ASN.1
        // string, and a substring match would misclassify it as PEM and then
        // fail to parse a perfectly valid anchor.
        if data.trim_ascii_start().starts_with(PEM_ARMOR) {
            self.add_pem_data(data)
        } else {
            self.add_der_certificate(data)
        }
    }

    /// Add a single trust anchor from DER-encoded bytes.
    pub fn add_der_certificate(&mut self, der: &[u8]) -> Result<(), TrustError> {
        let cert = Certificate::from_der(der)
            .map_err(|e| TrustError::CertificateParse(format!("DER decode failed: {e}")))?;
        self.anchors.push(TrustAnchor {
            cert,
            der: der.to_vec(),
        });
        Ok(())
    }

    /// Add a trust anchor from an already-parsed `Certificate`.
    pub fn add_certificate(&mut self, cert: Certificate) -> Result<(), TrustError> {
        let der = cert
            .to_der()
            .map_err(|e| TrustError::CertificateParse(format!("DER encode failed: {e}")))?;
        self.anchors.push(TrustAnchor { cert, der });
        Ok(())
    }

    /// Add trust anchors from PEM-encoded data (may contain multiple certs).
    pub fn add_pem_data(&mut self, pem_data: &[u8]) -> Result<(), TrustError> {
        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|e| TrustError::CertificateParse(format!("invalid UTF-8 in PEM: {e}")))?;

        let mut found_any = false;

        // Parse PEM by looking for BEGIN/END CERTIFICATE markers
        let mut remaining = pem_str;
        while let Some(begin_pos) = remaining.find("-----BEGIN CERTIFICATE-----") {
            let block_start = &remaining[begin_pos..];
            if let Some(end_pos) = block_start.find("-----END CERTIFICATE-----") {
                let end = end_pos + "-----END CERTIFICATE-----".len();
                let pem_block = &block_start[..end];

                // Decode the base64 between the markers
                let b64: String = pem_block
                    .lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect();

                use base64::Engine;
                let der_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .map_err(|e| {
                        TrustError::CertificateParse(format!("base64 decode error: {e}"))
                    })?;

                self.add_der_certificate(&der_bytes)?;
                found_any = true;

                remaining = &block_start[end..];
            } else {
                break;
            }
        }

        if !found_any {
            return Err(TrustError::CertificateParse(
                "no CERTIFICATE blocks found in PEM data".into(),
            ));
        }

        Ok(())
    }

    // ── Query methods ────────────────────────────────────────────────

    /// Check whether a given certificate (DER) is directly one of our anchors.
    ///
    /// Comparison is by raw DER bytes (exact match).
    pub fn contains_der(&self, cert_der: &[u8]) -> bool {
        self.anchors.iter().any(|a| a.der == cert_der)
    }

    /// Find the trust anchor that issued the given certificate, if any.
    ///
    /// Matching is done by comparing the certificate's issuer name with
    /// each anchor's subject name. Returns the **first** name-match.
    /// This does NOT verify the signature —
    /// use [`verify_chain`](Self::verify_chain) for full validation.
    pub fn find_issuer(&self, cert: &Certificate) -> Option<&Certificate> {
        let issuer = &cert.tbs_certificate.issuer;
        self.anchors.iter().find_map(|anchor| {
            if &anchor.cert.tbs_certificate.subject == issuer {
                Some(&anchor.cert)
            } else {
                None
            }
        })
    }

    /// Find **all** trust anchors whose subject matches the given certificate's issuer.
    ///
    /// This is used by [`verify_chain`](Self::verify_chain) so that when multiple
    /// anchors share the same subject name (but have different keys), each can be
    /// tried until one successfully verifies the certificate's signature.
    fn find_all_issuers(&self, cert: &Certificate) -> Vec<&Certificate> {
        let issuer = &cert.tbs_certificate.issuer;
        self.anchors
            .iter()
            .filter_map(|anchor| {
                if &anchor.cert.tbs_certificate.subject == issuer {
                    Some(&anchor.cert)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find the trust anchor that issued the given DER-encoded certificate.
    pub fn find_issuer_for_der(&self, cert_der: &[u8]) -> Option<&Certificate> {
        let cert = Certificate::from_der(cert_der).ok()?;
        self.find_issuer(&cert)
    }

    /// Get an iterator over all trust anchor certificates.
    pub fn certificates(&self) -> impl Iterator<Item = &Certificate> {
        self.anchors.iter().map(|a| &a.cert)
    }

    /// Get an iterator over all trust anchor DER encodings.
    pub fn certificates_der(&self) -> impl Iterator<Item = &[u8]> {
        self.anchors.iter().map(|a| a.der.as_slice())
    }

    /// Verify a certificate chain from leaf to a trust anchor.
    ///
    /// The chain should be ordered: `[leaf, intermediate_0, ..., intermediate_n]`.
    /// This method checks:
    /// 1. Each certificate's issuer matches the next certificate's subject
    /// 2. The final certificate's issuer matches a trust anchor's subject
    /// 3. Each certificate's signature is verified against its issuer's public key
    /// 4. Time validity (not before / not after) if `validation_time` is provided
    ///
    /// Returns the matching trust anchor on success.
    ///
    /// Signature verification honours this store's
    /// [`signature_policy`](Self::signature_policy): by default a chain
    /// containing a certificate signed with MD5/SHA-1/SHA-224 is rejected.
    /// Build the store with [`allow_legacy_signatures`](Self::allow_legacy_signatures)
    /// to validate such historical chains.
    pub fn verify_chain(
        &self,
        chain: &[Certificate],
        validation_time: Option<der::DateTime>,
    ) -> Result<&Certificate, TrustError> {
        self.verify_chain_inner(chain, validation_time, None)
    }

    /// Verify a certificate chain and additionally bind the **leaf**
    /// (`chain[0]`, the end-entity) to an expected purpose.
    ///
    /// This is [`verify_chain`](Self::verify_chain) plus a leaf
    /// extension-profile check: the leaf's `keyUsage`/`extendedKeyUsage` (etc.)
    /// must match the supplied [`crate::ltv::CertRole`] via
    /// [`validate_extensions_for_role`](crate::ltv::validate_extensions_for_role).
    /// Plain `verify_chain` validates only the *intermediates'* CA profile and
    /// the trust anchor; without this, a certificate that legitimately chains to
    /// an anchor but is **not authorised for the purpose at hand** (e.g. a TLS
    /// server certificate presented as an OCSP-signing or timestamping
    /// certificate) would be accepted — a purpose-confusion fail-open.
    ///
    /// Callers that know the role the leaf must satisfy (timestamping, OCSP
    /// signing, TLS/end-entity, ...) should use this instead of
    /// [`verify_chain`](Self::verify_chain).
    #[cfg(feature = "ltv")]
    pub fn verify_chain_for_purpose(
        &self,
        chain: &[Certificate],
        validation_time: Option<der::DateTime>,
        purpose: crate::ltv::CertRole,
    ) -> Result<&Certificate, TrustError> {
        self.verify_chain_inner(chain, validation_time, Some(purpose))
    }

    /// Core chain verification. `leaf_purpose`, when `Some`, binds the leaf
    /// (`chain[0]`) to a [`CertRole`](crate::ltv::CertRole) extension profile.
    fn verify_chain_inner(
        &self,
        chain: &[Certificate],
        validation_time: Option<der::DateTime>,
        #[cfg(feature = "ltv")] leaf_purpose: Option<crate::ltv::CertRole>,
        #[cfg(not(feature = "ltv"))] leaf_purpose: Option<()>,
    ) -> Result<&Certificate, TrustError> {
        let policy = &self.signature_policy;
        if chain.is_empty() {
            return Err(TrustError::EmptyChain);
        }

        // RFC 5280 §4.2: reject any certificate (leaf, intermediate, or anchor)
        // that asserts an unrecognized *critical* extension — fail closed.
        for (i, cert) in chain.iter().enumerate() {
            reject_unknown_critical_extensions(cert, &format!("certificate at index {i}"))?;
        }

        // Bind the leaf (chain[0]) to its expected purpose, when supplied. This
        // closes the purpose-confusion fail-open: a cert that chains to an anchor
        // but is not authorised for the role at hand must be rejected.
        #[cfg(feature = "ltv")]
        if let Some(role) = leaf_purpose {
            crate::ltv::validate_extensions_for_role(&chain[0], role).map_err(|e| {
                TrustError::ProfileViolation(format!(
                    "leaf certificate does not satisfy required purpose {role}: {e}"
                ))
            })?;
        }
        #[cfg(not(feature = "ltv"))]
        let _ = leaf_purpose;

        // Check time validity of all certificates in the chain
        if let Some(time) = validation_time {
            for (i, cert) in chain.iter().enumerate() {
                let validity = &cert.tbs_certificate.validity;
                if time < validity.not_before.to_date_time() {
                    return Err(TrustError::NotYetValid {
                        index: i,
                        not_before: validity.not_before.to_date_time(),
                    });
                }
                if time > validity.not_after.to_date_time() {
                    return Err(TrustError::Expired {
                        index: i,
                        not_after: validity.not_after.to_date_time(),
                    });
                }
            }
        }

        // Walk the chain: each cert's issuer must match next cert's subject
        // Track path length for pathLenConstraint enforcement (M-5).
        // CA depth starts at 0 (the leaf at chain[0]) and increments for each
        // intermediate. The anchor (last element) is a root that established
        // the trust; pathLen constraints on it apply to the chain beneath it.
        for i in 0..chain.len().saturating_sub(1) {
            let cert = &chain[i];
            let issuer_cert = &chain[i + 1];

            // Issuer name must match the next certificate's subject name
            if cert.tbs_certificate.issuer != issuer_cert.tbs_certificate.subject {
                return Err(TrustError::ChainBroken {
                    index: i,
                    expected_issuer: format!("{}", cert.tbs_certificate.issuer),
                    found_subject: format!("{}", issuer_cert.tbs_certificate.subject),
                });
            }

            // Verify signature of cert against issuer's public key
            crate::crypto::verify::verify_certificate_signature_with_policy(
                cert,
                issuer_cert,
                policy,
            )?;

            // Validate extensions: intermediates must have CA:TRUE + keyCertSign.
            // Enforced in every build configuration (L-3) — the RFC 3161 token
            // path reaches verify_chain even without the `ltv` feature, so this
            // must not be gated behind it.
            validate_intermediate_ca_extensions(
                issuer_cert,
                &format!("issuer at index {}", i + 1),
            )?;

            // Enforce pathLenConstraint (M-5), in every build configuration —
            // TSP-only token verification reaches `verify_chain` too, so this
            // must not be gated behind `ltv`. Per RFC 5280 §4.2.1.9 the
            // constraint bounds the number of CA certificates that may *follow*
            // this CA toward the leaf in a valid path. The certs below this
            // issuer are `chain[0..=i]`.
            enforce_path_len(
                issuer_cert,
                &chain[0..=i],
                &format!("intermediate index {}", i + 1),
            )?;
        }

        // The last cert in the chain must be issued by a trust anchor
        let last = chain.last().unwrap();

        // Check if the last cert is self-signed and directly in the store
        // (i.e., the chain includes the root itself)
        if last.tbs_certificate.issuer == last.tbs_certificate.subject {
            let last_der = last.to_der().map_err(|e| {
                TrustError::CertificateParse(format!(
                    "failed to encode certificate for anchor lookup: {e}"
                ))
            })?;
            if let Some(anchor) = self.anchors.iter().find(|a| a.der == last_der) {
                // Self-signed cert is directly trusted — verify its self-signature
                crate::crypto::verify::verify_certificate_signature_with_policy(
                    last, last, policy,
                )?;
                // The anchor is already the last element of `chain`; the full
                // path is `chain` itself.
                #[cfg(feature = "ltv")]
                {
                    let path: Vec<&Certificate> = chain.iter().collect();
                    enforce_name_constraints_path(&path)?;
                }
                return Ok(&anchor.cert);
            }
        }

        let candidates = self.find_all_issuers(last);
        if candidates.is_empty() {
            return Err(TrustError::UntrustedRoot {
                issuer: format!("{}", last.tbs_certificate.issuer),
            });
        }

        // Try each candidate anchor — different anchors may share the same
        // subject name but have different keys (e.g., re-issued roots).
        let mut last_err = None;
        for anchor in &candidates {
            match crate::crypto::verify::verify_certificate_signature_with_policy(
                last, anchor, policy,
            ) {
                Ok(()) => {
                    // The anchor is not part of `chain`, so its own critical
                    // extensions were not checked in the per-chain loop above —
                    // check them here (RFC 5280 §4.2 MUST-reject, fail closed).
                    reject_unknown_critical_extensions(anchor, "trust anchor")?;
                    validate_intermediate_ca_extensions(anchor, "trust anchor")?;

                    // Enforce the anchor's own pathLenConstraint. The chain
                    // builder stops before appending the anchor, so this anchor
                    // is not in `chain` and its constraint would otherwise never
                    // be checked. Every certificate in `chain` is subordinate to
                    // it.
                    enforce_path_len(anchor, chain, "trust anchor")?;

                    // Signature verified — now check anchor time validity
                    if let Some(time) = validation_time {
                        let validity = &anchor.tbs_certificate.validity;
                        if time < validity.not_before.to_date_time() {
                            return Err(TrustError::NotYetValid {
                                index: chain.len(),
                                not_before: validity.not_before.to_date_time(),
                            });
                        }
                        if time > validity.not_after.to_date_time() {
                            return Err(TrustError::Expired {
                                index: chain.len(),
                                not_after: validity.not_after.to_date_time(),
                            });
                        }
                    }

                    // Enforce name constraints over the full path with the anchor
                    // appended (it is not in `chain`).
                    #[cfg(feature = "ltv")]
                    {
                        let mut path: Vec<&Certificate> = chain.iter().collect();
                        path.push(anchor);
                        enforce_name_constraints_path(&path)?;
                    }
                    return Ok(anchor);
                }
                Err(e) => {
                    last_err = Some(e);
                    // Try next candidate
                }
            }
        }

        // All candidates failed signature verification
        Err(last_err.unwrap())
    }
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustStore")
            .field("label", &self.label)
            .field("anchors", &self.anchors.len())
            .finish()
    }
}

// Signature verification is now in crate::crypto::verify

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::verify::SignaturePolicy;

    /// Build a self-signed root certificate signed with SHA-1 + RSA
    /// (`sha1WithRSAEncryption`) at runtime, so we can exercise the weak-digest
    /// policy without committing a legacy fixture.
    ///
    /// `rsa`'s builder signer only emits SHA-2/3 signature OIDs, so we build a
    /// well-formed TBS with SHA-256, then re-sign that TBS with SHA-1 and
    /// relabel the outer `signatureAlgorithm` — yielding a certificate whose
    /// outer signature is a genuine, valid `sha1WithRSAEncryption` signature.
    fn sha1_self_signed_root() -> Certificate {
        use der::asn1::BitString;
        use der::{Any, Encode};
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Keypair;
        use rsa::{Pkcs1v15Sign, RsaPrivateKey};
        use sha1::{Digest, Sha1};
        use sha2::Sha256;
        use spki::AlgorithmIdentifierOwned;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
        let signer = SigningKey::<Sha256>::new(key.clone());
        let spki =
            SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).expect("SPKI from key");

        let serial = SerialNumber::new(&[0x01]).unwrap();
        let validity =
            Validity::from_now(std::time::Duration::from_secs(3650 * 24 * 3600)).unwrap();
        let subject: Name = "CN=Legacy SHA-1 Root,O=tsp-ltv tests".parse().unwrap();
        let base = CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, &signer)
            .expect("cert builder")
            .build()
            .expect("build base root");

        // Set the inner tbsCertificate.signature to SHA-1 too, then re-sign that
        // TBS with SHA-1. The result is well-formed (outer == inner per RFC 5280
        // §4.1.1.2) and genuinely SHA-1-signed, so it exercises the weak-digest
        // gate rather than the signatureAlgorithm-mismatch check (L-5).
        let sha1_algid = AlgorithmIdentifierOwned {
            oid: crate::crypto::algorithm::OID_SHA1_WITH_RSA,
            // sha1WithRSAEncryption carries an explicit NULL parameter.
            parameters: Some(Any::from_der(&[0x05, 0x00]).unwrap()),
        };
        let mut tbs = base.tbs_certificate.clone();
        tbs.signature = sha1_algid.clone();
        let tbs_der = tbs.to_der().unwrap();
        let hash = Sha1::digest(&tbs_der);
        let sig = key
            .sign(Pkcs1v15Sign::new::<Sha1>(), &hash)
            .expect("SHA-1 RSA sign");
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sha1_algid,
            signature: BitString::from_bytes(&sig).unwrap(),
        }
    }

    #[test]
    fn test_verify_chain_rejects_sha1_by_default_and_accepts_with_legacy() {
        let root = sha1_self_signed_root();
        // Sanity: it really is a weak (SHA-1) signature algorithm.
        assert!(crate::crypto::verify::is_weak_signature_oid(
            &root.signature_algorithm.oid
        ));

        let mut store = TrustStore::new();
        store.add_certificate(root.clone()).unwrap();
        let chain = [root];

        // Strict default: the SHA-1 self-signature is refused.
        let err = store.verify_chain(&chain, None).unwrap_err();
        assert!(
            matches!(err, TrustError::WeakAlgorithm(_)),
            "strict store must reject a SHA-1-signed chain, got {err:?}"
        );

        // Legacy opt-in via the builder: the same chain now verifies. This is
        // the reachable path a consumer (e.g. bergshamra's XML-DSig interop
        // fixtures) uses.
        let legacy_store = TrustStore::new()
            .allow_legacy_signatures()
            .with_label("legacy");
        let mut legacy_store = legacy_store;
        legacy_store.add_certificate(chain[0].clone()).unwrap();
        legacy_store
            .verify_chain(&chain, None)
            .expect("legacy store must accept a SHA-1-signed chain");

        assert_eq!(
            legacy_store.signature_policy(),
            SignaturePolicy::allow_legacy()
        );
        assert_eq!(store.signature_policy(), SignaturePolicy::strict());
    }

    /// Issue a certificate with the given builder `profile`, subject key, and
    /// issuer signer (the parent CA's key; for a root, pass its own key). Built
    /// at runtime so no fixtures are committed.
    fn issue_cert(
        profile: x509_cert::builder::Profile,
        subject: &str,
        subject_key: &rsa::RsaPrivateKey,
        issuer_signer: &rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    ) -> Certificate {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Keypair;
        use sha2::Sha256;
        use x509_cert::builder::{Builder, CertificateBuilder};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        let subject_signer = SigningKey::<Sha256>::new(subject_key.clone());
        let spki = SubjectPublicKeyInfoOwned::from_key(subject_signer.verifying_key())
            .expect("SPKI from key");
        let serial = SerialNumber::new(&[0x01]).unwrap();
        let validity =
            Validity::from_now(std::time::Duration::from_secs(3650 * 24 * 3600)).unwrap();
        let subject: Name = subject.parse().unwrap();
        CertificateBuilder::new(profile, serial, validity, subject, spki, issuer_signer)
            .expect("cert builder")
            .build()
            .expect("build cert")
    }

    /// Build a `[leaf_subca, mid_subca, root]` chain where `mid_subca` carries
    /// `pathLenConstraint = path_len`. `chain[0]` is itself a CA — the case the
    /// old `subordinate_ca_count = i` shortcut undercounted (it never counted
    /// the leaf). Returns `(store_with_root_anchor, chain)`.
    fn ca_leaf_chain(path_len: Option<u8>) -> (TrustStore, Vec<Certificate>) {
        use rsa::pkcs1v15::SigningKey;
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use x509_cert::builder::Profile;
        use x509_cert::name::Name;

        let mut rng = rand::thread_rng();
        let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("root key");
        let mid_key = RsaPrivateKey::new(&mut rng, 2048).expect("mid key");
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).expect("leaf key");

        let root_signer = SigningKey::<Sha256>::new(root_key.clone());
        let mid_signer = SigningKey::<Sha256>::new(mid_key.clone());

        let root_name = "CN=PathLen Root,O=tsp-ltv tests";
        let mid_name = "CN=PathLen Mid,O=tsp-ltv tests";
        let leaf_name = "CN=PathLen Leaf CA,O=tsp-ltv tests";
        let root_issuer: Name = root_name.parse().unwrap();
        let mid_issuer: Name = mid_name.parse().unwrap();

        let root = issue_cert(Profile::Root, root_name, &root_key, &root_signer);
        let mid = issue_cert(
            Profile::SubCA {
                issuer: root_issuer,
                path_len_constraint: path_len,
            },
            mid_name,
            &mid_key,
            &root_signer,
        );
        // leaf is itself a CA (SubCA), so chain[0] is a CA certificate.
        let leaf = issue_cert(
            Profile::SubCA {
                issuer: mid_issuer,
                path_len_constraint: None,
            },
            leaf_name,
            &leaf_key,
            &mid_signer,
        );

        let mut store = TrustStore::new();
        store.add_certificate(root.clone()).unwrap();
        (store, vec![leaf, mid, root])
    }

    #[test]
    fn test_verify_chain_pathlen_rejects_ca_leaf_below_zero_constraint() {
        // mid_subca has pathLenConstraint = 0, but a CA (leaf_subca) sits below
        // it. The leaf must be counted, so the chain is rejected.
        let (store, chain) = ca_leaf_chain(Some(0));
        let err = store
            .verify_chain(&chain, None)
            .expect_err("pathLen=0 with a CA leaf below must be rejected");
        assert!(
            matches!(err, TrustError::ProfileViolation(ref m) if m.contains("pathLenConstraint")),
            "expected pathLenConstraint rejection, got: {err:?}"
        );
    }

    #[test]
    fn test_verify_chain_pathlen_allows_ca_leaf_within_constraint() {
        // Same chain but pathLenConstraint = 1 permits exactly one CA below the
        // mid CA — the chain verifies (guards against over-rejection).
        let (store, chain) = ca_leaf_chain(Some(1));
        store
            .verify_chain(&chain, None)
            .expect("pathLen=1 with one CA leaf below must be accepted");
    }

    /// Build a chain `[leaf_subca, mid_subca]` that does NOT include the root,
    /// with the self-signed root anchor carrying `pathLenConstraint = root_plen`.
    /// The anchor lives only in the store, so its constraint is reached via the
    /// `find_all_issuers` path rather than the in-chain walk.
    fn anchor_only_chain(root_plen: Option<u8>) -> (TrustStore, Vec<Certificate>) {
        use rsa::pkcs1v15::SigningKey;
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use x509_cert::builder::Profile;
        use x509_cert::name::Name;

        let mut rng = rand::thread_rng();
        let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("root key");
        let mid_key = RsaPrivateKey::new(&mut rng, 2048).expect("mid key");
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).expect("leaf key");

        let root_signer = SigningKey::<Sha256>::new(root_key.clone());
        let mid_signer = SigningKey::<Sha256>::new(mid_key.clone());

        let root_name = "CN=Anchor Root,O=tsp-ltv tests";
        let mid_name = "CN=Anchor Mid,O=tsp-ltv tests";
        let leaf_name = "CN=Anchor Leaf CA,O=tsp-ltv tests";
        let root_issuer: Name = root_name.parse().unwrap();
        let mid_issuer: Name = mid_name.parse().unwrap();

        // Self-signed root WITH a pathLenConstraint: Profile::Root forces None,
        // so build it as a SubCA whose issuer is its own name.
        let root = issue_cert(
            Profile::SubCA {
                issuer: root_issuer.clone(),
                path_len_constraint: root_plen,
            },
            root_name,
            &root_key,
            &root_signer,
        );
        let mid = issue_cert(
            Profile::SubCA {
                issuer: root_issuer,
                path_len_constraint: None,
            },
            mid_name,
            &mid_key,
            &root_signer,
        );
        let leaf = issue_cert(
            Profile::SubCA {
                issuer: mid_issuer,
                path_len_constraint: None,
            },
            leaf_name,
            &leaf_key,
            &mid_signer,
        );

        let mut store = TrustStore::new();
        store.add_certificate(root).unwrap();
        // Chain stops below the anchor — the root is only in the store.
        (store, vec![leaf, mid])
    }

    #[test]
    fn test_verify_chain_anchor_pathlen_enforced() {
        // The root anchor (not in the chain) is constrained to pathLen=0 but two
        // subordinate CAs sit below it. The anchor's constraint must be checked.
        let (store, chain) = anchor_only_chain(Some(0));
        let err = store
            .verify_chain(&chain, None)
            .expect_err("anchor pathLen=0 with CAs below must be rejected");
        assert!(
            matches!(err, TrustError::ProfileViolation(ref m) if m.contains("pathLenConstraint") && m.contains("trust anchor")),
            "expected trust-anchor pathLenConstraint rejection, got: {err:?}"
        );
    }

    #[test]
    fn test_verify_chain_anchor_pathlen_within_constraint() {
        // pathLen=2 permits the two subordinate CAs — chain verifies.
        let (store, chain) = anchor_only_chain(Some(2));
        store
            .verify_chain(&chain, None)
            .expect("anchor pathLen=2 with two CAs below must be accepted");
    }

    /// Build a chain containing a self-issued CA certificate below a root
    /// anchor. Self-issued rollover CAs do not consume pathLenConstraint.
    fn self_issued_ca_below_anchor(root_plen: Option<u8>) -> (TrustStore, Vec<Certificate>) {
        use rsa::pkcs1v15::SigningKey;
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use x509_cert::builder::Profile;
        use x509_cert::name::Name;

        let mut rng = rand::thread_rng();
        let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("root key");
        let rollover_key = RsaPrivateKey::new(&mut rng, 2048).expect("rollover key");

        let root_signer = SigningKey::<Sha256>::new(root_key.clone());

        let root_name = "CN=Rollover Root,O=tsp-ltv tests";
        let root_issuer: Name = root_name.parse().unwrap();

        let root = issue_cert(
            Profile::SubCA {
                issuer: root_issuer.clone(),
                path_len_constraint: root_plen,
            },
            root_name,
            &root_key,
            &root_signer,
        );
        let rollover = issue_cert(
            Profile::SubCA {
                issuer: root_issuer,
                path_len_constraint: None,
            },
            root_name,
            &rollover_key,
            &root_signer,
        );

        let mut store = TrustStore::new();
        store.add_certificate(root).unwrap();
        (store, vec![rollover])
    }

    #[test]
    fn test_verify_chain_pathlen_ignores_self_issued_ca_below_anchor() {
        // A self-issued rollover CA below the anchor does not consume the
        // anchor's pathLen budget, so pathLen=0 remains valid.
        let (store, chain) = self_issued_ca_below_anchor(Some(0));
        store
            .verify_chain(&chain, None)
            .expect("self-issued CA below anchor must not consume pathLenConstraint");
    }

    #[test]
    fn test_parse_key_cert_sign_bit() {
        use crate::der_utils::encode_tlv;

        // BIT STRING { unused=1, 0x04 } -> keyCertSign (bit 5) set.
        assert!(parse_key_cert_sign_bit(&encode_tlv(0x03, &[0x01, 0x04])).unwrap());
        // BIT STRING { unused=7, 0x80 } -> digitalSignature only; keyCertSign not set.
        assert!(!parse_key_cert_sign_bit(&encode_tlv(0x03, &[0x07, 0x80])).unwrap());

        // Not a BIT STRING.
        assert!(parse_key_cert_sign_bit(&encode_tlv(0x04, &[0x01, 0x04])).is_err());
        // Trailing data after the BIT STRING is rejected (parse_tlv would ignore it).
        let mut trailing = encode_tlv(0x03, &[0x01, 0x04]);
        trailing.extend_from_slice(&[0x05, 0x00]); // a stray NULL
        assert!(parse_key_cert_sign_bit(&trailing).is_err());
        // Empty value (no unused-bits octet) is rejected.
        assert!(parse_key_cert_sign_bit(&encode_tlv(0x03, &[])).is_err());
        // Only the unused-bits octet, no content octets -> rejected (not Some(false)).
        assert!(parse_key_cert_sign_bit(&encode_tlv(0x03, &[0x00])).is_err());
        // Invalid unused-bits count (>7) is rejected.
        assert!(parse_key_cert_sign_bit(&encode_tlv(0x03, &[0x08, 0x04])).is_err());
        // Non-zero unused bits in the final octet are invalid DER (X.690
        // §11.2.1) and rejected: unused=1 but the low bit of 0x05 is set.
        assert!(parse_key_cert_sign_bit(&encode_tlv(0x03, &[0x01, 0x05])).is_err());
        // keyCertSign bit set *and* a clean (zero) unused-bit pad still parses.
        assert!(parse_key_cert_sign_bit(&encode_tlv(0x03, &[0x01, 0x06])).unwrap());
    }

    #[test]
    fn test_verify_chain_rejects_non_ca_intermediate() {
        // L-3: an intermediate that is not a CA (basicConstraints CA:FALSE) must
        // be rejected by verify_chain in every build configuration, even when its
        // signature over the leaf is valid. This check used to be gated behind
        // the `ltv` feature.
        use rsa::pkcs1v15::SigningKey;
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use x509_cert::builder::Profile;
        use x509_cert::name::Name;

        let mut rng = rand::thread_rng();
        let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("root key");
        let mid_key = RsaPrivateKey::new(&mut rng, 2048).expect("mid key");
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).expect("leaf key");

        let root_signer = SigningKey::<Sha256>::new(root_key.clone());
        let mid_signer = SigningKey::<Sha256>::new(mid_key.clone());

        let root_name = "CN=NonCA Root,O=tsp-ltv tests";
        let mid_name = "CN=NonCA Mid,O=tsp-ltv tests";
        let leaf_name = "CN=NonCA Leaf,O=tsp-ltv tests";
        let root_issuer: Name = root_name.parse().unwrap();
        let mid_issuer: Name = mid_name.parse().unwrap();

        let root = issue_cert(Profile::Root, root_name, &root_key, &root_signer);
        // mid is an end-entity profile (CA:FALSE) but is (mis)used as an issuer.
        let mid = issue_cert(
            Profile::Leaf {
                issuer: root_issuer,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            mid_name,
            &mid_key,
            &root_signer,
        );
        let leaf = issue_cert(
            Profile::Leaf {
                issuer: mid_issuer,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            leaf_name,
            &leaf_key,
            &mid_signer,
        );

        let mut store = TrustStore::new();
        store.add_certificate(root.clone()).unwrap();
        let chain = vec![leaf, mid, root];

        let err = store
            .verify_chain(&chain, None)
            .expect_err("a non-CA intermediate must be rejected");
        assert!(
            matches!(err, TrustError::ProfileViolation(ref m) if m.contains("not a CA")),
            "expected non-CA intermediate rejection, got: {err:?}"
        );
    }

    #[test]
    fn test_verify_chain_rejects_non_ca_trust_anchor_out_of_chain() {
        // A trust anchor found from the store must meet the same CA profile as
        // an in-chain issuer/root. Leaving the root out of `chain` exercises the
        // find_all_issuers path.
        use rsa::pkcs1v15::SigningKey;
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use x509_cert::builder::Profile;
        use x509_cert::name::Name;

        let mut rng = rand::thread_rng();
        let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("root key");
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).expect("leaf key");
        let root_signer = SigningKey::<Sha256>::new(root_key.clone());

        let root_name = "CN=NonCA Anchor,O=tsp-ltv tests";
        let leaf_name = "CN=NonCA Anchor Leaf,O=tsp-ltv tests";
        let root_issuer: Name = root_name.parse().unwrap();

        let root = issue_cert(
            Profile::Leaf {
                issuer: root_issuer.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            root_name,
            &root_key,
            &root_signer,
        );
        let leaf = issue_cert(
            Profile::Leaf {
                issuer: root_issuer,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            leaf_name,
            &leaf_key,
            &root_signer,
        );

        let mut store = TrustStore::new();
        store.add_certificate(root).unwrap();
        let chain = vec![leaf];

        let err = store
            .verify_chain(&chain, None)
            .expect_err("a non-CA trust anchor must be rejected");
        assert!(
            matches!(err, TrustError::ProfileViolation(ref m) if m.contains("trust anchor") && m.contains("not a CA")),
            "expected non-CA trust-anchor rejection, got: {err:?}"
        );
    }

    // ── B4/M3, B3/M4, M2 helpers and tests ────────────────────────

    /// Re-build a self-signed root certificate, replacing its extension list
    /// with `extra_extensions` (each `(oid, critical, der_value)`) merged into
    /// whatever the builder already emitted, then re-sign the TBS with `key`
    /// under SHA-256 so the self-signature stays valid.
    fn root_with_extensions(
        common_name: &str,
        key: &rsa::RsaPrivateKey,
        extra_extensions: Vec<x509_cert::ext::Extension>,
    ) -> Certificate {
        use der::asn1::BitString;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Sha256;
        use x509_cert::builder::Profile;

        let signer = SigningKey::<Sha256>::new(key.clone());
        let base = issue_cert(Profile::Root, common_name, key, &signer);

        let mut tbs = base.tbs_certificate.clone();
        let mut exts = tbs.extensions.clone().unwrap_or_default();
        exts.extend(extra_extensions);
        tbs.extensions = Some(exts);

        let tbs_der = tbs.to_der().unwrap();
        let sig = signer.sign(&tbs_der);
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: base.signature_algorithm.clone(),
            signature: BitString::from_bytes(&sig.to_bytes()).unwrap(),
        }
    }

    fn ext(oid: &str, critical: bool, value: &[u8]) -> x509_cert::ext::Extension {
        use der::asn1::OctetString;
        x509_cert::ext::Extension {
            extn_id: const_oid::ObjectIdentifier::new_unwrap(oid),
            critical,
            extn_value: OctetString::new(value.to_vec()).unwrap(),
        }
    }

    #[test]
    fn test_verify_chain_rejects_unknown_critical_extension() {
        // B4/M3: a self-signed anchor that asserts a *critical* extension we do
        // not recognise must be rejected (RFC 5280 §4.2 MUST-reject).
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        // OID 1.2.3.4.5 is not an extension we process. Mark it critical.
        let root = root_with_extensions(
            "CN=Critical Ext Root,O=tsp-ltv tests",
            &key,
            vec![ext("1.2.3.4.5", true, &[0x05, 0x00])],
        );

        let mut store = TrustStore::new();
        store.add_certificate(root.clone()).unwrap();
        let chain = [root];

        let err = store
            .verify_chain(&chain, None)
            .expect_err("unknown critical extension must be rejected");
        assert!(
            matches!(err, TrustError::ProfileViolation(ref m) if m.contains("unrecognized critical extension")),
            "expected unrecognized-critical-extension rejection, got: {err:?}"
        );
    }

    #[test]
    fn test_verify_chain_allows_unknown_noncritical_extension() {
        // The same unknown extension marked *non-critical* must NOT cause
        // rejection (guards against over-rejection).
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let root = root_with_extensions(
            "CN=NonCritical Ext Root,O=tsp-ltv tests",
            &key,
            vec![ext("1.2.3.4.5", false, &[0x05, 0x00])],
        );

        let mut store = TrustStore::new();
        store.add_certificate(root.clone()).unwrap();
        let chain = [root];
        store
            .verify_chain(&chain, None)
            .expect("a non-critical unknown extension must be accepted");
    }

    #[test]
    #[cfg(not(feature = "ltv"))]
    fn test_tsp_only_rejects_critical_ltv_only_extension() {
        // In a tsp-only build the crate has no processing path for
        // subjectAltName / cRLDistributionPoints / authorityInfoAccess, so a
        // certificate asserting any of them *critical* must be rejected
        // (RFC 5280 §4.2 — fail closed). A critical extendedKeyUsage, by
        // contrast, IS processed (tsp requires id-kp-timeStamping) and must
        // still be accepted.
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();

        // 2.5.29.17 subjectAltName, marked critical -> rejected without ltv.
        let san_root = root_with_extensions(
            "CN=Critical SAN Root,O=tsp-ltv tests",
            &key,
            // Minimal GeneralNames SEQUENCE; value is irrelevant to the
            // critical-OID check.
            vec![ext("2.5.29.17", true, &[0x30, 0x00])],
        );
        let mut store = TrustStore::new();
        store.add_certificate(san_root.clone()).unwrap();
        let err = store
            .verify_chain(&[san_root], None)
            .expect_err("critical subjectAltName must be rejected in a tsp-only build");
        assert!(
            matches!(err, TrustError::ProfileViolation(ref m) if m.contains("unrecognized critical extension")),
            "expected unrecognized-critical-extension rejection, got: {err:?}"
        );

        // 2.5.29.37 extendedKeyUsage, marked critical -> still accepted.
        let eku_root = root_with_extensions(
            "CN=Critical EKU Root,O=tsp-ltv tests",
            &key,
            vec![ext("2.5.29.37", true, &[0x30, 0x00])],
        );
        let mut store = TrustStore::new();
        store.add_certificate(eku_root.clone()).unwrap();
        store
            .verify_chain(&[eku_root], None)
            .expect("a critical extendedKeyUsage is processed and must be accepted");
    }

    /// Build `[leaf, root]` where the root is a CA anchor and `leaf` is signed by
    /// it. `leaf_profile` controls the leaf's extensions (EKU/keyUsage).
    #[cfg(feature = "ltv")]
    fn leaf_and_root(leaf_profile: x509_cert::builder::Profile) -> (TrustStore, Vec<Certificate>) {
        use rsa::pkcs1v15::SigningKey;
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use x509_cert::builder::Profile;

        let mut rng = rand::thread_rng();
        let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let root_signer = SigningKey::<Sha256>::new(root_key.clone());

        let root = issue_cert(
            Profile::Root,
            "CN=Purpose Root,O=tsp-ltv tests",
            &root_key,
            &root_signer,
        );
        let leaf = issue_cert(
            leaf_profile,
            "CN=Purpose Leaf,O=tsp-ltv tests",
            &leaf_key,
            &root_signer,
        );

        let mut store = TrustStore::new();
        store.add_certificate(root.clone()).unwrap();
        (store, vec![leaf, root])
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_verify_chain_for_purpose_rejects_wrong_eku() {
        use crate::ltv::CertRole;
        use x509_cert::builder::Profile;
        use x509_cert::name::Name;

        let root_issuer: Name = "CN=Purpose Root,O=tsp-ltv tests".parse().unwrap();
        // A plain TLS-style end-entity leaf (digitalSignature, no OCSPSigning EKU).
        let (store, chain) = leaf_and_root(Profile::Leaf {
            issuer: root_issuer,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        });

        // Plain verify_chain (no purpose) accepts it — it is a valid end-entity.
        store
            .verify_chain(&chain, None)
            .expect("end-entity leaf should chain to anchor");

        // But binding it to the OcspResponder purpose must fail: it lacks the
        // id-kp-OCSPSigning EKU.
        let err = store
            .verify_chain_for_purpose(&chain, None, CertRole::OcspResponder)
            .expect_err("leaf without OCSPSigning EKU must fail OcspResponder purpose");
        assert!(
            matches!(err, TrustError::ProfileViolation(ref m) if m.contains("required purpose")),
            "expected purpose-binding rejection, got: {err:?}"
        );
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_verify_chain_for_purpose_accepts_end_entity() {
        use crate::ltv::CertRole;
        use x509_cert::builder::Profile;
        use x509_cert::name::Name;

        let root_issuer: Name = "CN=Purpose Root,O=tsp-ltv tests".parse().unwrap();
        let (store, chain) = leaf_and_root(Profile::Leaf {
            issuer: root_issuer,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        });
        // The leaf satisfies EndEntity (CA:FALSE + digitalSignature).
        store
            .verify_chain_for_purpose(&chain, None, CertRole::EndEntity)
            .expect("end-entity leaf must satisfy EndEntity purpose");
    }

    // ── M2 name constraints ───────────────────────────────────────

    /// Encode a NameConstraints extension value with a single dNSName subtree
    /// under either permittedSubtrees [0] or excludedSubtrees [1].
    #[cfg(feature = "ltv")]
    fn name_constraints_dns(dns: &str, excluded: bool) -> Vec<u8> {
        use crate::der_utils::{encode_sequence_raw, encode_tlv};
        // GeneralName dNSName [2] IA5String (primitive, tag 0x82).
        let gn = encode_tlv(0x82, dns.as_bytes());
        // GeneralSubtree ::= SEQUENCE { base GeneralName }
        let subtree = encode_sequence_raw(&gn);
        // GeneralSubtrees ::= SEQUENCE OF GeneralSubtree (raw concatenation; one here)
        // permittedSubtrees [0] / excludedSubtrees [1] (constructed context tag).
        let tag = if excluded { 0xA1 } else { 0xA0 };
        let subtrees = encode_tlv(tag, &subtree);
        // NameConstraints ::= SEQUENCE { ... }
        encode_sequence_raw(&subtrees)
    }

    /// Build `[leaf, root]` where `root` is a CA anchor carrying a critical
    /// nameConstraints extension and `leaf` asserts `leaf_dns` via subjectAltName.
    #[cfg(feature = "ltv")]
    fn constrained_chain(
        constraint_dns: &str,
        excluded: bool,
        leaf_dns: &str,
    ) -> (TrustStore, Vec<Certificate>) {
        use crate::der_utils::{encode_sequence_raw, encode_tlv};
        use der::asn1::BitString;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use x509_cert::builder::Profile;

        let mut rng = rand::thread_rng();
        let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let root_signer = SigningKey::<Sha256>::new(root_key.clone());

        // Root with a critical nameConstraints extension.
        let nc_value = name_constraints_dns(constraint_dns, excluded);
        let root = root_with_extensions(
            "CN=NC Root,O=tsp-ltv tests",
            &root_key,
            vec![ext("2.5.29.30", true, &nc_value)],
        );

        // Leaf with a subjectAltName dNSName = leaf_dns, signed by the root.
        let root_issuer: x509_cert::name::Name = root.tbs_certificate.subject.clone();
        let leaf_base = issue_cert(
            Profile::Leaf {
                issuer: root_issuer,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            "CN=NC Leaf,O=tsp-ltv tests",
            &leaf_key,
            &root_signer,
        );
        // subjectAltName ::= GeneralNames ::= SEQUENCE OF GeneralName.
        let san_gn = encode_tlv(0x82, leaf_dns.as_bytes());
        let san_value = encode_sequence_raw(&san_gn);

        let mut tbs = leaf_base.tbs_certificate.clone();
        let mut exts = tbs.extensions.clone().unwrap_or_default();
        exts.push(ext("2.5.29.17", false, &san_value));
        tbs.extensions = Some(exts);
        let tbs_der = tbs.to_der().unwrap();
        let sig = root_signer.sign(&tbs_der);
        let leaf = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: leaf_base.signature_algorithm.clone(),
            signature: BitString::from_bytes(&sig.to_bytes()).unwrap(),
        };

        let mut store = TrustStore::new();
        store.add_certificate(root.clone()).unwrap();
        (store, vec![leaf, root])
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_name_constraints_permitted_violation_rejected() {
        // Anchor permits only *.example.com; a leaf SAN of host.evil.com is
        // outside every permitted subtree → rejected.
        let (store, chain) = constrained_chain("example.com", false, "host.evil.com");
        let err = store
            .verify_chain(&chain, None)
            .expect_err("SAN outside permitted subtree must be rejected");
        assert!(
            matches!(err, TrustError::ProfileViolation(ref m) if m.contains("name constraint")),
            "expected name-constraint violation, got: {err:?}"
        );
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_name_constraints_permitted_within_accepted() {
        // The same constraint with a leaf SAN inside the permitted subtree
        // verifies (guards against over-rejection).
        let (store, chain) = constrained_chain("example.com", false, "host.example.com");
        store
            .verify_chain(&chain, None)
            .expect("SAN inside permitted subtree must be accepted");
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_name_constraints_excluded_violation_rejected() {
        // Anchor excludes bad.example.com; a leaf SAN inside it → rejected.
        let (store, chain) = constrained_chain("bad.example.com", true, "host.bad.example.com");
        let err = store
            .verify_chain(&chain, None)
            .expect_err("SAN within excluded subtree must be rejected");
        assert!(
            matches!(err, TrustError::ProfileViolation(ref m) if m.contains("name constraint")),
            "expected excluded-subtree violation, got: {err:?}"
        );
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_name_constraints_unsupported_type_fails_closed() {
        // A critical nameConstraints (on the anchor CA, which has a subordinate
        // leaf below it) constraining an unsupported GeneralName type ([6] URI,
        // tag 0x86) must be rejected as unsupported (fail closed) when the chain
        // is walked.
        use crate::der_utils::{encode_sequence_raw, encode_tlv};
        use der::asn1::BitString;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use x509_cert::builder::Profile;

        let mut rng = rand::thread_rng();
        let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let root_signer = SigningKey::<Sha256>::new(root_key.clone());

        // permittedSubtrees [0] with a single [6] uniformResourceIdentifier base.
        let gn = encode_tlv(0x86, b"http://example.com/");
        let subtree = encode_sequence_raw(&gn);
        let subtrees = encode_tlv(0xA0, &subtree);
        let nc_value = encode_sequence_raw(&subtrees);

        let root = root_with_extensions(
            "CN=NC Unsupported Root,O=tsp-ltv tests",
            &root_key,
            vec![ext("2.5.29.30", true, &nc_value)],
        );

        // A leaf below the anchor so the anchor's constraints are actually
        // evaluated during the walk.
        let root_issuer: x509_cert::name::Name = root.tbs_certificate.subject.clone();
        let leaf_base = issue_cert(
            Profile::Leaf {
                issuer: root_issuer,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            "CN=NC Unsupported Leaf,O=tsp-ltv tests",
            &leaf_key,
            &root_signer,
        );
        let tbs = leaf_base.tbs_certificate.clone();
        let tbs_der = tbs.to_der().unwrap();
        let sig = root_signer.sign(&tbs_der);
        let leaf = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: leaf_base.signature_algorithm.clone(),
            signature: BitString::from_bytes(&sig.to_bytes()).unwrap(),
        };

        let mut store = TrustStore::new();
        store.add_certificate(root.clone()).unwrap();
        let chain = [leaf, root];

        let err = store
            .verify_chain(&chain, None)
            .expect_err("unsupported name-constraint type must fail closed");
        assert!(
            matches!(err, TrustError::ProfileViolation(ref m) if m.contains("unsupported name constraint")),
            "expected unsupported-name-constraint rejection, got: {err:?}"
        );
    }

    // ── B5: trust-store directory load failures are surfaced ──────

    #[test]
    fn test_from_pem_directory_fails_closed_on_malformed_anchor() {
        let dir = tempfile::tempdir().unwrap();
        // One valid anchor.
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        std::fs::write(dir.path().join("good.pem"), ca_pem).unwrap();
        // One malformed anchor file with a recognised extension.
        std::fs::write(
            dir.path().join("bad.pem"),
            "-----BEGIN CERTIFICATE-----\nnot base64!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        // B5: the malformed file must NOT be silently skipped — it surfaces as
        // an error rather than shrinking the trust set.
        let err = TrustStore::from_pem_directory(dir.path())
            .expect_err("a malformed anchor file must surface as an error");
        assert!(
            matches!(err, TrustError::CertificateParse(ref m) if m.contains("bad.pem")),
            "error should name the offending file, got: {err:?}"
        );
        // The inner TrustError message is unwrapped, so the Display prefix is
        // not duplicated ("certificate parse error: ...: certificate parse
        // error: ...").
        assert_eq!(
            err.to_string().matches("certificate parse error").count(),
            1,
            "error prefix should not be duplicated: {err}"
        );
    }

    #[test]
    fn test_from_pem_directory_read_failure_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        // A directory with a certificate extension is a candidate path, but it
        // cannot be read as an anchor file. This exercises the strict loader's
        // file-read failure path without relying on platform-specific chmod
        // behavior.
        std::fs::create_dir(dir.path().join("unreadable.pem")).unwrap();

        let err = TrustStore::from_pem_directory(dir.path())
            .expect_err("a trust-anchor read failure must surface as I/O");
        assert!(
            matches!(err, TrustError::Io(ref e) if e.to_string().contains("unreadable.pem")),
            "expected TrustError::Io naming the offending path, got: {err:?}"
        );
    }

    #[test]
    fn test_from_pem_directory_lenient_reports_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        std::fs::write(dir.path().join("good.pem"), ca_pem).unwrap();
        std::fs::write(dir.path().join("bad.crt"), "garbage, not a PEM at all").unwrap();

        let (store, skipped) =
            TrustStore::from_pem_directory_lenient(dir.path()).expect("lenient load");
        // The good anchor loaded.
        assert_eq!(store.len(), 1, "the valid anchor must still load");
        // The bad one is reported (not silently dropped).
        assert_eq!(skipped.len(), 1, "the malformed file must be reported");
        assert!(skipped[0].0.ends_with("bad.crt"));
    }

    #[test]
    fn test_from_pem_directory_accepts_der_crt() {
        // A `.crt`/`.cer` anchor is commonly raw DER rather than PEM. It must
        // load rather than fail-close with an "invalid UTF-8 in PEM" error.
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        // Recover the DER of the fixture certificate.
        let mut tmp = TrustStore::new();
        tmp.add_pem_data(ca_pem.as_bytes()).unwrap();
        let der = tmp.anchors[0].der.clone();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("anchor.crt"), &der).unwrap();

        // Strict loader accepts the DER anchor.
        let store = TrustStore::from_pem_directory(dir.path())
            .expect("a DER-encoded .crt anchor must load");
        assert_eq!(store.len(), 1);

        // Lenient loader too, with nothing skipped.
        let (store, skipped) =
            TrustStore::from_pem_directory_lenient(dir.path()).expect("lenient load");
        assert_eq!(store.len(), 1);
        assert!(skipped.is_empty(), "a valid DER anchor must not be skipped");
    }

    #[test]
    fn test_anchor_file_pem_detection_is_anchored() {
        // A DER blob that merely *contains* the PEM armor later in the bytes
        // must be classified as DER, not PEM: the armor check is anchored to the
        // start (after optional whitespace), not a substring search.
        let mut store = TrustStore::new();
        let mut der_like = vec![0x30u8, 0x03, 0x02, 0x01, 0x00];
        der_like.extend_from_slice(b"-----BEGIN CERTIFICATE-----");
        let err = store
            .add_anchor_file_data(&der_like)
            .expect_err("armor not at the start must take the DER path");
        assert!(
            matches!(err, TrustError::CertificateParse(ref m) if m.contains("DER")),
            "embedded armor must not trigger PEM parsing, got: {err:?}"
        );

        // Leading whitespace before genuine PEM armor is still recognised.
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        let padded = format!("\n  \t{ca_pem}");
        store
            .add_anchor_file_data(padded.as_bytes())
            .expect("leading-whitespace PEM must be recognised and loaded");
        assert_eq!(store.len(), 1);
    }
}
