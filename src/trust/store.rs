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
        TrustError::SignatureVerification(format!(
            "failed to parse basicConstraints for {label}: {e}"
        ))
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
            TrustError::SignatureVerification(format!(
                "failed to parse basicConstraints below {label}: {e}"
            ))
        })?;
        if is_ca && !is_self_issued(cert) {
            subordinate_ca_count += 1;
        }
    }
    if subordinate_ca_count > max_depth {
        return Err(TrustError::SignatureVerification(format!(
            "pathLenConstraint ({max_depth}) exceeded for {label}: {subordinate_ca_count} non-self-issued subordinate CA certs below"
        )));
    }
    Ok(())
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

    /// Load trust anchors from all PEM files (*.pem, *.crt, *.cer) in a directory.
    ///
    /// Non-PEM files and files that fail to parse are silently skipped.
    pub fn from_pem_directory(dir: impl AsRef<Path>) -> Result<Self, TrustError> {
        let dir = dir.as_ref();
        if !dir.is_dir() {
            return Err(TrustError::NotADirectory(dir.display().to_string()));
        }

        let mut store = Self::new();
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map_err(TrustError::Io)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_lowercase();
                if ext == "pem" || ext == "crt" || ext == "cer" {
                    if let Ok(data) = std::fs::read(&path) {
                        // Best effort — skip files that aren't valid PEM
                        let _ = store.add_pem_data(&data);
                    }
                }
            }
        }

        Ok(store)
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
        let policy = &self.signature_policy;
        if chain.is_empty() {
            return Err(TrustError::EmptyChain);
        }

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
            // This deeper role validation lives in the `ltv` extension module.
            #[cfg(feature = "ltv")]
            {
                use crate::ltv::x509_ext::{validate_extensions_for_role, CertRole};
                validate_extensions_for_role(issuer_cert, CertRole::IntermediateCa).map_err(
                    |e| {
                        TrustError::SignatureVerification(format!(
                            "intermediate at index {} failed extension validation: {e}",
                            i + 1
                        ))
                    },
                )?;
            }

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

        // Re-sign the TBS with SHA-1 and relabel the outer algorithm.
        let tbs_der = base.tbs_certificate.to_der().unwrap();
        let hash = Sha1::digest(&tbs_der);
        let sig = key
            .sign(Pkcs1v15Sign::new::<Sha1>(), &hash)
            .expect("SHA-1 RSA sign");
        Certificate {
            tbs_certificate: base.tbs_certificate.clone(),
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: crate::crypto::algorithm::OID_SHA1_WITH_RSA,
                // sha1WithRSAEncryption carries an explicit NULL parameter.
                parameters: Some(Any::from_der(&[0x05, 0x00]).unwrap()),
            },
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
            matches!(err, TrustError::SignatureVerification(ref m) if m.contains("pathLenConstraint")),
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
            matches!(err, TrustError::SignatureVerification(ref m) if m.contains("pathLenConstraint") && m.contains("trust anchor")),
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
}
