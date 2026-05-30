//! Chain building from a pool of certificates.
//!
//! Given a leaf certificate and an unordered pool of intermediate certificates,
//! build an ordered chain `[leaf, intermediate_0, ..., intermediate_n]` suitable
//! for [`TrustStore::verify_chain()`](super::TrustStore::verify_chain).
//!
//! This is a local-only chain builder (no network fetching). It matches
//! certificates by subject/issuer name and verifies each link's signature
//! before including it in the chain.

use crate::error::TrustError;
use der::Encode;
use x509_cert::Certificate;

/// Build an ordered certificate chain from a leaf to a trust anchor,
/// using a local pool of intermediate certificates.
///
/// The returned chain is ordered `[leaf, intermediate_0, ..., intermediate_n]`
/// and is ready to be passed to [`TrustStore::verify_chain()`](super::TrustStore::verify_chain).
///
/// The function walks from the leaf upward, matching each certificate's issuer
/// name against the subject names of certificates in the pool. At each step,
/// the candidate's signature is verified before it is added to the chain.
///
/// The walk stops when:
/// - A certificate's issuer matches a trust anchor's subject (chain is complete)
/// - A self-signed certificate is reached
/// - No issuer can be found in the pool (returns an error)
/// - The chain exceeds `max_depth` (default 10) to prevent infinite loops
///
/// # Arguments
///
/// * `leaf` — The leaf (end-entity) certificate to start from.
/// * `pool` — Unordered pool of intermediate certificates.
/// * `trust_anchor_subjects` — DER-encoded subject names of trust anchors.
///   Used to know when to stop walking (don't include anchors in the chain).
/// * `max_depth` — Maximum chain length (excluding the leaf). Pass `None` for default (10).
///
/// # Errors
///
/// Returns `TrustError` if no valid chain can be built.
pub fn build_chain_from_pool(
    leaf: &Certificate,
    pool: &[Certificate],
    trust_anchor_subjects: &[Vec<u8>],
    max_depth: Option<usize>,
) -> Result<Vec<Certificate>, TrustError> {
    build_chain_from_pool_with_policy(
        leaf,
        pool,
        trust_anchor_subjects,
        max_depth,
        &crate::crypto::verify::SignaturePolicy::default(),
    )
}

/// Like [`build_chain_from_pool`] but with an explicit
/// [`SignaturePolicy`](crate::crypto::verify::SignaturePolicy) for the per-link
/// signature checks.
///
/// Pass [`SignaturePolicy::allow_legacy`](crate::crypto::verify::SignaturePolicy::allow_legacy)
/// to build chains whose links are signed with weak digests (MD5/SHA-1/SHA-224)
/// — e.g. historical XML-DSig interop fixtures. The default rejects them, which
/// would otherwise make chain construction fail before
/// [`TrustStore::verify_chain`](super::TrustStore::verify_chain) (and its own
/// policy) ever runs. Use the same policy the verifying store was built with.
pub fn build_chain_from_pool_with_policy(
    leaf: &Certificate,
    pool: &[Certificate],
    trust_anchor_subjects: &[Vec<u8>],
    max_depth: Option<usize>,
    policy: &crate::crypto::verify::SignaturePolicy,
) -> Result<Vec<Certificate>, TrustError> {
    let max_depth = max_depth.unwrap_or(10);
    let mut chain = vec![leaf.clone()];
    let mut current = leaf.clone();

    // Track visited certs by DER encoding to prevent cycles
    let mut visited: Vec<Vec<u8>> = vec![leaf
        .to_der()
        .map_err(|e| TrustError::CertificateParse(format!("DER encode failed: {e}")))?];

    for _ in 0..max_depth {
        let issuer_name_der = current.tbs_certificate.issuer.to_der().unwrap_or_default();
        let subject_name_der = current.tbs_certificate.subject.to_der().unwrap_or_default();

        // If self-signed, stop (the trust store will handle root matching)
        if issuer_name_der == subject_name_der {
            break;
        }

        // If the issuer matches a trust anchor, we're done — the chain is complete
        if trust_anchor_subjects.iter().any(|s| *s == issuer_name_der) {
            break;
        }

        // Search the pool for an issuer
        let mut found = false;
        for candidate in pool {
            let candidate_der = candidate
                .to_der()
                .map_err(|e| TrustError::CertificateParse(format!("DER encode failed: {e}")))?;

            if visited.contains(&candidate_der) {
                continue; // avoid cycles
            }

            let candidate_subject_der = candidate
                .tbs_certificate
                .subject
                .to_der()
                .unwrap_or_default();

            if candidate_subject_der == issuer_name_der {
                // Verify the signature before accepting this link
                if crate::crypto::verify::verify_certificate_signature_with_policy(
                    &current, candidate, policy,
                )
                .is_ok()
                {
                    visited.push(candidate_der);
                    chain.push(candidate.clone());
                    current = candidate.clone();
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(TrustError::ChainBroken {
                index: chain.len() - 1,
                expected_issuer: format!("{}", current.tbs_certificate.issuer),
                found_subject: "no matching certificate in pool".into(),
            });
        }
    }

    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::verify::SignaturePolicy;

    /// Build (issuer, leaf) where the leaf is signed by the issuer with SHA-1
    /// (`sha1WithRSAEncryption`). The issuer is a self-signed SHA-256 root, so
    /// only the leaf→issuer link is weak — exactly the case that must fail at
    /// chain construction under the strict default.
    fn issuer_and_sha1_leaf() -> (Certificate, Certificate) {
        use der::asn1::BitString;
        use der::{Any, Decode};
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
        let validity =
            Validity::from_now(std::time::Duration::from_secs(3650 * 24 * 3600)).unwrap();

        // Self-signed SHA-256 issuer.
        let issuer_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let issuer_signer = SigningKey::<Sha256>::new(issuer_key.clone());
        let issuer_spki =
            SubjectPublicKeyInfoOwned::from_key(issuer_signer.verifying_key()).unwrap();
        let issuer_name: Name = "CN=Legacy Issuer,O=tsp-ltv tests".parse().unwrap();
        let issuer = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::new(&[0x01]).unwrap(),
            validity,
            issuer_name.clone(),
            issuer_spki,
            &issuer_signer,
        )
        .unwrap()
        .build()
        .unwrap();

        // Leaf issued by the issuer; build a well-formed TBS with SHA-256, then
        // re-sign that TBS with the issuer key under SHA-1.
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let leaf_spki = SubjectPublicKeyInfoOwned::from_key(
            SigningKey::<Sha256>::new(leaf_key).verifying_key(),
        )
        .unwrap();
        let leaf_subject: Name = "CN=Legacy Leaf,O=tsp-ltv tests".parse().unwrap();
        let base = CertificateBuilder::new(
            Profile::Leaf {
                issuer: issuer.tbs_certificate.subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::new(&[0x02]).unwrap(),
            validity,
            leaf_subject,
            leaf_spki,
            &issuer_signer,
        )
        .unwrap()
        .build()
        .unwrap();

        let tbs_der = base.tbs_certificate.to_der().unwrap();
        let hash = Sha1::digest(&tbs_der);
        let sig = issuer_key
            .sign(Pkcs1v15Sign::new::<Sha1>(), &hash)
            .expect("SHA-1 RSA sign");
        let leaf = Certificate {
            tbs_certificate: base.tbs_certificate.clone(),
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: crate::crypto::algorithm::OID_SHA1_WITH_RSA,
                parameters: Some(Any::from_der(&[0x05, 0x00]).unwrap()),
            },
            signature: BitString::from_bytes(&sig).unwrap(),
        };

        (issuer, leaf)
    }

    #[test]
    fn test_build_chain_rejects_sha1_link_by_default_and_accepts_with_legacy() {
        let (issuer, leaf) = issuer_and_sha1_leaf();
        let pool = [issuer];

        // Strict default: the SHA-1 leaf→issuer link fails the per-link check,
        // so the chain cannot be built — this is the contract break the policy
        // must let callers avoid.
        let err = build_chain_from_pool(&leaf, &pool, &[], None).unwrap_err();
        assert!(
            matches!(err, TrustError::ChainBroken { .. }),
            "strict build must fail on a SHA-1 link, got {err:?}"
        );

        // Legacy opt-in (same policy a legacy TrustStore is built with): the
        // chain now constructs end-to-end.
        let chain = build_chain_from_pool_with_policy(
            &leaf,
            &pool,
            &[],
            None,
            &SignaturePolicy::allow_legacy(),
        )
        .expect("legacy build must succeed on a SHA-1 link");
        assert_eq!(chain.len(), 2, "chain should be [leaf, issuer]");
    }
}

/// Convenience: extract the DER-encoded subject names from a [`TrustStore`](super::TrustStore).
///
/// This is useful for passing to [`build_chain_from_pool`] as the
/// `trust_anchor_subjects` argument.
pub fn trust_anchor_subjects(store: &super::TrustStore) -> Vec<Vec<u8>> {
    store
        .certificates()
        .filter_map(|cert| cert.tbs_certificate.subject.to_der().ok())
        .collect()
}
