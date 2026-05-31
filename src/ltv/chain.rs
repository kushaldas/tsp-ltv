//! AIA-based certificate chain discovery.
//!
//! Follows Authority Information Access (AIA) `caIssuers` extensions
//! to build a complete certificate chain from leaf to trust anchor.

use std::time::Duration;

use der::{Decode, Encode};
use reqwest::Client;
use x509_cert::Certificate;

use super::ocsp::{extract_aia_urls, AiaAccessMethod};
use crate::error::LtvError;
use crate::trust::TrustStore;

/// Maximum chain depth to prevent infinite loops.
const MAX_CHAIN_DEPTH: usize = 10;

/// Certificate chain builder.
///
/// Discovers and fetches intermediate certificates by following AIA
/// `caIssuers` extensions, building a chain up to a trust anchor.
#[derive(Debug, Clone)]
pub struct ChainBuilder {
    http_client: Client,
    timeout: Duration,
}

impl ChainBuilder {
    /// Create a new chain builder with default settings.
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

    /// Build a complete certificate chain from `leaf` up to a trust anchor.
    ///
    /// Starts with the leaf certificate and follows AIA `caIssuers` URLs
    /// to discover intermediate certificates. Stops when a trust anchor
    /// is found or the chain can no longer be extended.
    ///
    /// Returns the chain as a vector of DER-encoded certificates,
    /// starting with the leaf and ending with (but not including) the trust anchor.
    ///
    /// # Warning — ordering only, NOT a verified chain (L-2)
    ///
    /// This assembles certificates into issuer order by **name matching only**.
    /// It performs **no signature verification** and applies **no trust
    /// decision** — the returned chain is untrusted candidate material. You
    /// **MUST** pass it to [`crate::trust::TrustStore::verify_chain`] (which
    /// verifies every link's signature and the anchor) before relying on it.
    ///
    /// Additionally, this method fetches issuer certificates from the AIA
    /// `caIssuers` URLs embedded in the (attacker-influenced) certificate, i.e.
    /// it performs outbound requests to URLs taken from untrusted input (an SSRF
    /// surface). Only call it with a hardened HTTP client / network policy.
    pub async fn build_chain(
        &self,
        leaf: &Certificate,
        trust_store: &TrustStore,
    ) -> Result<Vec<Vec<u8>>, LtvError> {
        let mut chain: Vec<Vec<u8>> = Vec::new();
        let mut current = leaf.clone();

        for depth in 0..MAX_CHAIN_DEPTH {
            // Add current cert to chain
            let current_der = current
                .to_der()
                .map_err(|e| LtvError::Chain(format!("failed to encode certificate: {e}")))?;
            chain.push(current_der.clone());

            // Check if the current cert's issuer is in the trust store
            if trust_store.find_issuer(&current).is_some() {
                log::debug!("Chain complete at depth {depth}: found trust anchor");
                return Ok(chain);
            }

            // Check if self-signed (root CA)
            if is_self_signed(&current) {
                log::debug!("Chain complete at depth {depth}: self-signed certificate");
                return Ok(chain);
            }

            // Follow AIA caIssuers to find the issuer
            let ca_issuer_urls = extract_aia_urls(&current, AiaAccessMethod::CaIssuers);
            if ca_issuer_urls.is_empty() {
                log::debug!("Chain building stopped at depth {depth}: no AIA caIssuers URLs");
                return Ok(chain);
            }

            let mut found_issuer = false;
            for url in &ca_issuer_urls {
                match self.fetch_certificate(url).await {
                    Ok(issuer_cert) => {
                        current = issuer_cert;
                        found_issuer = true;
                        break;
                    }
                    Err(e) => {
                        log::warn!("Failed to fetch CA cert from {url}: {e}");
                    }
                }
            }

            if !found_issuer {
                log::debug!(
                    "Chain building stopped at depth {depth}: could not fetch issuer from any AIA URL"
                );
                return Ok(chain);
            }
        }

        log::warn!("Chain building reached maximum depth ({MAX_CHAIN_DEPTH})");
        Ok(chain)
    }

    /// Build a chain from a list of already-known certificates.
    ///
    /// This is used when certificates are already embedded in the CMS
    /// SignedData. It orders them into a proper chain.
    ///
    /// # Warning — ordering only, NOT a verified chain (L-2)
    ///
    /// Certificates are ordered by **issuer/subject name matching only**, with
    /// **no signature verification** and **no trust decision**. The result is
    /// untrusted candidate material that you **MUST** hand to
    /// [`crate::trust::TrustStore::verify_chain`] (which checks every link's
    /// signature and the trust anchor) before relying on it.
    pub fn build_chain_from_certs(
        leaf: &Certificate,
        available_certs: &[Certificate],
        trust_store: &TrustStore,
    ) -> Vec<Vec<u8>> {
        let mut chain: Vec<Vec<u8>> = Vec::new();
        let mut current = leaf.clone();

        for _ in 0..MAX_CHAIN_DEPTH {
            // A re-encode failure on an already-parsed certificate is not
            // expected; stop extending the chain rather than emitting an empty
            // DER entry (which verify_chain would reject anyway).
            let Ok(current_der) = current.to_der() else {
                break;
            };
            chain.push(current_der);

            // Check if we reached a trust anchor
            if trust_store.find_issuer(&current).is_some() {
                break;
            }

            if is_self_signed(&current) {
                break;
            }

            // Find issuer among available certs
            let issuer_name = &current.tbs_certificate.issuer;
            let found = available_certs
                .iter()
                .find(|c| &c.tbs_certificate.subject == issuer_name);

            match found {
                Some(issuer) => {
                    current = issuer.clone();
                }
                None => break,
            }
        }

        chain
    }

    /// Fetch a certificate from a URL.
    async fn fetch_certificate(&self, url: &str) -> Result<Certificate, LtvError> {
        log::debug!("Fetching CA certificate from {url}");

        let response = self
            .http_client
            .get(url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| LtvError::Chain(format!("failed to fetch cert from {url}: {e}")))?;

        if !response.status().is_success() {
            return Err(LtvError::Chain(format!(
                "cert fetch from {url} returned HTTP {}",
                response.status()
            )));
        }

        let cert_bytes = response
            .bytes()
            .await
            .map_err(|e| LtvError::Chain(format!("failed to read cert response: {e}")))?
            .to_vec();

        // Try DER first, then PEM
        if let Ok(cert) = Certificate::from_der(&cert_bytes) {
            return Ok(cert);
        }

        // Try PEM
        if let Ok((_label, der)) = pem_rfc7468::decode_vec(&cert_bytes) {
            if let Ok(cert) = Certificate::from_der(&der) {
                return Ok(cert);
            }
        }

        Err(LtvError::Chain(format!(
            "could not parse certificate from {url} (tried DER and PEM)"
        )))
    }
}

impl Default for ChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a certificate is self-signed (subject == issuer).
fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_builder_default() {
        let builder = ChainBuilder::new();
        assert_eq!(builder.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_is_self_signed() {
        // Load root CA cert which should be self-signed
        let cert_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        let (_label, der) = pem_rfc7468::decode_vec(cert_pem.as_bytes()).unwrap();
        let cert = Certificate::from_der(&der).unwrap();
        assert!(is_self_signed(&cert), "root CA should be self-signed");
    }

    #[test]
    fn test_is_not_self_signed() {
        // Load signer cert which should not be self-signed
        let cert_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let (_label, der) = pem_rfc7468::decode_vec(cert_pem.as_bytes()).unwrap();
        let cert = Certificate::from_der(&der).unwrap();
        assert!(
            !is_self_signed(&cert),
            "signer cert should not be self-signed"
        );
    }

    #[test]
    fn test_build_chain_from_certs() {
        // Load our test fixture certificates
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        let signer_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));

        let (_label, ca_der) = pem_rfc7468::decode_vec(ca_pem.as_bytes()).unwrap();

        let (_label, signer_der) = pem_rfc7468::decode_vec(signer_pem.as_bytes()).unwrap();
        let signer_cert = Certificate::from_der(&signer_der).unwrap();

        let mut trust_store = TrustStore::new();
        trust_store.add_der_certificate(&ca_der).unwrap();

        // Check if there's an intermediate cert
        let chain_pem_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chain.pem");
        let chain_pem = std::fs::read_to_string(chain_pem_path).unwrap_or_default();

        let mut available_certs = vec![signer_cert.clone()];

        // Parse chain PEM which may contain intermediate certs.
        // pem_rfc7468::decode_vec doesn't return remaining data, so we only get
        // the first cert this way. For proper multi-PEM parsing we'd need to
        // find the next BEGIN marker.
        let pem_data = chain_pem.as_bytes();
        if let Ok((_label, der)) = pem_rfc7468::decode_vec(pem_data) {
            if let Ok(cert) = Certificate::from_der(&der) {
                available_certs.push(cert);
            }
        }

        let chain =
            ChainBuilder::build_chain_from_certs(&signer_cert, &available_certs, &trust_store);

        assert!(!chain.is_empty(), "chain should not be empty");
        // First cert in chain should be the signer cert
        assert_eq!(chain[0], signer_der, "first cert should be the signer");
    }
}
