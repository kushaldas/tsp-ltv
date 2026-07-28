//! AIA-based certificate chain discovery.
//!
//! Follows Authority Information Access (AIA) `caIssuers` extensions
//! to build a complete certificate chain from leaf to trust anchor.

use std::time::Duration;

use der::{Decode, Encode};
use x509_cert::Certificate;

use super::ocsp::{extract_aia_urls, AiaAccessMethod};
use crate::error::LtvError;
use crate::net::AttestedHttpClient;
use crate::trust::TrustStore;

/// Maximum chain depth to prevent infinite loops.
const MAX_CHAIN_DEPTH: usize = 10;

/// Maximum allowed AIA `caIssuers` response body size (1 MiB).
///
/// A DER/PEM certificate (or even a `certs-only` PKCS#7 bundle) is small; 1 MiB
/// is far above any legitimate response while bounding the memory a malicious or
/// compromised AIA endpoint can force the validator to buffer.
const MAX_CERT_BODY_SIZE: usize = 1024 * 1024;

/// Certificate chain builder.
///
/// Discovers and fetches intermediate certificates by following AIA
/// `caIssuers` extensions, building a chain up to a trust anchor.
///
/// AIA `caIssuers` URLs are carried inside the (attacker-influenced) certificate
/// under validation, so fetching them is an SSRF surface. The default client is
/// built with [`crate::net::hardened_http_client`] and every URL is run through
/// [`crate::net::validate_fetch_url`] before egress: fetches are restricted to
/// `http`/`https` and the resolved host must be a public address (loopback,
/// private, link-local/metadata, unique-local, multicast, and CGNAT ranges are
/// refused). Fetched bodies are capped at `MAX_CERT_BODY_SIZE`. These are the
/// same controls the CRL fetch path uses (ADR-0010), shared via [`crate::net`].
#[derive(Debug, Clone)]
pub struct ChainBuilder {
    http_client: AttestedHttpClient,
    timeout: Duration,
    /// Maximum response body size for a fetched certificate (1 MiB default).
    max_body_size: usize,
}

impl ChainBuilder {
    /// Create a new chain builder with default settings.
    ///
    /// The default HTTP client is SSRF-hardened (bounded, internal-address-aware
    /// redirect policy); see [`ChainBuilder`].
    pub fn new() -> Result<Self, LtvError> {
        Ok(Self {
            http_client: crate::net::hardened_http_client()?,
            timeout: Duration::from_secs(30),
            max_body_size: MAX_CERT_BODY_SIZE,
        })
    }

    /// Set the HTTP client.
    ///
    /// The supplied client is used verbatim; if you replace the default,
    /// preserve a bounded, internal-address-aware redirect policy
    /// (see [`crate::net::hardened_http_client`]) so the redirect-to-internal
    /// SSRF bypass stays closed.
    pub fn http_client(mut self, client: AttestedHttpClient) -> Self {
        self.http_client = client;
        self
    }

    /// Explicitly inject an unattested reqwest client outside FIPS mode.
    #[cfg(not(feature = "fips"))]
    pub fn unverified_http_client(mut self, client: reqwest::Client) -> Result<Self, LtvError> {
        self.http_client = crate::net::unverified_http_client(client)?;
        Ok(self)
    }

    /// Set the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum response body size for a fetched certificate.
    pub fn max_body_size(mut self, max: usize) -> Self {
        self.max_body_size = max;
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
    ///
    /// The URL comes from an attacker-influenced AIA `caIssuers` extension, so
    /// it is validated against the SSRF guard (`http`/`https` scheme allowlist
    /// **and** resolved-IP filtering) before any network egress, and the
    /// response body is capped at `self.max_body_size`. These mirror the CRL
    /// fetch path (ADR-0010) via the shared [`crate::net`] helper.
    async fn fetch_certificate(&self, url: &str) -> Result<Certificate, LtvError> {
        log::debug!("Fetching CA certificate from {url}");

        // SSRF guard: validate scheme *and* that the host resolves to a public
        // address before any network egress. A cert's AIA caIssuers URL is
        // attacker-controlled. The guard's DNS resolution is bounded by the same
        // timeout as the HTTP GET so a slow/blocked resolver cannot make this
        // exceed `self.timeout`.
        match tokio::time::timeout(self.timeout, crate::net::validate_fetch_url(url)).await {
            Ok(result) => result.map_err(|e| LtvError::Chain(format!("AIA caIssuers {e}")))?,
            Err(_) => {
                return Err(LtvError::Chain(format!(
                    "AIA caIssuers URL validation timed out after {:?}",
                    self.timeout
                )))
            }
        }

        let response = self
            .http_client
            .client()
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

        // Reject up front if the advertised Content-Length already exceeds the
        // cap, so an oversized body is never even streamed.
        if let Some(len) = response.content_length() {
            if len > self.max_body_size as u64 {
                return Err(LtvError::Chain(format!(
                    "cert from {url} exceeds max body size ({len} > {})",
                    self.max_body_size
                )));
            }
        }

        // Stream the body and abort as soon as the accumulated bytes exceed the
        // cap, bounding peak memory even when Content-Length is absent or lies.
        let mut cert_bytes: Vec<u8> = Vec::new();
        let mut response = response;
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|e| LtvError::Chain(format!("failed to read cert response: {e}")))?;
            let Some(chunk) = chunk else { break };
            if cert_bytes.len() + chunk.len() > self.max_body_size {
                return Err(LtvError::Chain(format!(
                    "cert from {url} exceeds max body size (> {})",
                    self.max_body_size
                )));
            }
            cert_bytes.extend_from_slice(&chunk);
        }

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

/// Check if a certificate is self-signed (subject == issuer).
fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_builder_default() {
        let builder = ChainBuilder::new().unwrap();
        assert_eq!(builder.timeout, Duration::from_secs(30));
        assert_eq!(builder.max_body_size, MAX_CERT_BODY_SIZE);
    }

    #[tokio::test]
    async fn test_fetch_certificate_rejects_private_ip_aia_url() {
        // B1: an AIA caIssuers URL pointing at a private/loopback/metadata
        // address must be refused before any network egress (SSRF guard).
        let builder = ChainBuilder::new().unwrap();
        for url in [
            "http://127.0.0.1/ca.crt",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/ca.crt",
            "http://[::1]/ca.crt",
        ] {
            let err = builder
                .fetch_certificate(url)
                .await
                .expect_err("private/loopback AIA URL must be rejected");
            let msg = format!("{err}");
            assert!(
                msg.contains("non-public") || msg.contains("SSRF"),
                "expected SSRF rejection for {url}, got: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn test_fetch_certificate_rejects_non_http_scheme() {
        // B1: non-web schemes (file://, gopher://) are refused by the scheme
        // allowlist before egress.
        let builder = ChainBuilder::new().unwrap();
        let err = builder
            .fetch_certificate("file:///etc/passwd")
            .await
            .expect_err("non-http AIA URL must be rejected");
        assert!(
            format!("{err}").contains("scheme not allowed"),
            "expected scheme rejection, got: {err}"
        );
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
