//! TSA HTTP client for RFC 3161 timestamp requests.
//!
//! Provides `TsaClient` for communicating with a single TSA server,
//! and `TsaClientPool` for fallback across multiple TSA URLs.

use std::time::Duration;

use reqwest::Client;

use super::token;
use crate::crypto::algorithm::DigestAlgorithm;
use crate::error::TspError;

/// HTTP Content-Type for RFC 3161 timestamp requests.
const TSP_REQUEST_CONTENT_TYPE: &str = "application/timestamp-query";

/// HTTP Content-Type for RFC 3161 timestamp responses.
const TSP_RESPONSE_CONTENT_TYPE: &str = "application/timestamp-reply";

/// RFC 3161 Time-Stamp Authority client.
///
/// Sends `TimeStampReq` messages to a TSA server via HTTP POST and
/// parses the `TimeStampResp`.
///
/// # Example
///
/// ```no_run
/// use tsp_ltv::tsp::TsaClient;
/// use tsp_ltv::crypto::algorithm::DigestAlgorithm;
///
/// # async fn example() -> Result<(), tsp_ltv::error::TspError> {
/// let client = TsaClient::new("http://timestamp.digicert.com")
///     .digest_algorithm(DigestAlgorithm::Sha256)
///     .timeout(std::time::Duration::from_secs(10));
///
/// let data_hash = DigestAlgorithm::Sha256.digest(b"hello");
/// let token = client.timestamp(&data_hash).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TsaClient {
    /// TSA server URL.
    url: String,
    /// HTTP client (shared, connection-pooled).
    http_client: Client,
    /// Digest algorithm for the timestamp request.
    digest_algorithm: DigestAlgorithm,
    /// Optional TSA policy OID to include in the request.
    policy_oid: Option<const_oid::ObjectIdentifier>,
    /// HTTP request timeout.
    timeout: Duration,
    /// Whether to request the TSA certificate in the response.
    cert_req: bool,
    /// TSA signing certificates supplied out-of-band, used to verify the
    /// returned token when it omits the CMS `certificates` field (i.e. when
    /// `cert_req` is false). Empty by default; not needed when `cert_req` is
    /// true (the cert is then embedded in the token).
    verification_certs: Vec<x509_cert::Certificate>,
}

impl TsaClient {
    /// Create a new TSA client for the given URL.
    ///
    /// Uses sensible defaults:
    /// - SHA-256 digest algorithm
    /// - 30-second timeout
    /// - No policy OID
    /// - certReq = true (request TSA cert in response)
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            http_client: Client::new(),
            digest_algorithm: DigestAlgorithm::Sha256,
            policy_oid: None,
            timeout: Duration::from_secs(30),
            cert_req: true,
            verification_certs: Vec::new(),
        }
    }

    /// Set the digest algorithm.
    pub fn digest_algorithm(mut self, alg: DigestAlgorithm) -> Self {
        self.digest_algorithm = alg;
        self
    }

    /// Set the TSA policy OID.
    pub fn policy_oid(mut self, oid: const_oid::ObjectIdentifier) -> Self {
        self.policy_oid = Some(oid);
        self
    }

    /// Set the HTTP request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set whether to request the TSA certificate in the response.
    ///
    /// When `false`, the returned token will not embed the TSA certificate, so
    /// the built-in verification cannot check the signature unless the
    /// certificate is supplied via [`verification_certs`](Self::verification_certs).
    pub fn cert_req(mut self, cert_req: bool) -> Self {
        self.cert_req = cert_req;
        self
    }

    /// Supply TSA signing certificate(s) used to verify the returned token when
    /// it omits the CMS `certificates` field (i.e. when `cert_req` is false).
    ///
    /// Not required when `cert_req` is true (the default), since the certificate
    /// is then embedded in the token.
    pub fn verification_certs(mut self, certs: Vec<x509_cert::Certificate>) -> Self {
        self.verification_certs = certs;
        self
    }

    /// Set a custom reqwest HTTP client (e.g., for custom TLS config).
    pub fn http_client(mut self, client: Client) -> Self {
        self.http_client = client;
        self
    }

    /// Get the TSA URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Request a timestamp token for the given data hash.
    ///
    /// The `data_hash` should be the hash of the data to timestamp
    /// (e.g., the CMS signature value for PAdES-B-T).
    ///
    /// Returns the raw DER-encoded TimeStampToken (a CMS ContentInfo
    /// wrapping SignedData with TSTInfo as the encapsulated content).
    pub async fn timestamp(&self, data_hash: &[u8]) -> Result<Vec<u8>, TspError> {
        // Generate nonce for replay protection
        let nonce = token::generate_nonce();

        // Build the TimeStampReq
        let req_der = token::build_timestamp_request(
            self.digest_algorithm,
            data_hash,
            self.policy_oid.as_ref(),
            Some(nonce),
            self.cert_req,
        )?;

        log::debug!(
            "Sending TimeStampReq to {} ({} bytes, nonce={})",
            self.url,
            req_der.len(),
            nonce,
        );

        // HTTP POST to TSA
        let response = self
            .http_client
            .post(&self.url)
            .header("Content-Type", TSP_REQUEST_CONTENT_TYPE)
            .timeout(self.timeout)
            .body(req_der)
            .send()
            .await
            .map_err(|e| TspError::HttpError(format!("TSA request to {} failed: {e}", self.url)))?;

        // Check HTTP status
        let status = response.status();
        if !status.is_success() {
            return Err(TspError::HttpError(format!(
                "TSA {} returned HTTP {status}",
                self.url,
            )));
        }

        // Verify Content-Type (some TSAs use slightly different types)
        if let Some(ct) = response.headers().get("content-type") {
            let ct_str = ct.to_str().unwrap_or("");
            if !ct_str.starts_with(TSP_RESPONSE_CONTENT_TYPE)
                && !ct_str.starts_with("application/timestamp-response")
            {
                log::warn!(
                    "TSA {} returned unexpected Content-Type: {ct_str}",
                    self.url,
                );
            }
        }

        // Read the response body
        let resp_bytes = response
            .bytes()
            .await
            .map_err(|e| TspError::HttpError(format!("failed to read TSA response body: {e}")))?;

        log::debug!(
            "Received TimeStampResp from {} ({} bytes)",
            self.url,
            resp_bytes.len(),
        );

        // Parse and validate the response
        let resp = token::parse_timestamp_response(&resp_bytes)?;
        let token_der = token::validate_timestamp_response(
            &resp,
            data_hash,
            Some(nonce),
            self.digest_algorithm,
            &self.verification_certs,
        )?;

        log::debug!(
            "Timestamp token obtained from {} ({} bytes)",
            self.url,
            token_der.len(),
        );

        Ok(token_der)
    }

    /// Blocking variant of [`timestamp`](Self::timestamp).
    ///
    /// Available with the `blocking` feature flag.
    #[cfg(feature = "blocking")]
    pub fn timestamp_blocking(&self, data_hash: &[u8]) -> Result<Vec<u8>, TspError> {
        tokio::runtime::Handle::current().block_on(self.timestamp(data_hash))
    }
}

/// Pool of TSA clients with fallback support.
///
/// Tries each TSA in order. If the first TSA fails, falls back to the next one.
/// This provides resilience against TSA downtime.
///
/// # Example
///
/// ```no_run
/// use tsp_ltv::tsp::{TsaClient, TsaClientPool};
///
/// let pool = TsaClientPool::new(vec![
///     TsaClient::new("http://timestamp.digicert.com"),
///     TsaClient::new("http://timestamp.globalsign.com/tsa/r6advanced1"),
/// ]);
/// ```
#[derive(Debug, Clone)]
pub struct TsaClientPool {
    /// Ordered list of TSA clients (first = primary, rest = fallbacks).
    clients: Vec<TsaClient>,
}

impl TsaClientPool {
    /// Create a new pool from a list of TSA clients.
    ///
    /// # Panics
    ///
    /// Panics if `clients` is empty.
    pub fn new(clients: Vec<TsaClient>) -> Self {
        assert!(
            !clients.is_empty(),
            "TsaClientPool requires at least one client"
        );
        Self { clients }
    }

    /// Create a pool from a single URL with default settings.
    pub fn from_url(url: &str) -> Self {
        Self::new(vec![TsaClient::new(url)])
    }

    /// Create a pool from multiple URLs with default settings.
    pub fn from_urls(urls: &[&str]) -> Self {
        let clients = urls.iter().map(|u| TsaClient::new(u)).collect();
        Self::new(clients)
    }

    /// Request a timestamp token, trying each TSA in the pool.
    ///
    /// Returns the token from the first TSA that succeeds.
    /// If all TSAs fail, returns the error from the last one.
    pub async fn timestamp(&self, data_hash: &[u8]) -> Result<Vec<u8>, TspError> {
        let mut last_error = None;

        for (i, client) in self.clients.iter().enumerate() {
            match client.timestamp(data_hash).await {
                Ok(token) => return Ok(token),
                Err(e) => {
                    log::warn!(
                        "TSA {} ({}) failed: {e}; trying next ({}/{} remaining)",
                        client.url(),
                        i + 1,
                        self.clients.len() - i - 1,
                        self.clients.len(),
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| TspError::HttpError("no TSA clients configured".into())))
    }

    /// Blocking variant of [`timestamp`](Self::timestamp).
    #[cfg(feature = "blocking")]
    pub fn timestamp_blocking(&self, data_hash: &[u8]) -> Result<Vec<u8>, TspError> {
        tokio::runtime::Handle::current().block_on(self.timestamp(data_hash))
    }

    /// Get the number of TSA clients in the pool.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Check if the pool is empty (should never be true after construction).
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}
