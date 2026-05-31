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
    find_tagged_value, integer_bodies_equal, parse_integer_body, parse_tlv, parse_tlv_with_rest,
    parse_x509_time,
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
///
/// As an SSRF mitigation against attacker-controlled distribution-point URLs,
/// fetches are restricted to `http`/`https` and the resolved host must be a
/// public address — loopback, private, link-local, unique-local, and metadata
/// ranges are refused (see [`CrlClient::validate_url`]), and the default client
/// will not follow redirects to literal non-public addresses. Fetched CRL
/// bodies are capped at [`MAX_BODY_SIZE`] to prevent memory exhaustion.
#[derive(Debug, Clone)]
pub struct CrlClient {
    http_client: Client,
    timeout: Duration,
    /// In-memory cache: URL -> CRL entry
    cache: Arc<Mutex<HashMap<String, CrlCacheEntry>>>,
    /// How long cached CRLs remain valid.
    grace_period: Duration,
    /// Maximum response body size (10 MiB default).
    max_body_size: usize,
    /// Freshness policy used to decide whether a cached or just-fetched CRL is
    /// still current (within its own `thisUpdate`/`nextUpdate` window). This is a
    /// *fetch-time* check against the wall clock — distinct from the orchestrator's
    /// authoritative [`check_revocation`] check against the historical
    /// `validation_time`. It ensures a CRL that has crossed its `nextUpdate` is
    /// re-fetched (not served from cache) and that a stale distribution point does
    /// not shadow a fresh one.
    freshness: CrlFreshness,
}

/// Maximum allowed CRL response body size (10 MiB).
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Maximum HTTP redirects followed when fetching a CRL.
const MAX_REDIRECTS: usize = 5;

/// Classify an IPv4 address as non-public (loopback, private, link-local,
/// unspecified, broadcast, documentation, multicast, or RFC 6598 CGNAT shared
/// space).
fn is_disallowed_ipv4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_multicast()
        // CGNAT shared address space 100.64.0.0/10 (RFC 6598)
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
}

/// Classify an IP address as non-public, so the CRL SSRF guard can refuse
/// fetches whose host resolves to an internal or metadata address. IPv4-mapped
/// IPv6 addresses are unwrapped and re-checked.
fn is_disallowed_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => is_disallowed_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_disallowed_ipv4(v4);
            }
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique local fc00::/7
                || (first & 0xfe00) == 0xfc00
                // link-local unicast fe80::/10
                || (first & 0xffc0) == 0xfe80
        }
    }
}

/// Build the default CRL HTTP client with a bounded redirect policy that
/// refuses to follow redirects to literal non-public addresses — complementing
/// the resolve-time SSRF check in [`CrlClient::validate_url`].
fn default_http_client() -> Client {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many CRL redirects");
        }
        if let Some(host) = attempt.url().host_str() {
            // `host_str()` brackets IPv6 literals (`[::1]`); strip for parsing.
            let bare = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(host);
            if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
                if is_disallowed_ip(ip) {
                    // Stop following; the caller sees the 3xx and rejects it.
                    return attempt.stop();
                }
            }
        }
        attempt.follow()
    });
    // Fail closed: never degrade to a client with reqwest's default (unhardened)
    // redirect behaviour. A build failure here is a system/TLS fault, on which
    // `reqwest::Client::new()` would itself panic.
    Client::builder()
        .redirect(policy)
        .build()
        .expect("failed to build hardened CRL HTTP client")
}

impl CrlClient {
    /// Create a new CRL client with default settings.
    ///
    /// Default grace period: 1 hour.
    pub fn new() -> Self {
        Self {
            http_client: default_http_client(),
            timeout: Duration::from_secs(30),
            cache: Arc::new(Mutex::new(HashMap::new())),
            grace_period: Duration::from_secs(3600),
            max_body_size: MAX_BODY_SIZE,
            freshness: CrlFreshness::default(),
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

    /// Set the fetch-time freshness policy (see [`CrlFreshness`]).
    pub fn freshness(mut self, freshness: CrlFreshness) -> Self {
        self.freshness = freshness;
        self
    }

    /// Set the maximum response body size.
    pub fn max_body_size(mut self, max: usize) -> Self {
        self.max_body_size = max;
        self
    }

    /// Validate that a URL is safe to fetch before any network egress.
    ///
    /// Enforces an `http`/`https` scheme allowlist **and** resolves the host,
    /// rejecting the fetch when any resolved address is loopback, private,
    /// link-local, unique-local, multicast, or otherwise non-public. Scheme
    /// filtering alone does not stop SSRF — a CRL distribution point URL is
    /// attacker-controlled and can name `127.0.0.1`, `169.254.169.254`
    /// (cloud metadata), or an RFC 1918 host directly or via DNS.
    ///
    /// Residual limitation: the host is resolved here while `reqwest` re-resolves
    /// at connect time, so a DNS-rebinding attacker who flips the record between
    /// the two lookups is not fully prevented. The default client's redirect
    /// policy additionally refuses redirects to literal non-public addresses.
    async fn validate_url(url: &str) -> Result<(), LtvError> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| LtvError::Crl(format!("invalid CRL URL {url}: {e}")))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(LtvError::Crl(format!(
                    "CRL URL scheme not allowed: {other} (only http/https are supported)"
                )))
            }
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| LtvError::Crl(format!("CRL URL has no host: {url}")))?;
        // `host_str()` brackets IPv6 literals (`[::1]`); strip them for parsing.
        let host_bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);

        // A literal IP needs no DNS — check it directly.
        if let Ok(ip) = host_bare.parse::<std::net::IpAddr>() {
            if is_disallowed_ip(ip) {
                return Err(LtvError::Crl(format!(
                    "CRL host {host_bare} is a non-public address (SSRF guard)"
                )));
            }
            return Ok(());
        }

        // Hostname: resolve off the async executor and reject any non-public
        // destination among the resolved addresses.
        let port = parsed.port_or_known_default().unwrap_or(0);
        let host_owned = host_bare.to_string();
        let host_for_lookup = host_owned.clone();
        let addrs: Vec<std::net::SocketAddr> = tokio::task::spawn_blocking(move || {
            use std::net::ToSocketAddrs;
            (host_for_lookup.as_str(), port)
                .to_socket_addrs()
                .map(|it| it.collect::<Vec<_>>())
        })
        .await
        .map_err(|e| LtvError::Crl(format!("DNS resolution task failed: {e}")))?
        .map_err(|e| LtvError::Crl(format!("failed to resolve CRL host {host_owned}: {e}")))?;

        if addrs.is_empty() {
            return Err(LtvError::Crl(format!(
                "CRL host {host_owned} resolved to no addresses"
            )));
        }
        for addr in &addrs {
            if is_disallowed_ip(addr.ip()) {
                return Err(LtvError::Crl(format!(
                    "CRL host {host_owned} resolves to non-public address {} (SSRF guard)",
                    addr.ip()
                )));
            }
        }
        Ok(())
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
    ///
    /// A cached entry is only served while it is both within the local cache
    /// grace period *and* still inside its own `thisUpdate`/`nextUpdate` validity
    /// window (as of the wall clock), per this client's [`freshness`](Self::freshness)
    /// policy. A cached CRL that has crossed its `nextUpdate` is treated as a cache
    /// miss and re-fetched, so the freshness enforcement in [`check_revocation`]
    /// never hard-fails on a superseded CRL that the issuer has already replaced.
    pub async fn fetch_crl(&self, url: &str) -> Result<Vec<u8>, LtvError> {
        self.fetch_crl_with_freshness(url, &self.freshness).await
    }

    /// Like [`fetch_crl`](Self::fetch_crl) but uses an explicit [`CrlFreshness`]
    /// for the cache-currentness decision instead of this client's default.
    ///
    /// The revocation orchestrator uses this so the *same* freshness policy
    /// (`RevocationConfig::crl_freshness`) governs the cache/fetch selection and
    /// the authoritative [`check_revocation`] check — a caller who widens the
    /// policy is never blocked by a stricter default at the fetch layer.
    pub async fn fetch_crl_with_freshness(
        &self,
        url: &str,
        freshness: &CrlFreshness,
    ) -> Result<Vec<u8>, LtvError> {
        // Check cache first. A cache hit performs no network egress, so the SSRF
        // guard (which resolves DNS) only needs to run on the fetch path below.
        {
            let cache = self
                .cache
                .lock()
                .map_err(|e| LtvError::Crl(format!("cache lock poisoned: {e}")))?;
            if let Some(entry) = cache.get(url) {
                if entry.fetched_at.elapsed() < self.grace_period
                    && crl_is_current(&entry.der, chrono::Utc::now(), freshness)
                {
                    log::debug!("CRL cache hit for {url}");
                    return Ok(entry.der.clone());
                }
                log::debug!("CRL cache entry for {url} is stale or expired; re-fetching");
            }
        }

        // Validate scheme *and* that the host resolves to a public address
        // before any network egress (SSRF guard). A certificate's CRL
        // distribution point URL is attacker-controlled.
        Self::validate_url(url).await?;

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

        // Reject up front if the advertised Content-Length already exceeds the
        // cap, so an oversized body is never even streamed.
        if let Some(len) = response.content_length() {
            if len > self.max_body_size as u64 {
                return Err(LtvError::Crl(format!(
                    "CRL from {url} exceeds max body size ({len} > {})",
                    self.max_body_size
                )));
            }
        }

        // Stream the body and abort as soon as the accumulated bytes exceed the
        // cap, bounding peak memory even when Content-Length is absent or lies.
        let mut crl_bytes: Vec<u8> = Vec::new();
        let mut response = response;
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|e| LtvError::Crl(format!("failed to read CRL response body: {e}")))?;
            let Some(chunk) = chunk else { break };
            if crl_bytes.len() + chunk.len() > self.max_body_size {
                return Err(LtvError::Crl(format!(
                    "CRL from {url} exceeds max body size (> {})",
                    self.max_body_size
                )));
            }
            crl_bytes.extend_from_slice(&chunk);
        }

        // Validate that it looks like a DER-encoded CRL (starts with SEQUENCE tag)
        if crl_bytes.is_empty() || crl_bytes[0] != 0x30 {
            return Err(LtvError::Crl(format!(
                "CRL from {url} does not appear to be DER-encoded"
            )));
        }

        log::debug!("CRL from {url}: {} bytes", crl_bytes.len());

        // Update cache
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|e| LtvError::Crl(format!("cache lock poisoned: {e}")))?;
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

    /// Fetch a usable CRL for a certificate, trying every distribution point.
    ///
    /// Distribution points are tried in order. The **first CRL that both downloads
    /// and is current** (within its own `nextUpdate` window as of the wall clock)
    /// is returned immediately — so a stale or lagging endpoint never shadows a
    /// fresh one at a later distribution point.
    ///
    /// If no distribution point yields a current CRL, the first one that merely
    /// downloaded is returned as a fallback. That CRL is stale, so the
    /// orchestrator's [`check_revocation`] freshness check will make a definitive
    /// fail-closed (`Invalid`) decision — rather than the caller silently seeing
    /// "no CRL" (`Unknown`). When nothing downloads at all, an empty vec is
    /// returned (→ `Unknown`), unchanged from before.
    ///
    /// Currentness is judged by this client's [`freshness`](Self::freshness)
    /// policy; use [`fetch_crls_for_cert_with_freshness`](Self::fetch_crls_for_cert_with_freshness)
    /// to supply an explicit one.
    pub async fn fetch_crls_for_cert(&self, cert: &Certificate) -> Result<Vec<Vec<u8>>, LtvError> {
        self.fetch_crls_for_cert_with_freshness(cert, &self.freshness)
            .await
    }

    /// Like [`fetch_crls_for_cert`](Self::fetch_crls_for_cert) but uses an
    /// explicit [`CrlFreshness`] for distribution-point selection and the
    /// cache-currentness decision.
    ///
    /// The revocation orchestrator passes `RevocationConfig::crl_freshness` here
    /// so a single policy governs both the fetch/cache selection and the
    /// authoritative [`check_revocation`] check.
    pub async fn fetch_crls_for_cert_with_freshness(
        &self,
        cert: &Certificate,
        freshness: &CrlFreshness,
    ) -> Result<Vec<Vec<u8>>, LtvError> {
        let urls = Self::extract_crl_urls(cert);
        let mut stale_fallback: Option<Vec<u8>> = None;

        for url in &urls {
            match self.fetch_crl_with_freshness(url, freshness).await {
                Ok(crl) => {
                    // Evaluate currentness at the moment this CRL is checked, not
                    // at a timestamp captured before the (possibly slow) fetches —
                    // otherwise an endpoint that crosses nextUpdate while earlier
                    // fetches run could still be returned and then rejected
                    // downstream, shadowing a later fresh distribution point.
                    if crl_is_current(&crl, chrono::Utc::now(), freshness) {
                        // Current CRL at this distribution point — authoritative.
                        return Ok(vec![crl]);
                    }
                    log::warn!("CRL from {url} is stale; trying other distribution points");
                    // Keep the first stale CRL as a fail-closed fallback.
                    stale_fallback.get_or_insert(crl);
                }
                Err(e) => {
                    log::warn!("Failed to fetch CRL from {url}: {e}");
                    // Try next URL
                }
            }
        }

        Ok(stale_fallback.into_iter().collect())
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
                if let Ok((inner_tag, inner_body, _)) = parse_tlv_with_rest(dp_body) {
                    if inner_tag == 0xA0 {
                        // DistributionPointName — look for fullName [0]
                        if let Ok((fn_tag, fn_body, _)) = parse_tlv_with_rest(inner_body) {
                            if fn_tag == 0xA0 {
                                // GeneralNames — look for URI [6]
                                let mut gn_pos = fn_body;
                                while !gn_pos.is_empty() {
                                    if let Ok((gn_tag, gn_body, gn_rest)) =
                                        parse_tlv_with_rest(gn_pos)
                                    {
                                        if gn_tag == 0x86 {
                                            // uniformResourceIdentifier [6] IMPLICIT IA5String
                                            if let Ok(uri) = std::str::from_utf8(gn_body) {
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

/// OID for delta CRL indicator (2.5.29.27).
const DELTA_CRL_INDICATOR_OID: &[u8] = &[0x55, 0x1D, 0x1B];

/// OID for Issuing Distribution Point (2.5.29.28).
const ISSUING_DIST_POINT_OID: &[u8] = &[0x55, 0x1D, 0x1C];

/// Helper: report whether an Extensions SEQUENCE body contains an extension
/// with the given OID.
///
/// Returns `Ok(true)` when the OID is present, `Ok(false)` when it is absent
/// from a well-formed list, and `Err` when an extension is malformed. Two
/// fail-closed properties matter for delta/partitioned-CRL detection:
/// - a parse error is **not** conflated with "absent" (a malformed extension
///   ahead of the marker must not abort the scan and let the CRL through), and
/// - presence is decided by the OID match alone; a matched marker whose
///   `extnValue` is missing/malformed still counts as present (reject), rather
///   than being treated as absent.
fn extensions_contain_oid(extensions_body: &[u8], target_oid: &[u8]) -> Result<bool, String> {
    // Extensions SEQUENCE body: iterate over Extension SEQUENCEs.
    let mut pos = extensions_body;
    while !pos.is_empty() {
        let (ext_tag, ext_value, rest) = parse_tlv_with_rest(pos)?;
        if ext_tag != 0x30 {
            return Err(format!(
                "expected Extension SEQUENCE (0x30), got 0x{ext_tag:02x}"
            ));
        }
        // Extension ::= SEQUENCE { extnID OID, ... extnValue OCTET STRING }
        let (oid_tag, oid_body, _ext_rest) = parse_tlv_with_rest(ext_value)?;
        if oid_tag == 0x06 && oid_body == target_oid {
            return Ok(true);
        }
        pos = rest;
    }
    Ok(false)
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
    let mut tbs_pos = tbs_value;

    // Optional: version [0] EXPLICIT INTEGER (v2 = 1)
    if !tbs_pos.is_empty() && tbs_pos[0] == 0x02 {
        // Check if first field is an INTEGER — could be version if small,
        // or could be the AlgorithmIdentifier. Actually version is optional
        // and v1 CRLs might omit it. The next field after optional version
        // is a SEQUENCE (AlgorithmIdentifier). Let's peek:
        // If we see INTEGER, skip it as version.
        let (_, _, r) =
            parse_tlv_with_rest(tbs_pos).map_err(|e| LtvError::Crl(format!("CRL version: {e}")))?;
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
    let (issuer_tag, _issuer_body, rest_after_issuer) =
        parse_tlv_with_rest(tbs_pos).map_err(|e| LtvError::Crl(format!("CRL issuer: {e}")))?;
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
    let (time_tag, time_body, rest_after_this) =
        parse_tlv_with_rest(tbs_pos).map_err(|e| LtvError::Crl(format!("CRL thisUpdate: {e}")))?;
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
    // Remaining: optional [0] crlExtensions — parse for delta CRL detection and
    // IssuingDistributionPoint (M-1).
    if !tbs_pos.is_empty() && tbs_pos[0] == 0xA0 {
        // crlExtensions [0] EXPLICIT Extensions. The [0] body is the inner
        // `Extensions ::= SEQUENCE OF Extension` TLV; unwrap it so the OID scan
        // iterates over the individual Extension entries rather than seeing the
        // wrapping SEQUENCE as a single (OID-less) extension.
        let (wrap_tag, wrap_body, _) = parse_tlv_with_rest(tbs_pos)
            .map_err(|e| LtvError::Crl(format!("crlExtensions: {e}")))?;
        // tbs_pos[0] == 0xA0 was checked above, so wrap_tag is 0xA0.
        debug_assert_eq!(wrap_tag, 0xA0);
        let (seq_tag, extensions_body, _) = parse_tlv_with_rest(wrap_body)
            .map_err(|e| LtvError::Crl(format!("crlExtensions SEQUENCE: {e}")))?;
        // The [0] body must be an Extensions SEQUENCE. Anything else is
        // malformed and must be rejected (fail closed), not silently skipped —
        // otherwise a bogus wrapper would bypass delta/partitioned detection.
        if seq_tag != 0x30 {
            return Err(LtvError::Crl(format!(
                "crlExtensions: expected Extensions SEQUENCE (0x30), got 0x{seq_tag:02x}"
            )));
        }

        // A malformed crlExtensions list is a parse error (fail closed), not a
        // silent "no such extension" result.
        // Check for delta CRL indicator (2.5.29.27) — reject if present. Delta
        // CRLs only contain changes since a base CRL; using one as a complete
        // revocation source would miss entries from the base CRL.
        let has_delta = extensions_contain_oid(extensions_body, DELTA_CRL_INDICATOR_OID)
            .map_err(|e| LtvError::Crl(format!("crlExtensions scan: {e}")))?;
        if has_delta {
            return Err(LtvError::Crl(
                "delta CRL (2.5.29.27) not supported; only full CRLs are accepted".into(),
            ));
        }
        // Check for IssuingDistributionPoint (2.5.29.28). A partitioned CRL
        // cannot serve as a complete revocation source for all certs under the
        // issuer, so we reject it.
        let has_idp = extensions_contain_oid(extensions_body, ISSUING_DIST_POINT_OID)
            .map_err(|e| LtvError::Crl(format!("crlExtensions scan: {e}")))?;
        if has_idp {
            return Err(LtvError::Crl(
                "partitioned CRL (IssuingDistributionPoint) not supported; only full CRLs are accepted".into(),
            ));
        }
    }

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
        let (entry_tag, entry_body, rest) =
            parse_tlv_with_rest(pos).map_err(|e| LtvError::Crl(format!("revoked entry: {e}")))?;
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
    let mut pos = ext_body;
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
pub fn verify_crl_signature(parsed_crl: &ParsedCrl, issuer: &Certificate) -> Result<(), LtvError> {
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

// ── Freshness policy ───────────────────────────────────────────────

/// Freshness policy for CRLs (RFC 5280 §6.3.3).
///
/// A CRL carries a validity window: it asserts revocation status as of
/// `thisUpdate` and the issuer promises a fresher list by `nextUpdate`. RFC 5280
/// §6.3.3 forbids relying on a CRL whose `nextUpdate` is in the past — without
/// this check a legitimately-signed but superseded CRL can be replayed forever
/// (served by an on-path attacker or a stale CDN/cache), hiding a serial that a
/// later CRL revokes.
///
/// All comparisons are made against the *validation time* (`now`), which for
/// long-term validation is the historical instant being validated, not the wall
/// clock. A CRL whose window lies at or after that instant (later-collected
/// archival evidence) is accepted; only staleness relative to `now` is a
/// failure. This mirrors [`OcspFreshness`](crate::ltv::ocsp::OcspFreshness).
#[derive(Debug, Clone)]
pub struct CrlFreshness {
    /// Clock skew tolerance, to accommodate small differences between the
    /// issuer's and the validator's clocks. Default: 5 minutes.
    ///
    /// It widens the **staleness** bound: the authoritative check
    /// ([`validate_crl_freshness`]) tolerates `now` being up to `clock_skew`
    /// past `nextUpdate` (or, lacking `nextUpdate`, past the max-age bound). It
    /// is deliberately *not* applied as a lower bound there — a CRL whose window
    /// lies at or after the validation instant (later-collected archival
    /// evidence) is accepted outright, not merely within skew. The fetch/cache
    /// currentness check ([`crl_is_current`]) additionally uses it as a
    /// not-yet-valid tolerance, since for caching a CRL whose window is still in
    /// the future is not yet the issuer's live list.
    pub clock_skew: chrono::Duration,

    /// Maximum age (measured from `thisUpdate`) tolerated for a CRL that omits
    /// the optional `nextUpdate` field. RFC 5280 makes `nextUpdate` optional;
    /// rather than treat such a CRL as eternally fresh, it is rejected once it is
    /// older than this bound. Default: 24 hours.
    pub max_age_without_next_update: chrono::Duration,
}

impl Default for CrlFreshness {
    fn default() -> Self {
        Self {
            clock_skew: chrono::Duration::minutes(5),
            max_age_without_next_update: chrono::Duration::hours(24),
        }
    }
}

/// Validate that a CRL is fresh enough to be relied upon at `now`.
///
/// Enforces RFC 5280 §6.3.3: a CRL must not be **stale** as of the validation
/// time — the validation instant must not be past `nextUpdate` (widened by the
/// allowed clock skew). When `nextUpdate` is absent the CRL is instead bounded by
/// [`CrlFreshness::max_age_without_next_update`] measured from `thisUpdate`, so a
/// `nextUpdate`-less CRL is never treated as eternally fresh.
///
/// A CRL whose window lies at or after the validation instant is explicitly
/// **accepted**: in archival / long-term validation, `validation_time` is the
/// historical instant being validated (e.g. signing or timestamp `genTime`) and
/// the revocation evidence is normally collected shortly afterwards, so its
/// `thisUpdate` legitimately falls after `validation_time`.
///
/// Fails closed: an out-of-range (stale/expired) CRL returns an `Err`, which the
/// orchestrator classifies as a definitive `Invalid` (a received-but-unusable
/// CRL), never the fail-open `Unknown`.
fn validate_crl_freshness(
    parsed: &ParsedCrl,
    now: chrono::DateTime<chrono::Utc>,
    freshness: &CrlFreshness,
) -> Result<(), LtvError> {
    let skew = freshness.clock_skew;

    match parsed.next_update {
        Some(next_update) => {
            // Sanity: a window that ends before it starts is malformed.
            if next_update < parsed.this_update {
                return Err(LtvError::Crl(format!(
                    "CRL has nextUpdate ({next_update}) before thisUpdate ({})",
                    parsed.this_update
                )));
            }
            // Anti-replay: reject once the validation instant is past nextUpdate.
            // (A CRL whose window lies at/after the validation instant —
            // later-collected archival evidence — is not stale and is kept.)
            if now > next_update + skew {
                return Err(LtvError::Crl(format!(
                    "CRL is stale: nextUpdate ({next_update}) is before validation time ({now})"
                )));
            }
        }
        None => {
            // No nextUpdate: bound the CRL's age from thisUpdate so an old CRL
            // cannot be relied on indefinitely. A CRL whose window starts at/after
            // the validation time is always within bound.
            let max_valid = parsed.this_update + freshness.max_age_without_next_update + skew;
            if now > max_valid {
                return Err(LtvError::Crl(format!(
                    "CRL without nextUpdate is too old: thisUpdate ({}), validation time ({now}), max age {}",
                    parsed.this_update, freshness.max_age_without_next_update
                )));
            }
        }
    }

    Ok(())
}

/// Whether a raw CRL is **current** (inside its own validity window) as of `now`.
///
/// Used by the fetch/cache layer ([`CrlClient::fetch_crl`],
/// [`CrlClient::fetch_crls_for_cert`]) to decide whether a cached or just-fetched
/// CRL is still the issuer's live list, or has been superseded and should be
/// re-fetched / skipped in favour of another distribution point.
///
/// Unlike [`validate_crl_freshness`], this is a presence check on a *current*
/// CRL: a CRL whose window lies entirely in the future relative to `now` is not
/// "current" either, so it is never treated as live in the cache. (The
/// archival "later-collected evidence" carve-out lives in the orchestrator's
/// `validation_time` check, not here.) An unparseable CRL is treated as not
/// current so it is re-fetched rather than trusted.
fn crl_is_current(
    der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
    freshness: &CrlFreshness,
) -> bool {
    let Ok(parsed) = parse_crl(der) else {
        return false;
    };
    // Not yet valid (window starts in the future, beyond skew) → not current.
    if now + freshness.clock_skew < parsed.this_update {
        return false;
    }
    // Past nextUpdate / max-age → not current.
    validate_crl_freshness(&parsed, now, freshness).is_ok()
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
///
/// Freshness is validated with [`CrlFreshness::default`]; use
/// [`check_revocation_with_options`] to supply a custom freshness policy.
pub fn check_revocation_with_policy(
    crl_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
) -> Result<ValidationStatus, LtvError> {
    check_revocation_with_options(
        crl_der,
        cert,
        issuer,
        validation_time,
        policy,
        &CrlFreshness::default(),
    )
}

/// Like [`check_revocation_with_policy`] but with an explicit [`CrlFreshness`]
/// policy controlling the RFC 5280 §6.3.3 time-window check.
///
/// A CRL that is stale as of `validation_time` (the validation instant is past
/// `nextUpdate`, or — lacking `nextUpdate` — the CRL is older than the configured
/// maximum age) fails closed with an `Err`, classified by the orchestrator as
/// `Invalid` (a received-but-unusable CRL), never the fail-open `Unknown`.
/// Later-collected evidence (window at/after the validation instant) is accepted.
pub fn check_revocation_with_options(
    crl_der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    validation_time: Option<chrono::DateTime<chrono::Utc>>,
    policy: &crate::crypto::verify::SignaturePolicy,
    freshness: &CrlFreshness,
) -> Result<ValidationStatus, LtvError> {
    let now = validation_time.unwrap_or_else(chrono::Utc::now);

    // 1. Parse CRL
    let parsed = parse_crl(crl_der)?;

    // 2. Verify CRL signature
    verify_crl_signature_with_policy(&parsed, issuer, policy)?;

    // 3. Check CRL freshness (RFC 5280 §6.3.3). A CRL that is stale as of `now`
    //    (validation instant past nextUpdate, or — lacking nextUpdate — older
    //    than the configured maximum age) is rejected — fail closed — so a
    //    superseded CRL cannot be replayed to hide a serial that a fresher CRL
    //    revokes. Later-collected archival evidence is kept.
    validate_crl_freshness(&parsed, now, freshness)?;

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
    use crate::der_utils::{
        encode_integer_u64, encode_sequence_from_parts, encode_sequence_raw, encode_tlv,
    };
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
        // Default window: thisUpdate 2026-01-01, nextUpdate 2027-01-01.
        build_test_crl_with_window(
            issuer_cert,
            issuer_key_pem,
            revoked_serials,
            "260101000000Z",
            Some("270101000000Z"),
        )
    }

    /// Like [`build_test_crl`] but with an explicit `thisUpdate` and optional
    /// `nextUpdate` (both `"YYMMDDHHMMSSZ"` UTCTime). Used to construct CRLs that
    /// are stale or `nextUpdate`-less for freshness tests.
    fn build_test_crl_with_window(
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
        revoked_serials: &[(Vec<u8>, &str)],
        this_update: &str,
        next_update: Option<&str>,
    ) -> Vec<u8> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::SignatureEncoding;
        use rsa::signature::Signer;
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
        let issuer_name_der = issuer_cert.tbs_certificate.subject.to_der().unwrap();
        tbs_body.extend_from_slice(&issuer_name_der);

        // thisUpdate UTCTime
        let this_update_utc = encode_tlv(0x17, this_update.as_bytes());
        tbs_body.extend_from_slice(&this_update_utc);

        // nextUpdate UTCTime (OPTIONAL)
        if let Some(next_update) = next_update {
            let next_update_utc = encode_tlv(0x17, next_update.as_bytes());
            tbs_body.extend_from_slice(&next_update_utc);
        }

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
        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&key_der).unwrap();
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature: rsa::pkcs1v15::Signature = signing_key.sign(&tbs_der);
        let sig_bytes = signature.to_vec();

        // Build outer CertificateList SEQUENCE
        let outer_alg_id = alg_id.clone();
        // BIT STRING: 0x00 unused bits prefix + signature bytes
        let mut bit_string_value = vec![0x00];
        bit_string_value.extend_from_slice(&sig_bytes);
        let sig_bit_string = encode_tlv(0x03, &bit_string_value);

        encode_sequence_from_parts(&[&tbs_der, &outer_alg_id, &sig_bit_string])
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
            eprintln!(
                "skipping test: intermediate_ca_key.pem not found (run gen-test-fixtures.sh)"
            );
            return;
        };

        let issuer = intermediate_ca_cert();
        let crl_der = build_test_crl(&issuer, &key_pem, &[]);
        let parsed = parse_crl(&crl_der).unwrap();

        assert!(parsed.revoked_entries.is_empty());
        assert!(parsed.next_update.is_some());
        assert_eq!(parsed.this_update.to_rfc3339(), "2026-01-01T00:00:00+00:00");
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

    /// Build a minimal, structurally-valid CRL carrying a single `crlExtension`
    /// with the given OID (and an empty `extnValue`). The signature is a dummy
    /// BIT STRING: `parse_crl` validates `crlExtensions` (delta / IDP rejection)
    /// while parsing, *before* any signature verification, so these structural
    /// tests need no real key. The `[0] EXPLICIT Extensions` wrapping mirrors a
    /// real CRL, exercising the SEQUENCE-unwrap in the OID scan.
    fn build_crl_with_extension(ext_oid: &[u8]) -> Vec<u8> {
        // Extension ::= SEQUENCE { extnID OID, extnValue OCTET STRING }
        let oid_tlv = encode_tlv(0x06, ext_oid);
        let value_tlv = encode_tlv(0x04, &[]); // empty extnValue OCTET STRING
        let extension = encode_sequence_from_parts(&[&oid_tlv, &value_tlv]);
        build_crl_with_extensions_body(&extension)
    }

    /// Like [`build_crl_with_extension`] but takes the raw `Extensions` SEQUENCE
    /// body verbatim, so tests can inject a malformed extension list.
    fn build_crl_with_extensions_body(extensions_body: &[u8]) -> Vec<u8> {
        let mut tbs_body = Vec::new();
        // version INTEGER 1 (v2)
        tbs_body.extend_from_slice(&encode_integer_u64(1));
        // signature AlgorithmIdentifier: sha256WithRSAEncryption
        let sha256_rsa_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        let alg_id = encode_sequence_from_parts(&[sha256_rsa_oid, &[0x05, 0x00]]);
        tbs_body.extend_from_slice(&alg_id);
        // issuer Name — minimal empty RDNSequence SEQUENCE
        tbs_body.extend_from_slice(&encode_sequence_raw(&[]));
        // thisUpdate / nextUpdate UTCTime
        tbs_body.extend_from_slice(&encode_tlv(0x17, b"260101000000Z"));
        tbs_body.extend_from_slice(&encode_tlv(0x17, b"270101000000Z"));
        // crlExtensions [0] EXPLICIT Extensions ::= SEQUENCE OF Extension
        let extensions_seq = encode_sequence_raw(extensions_body);
        tbs_body.extend_from_slice(&encode_tlv(0xA0, &extensions_seq));

        let tbs_der = encode_sequence_raw(&tbs_body);
        // Dummy signature BIT STRING (0 unused bits + arbitrary bytes).
        let sig_bit_string = encode_tlv(0x03, &[0x00, 0xDE, 0xAD]);
        encode_sequence_from_parts(&[&tbs_der, &alg_id, &sig_bit_string])
    }

    #[test]
    fn test_parse_crl_rejects_delta_crl() {
        // deltaCRLIndicator (2.5.29.27) → 0x55, 0x1D, 0x1B.
        let crl_der = build_crl_with_extension(&[0x55, 0x1D, 0x1B]);
        let err = parse_crl(&crl_der).expect_err("delta CRL must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("delta CRL"), "unexpected error: {msg}");
    }

    #[test]
    fn test_parse_crl_rejects_partitioned_crl() {
        // IssuingDistributionPoint (2.5.29.28) → 0x55, 0x1D, 0x1C.
        let crl_der = build_crl_with_extension(&[0x55, 0x1D, 0x1C]);
        let err = parse_crl(&crl_der).expect_err("partitioned CRL must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("partitioned CRL"), "unexpected error: {msg}");
    }

    #[test]
    fn test_parse_crl_accepts_benign_extension() {
        // cRLNumber (2.5.29.20) is a normal full-CRL extension and must parse:
        // guards against the OID scan over-rejecting after the SEQUENCE unwrap.
        let crl_der = build_crl_with_extension(&[0x55, 0x1D, 0x14]);
        let parsed = parse_crl(&crl_der).expect("benign extension must parse");
        assert!(parsed.revoked_entries.is_empty());
        assert!(parsed.next_update.is_some());
    }

    #[test]
    fn test_parse_crl_rejects_delta_with_missing_extnvalue() {
        // A deltaCRLIndicator extension whose extnValue OCTET STRING is absent
        // must still be detected as present and rejected (fail closed), not
        // treated as "extension absent" just because the value is unparseable.
        let ext = encode_sequence_from_parts(&[&encode_tlv(0x06, &[0x55, 0x1D, 0x1B])]); // OID only
        let crl_der = build_crl_with_extensions_body(&ext);
        let err = parse_crl(&crl_der).expect_err("delta marker w/o extnValue must be rejected");
        assert!(
            format!("{err}").contains("delta CRL"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_crl_rejects_non_sequence_crl_extensions() {
        // The [0] EXPLICIT body must be an Extensions SEQUENCE. A bogus wrapper
        // (here an INTEGER inside [0]) must fail closed, not be silently skipped.
        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&encode_integer_u64(1));
        let sha256_rsa_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        let alg_id = encode_sequence_from_parts(&[sha256_rsa_oid, &[0x05, 0x00]]);
        tbs_body.extend_from_slice(&alg_id);
        tbs_body.extend_from_slice(&encode_sequence_raw(&[]));
        tbs_body.extend_from_slice(&encode_tlv(0x17, b"260101000000Z"));
        tbs_body.extend_from_slice(&encode_tlv(0x17, b"270101000000Z"));
        // crlExtensions [0] wrapping an INTEGER instead of an Extensions SEQUENCE.
        tbs_body.extend_from_slice(&encode_tlv(0xA0, &encode_integer_u64(7)));
        let tbs_der = encode_sequence_raw(&tbs_body);
        let sig = encode_tlv(0x03, &[0x00, 0xDE, 0xAD]);
        let crl_der = encode_sequence_from_parts(&[&tbs_der, &alg_id, &sig]);

        let err = parse_crl(&crl_der).expect_err("non-SEQUENCE crlExtensions must be rejected");
        assert!(
            format!("{err}").contains("Extensions SEQUENCE"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_crl_rejects_malformed_extension_list() {
        // A malformed extension ahead of any delta/IDP marker must be a parse
        // error (fail closed), not a silent "not found" that accepts the CRL.
        // Here: a benign cRLNumber extension followed by a truncated TLV.
        let benign = encode_sequence_from_parts(&[
            &encode_tlv(0x06, &[0x55, 0x1D, 0x14]),
            &encode_tlv(0x04, &[]),
        ]);
        let mut extensions_body = benign;
        extensions_body.extend_from_slice(&[0x30, 0x05, 0x06, 0x03]); // SEQUENCE len 5, truncated
        let crl_der = build_crl_with_extensions_body(&extensions_body);
        let err = parse_crl(&crl_der).expect_err("malformed crlExtensions must be rejected");
        assert!(
            format!("{err}").contains("crlExtensions scan"),
            "unexpected error: {err}"
        );
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
    fn test_check_revocation_stale_crl_rejected() {
        // H-3: a legitimately-signed but superseded CRL (nextUpdate in the past
        // relative to the validation instant) must NOT be relied upon. An on-path
        // attacker replaying CRL v1 to hide a serial that CRL v2 revokes must
        // fail closed.
        let key_path = intermediate_ca_key_pem();
        let Ok(key_pem) = std::fs::read_to_string(key_path) else {
            eprintln!("skipping test: intermediate_ca_key.pem not found");
            return;
        };

        let issuer = intermediate_ca_cert();
        let cert = signer_cert();

        // CRL window is thisUpdate 2026-01-01 / nextUpdate 2027-01-01.
        let crl_der = build_test_crl(&issuer, &key_pem, &[]);
        // Validate well past nextUpdate (+ skew): the CRL is stale.
        let validation_time = chrono::DateTime::parse_from_rfc3339("2027-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let result = check_revocation(&crl_der, &cert, &issuer, Some(validation_time));
        assert!(
            result.is_err(),
            "stale CRL must fail closed (Err → Invalid), got {result:?}"
        );
    }

    /// Parse a real signed test CRL into a `ParsedCrl` for freshness unit tests,
    /// or `None` if the signing key fixture is unavailable.
    fn parse_test_crl() -> Option<ParsedCrl> {
        let key_pem = std::fs::read_to_string(intermediate_ca_key_pem()).ok()?;
        let issuer = intermediate_ca_cert();
        let crl_der = build_test_crl(&issuer, &key_pem, &[]);
        Some(parse_crl(&crl_der).unwrap())
    }

    fn instant(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn test_validate_crl_freshness_within_window() {
        let Some(parsed) = parse_test_crl() else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        // thisUpdate 2026-01-01 .. nextUpdate 2027-01-01; validate mid-window.
        let res = validate_crl_freshness(
            &parsed,
            instant("2026-06-01T00:00:00Z"),
            &CrlFreshness::default(),
        );
        assert!(res.is_ok(), "in-window CRL should be fresh: {res:?}");
    }

    #[test]
    fn test_validate_crl_freshness_stale() {
        let Some(parsed) = parse_test_crl() else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        // Past nextUpdate (2027-01-01) beyond the 5-minute skew → stale.
        let res = validate_crl_freshness(
            &parsed,
            instant("2027-01-01T00:10:00Z"),
            &CrlFreshness::default(),
        );
        assert!(res.is_err(), "CRL past nextUpdate must be stale");
    }

    #[test]
    fn test_validate_crl_freshness_skew_grace() {
        let Some(parsed) = parse_test_crl() else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        // Two minutes past nextUpdate is within the default 5-minute skew → fresh.
        let res = validate_crl_freshness(
            &parsed,
            instant("2027-01-01T00:02:00Z"),
            &CrlFreshness::default(),
        );
        assert!(res.is_ok(), "within-skew CRL should be accepted: {res:?}");
    }

    #[test]
    fn test_validate_crl_freshness_later_collected_evidence() {
        let Some(parsed) = parse_test_crl() else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        // Validation instant BEFORE the CRL window (archival/LTV: the CRL was
        // collected after the historical instant being validated). Accepted.
        let res = validate_crl_freshness(
            &parsed,
            instant("2025-06-01T00:00:00Z"),
            &CrlFreshness::default(),
        );
        assert!(res.is_ok(), "later-collected CRL should be kept: {res:?}");
    }

    #[test]
    fn test_validate_crl_freshness_no_next_update_within_max_age() {
        let Some(mut parsed) = parse_test_crl() else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        // Drop nextUpdate: bounded by max_age_without_next_update (24h) from
        // thisUpdate (2026-01-01T00:00:00Z).
        parsed.next_update = None;
        let res = validate_crl_freshness(
            &parsed,
            instant("2026-01-01T12:00:00Z"),
            &CrlFreshness::default(),
        );
        assert!(res.is_ok(), "within max-age should be fresh: {res:?}");
    }

    #[test]
    fn test_validate_crl_freshness_no_next_update_too_old() {
        let Some(mut parsed) = parse_test_crl() else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        // Drop nextUpdate and validate well beyond the 24h max age → rejected,
        // so a nextUpdate-less CRL is not treated as eternally fresh.
        parsed.next_update = None;
        let res = validate_crl_freshness(
            &parsed,
            instant("2026-01-03T00:00:00Z"),
            &CrlFreshness::default(),
        );
        assert!(
            res.is_err(),
            "beyond max-age without nextUpdate must be rejected"
        );
    }

    #[test]
    fn test_validate_crl_freshness_malformed_window() {
        let Some(mut parsed) = parse_test_crl() else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        // nextUpdate before thisUpdate is malformed → rejected.
        parsed.next_update = Some(parsed.this_update - chrono::Duration::hours(1));
        let res = validate_crl_freshness(
            &parsed,
            instant("2026-06-01T00:00:00Z"),
            &CrlFreshness::default(),
        );
        assert!(
            res.is_err(),
            "nextUpdate before thisUpdate must be rejected"
        );
    }

    // ── Fetch/cache freshness (crl_is_current) ─────────────────────

    /// Build a signed test CRL with a custom validity window, or `None` if the
    /// signing-key fixture is unavailable.
    fn build_crl_or_skip(this_update: &str, next_update: Option<&str>) -> Option<Vec<u8>> {
        let key_pem = std::fs::read_to_string(intermediate_ca_key_pem()).ok()?;
        let issuer = intermediate_ca_cert();
        Some(build_test_crl_with_window(
            &issuer,
            &key_pem,
            &[],
            this_update,
            next_update,
        ))
    }

    /// A UTCTime string (`"YYMMDDHHMMSSZ"`) `days_offset` days from *now*. Used by
    /// the wall-clock-driven fetch/cache tests so they never time-bomb when the
    /// real date moves past a hard-coded window (`fetch_crl` compares against
    /// `Utc::now()` internally, so the window must track the wall clock).
    fn utctime_from_now(days_offset: i64) -> String {
        (chrono::Utc::now() + chrono::Duration::days(days_offset))
            .format("%y%m%d%H%M%SZ")
            .to_string()
    }

    #[test]
    fn test_crl_is_current_within_window() {
        let Some(der) = build_crl_or_skip("260101000000Z", Some("270101000000Z")) else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        assert!(crl_is_current(
            &der,
            instant("2026-06-01T00:00:00Z"),
            &CrlFreshness::default()
        ));
    }

    #[test]
    fn test_crl_is_current_stale_window() {
        // Window entirely in the past relative to `now` → superseded, not current.
        let Some(der) = build_crl_or_skip("200101000000Z", Some("210101000000Z")) else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        assert!(!crl_is_current(
            &der,
            instant("2026-06-01T00:00:00Z"),
            &CrlFreshness::default()
        ));
    }

    #[test]
    fn test_crl_is_current_future_window_not_current() {
        // Window starts well in the future relative to `now`. For *cache* purposes
        // this CRL is not the issuer's live list yet, so it must not be cached as
        // current. (Archival acceptance of after-the-instant evidence is the
        // orchestrator's job, against validation_time — not the fetch layer.)
        let Some(der) = build_crl_or_skip("300101000000Z", Some("310101000000Z")) else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        assert!(!crl_is_current(
            &der,
            instant("2026-06-01T00:00:00Z"),
            &CrlFreshness::default()
        ));
    }

    #[test]
    fn test_crl_is_current_unparseable() {
        // Garbage bytes are never "current" → re-fetch rather than trust.
        assert!(!crl_is_current(
            &[0x04, 0x00],
            instant("2026-06-01T00:00:00Z"),
            &CrlFreshness::default()
        ));
    }

    #[test]
    fn test_is_disallowed_ip_classification() {
        use std::net::IpAddr;
        let blocked = [
            "127.0.0.1",
            "169.254.169.254", // cloud metadata (link-local)
            "10.0.0.1",
            "172.16.5.5",
            "192.168.1.1",
            "0.0.0.0",
            "100.64.0.1", // CGNAT
            "::1",
            "fc00::1",          // unique local
            "fe80::1",          // link-local
            "::ffff:127.0.0.1", // IPv4-mapped loopback
        ];
        for s in blocked {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_disallowed_ip(ip), "{s} should be disallowed");
        }
        let allowed = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ];
        for s in allowed {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_disallowed_ip(ip), "{s} should be allowed");
        }
    }

    #[tokio::test]
    async fn test_validate_url_rejects_non_http_scheme() {
        let err = CrlClient::validate_url("ftp://example.com/x.crl")
            .await
            .expect_err("non-http scheme must be rejected");
        assert!(format!("{err}").contains("scheme not allowed"));
    }

    #[tokio::test]
    async fn test_validate_url_blocks_each_internal_target() {
        for url in [
            "http://127.0.0.1/x.crl",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/x.crl",
            "http://192.168.1.1/x.crl",
            "http://[::1]/x.crl",
        ] {
            let err = CrlClient::validate_url(url)
                .await
                .expect_err("internal address must be refused");
            assert!(
                format!("{err}").contains("non-public"),
                "unexpected error for {url}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_validate_url_allows_public_literal() {
        // A public literal IP resolves without DNS and must pass (no fetch).
        CrlClient::validate_url("http://1.1.1.1/x.crl")
            .await
            .expect("public address must be allowed");
    }

    #[tokio::test]
    async fn test_fetch_crl_serves_fresh_cache_entry() {
        // A cached CRL that is within both the grace period and its own validity
        // window is served without touching the network. The window is built
        // relative to `Utc::now()` so the test is wall-clock-independent.
        let this_update = utctime_from_now(-1);
        let next_update = utctime_from_now(365);
        let Some(der) = build_crl_or_skip(&this_update, Some(&next_update)) else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        let client = CrlClient::new();
        let url = "http://crl.invalid.example/fresh.crl";
        client.cache.lock().unwrap().insert(
            url.to_string(),
            CrlCacheEntry {
                der: der.clone(),
                fetched_at: Instant::now(),
            },
        );

        let got = client
            .fetch_crl(url)
            .await
            .expect("fresh cached CRL should be served");
        assert_eq!(got, der, "served bytes should be the cached CRL");
    }

    #[tokio::test]
    async fn test_fetch_crl_skips_stale_cache_entry() {
        // A cached CRL that has crossed its nextUpdate must NOT be served even
        // though it is within the grace period; the client falls through to a
        // network fetch (which here fails against an unreachable host), proving it
        // did not return the stale cached object. The window is built relative to
        // `Utc::now()` (a year-old, year-expired CRL) so the test never time-bombs.
        let this_update = utctime_from_now(-730);
        let next_update = utctime_from_now(-365);
        let Some(stale) = build_crl_or_skip(&this_update, Some(&next_update)) else {
            eprintln!("skipping: intermediate_ca_key.pem not found");
            return;
        };
        let client = CrlClient::new().timeout(Duration::from_millis(200));
        let url = "http://crl.invalid.example/stale.crl";
        client.cache.lock().unwrap().insert(
            url.to_string(),
            CrlCacheEntry {
                der: stale,
                fetched_at: Instant::now(), // within grace period
            },
        );

        let res = client.fetch_crl(url).await;
        assert!(
            res.is_err(),
            "stale cache entry must not be served; expected a (failed) re-fetch"
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
