#![cfg(feature = "fips")]

use tsp_ltv::crypto::algorithm::DigestAlgorithm;

#[test]
fn digest_requires_explicit_backend_initialization() {
    let error = DigestAlgorithm::Sha256
        .digest(b"must fail closed")
        .expect_err("FIPS digest before initialization must fail");
    assert!(matches!(
        error,
        kryptering::Error::BackendNotInitialized { .. }
    ));
}

#[cfg(feature = "tsp")]
#[test]
fn https_client_requires_explicit_backend_initialization() {
    let error = tsp_ltv::net::hardened_http_client()
        .expect_err("FIPS HTTPS client before initialization must fail");
    assert!(matches!(
        error,
        tsp_ltv::net::HttpClientError::Crypto(kryptering::Error::BackendNotInitialized { .. })
    ));
}
