#![cfg(all(feature = "fips", feature = "tsp"))]

use tsp_ltv::{initialize_backend, FipsStatus};

#[test]
fn digest_and_https_client_use_attested_fips_providers() {
    let info = initialize_backend().expect("selected FIPS providers must initialize");
    assert_eq!(info.fips, FipsStatus::Active);

    let digest = tsp_ltv::crypto::algorithm::DigestAlgorithm::Sha256
        .digest(b"provider attestation")
        .expect("approved digest after initialization");
    assert_eq!(digest.len(), 32);

    let client = tsp_ltv::net::hardened_http_client()
        .expect("HTTPS client must use the selected attested TLS provider");
    assert!(client.is_verified());
    assert_eq!(client.backend_info().fips, FipsStatus::Active);
}
