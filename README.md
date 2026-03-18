# tsp-ltv

Shared timestamping (RFC 3161) and long-term validation infrastructure for
Advanced Electronic Signature (AdES) formats. Provides OCSP, CRL, trust
stores, and certificate chain building used by
[underskrift](https://github.com/kushaldas/underskrift) (PAdES/CAdES),
bergshamra (XAdES), and jades (JAdES).

## Features

- **RFC 3161 timestamping** — TSA client and pool with failover, TimeStampReq/Resp
  ASN.1 building and parsing, nonce-based replay protection
- **OCSP client** (RFC 6960) — request building, response parsing and validation,
  AIA extension extraction, responder signature verification
- **CRL client** (RFC 5280) — CRL fetching from distribution points, in-memory
  caching with configurable grace period, revocation status checking
- **Certificate chain building** — local pool-based chain construction from
  unordered intermediates (subject/issuer name matching with signature
  verification at each link), AIA-based intermediate discovery, configurable
  recursion depth
- **Trust stores** — load PEM files/directories, DER, PKCS#7 bundles; typed
  store sets for signature, timestamp, and SVT validation; chain verification
  with time validity checking
- **X.509 extension validation** — BasicConstraints, KeyUsage, ExtendedKeyUsage,
  role-based validation (end entity, intermediate CA, CRL signer, OCSP responder)
- **Revocation checking** — concurrent OCSP + CRL with priority-based result
  merging, configurable timeouts and policies
- **Signature verification** — RSA PKCS#1 v1.5 (SHA-1, SHA-224, SHA-256,
  SHA-384, SHA-512, MD5), RSA-PSS, ECDSA (P-256, P-384, P-521 with SHA-1
  through SHA-512), Ed25519 for certificate, OCSP, and CRL signature validation
- **Algorithm coverage** — SHA-1, SHA-224, SHA-256/384/512, SHA3-256/384/512,
  MD5 digest algorithms with OID mappings

## Design

This crate is **format-agnostic** — it does not know about PDF, XML, or JSON.
Each AdES crate builds its own format-specific embedding (DSS dictionaries for
PAdES, XAdES qualifying properties, JAdES `etsiU` headers) on top of these
shared clients. Consumer crates typically re-export tsp-ltv modules as thin
facades (e.g. `pub use tsp_ltv::trust::*;`).

```
tsp-ltv (this crate)
   ├── tsp     — RFC 3161 TSA client + ASN.1 parsing
   ├── ltv     — OCSP, CRL, chain building, revocation
   ├── trust   — trust stores, chain building from cert pools, chain validation
   ├── crypto  — digest algorithms, signature verification, OID constants
   └── der_utils — ASN.1/DER parsing utilities

Used by:
   ├── underskrift  (PAdES/CAdES — adds DSS dictionary embedding)
   ├── bergshamra   (XAdES — adds qualifying property embedding)
   └── jades        (JAdES — adds etsiU header construction)
```

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
tsp-ltv = "0.1"
```

All features are enabled by default (`tsp`, `ltv`, `blocking`). To use only
a subset:

```toml
[dependencies]
tsp-ltv = { version = "0.1", default-features = false, features = ["tsp"] }
```

For crates that only need trust store management and certificate verification
(no network operations):

```toml
[dependencies]
tsp-ltv = { version = "0.1", default-features = false }
```

This gives you access to the `trust` and `crypto` modules without pulling in
OCSP, CRL, or TSP client dependencies.

### Request a timestamp

```rust
use tsp_ltv::tsp::{TsaClient, TsaClientPool};

let client = TsaClient::new("http://timestamp.digicert.com");
let hash = vec![0u8; 32]; // SHA-256 hash of signature value
let token = client.timestamp(&hash).await?;

// Multiple TSAs with automatic failover
let pool = TsaClientPool::from_urls(&[
    "http://timestamp.digicert.com",
    "http://timestamp.globalsign.com/tsa/r6advanced1",
]);
let token = pool.timestamp(&hash).await?;
```

### Check certificate revocation

```rust
use tsp_ltv::ltv::{OcspClient, CrlClient, RevocationConfig, check_certificate_revocation};

let ocsp = OcspClient::new();
let crl = CrlClient::new();
let config = RevocationConfig::default();

let status = check_certificate_revocation(
    &cert, &issuer, &config, &crl, &ocsp, &[],
).await?;
```

### Load trust anchors

```rust
use tsp_ltv::trust::{TrustStore, TrustStoreSet};

let sig_store = TrustStore::from_pem_file("ca-certs.pem")?;
let tsa_store = TrustStore::from_pem_directory("/etc/ssl/certs")?;

let stores = TrustStoreSet::new()
    .with_sig_store(sig_store)
    .with_tsa_store(tsa_store);
```

### Build and verify a certificate chain

```rust
use tsp_ltv::trust::{TrustStore, build_chain_from_pool, trust_anchor_subjects};

// Load trust anchors
let trust_store = TrustStore::from_pem_file("ca-certs.pem")?;

// Build an ordered chain from a leaf and unordered intermediates
let anchor_subjects = trust_anchor_subjects(&trust_store);
let chain = build_chain_from_pool(&leaf_cert, &intermediates, &anchor_subjects, None)?;

// Verify signatures and time validity
trust_store.verify_chain(&chain, None)?;
```

## Feature flags

| Flag | Default | Description |
|------|---------|-------------|
| `tsp` | yes | RFC 3161 timestamping (requires network) |
| `ltv` | yes | OCSP/CRL/chain building (implies `tsp`) |
| `blocking` | yes | Synchronous API wrappers via `tokio::runtime::Runtime::block_on` |

With `default-features = false`, the `trust`, `crypto`, `error`, and
`der_utils` modules are always available.

## License

BSD-2-Clause
