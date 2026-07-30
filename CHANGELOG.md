# Changelog

## 0.4.0 [2026-07-30]

### Added

- Forwarded RustCrypto and AWS-LC document providers plus independent ring and
  AWS-LC TLS providers from Kryptering 0.5. FIPS mode selects AWS-LC
  exclusively.
- Attested HTTP client wrapper and hardened, fallible TSA/OCSP/CRL/chain client
  construction. The named raw-client escape hatch is excluded from FIPS builds.
- Active AWS-LC FIPS digest and HTTPS-client attestation on x86_64 and aarch64
  CI runners.
- `CertRole::TimestampSigner`: requires that `basicConstraints` does not assert
  `cA:TRUE` (an absent extension denotes a non-CA end-entity per RFC 5280
  §4.2.1.9 and is accepted) and a **critical** `id-kp-timeStamping` EKU
  (RFC 3161 §2.3). `verify_timestamp_token`
  now binds the TSA chain to this purpose via `verify_chain_for_purpose` when
  the `ltv` feature is enabled, completing audit finding H-4. The same TSA
  profile (critical timeStamping EKU and not-a-CA) is enforced feature-
  independently in the always-compiled CMS verification path, so `tsp`-only
  and `ltv` builds reject the same certificates.

### Security

- The delegated-OCSP-responder revocation sub-check (RFC 6960 §4.2.2.2.1) now
  inherits `require_revocation_check`: under the strict default, a delegated
  responder without `id-pkix-ocsp-nocheck` whose own revocation status cannot
  be established hard-fails (`Invalid`) instead of passing. Relaxed
  configurations keep the previous tolerance.
- directoryName name-constraint matching uses RFC 5280 §7.1 `caseIgnoreMatch`
  semantics across the interchangeable directory string types
  (PrintableString / UTF8String / IA5String) instead of DER byte-equality, so
  an excluded subtree can no longer be evaded by re-encoding or re-casing an
  RDN. A directory-string value that is not well-formed for its declared type
  (invalid UTF-8 in a UTF8String, non-ASCII in a PrintableString/IA5String)
  aborts the constraint check as a parse error (fail closed) instead of
  falling back to byte-equality, closing a malformed-name evasion of an
  excluded subtree.
- CRL signature verification requires the issuer certificate's `keyUsage`
  (when present) to assert `cRLSign` (RFC 5280 §4.2.1.3) before any signature
  math.
- Documented that `extract_tst_info` performs **no** cryptographic
  verification (use `verify_timestamp_token`) and that the low-level
  `ocsp::check_revocation*` / `crl::check_revocation*` APIs apply no
  fail-closed policy (use `ltv::check_certificate_revocation`).
- All 23 findings of the security audit (`SECURITY_AUDIT_REPORT.md`) are now
  resolved and re-verified against this tree.

### Changed

- **Breaking:** all digesting, randomness, nonce generation, and certificate,
  OCSP, CRL, and timestamp signature verification now use Kryptering.
- **Breaking:** streaming digest construction and network client constructors
  are fallible; the concrete digest enum is opaque.
- MSRV is Rust 1.88. `--all-features` is intentionally invalid because provider
  selections are mutually exclusive.
- The DSA verification tests assert per feature configuration: builds without
  `legacy-algorithms` pin the fail-closed `UnsupportedAlgorithm` behaviour, so
  every provider/feature combination passes without losing DSA coverage.

## 0.3.1 [2026-07-01]

### Added

- DSA (DSS) certificate/CRL/OCSP signature verification: `dsaWithSHA1`
  (`1.2.840.10040.4.3`, legacy) and `dsa-with-SHA256` (`2.16.840.1.101.3.4.3.2`).
  The DSA domain parameters and public value are read from the issuer's SPKI.
  `dsaWithSHA1` is treated as a weak-digest algorithm — rejected under the strict
  [`SignaturePolicy`] and accepted only under `allow_legacy()`, consistent with
  the existing SHA-1/MD5 handling.


## 0.3.0 [2026-06-27]

Chain-validation hardening: AIA SSRF guard, critical-extension rejection, leaf
purpose binding, RFC 5280 name constraints, delegated-OCSP-responder checking,
and fail-closed trust-anchor loading. See `docs/adr/0015-chain-validation-hardening.md`.

### Breaking Changes

#### `from_pem_directory` now fails closed on a malformed anchor

`TrustStore::from_pem_directory` previously did a best-effort load, silently
skipping any file it could not read or parse — which shrinks the trust-anchor
set without the operator noticing. It now returns `Err` on the first
unreadable/unparseable candidate (or directory-entry I/O error), naming the
offending file. Callers that want the old best-effort behaviour must switch to
the new `from_pem_directory_lenient`, which returns `(store, skipped)` and
reports — never silently drops — the skipped files.

#### New `TrustError::ProfileViolation` variant

RFC 5280 certificate-profile / path-validation failures — `basicConstraints` /
`keyUsage`, `pathLenConstraint`, an unrecognized critical extension, a name
constraint, or leaf purpose binding — now return `TrustError::ProfileViolation`
("certificate profile violation: …") instead of `TrustError::SignatureVerification`
("signature verification failed: …"), which was misleading. Genuine
cryptographic signature failures still return `SignatureVerification`. Code that
matched `SignatureVerification` for these profile checks — or that matches
`TrustError` exhaustively — must be updated.

### Added

#### Shared SSRF guard (`crate::net`)

The SSRF controls originally embedded in the CRL fetch path are extracted into a
new `net` module so the CRL and AIA paths share one audited implementation:

- `validate_fetch_url` — `http`/`https` scheme allowlist **and** resolved-IP
  filtering (loopback, private, link-local/metadata, unique-local, multicast,
  CGNAT, and the other non-globally-routable blocks), run before any egress.
- `hardened_http_client` — a `reqwest::Client` with a bounded redirect policy
  that refuses redirects to literal non-public addresses.
- `is_disallowed_ip` — the address classifier shared by both.

#### AIA chain-builder SSRF guard

`ChainBuilder::fetch_certificate` now validates each attacker-influenced
`caIssuers` URL through `crate::net` before egress and caps the response body at
1 MiB, matching the CRL fetch path.

#### Critical-extension rejection (RFC 5280 §4.2)

`verify_chain` now rejects any certificate (leaf, intermediate, or anchor) that
asserts a *critical* extension whose OID it cannot process. Extensions processed
only under the `ltv` feature (`subjectAltName`, `cRLDistributionPoints`,
`authorityInfoAccess`, `nameConstraints`) are recognised only in that build, so a
tsp-only build keeps such a critical extension fail-closed.

#### Leaf purpose binding

`TrustStore::verify_chain_for_purpose(chain, time, purpose: CertRole)` binds the
leaf to its expected role (EKU / keyUsage), closing a purpose-confusion
fail-open. The existing `verify_chain` signature is unchanged (it delegates with
no leaf purpose), so external callers are unaffected.

#### RFC 5280 name constraints (`ltv::name_constraints`)

A processor for `NameConstraints` (`2.5.29.30`) covering the common GeneralName
types — dNSName, rfc822Name, iPAddress (CIDR), and directoryName (RDN-prefix) —
enforcing permitted/excluded subtrees accumulated top-down from the anchor. A
constraint over an unsupported GeneralName type is rejected as unsupported —
fail closed, never silently ignored.

#### OCSP delegated-responder hardening

`validate_responder_trust` binds the responder certificate to the response's
`responderID` (byName subject / byKeyHash SHA-1). The new
`check_revocation_detailed` → `OcspCheckOutcome` surfaces a delegated responder
that lacks `id-pkix-ocsp-nocheck`; the orchestrator then checks that responder's
own revocation status (bounded by `max_ocsp_recursion`) and fails closed if it
is revoked or cannot be confirmed unrevoked.

#### Trust-anchor directory loading

- `from_pem_directory_lenient` returns `(store, skipped)` for explicit
  best-effort loading, reporting the skipped files and reasons.
- Both directory loaders accept PEM (one or more certificates) **or** a single
  DER-encoded certificate, since `.crt`/`.cer` anchors are commonly raw DER.

### Changed

- The IPv4 SSRF deny-list mirrors `Ipv4Addr::is_global` (which is still
  nightly-only) instead of a hand-maintained subset, adding the previously
  missed non-routable blocks: `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, and
  `240.0.0.0/4`.
- The SSRF guard's DNS resolution is bounded by the same timeout as the HTTP
  request in `TsaClient::timestamp`, `OcspClient::send_ocsp_request`, and
  `ChainBuilder::fetch_certificate`, so a slow/blocked resolver cannot hang past
  the configured timeout.
- `UrlGuardError` wrapping no longer double-prefixes error messages (e.g. the
  OCSP/CRL/TSA path now reads "URL rejected: …" rather than "OCSP error:
  OCSP …"), and the non-public-address wording is no longer duplicated.

### Fixed

- `GeneralSubtree.minimum`/`maximum` are now enforced (RFC 5280 §4.2.1.10
  requires `minimum` to be 0 and `maximum` absent); a constraint encoding a
  non-zero minimum or any maximum is rejected instead of being silently ignored.
- A malformed-length `iPAddress` subjectAltName entry is rejected rather than
  skipped, so iPAddress constraints cannot be bypassed with an invalid SAN.
- PEM-vs-DER anchor detection checks for the `-----BEGIN` armor at the start of
  the file (after optional whitespace) instead of a substring scan, so a DER
  certificate containing those bytes inside an ASN.1 string is not misclassified.
- Trust-anchor file read failures are reported as `TrustError::Io` (preserving
  the path and `ErrorKind`) rather than `CertificateParse`, and re-wrapped parse
  errors are no longer double-prefixed.

## 0.2.0

Initial release: RFC 3161 timestamping client (`tsp`) and long-term validation
(`ltv`) — OCSP/CRL/chain building — over the RustCrypto `cms` / `x509-cert`
stack, with fail-closed revocation, OCSP/CRL freshness, weak-algorithm
rejection, pathLenConstraint enforcement, intermediate-CA extension validation,
algorithm-identifier binding, and SSRF-hardened CRL fetching. See
`docs/adr/0001`–`0014`.
