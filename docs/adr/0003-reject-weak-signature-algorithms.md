# 3. Reject weak signature algorithms (MD5, SHA-1, SHA-224) by default

Date: 2026-05-30

## Status

Accepted

## Context

`verify_signature_by_oid` is the single dispatch point every signature
verification in this crate flows through — directly, or via
`verify_signature_by_algid` (CRL/OCSP) and `verify_certificate_signature`
(trust store, chain builder, OCSP responder, CMS/RFC 3161 tokens). It dispatched
on the attacker-supplied signature-algorithm OID and **unconditionally** verified
signatures over broken digests:

- `md5WithRSAEncryption` → `verify_rsa_signature::<md5::Md5>`
- `sha1WithRSAEncryption` → `verify_rsa_signature::<sha1::Sha1>`
- `ecdsa-with-SHA1` → P-256/P-384 SHA-1 verification
- (and `sha224WithRSAEncryption`, below the modern 128-bit floor)

There was no flag or gate to refuse them. MD5 chosen-prefix collisions are
trivial and SHA-1 has been broken since SHAttered (2017); accepting either for a
trust decision lets an attacker who can get colliding material signed — or who
controls intermediate CA material the chain builder accepts — forge a
certificate, CRL, OCSP response, or timestamp token (`SECURITY_AUDIT_REPORT.md`,
finding H-1).

### Two constraints shaped the fix

1. **A real consumer needs the legacy path.** `bergshamra` (XML-DSig) validates
   the W3C/Apache interop test vectors (merlin, phaos, xmldsig11-interop), whose
   X.509 certificates are signed with `sha1WithRSAEncryption` and
   `md5WithRSAEncryption`. It does so through this crate's
   `verify_certificate_signature` and `TrustStore::verify_chain`. A hard removal
   of the legacy code, or a strict-only policy with no opt-in, would break that
   consumer. So the opt-in must exist **and be reachable from the public API** —
   not just promised by a low-level helper that the public flows bypass.

2. **`AlgorithmRegistry` is the wrong enforcement tool for the PKI path.** The
   PDF-signing-oriented `SignatureAlgorithm`/`DigestAlgorithm` enums cannot
   represent the weak OIDs at all, do not encode the ECDSA curve independently
   of the hash (so `ecdsa-with-SHA256` cannot map to a single curve, while the
   verifier legitimately trial-verifies P-256/384/521), and cannot express the
   strong-but-non-`standard()` algorithms the crate supports (P-521, Ed25519,
   SHA-3). Routing verification through `AlgorithmRegistry::validate()` would
   reject valid signatures. A flip of its `Default` to `standard()` was also
   considered and rejected: the enums already exclude MD5/SHA-1/SHA-224 by
   construction, so the change gave no weak-hash protection while silently
   breaking downstream `Default` users of Ed25519/SHA-3 (the README advertises
   both).

## Decision

Strict by default, with an explicit legacy opt-in that is reachable through the
stateful public configuration types.

- Add `SignaturePolicy` in `crypto/verify.rs`: `strict()` (the `Default`) refuses
  signatures over MD5/SHA-1/SHA-224; `allow_legacy()` re-enables them. The gate
  (`is_weak_signature_oid`) runs at the top of
  `verify_signature_by_oid_with_policy`, before any key material is touched, and
  returns the new `TrustError::WeakAlgorithm`. Unknown OIDs are *not* "weak" —
  they continue to fall through to `UnsupportedAlgorithm`.

- Provide `*_with_policy` variants of the three crypto primitives
  (`verify_signature_by_oid`, `verify_signature_by_algid`,
  `verify_certificate_signature`); the originals are thin strict-default
  wrappers, so every existing caller becomes fail-closed with no edits.

- Make the opt-in reachable where consumers actually configure verification,
  via a **builder field** rather than method-twins on the hot path:
  - `TrustStore::allow_legacy_signatures()` (+ `with_signature_policy`,
    `signature_policy`). `verify_chain` uses the stored policy. This is the
    path `bergshamra` uses for its interop chains; it also covers the TSA
    certificate chain validated by `verify_timestamp_token`.
  - `RevocationConfig::allow_legacy_signatures()` (+ `signature_policy` field),
    threaded into the OCSP and CRL signature checks
    (`ocsp::check_revocation_with_policy`, `crl::check_revocation_with_policy`).
  - `build_chain_from_pool_with_policy()` — the public local chain builder
    verifies each link as it walks, so it must use the same policy or
    construction fails *before* `verify_chain` runs. The plain
    `build_chain_from_pool` stays strict-default; callers building a legacy
    chain use the `_with_policy` form with the same policy as their store.
  - Inside `verify_timestamp_token`, the embedded-cert ordering heuristic
    (`order_chain`) uses the trust store's policy, so an ambiguous set of
    same-subject re-issued intermediates still prefers the
    cryptographically-correct (possibly legacy) issuer instead of falling back
    to a wrong name-only match.

- The RFC 3161 token's own CMS `SignerInfo` signature is **always** verified
  strictly: a timestamp token must not itself be freshly signed with a weak
  digest, and a SHA-1 `digestAlgorithm` is not representable in
  `DigestAlgorithm`, so a fully-SHA-1 token cannot be verified regardless. The
  realistic legacy case — a strong token signature over a SHA-1 *certificate
  chain* — is handled by the trust store's policy.

- `AlgorithmRegistry::default()` is left as `allow_all()` (see Context); its doc
  now states it is not the weak-hash enforcement point.

## Consequences

### Positive

- MD5/SHA-1/SHA-224 signatures no longer underpin any trust decision by default,
  enforced at one shared chokepoint — no per-path drift.
- The legacy opt-in is genuinely reachable from the public API (trust store and
  revocation config builders + the `*_with_policy` free functions), so the
  capability the docs describe actually exists.
- `WeakAlgorithm` is distinct from `UnsupportedAlgorithm`, so callers can tell a
  policy rejection from a genuinely unknown OID.
- No silent behaviour change to `AlgorithmRegistry`; README claims stay accurate.

### Negative / trade-offs

- **Behavioural change:** code paths that previously accepted SHA-1/MD5 now
  reject it by default. Consumers that must validate historical material
  (e.g. `bergshamra`'s interop fixtures) opt in explicitly:
  `TrustStore::new().allow_legacy_signatures()`, or
  `RevocationConfig { .. }.allow_legacy_signatures()`, or the
  `verify_certificate_signature_with_policy` free function for direct calls.
- The crypto layer carries both the plain and `*_with_policy` forms of three
  functions. Accepted as the cost of keeping existing callers fail-closed
  without churn.
- A fully-SHA-1 RFC 3161 token still cannot be verified (digest not
  representable); only its certificate chain can use the legacy policy.

### Follow-ups

- If a consumer needs SHA-1 *as the OCSP/CRL signature digest*, the
  `RevocationConfig` opt-in already covers it; no further work expected.
- Revisit whether `AlgorithmRegistry` should remain in this crate at all, or be
  superseded by `SignaturePolicy` for verification-side concerns.

## References

- RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
- RFC 3161 — Time-Stamp Protocol (TSP)
- "SHAttered" — first practical SHA-1 collision (2017)
- `SECURITY_AUDIT_REPORT.md` — finding H-1
- ADR 0002 — fail-closed revocation policy (Invalid > Unknown classification)
