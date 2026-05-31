# 13. Bind the verifying algorithm: outer/inner signatureAlgorithm consistency and ECDSA curve binding

Date: 2026-05-31

## Status

Accepted

## Context

Two signature-verification findings concern *which* algorithm the verifier
actually uses, relative to what the (untrusted) input declares
(`SECURITY_AUDIT_REPORT.md`, findings L-5 and L-8):

- **L-5 — outer vs. inner `signatureAlgorithm` not compared.** An X.509
  certificate carries the signature algorithm twice: once in the signed
  `tbsCertificate.signature` field and once in the outer, *unsigned*
  `signatureAlgorithm` field. RFC 5280 §4.1.1.2 requires them to be identical.
  `verify_certificate_signature` read only the outer field and never asserted it
  matched the signed inner one, so an attacker could alter the unauthenticated
  outer field; the structure is malformed and a strict verifier should reject it.

- **L-8 — ECDSA curve not bound to the declared signature algorithm.** ECDSA
  dispatch tried each NIST curve in turn (`verify_ecdsa_p256 …or_else… p384
  …or_else… p521`). A P-521 key could thus satisfy an `ecdsa-with-SHA256` OID — a
  curve/hash strength mismatch — and, more subtly, an `ecdsa-with-SHA256` OID
  could fall through to a P-384 verifier that internally hashes with SHA-384,
  i.e. a hash that contradicts the declared OID. The key is still bound to the
  message (not a forgery), but the verifier was not bound to a single, declared
  (curve, hash) pairing. ADR 0003 had cited this trial-verification as a reason
  *not* to route verification through `AlgorithmRegistry`; this ADR removes the
  trial behaviour and tightens the dispatch directly.

## Decision

Bind verification to the algorithm identity the structure commits to.

**L-5 — outer must equal inner.** `verify_certificate_signature_with_policy`
rejects, before any signature math, a certificate whose
`signature_algorithm` differs from the signed `tbs_certificate.signature`
(`spki::AlgorithmIdentifierOwned` compares OID *and* parameters):

```rust
if cert.signature_algorithm != cert.tbs_certificate.signature {
    return Err(TrustError::SignatureVerification(
        "outer signatureAlgorithm does not match the signed tbsCertificate.signature".into()));
}
```

**L-8 — dispatch on the SPKI named curve, with the OID's hash.** A new
`ec_named_curve(spki_der)` reads the curve OID from the EC SubjectPublicKeyInfo
parameters (rejecting a non-`id-ecPublicKey` SPKI or an unknown curve), and
`verify_ecdsa_bound(tbs, sig, spki, hash)` accepts only conformant
`(curve, declared-hash)` pairings instead of trying every curve:

```text
(P-256, SHA-256)  (P-384, SHA-384)  (P-521, SHA-512)        -- standard pairings
(P-521, SHA-256)  (P-521, SHA-384)                          -- real self-signed cases, kept
(P-256, SHA-1)    (P-384, SHA-1)                             -- legacy (only under allow_legacy)
anything else                                               -- reject (curve/hash mismatch)
```

The hash is taken from the signature-algorithm OID
(`ecdsa-with-SHA256/384/512`, or SHA-1 under the legacy policy), and the curve
from the key — so the key, the curve, and the declared hash must all agree.

## Consequences

### Positive

- A tampered outer `signatureAlgorithm` (the unauthenticated copy) is rejected;
  the verifier only ever acts on the algorithm the signature actually commits
  to (RFC 5280 §4.1.1.2).
- ECDSA verification is bound to a single declared (curve, hash) pairing read
  from the key and the OID — no cross-curve guessing, no silent hash/curve
  strength mismatch. The dispatch is deterministic rather than first-success.
- Refines ADR 0003: the "verifier trial-verifies P-256/384/521" caveat no longer
  applies; ECDSA now resolves the curve from the SPKI.

### Negative / trade-offs

- Non-standard ECDSA pairings that the old `or_else` chain would have
  accepted by accident (e.g. a P-384 key under an `ecdsa-with-SHA256` OID,
  verified with SHA-384) are now rejected. These were already non-conformant
  with the declared OID; conformant inputs are unaffected. The intentionally
  retained P-521/SHA-256 and P-521/SHA-384 cases preserve the existing
  self-signed-certificate support.
- The outer/inner equality check assumes both fields are present and canonically
  DER-encoded (true for conforming certificates); a benign producer that emitted
  inconsistent fields would now be rejected — which is the intended RFC behaviour.

## bergshamra usage

- Both checks sit under `verify_certificate_signature(_with_policy)` /
  `verify_signature_by_oid`, which `bergshamra` reaches via `verify_chain` and
  the self-signed-cert path in `validate_cert_chain`. Its RSA and ECDSA
  (P-256/384/521) XML-DSig interop certificates use standard, self-consistent
  algorithm identifiers, so they are unaffected — the full interop suite passes
  (447 OK / 0 FAIL).
- The ECDSA curve binding interacts with the legacy policy (ADR 0003): the two
  `(P-256/P-384, SHA-1)` legacy pairings are only reachable when the caller
  (e.g. `bergshamra` with its `legacy-algorithms` feature) selects
  `SignaturePolicy::allow_legacy()`.

## Related

- ADR 0001 — strict RSASSA-PSS handling and signature/digest hash consistency
  (the CMS-side "the declared hash must match what is verified" decision; this
  ADR is the certificate-side and ECDSA-curve analogue).
- ADR 0003 — reject weak signature algorithms (whose trial-verification
  rationale this ADR refines; supplies the legacy policy the SHA-1 ECDSA pairings
  depend on).
- `SECURITY_AUDIT_REPORT.md` — findings L-5, L-8.
- RFC 5280 §4.1.1.2 (signatureAlgorithm vs tbsCertificate.signature);
  RFC 5480 / RFC 5758 (ECDSA curves and hashes).
