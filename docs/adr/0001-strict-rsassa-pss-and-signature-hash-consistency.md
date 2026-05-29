# 1. Strict RSASSA-PSS parameter handling and signature/digest hash consistency

Date: 2026-05-30

## Status

Accepted

## Context

Signature verification in this crate spans four code paths that all need to
turn a signature `AlgorithmIdentifier` plus a public key into an accept/reject
decision:

- CMS `SignerInfo` verification of RFC 3161 timestamp tokens (`tsp/token.rs`);
- X.509 certificate-chain verification (`crypto/verify.rs`, used by the trust
  store and chain builder);
- CRL signature verification (`ltv/crl.rs`);
- OCSP responder signature verification (`ltv/ocsp.rs`).

A PR review of the timestamp-token verifier surfaced two problems that, on
inspection, applied to the shared signature layer as a whole:

1. **RSASSA-PSS parameters were ignored.** Verification forwarded only the
   algorithm OID and used hard-coded default PSS settings (salt length = digest
   size, MGF1 keyed to the message hash, trailer field `0xBC`). For PSS these
   values are part of the algorithm definition (RFC 4055) and live in the
   `AlgorithmIdentifier` parameters, not in the OID. The consequences were:
   - valid tokens/certs that used a non-default salt length or a different MGF1
     hash were rejected as generic signature failures (false negatives,
     non-compliance);
   - the verifier derived the PSS hash from `SignerInfo.digestAlgorithm` rather
     than from the PSS `hashAlgorithm` parameter, conflating two distinct
     fields.

2. **The signature hash was not cross-checked against the digest algorithm.**
   When `signatureAlgorithm` was a combined OID such as
   `sha256WithRSAEncryption`, it was passed through unchanged. A CMS token could
   therefore declare `digestAlgorithm = SHA-512` (used to compute the
   message-digest attribute) while `signatureAlgorithm` encoded SHA-256, and
   both checks would pass independently. This is a malformed, internally
   inconsistent structure that a strict verifier should reject. It is not a
   forgery vector — an attacker still needs a valid signature from the signer's
   key — but accepting it is a robustness/compliance defect and there was no
   test pinning the behaviour.

The PSS handling and the OID/parameter plumbing were duplicated, or absent, in
several of the four paths, so a fix applied only to the token path would leave
certificate/CRL/OCSP verification inconsistent.

## Decision

Introduce a single parameter-aware verification entry point and route every
path through it.

- Add `verify_signature_by_algid(tbs, sig, spki, &AlgorithmIdentifier)` in
  `crypto/verify.rs`. It dispatches RSASSA-PSS to a strict helper and delegates
  every other algorithm to the existing OID-based `verify_signature_by_oid`,
  whose hash is implied by the OID.

- Add `verify_rsa_pss_signature_strict(...)`, which decodes
  `RSASSA-PSS-params` (via `rsa::pkcs1::RsaPssParams`) and enforces:
  - parameters MUST be present — a bare PSS OID is rejected;
  - `hashAlgorithm` is a supported digest;
  - `maskGenAlgorithm` is MGF1 keyed to that same hash (the only form RFC 4055
    recommends and the underlying `rsa` crate can verify) — a divergent MGF1
    hash is rejected rather than silently mis-verified;
  - the declared `saltLength` is used (PSS verification is salt-length
    sensitive). `trailerField` can only decode to its single defined value, so
    `RsaPssParams` decoding already rejects anything else.

  Add `verify_rsa_pss_signature_with_salt::<D>(..., salt_len)`; the existing
  `verify_rsa_pss_signature::<D>` becomes a thin wrapper using the default salt.

- For CMS tokens, after the strict PSS check, additionally require that the PSS
  `hashAlgorithm` equals `SignerInfo.digestAlgorithm`. For combined-OID
  signatures, recover the hash the OID encodes (`combined_oid_digest`) and
  reject the token if it disagrees with `digestAlgorithm`. This binding is
  CMS-specific and stays in `tsp/token.rs`, because certificates, CRLs, and
  OCSP responses carry no separate `digestAlgorithm` field.

- Retain the full signature `AlgorithmIdentifier` (OID **and** parameters) where
  it was previously discarded: `verify_certificate_signature` now passes
  `cert.signature_algorithm`, and `ParsedCrl` / `ParsedBasicOcspResponse` now
  store `signature_algorithm: spki::AlgorithmIdentifierOwned` instead of a bare
  OID.

## Consequences

### Positive

- One place defines how PSS parameters are validated; all four paths behave
  identically and compliantly.
- Tokens/certs/CRLs/OCSP responses signed with non-default PSS salt lengths now
  verify correctly instead of being rejected.
- Internally inconsistent algorithm declarations (PSS hash vs `digestAlgorithm`,
  or combined-OID hash vs `digestAlgorithm`) are rejected explicitly with a
  clear error rather than silently accepted.
- The parsed CRL/OCSP structures now expose the complete signature algorithm,
  which is generally more useful than the OID alone.

### Negative / trade-offs

- `ParsedCrl.signature_algorithm_oid` and
  `ParsedBasicOcspResponse.signature_algorithm_oid` were replaced by
  `signature_algorithm`. This is a breaking change to those public fields;
  callers read the OID via `.signature_algorithm.oid`.
- MGF1 with a hash different from the message hash is now rejected as
  unsupported. This is intentional (the `rsa` crate cannot verify that form),
  but it means such signatures fail rather than being best-effort verified.
- `verify_signature_by_oid`'s internal PSS branch still trial-hashes with the
  default salt. It is now only a fallback for callers that lack parameters; all
  in-tree flows go through `verify_signature_by_algid`. Left in place to avoid
  widening the change; a future ADR may remove it.

### Follow-ups

- Consider deprecating/removing the trial-hash PSS fallback in
  `verify_signature_by_oid` once no caller relies on it.

## References

- RFC 4055 — Additional Algorithms and Identifiers for RSA Cryptography (PSS)
- RFC 3161 — Time-Stamp Protocol (TSP)
- RFC 5652 — Cryptographic Message Syntax (CMS)
