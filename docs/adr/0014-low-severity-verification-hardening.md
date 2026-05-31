# 14. Low-severity verification hardening: chain-builder docs, strict TSP response parsing, constant-time comparisons

Date: 2026-05-31

## Status

Accepted

## Context

Three lower-severity audit findings (`SECURITY_AUDIT_REPORT.md`, L-2, L-6, L-7)
share a theme — none is a forgery vector on its own, but each leaves the library
more lenient or more footgun-prone than a trust core should be:

- **L-2 — name-only chain builders are a footgun.** `ChainBuilder::build_chain`
  and `build_chain_from_certs` (`ltv/chain.rs`) assemble a chain by issuer/subject
  **name matching only**, with no signature verification, and `build_chain`
  additionally fetches issuer certificates from attacker-influenced AIA
  `caIssuers` URLs (an SSRF surface). The output is safe *only* if the caller
  subsequently runs `TrustStore::verify_chain`. Nothing in the API made that
  contract obvious, and `build_chain_from_certs` swallowed a DER re-encode error
  by pushing an empty entry.

- **L-6 — lenient / error-swallowing TSP response parsing.**
  `parse_timestamp_response` (`tsp/token.rs`) used `if let Ok(..) { } else
  { break }` over the optional `PKIStatusInfo` fields, silently degrading on a
  malformed structure, and decoded the `statusString` (`PKIFreeText ::= SEQUENCE
  OF UTF8String`) by discarding the inner tag and running `from_utf8_lossy` — so
  an OCTET STRING / IA5String, or invalid UTF-8, was accepted as if it were a
  valid UTF8String.

- **L-7 — non-constant-time comparisons.** The `messageImprint` hash and the
  nonce in `check_tst_info_matches` were compared with `!=`. These are public,
  locally-derived values, so the timing risk is low, but a constant-time compare
  is cheap defense-in-depth.

## Decision

**L-2 — make the contract unmistakable, fail closed on encode error.** Both
builders gain a prominent doc warning stating the result is *ordering-only,
unverified* candidate material that **MUST** be passed to
`TrustStore::verify_chain`, and that `build_chain` performs AIA fetches against
untrusted URLs (SSRF surface). `build_chain_from_certs` now stops extending the
chain on a re-encode failure instead of emitting an empty-DER entry. The public
builders are **not** renamed (API stability); the deeper caller-side audit of
the downstream AdES crates remains out of scope.

**L-6 — fail hard on malformed responses, parse `statusString` strictly.**
A structural parse failure of any `PKIStatusInfo` element, or a non-SEQUENCE
where the optional `TimeStampToken` is expected, is now a hard
`TspError::InvalidResponse`. The `statusString` inner element must carry the
UTF8String tag (`0x0c`) and is decoded with strict `std::str::from_utf8`; a
non-UTF8String type or invalid UTF-8 is rejected rather than lossily normalized.

**L-7 — constant-time comparison.** `check_tst_info_matches` compares the
`messageImprint` hash and the nonce via `subtle::ConstantTimeEq` (a new
`subtle` dependency), after a length pre-check for the hash.

## Consequences

### Positive

- The unverified nature of the name-only builders is documented at the call
  site; a re-encode failure can no longer inject an empty certificate.
- Malformed timestamp responses are rejected explicitly instead of being
  silently truncated; `statusString` is held to its ASN.1 type and to valid
  UTF-8, consistent with the fail-closed parsing posture (ADR 0011).
- Timing side channels on the imprint/nonce comparison are removed as
  defense-in-depth.

### Negative / trade-offs

- L-2 is a documentation + small-robustness change, not an enforced guarantee:
  the builders still return unverified material by design. Safety still depends
  on callers running `verify_chain` (recommended follow-up: a caller-side audit
  of the downstream crates).
- A previously-tolerated malformed `statusString` (wrong type or invalid UTF-8)
  now fails the whole response parse. This is intended; such a response is
  non-conforming.
- Adds the `subtle` dependency for one comparison site.

## bergshamra usage

- These changes are scoped so they do not affect `bergshamra`, which consumes
  this crate with `default-features = false`:
  - **L-6 / L-7** live in the `tsp` module (`tsp/token.rs`), which is **not
    compiled** without the `tsp` feature, so `bergshamra` never builds them.
  - **L-2** concerns `ltv/chain.rs` (the AIA/network builder), also not compiled
    by `bergshamra`. `bergshamra` builds chains with the *signature-verifying*
    `build_chain_from_pool` and then runs `TrustStore::verify_chain`, i.e. it
    already follows the contract the L-2 warning documents.
- Net effect on `bergshamra`: none functionally; the XML-DSig and XML-Enc
  interop suites remain at 447 OK / 0 FAIL and 701 OK / 0 FAIL respectively.

## Related

- ADR 0011 — fail-closed parsing of untrusted DER (the parsing posture L-6
  extends to the TSP response / `statusString`; also resolves L-1).
- ADR 0006 — CSPRNG nonce generation (the nonce L-7 now compares in constant
  time).
- `SECURITY_AUDIT_REPORT.md` — findings L-2, L-6, L-7.
- RFC 3161 / RFC 2510 (`PKIStatusInfo`, `PKIFreeText`).
