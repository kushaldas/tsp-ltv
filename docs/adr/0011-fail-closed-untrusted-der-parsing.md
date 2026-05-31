# 11. Fail-closed parsing of untrusted DER integers and time values

Date: 2026-05-31

## Status

Accepted

## Context

The DER helpers in `der_utils.rs` and the trust-chain walk in `trust/` operate
directly on attacker-controlled bytes (certificates, CRLs, OCSP/timestamp
tokens). A security audit raised three related findings where malformed or
adversarial input was handled by panicking, truncating, or silently producing a
degenerate value instead of returning an error:

- **M-4 (time-parse panic DoS).** `parse_generalized_time` and `parse_utc_time`
  sliced their input as a `&str` (e.g. `strip_suffix`, fixed-offset indexing)
  *after* a UTF-8 check but *without* an ASCII check. A multi-byte UTF-8
  character placed at a slice boundary causes a mid-character slice **panic**, so
  an attacker-controlled time field could crash the validator (DoS).
- **M-8 (integer truncation / sign confusion).** `decode_integer_u64` returned a
  bare `u64`, silently truncating values wider than 64 bits and silently
  misreading a negative INTEGER (high bit of the first significant byte set) as a
  large positive value. Call sites — `pathLenConstraint`, `PKIStatus`, the
  `TSTInfo` nonce — could thus act on a value that was not the one encoded.
- **L-1 (silent failure / panic in `verify_chain`).** The trust-anchor lookup
  used `last.to_der().unwrap_or_default()` — a DER encoding failure produced an
  *empty* `Vec`, which could then match against the store by accident — and
  `find_issuer(last).unwrap()`, which panics if the post-condition it assumes
  ever fails to hold.

The common thread: on the untrusted-input boundary, the code should return a
typed error, never panic and never fabricate a plausible-but-wrong value.

## Decision

Make all three paths reject malformed input explicitly.

**M-4 — ASCII gate before slicing.** Both time parsers check `s.is_ascii()`
immediately after the UTF-8 decode and before any `&str` slicing, so no slice can
ever fall in the middle of a multi-byte character:

```rust
let s = std::str::from_utf8(body)?;
if !s.is_ascii() {
    return Err("UTCTime: non-ASCII characters".to_string());
}
```

**M-8 — fallible, range-checked integer decode.** `decode_integer_u64` now
returns `Result<u64, String>`: it rejects an empty body, rejects a negative
INTEGER (high bit set without a leading `0x00` pad), and rejects more than 8
significant bytes rather than truncating. Every call site (`pathLenConstraint`,
`PKIStatus`, `TSTInfo` nonce) propagates the error:

```rust
pub fn decode_integer_u64(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() { return Err("empty INTEGER body".into()); }
    // strip leading 0x00 pad; else MSB set => negative => reject
    // > 8 significant bytes => reject (would truncate)
}
```

**L-1 — error propagation instead of silent default / panic.** In
`verify_chain`, `last.to_der()` errors are propagated as
`TrustError::CertificateParse` instead of collapsing to an empty `Vec`, and the
anchor is found by an inline search over `self.anchors` that returns the matched
anchor directly — removing the `unwrap()` whose post-condition could panic:

```rust
let last_der = last.to_der().map_err(|e| TrustError::CertificateParse(...))?;
if let Some(anchor) = self.anchors.iter().find(|a| a.der == last_der) {
    verify_certificate_signature_with_policy(last, last, policy)?;
    return Ok(&anchor.cert);
}
```

## Consequences

- A non-ASCII time field is a clean parse error, not a panic: the time-parse DoS
  is closed.
- Over-wide or negative INTEGERs are rejected at decode time rather than
  silently truncated or sign-flipped, so downstream policy decisions
  (`pathLenConstraint`, `PKIStatus`, nonce matching) act only on faithfully
  decoded values. This is an API change: `decode_integer_u64` now returns a
  `Result`, and all in-tree callers were updated to propagate it.
- The trust-anchor lookup can no longer match on an empty DER blob produced by a
  silent encode failure, nor panic on a violated `unwrap` post-condition — both
  become explicit, recoverable errors.
- General posture: every one of these paths now *fails closed* on malformed
  attacker input, consistent with the rest of the library.

## Related

- ADR 0002 — fail-closed revocation policy (the library-wide fail-closed
  posture this extends to the parsing boundary).
- ADR 0007 — pathLenConstraint enforcement (a consumer of the now-fallible
  `decode_integer_u64`).
