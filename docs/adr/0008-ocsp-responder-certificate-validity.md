# 8. Delegated OCSP responder certificate validity check

Date: 2026-05-31

## Status

Accepted

## Context

When an OCSP response is signed by a delegated responder (rather than by the
issuing CA directly), `validate_responder_trust` (`ltv/ocsp.rs`) establishes
that the responder certificate is authorised — it is the issuer itself, or it is
issued by the same CA and carries the `id-kp-OCSPSigning` extended key usage.

A security audit (finding **M-6**, Medium) found that the responder
certificate's own **validity period** (`notBefore` / `notAfter`) was never
checked. An expired — or not-yet-valid — delegated responder certificate would
be accepted as long as its signature and EKU checked out. An attacker holding an
expired responder key (whose certificate the CA has let lapse precisely so it can
no longer speak for the CA) could continue to issue `good` responses that this
library would honour.

## Decision

Thread the validation time `now` into `validate_responder_trust` and reject the
responder certificate when `now` falls outside its `[notBefore, notAfter]`
window, *before* the authorisation (issuer / EKU) checks return `Ok`:

```rust
fn validate_responder_trust(
    responder_cert: &Certificate,
    issuer: &Certificate,
    policy: &SignaturePolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), LtvError> {
    // ... convert responder notBefore/notAfter to chrono ...
    if now < nb { return Err(/* "not yet valid" */); }
    if now > na { return Err(/* "expired" */); }
    // ... existing issuer / OCSPSigning EKU checks ...
}
```

`check_revocation_with_options` passes its `now` argument through. As with all
freshness logic in this crate, the comparison is against the caller-supplied
**validation time**, not the wall clock — a responder certificate that was valid
at the historical validation instant remains acceptable for long-term
validation, even if it has since expired (see ADR 0005 for the same
validation-time rationale applied to CRLs).

## Consequences

- An OCSP response signed by a delegated responder whose certificate is expired
  or not-yet-valid *as of the validation time* is now rejected.
- Long-term / archival validation is unaffected: the responder certificate is
  checked against the historical validation instant, so evidence that was valid
  when collected stays valid.
- The direct-issuer case (response signed by the CA itself) still also passes
  through the validity window check, which is harmless — the issuer must be
  within its own validity for the chain to verify anyway.

## Related

- ADR 0004 — OCSP response freshness (the adjacent OCSP-response time check;
  this ADR adds the responder *certificate* time check).
- ADR 0005 — CRL freshness (the shared validation-time-not-wall-clock model).
