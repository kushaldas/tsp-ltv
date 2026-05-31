# 7. X.509 pathLenConstraint enforcement

Date: 2026-05-31

## Status

Accepted

## Context

`TrustStore::verify_chain` (`trust/store.rs`) walks an ordered certificate chain
`[leaf, intermediate_0, .., intermediate_n, root]`, verifying each link's
signature and that each issuer is a CA (`CA:TRUE` + `keyCertSign`, via
`validate_extensions_for_role`).

A security audit (finding **M-5**, Medium) found that the `pathLenConstraint`
field of each CA's `BasicConstraints` extension was parsed but never enforced.
RFC 5280 §4.2.1.9 defines `pathLenConstraint` as the maximum number of
*non-self-issued intermediate CA certificates* that may follow a CA in a valid
chain. A CA issued with `pathLenConstraint = 0` is authorised to sign
end-entity certificates only — **not** further sub-CAs.

Without enforcement, a CA constrained to `pathLen = 0` could issue a sub-CA,
that sub-CA could issue end-entity certs, and the chain would still verify.
This defeats a deliberate delegation boundary set by a higher authority and is a
classic chain-constraint bypass.

## Decision

Enforce `pathLenConstraint` during the chain walk in `verify_chain`. For each
issuer certificate `chain[i + 1]`, read its `BasicConstraints` via
`check_basic_constraints` (which returns `(is_ca, path_len)`). When `path_len`
is `Some(max_depth)`, compute the number of subordinate CA certificates that
appear beneath this issuer in the chain — `chain[1..=i]`, i.e. `i` certificates
(the leaf at `chain[0]` is an end-entity and does not count) — and reject the
chain when that count exceeds `max_depth`. The count is the number of CA
certificates in `chain[0..=i]` — `verify_chain` is generic leaf-to-anchor, so
`chain[0]` is **not** assumed to be an end-entity; a CA leaf (e.g. validating a
chain like `[intermediate_ca, root]`) is counted:

```rust
let (_is_ca, path_len) = check_basic_constraints(issuer_cert)?;
if let Some(max_depth) = path_len {
    let mut subordinate_ca_count = 0usize;
    for below in &chain[0..=i] {
        let (below_is_ca, _) = check_basic_constraints(below)?;
        if below_is_ca { subordinate_ca_count += 1; }
    }
    if subordinate_ca_count > max_depth as usize { /* reject */ }
}
```

A parse failure of any `BasicConstraints` on the path (the issuer or a cert
below it) is itself a chain rejection (`TrustError::SignatureVerification`), not
a silent skip — a malformed constraint cannot be used to evade the check.

### Enforced in every build configuration

`pathLenConstraint` enforcement must **not** be gated behind the `ltv` feature.
`verify_chain` is also reached by RFC 3161 timestamp-token verification
(`tsp::token`), and the crate builds with `--no-default-features --features tsp`
(no `ltv`). To keep the check live on that path, the `BasicConstraints` parser
used here is `der_utils::parse_basic_constraints` — a pure byte-level parser
with no feature or `x509-cert` dependency — wrapped by an ungated
`basic_constraints()` helper in the trust module. The deeper *role* validation
(`validate_extensions_for_role`: CA:TRUE + keyCertSign) remains in the `ltv`
extension module and stays feature-gated; only the path-length count is shared
across configurations. The ltv `check_basic_constraints` now delegates to the
same `der_utils` parser, so there is a single parsing implementation.

## Consequences

- A chain in which an intermediate CA exceeds its declared `pathLenConstraint`
  is now rejected. This is a behavioural tightening: chains that previously
  verified despite violating a CA's path-length budget now fail.
- Correctly-issued chains are unaffected — a CA without `pathLenConstraint`
  (the field is optional) imposes no limit, exactly as before.
- The count is over CA certificates below the constrained issuer (per RFC 5280),
  so an end-entity leaf contributes nothing while a *CA* leaf is correctly
  counted — closing the undercount that a fixed `count = i` shortcut would have
  on a leaf-is-CA chain such as `[intermediate_ca, root]`.
- The check now also covers TSP-only consumers: a timestamp token whose
  certificate chain violates a CA's `pathLenConstraint` is rejected even when the
  crate is built without the `ltv` feature.

## Related

- ADR 0003 — reject weak signature algorithms (another chain-walk policy
  tightening in the same verification path).
