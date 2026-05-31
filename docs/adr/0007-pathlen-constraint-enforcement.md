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

Enforce `pathLenConstraint` in `verify_chain` for every CA whose constraint
governs the path. A shared helper, `enforce_path_len(issuer, below, label)`,
reads `issuer`'s `BasicConstraints` and, when a constraint is present, counts the
non-self-issued CA certificates among `below` and rejects the chain when that
count exceeds the constraint:

```rust
fn enforce_path_len(issuer, below, label) -> Result<(), TrustError> {
    let (_is_ca, path_len) = basic_constraints(issuer)?;        // hard error on malformed
    let Some(max_depth) = path_len else { return Ok(()) };
    let mut subordinate_ca_count = 0;
    for cert in below {
    if basic_constraints(cert)?.0 && cert.subject != cert.issuer {
      subordinate_ca_count += 1;
    }
    }
  if subordinate_ca_count > max_depth { /* reject */ }
    Ok(())
}
```

The count is the number of **non-self-issued CA** certificates among the certs
subordinate to the issuer. `verify_chain` is generic leaf-to-anchor, so the
bottom certificate is **not** assumed to be an end-entity — a CA leaf (e.g.
validating a chain like `[intermediate_ca, root]`) is counted when it is not
self-issued, while an end-entity leaf contributes nothing and a self-issued
rollover CA does not consume the path-length budget.

The helper is applied at two points:

- **For each in-chain issuer** `chain[i + 1]`, against the certs below it,
  `chain[0..=i]`.
- **For the matched trust anchor.** The chain builder stops before appending the
  anchor, so an anchor that lives only in the store is absent from `chain` and
  its own `pathLenConstraint` would otherwise never be checked. After the anchor
  verifies `last`'s signature, `enforce_path_len(anchor, chain, "trust anchor")`
  runs with the *entire* chain as the subordinate set — so a root constrained to
  `pathLenConstraint = 0` rejects a chain containing a subordinate CA beneath it.
  (When the chain already includes the self-signed root, the per-issuer pass
  above has already covered it.)

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
- The count is over non-self-issued CA certificates below the constrained
  issuer (per RFC 5280), so an end-entity leaf contributes nothing, a
  non-self-issued *CA* leaf is correctly counted, and a self-issued rollover CA
  does not cause an over-rejection.
- The check now also covers TSP-only consumers: a timestamp token whose
  certificate chain violates a CA's `pathLenConstraint` is rejected even when the
  crate is built without the `ltv` feature.

## Related

- ADR 0003 — reject weak signature algorithms (another chain-walk policy
  tightening in the same verification path).
