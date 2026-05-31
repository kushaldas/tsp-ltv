# 12. Validate intermediate CA extensions in every build (keyUsage optional)

Date: 2026-05-31

## Status

Accepted

## Context

`TrustStore::verify_chain` walks a chain `[leaf, intermediate_0, …]` and, for
each issuer certificate, must confirm it is actually permitted to act as a CA
before trusting its signature over the certificate below it. The deeper
role-based extension check (`validate_extensions_for_role(.., IntermediateCa)`)
lived in `ltv/x509_ext.rs` and was invoked from `verify_chain` **behind
`#[cfg(feature = "ltv")]`** (`SECURITY_AUDIT_REPORT.md`, finding L-3).

Two problems followed from that:

1. **The check was compiled out of a `tsp`-only build.** `verify_chain` is
   reached by the RFC 3161 token path (`verify_timestamp_token`) even when the
   `ltv` feature is disabled. With `ltv` off, *no* CA-bit / keyUsage validation
   ran on intermediates at all — a chain could interpose a non-CA certificate as
   an issuer and only the signature math would object.

2. **The `ltv` check was stricter than RFC 5280 and over-rejected real CAs.**
   `validate_intermediate_ca` required a `keyUsage` extension to be *present* and
   to assert `keyCertSign`; a missing `keyUsage` was an error. RFC 5280 §4.2.1.3
   makes `keyUsage` **optional**: when it is absent there is no key-usage
   restriction, and `basicConstraints cA:TRUE` alone authorizes certificate
   signing. Requiring it rejects conforming CAs.

Problem 2 was caught concretely by the downstream consumer. **`bergshamra`**
(XML-DSig) consumes this crate with `default-features = false` — so only
`crypto` / `der_utils` / `error` / `trust` compile, and it had therefore *never*
run the `ltv`-gated intermediate check. When `verify_chain` was made to validate
intermediates unconditionally (problem 1's fix), `bergshamra`'s
`aleksey-xmldsig-01` interop chains began failing with *"intermediate is missing
the keyUsage extension"*: those interop intermediates carry `cA:TRUE` but no
`keyUsage` extension, which is perfectly valid per RFC 5280. The first
implementation reproduced the old `ltv` strictness and so regressed a real
consumer.

## Decision

Move the intermediate CA extension check into the always-compiled trust layer
and align it with RFC 5280.

- Add feature-independent helpers in `trust/store.rs`:
  - `key_cert_sign(cert) -> Result<Option<bool>, TrustError>` — `Ok(None)` when
    the `keyUsage` extension is absent, otherwise delegates to
    `parse_key_cert_sign_bit`.
  - `parse_key_cert_sign_bit(extn_value)` — parses the `keyUsage` BIT STRING
    strictly and returns whether bit 5 (keyCertSign) is set. Encoding errors are
    kept distinct from the semantic "keyCertSign not set" (`Ok(false)`): the
    value must be a single BIT STRING with **no trailing bytes**, a valid
    unused-bits count (`0..=7`), and **at least one content octet** (a
    content-less BIT STRING is rejected, since RFC 5280 §4.2.1.3 requires
    keyUsage to assert at least one bit). *(This strict parser replaced an
    earlier lenient `parse_tlv`-based read in response to PR #7 review.)*
  - `validate_intermediate_ca_extensions(cert, label)` — the unconditional
    check `verify_chain` now calls for every issuer in the walk.

- Remove the `#[cfg(feature = "ltv")]` gate around the intermediate-role check in
  `verify_chain`. The check now runs in **every** build configuration, including
  `tsp`-only token verification.

- Enforce RFC 5280 §4.2.1.3 semantics, not the stricter `ltv` form:
  - `basicConstraints cA:TRUE` is **required** (a non-CA issuer is rejected).
  - `keyCertSign` is required **only when a `keyUsage` extension is present**.
  - An **absent** `keyUsage` is **accepted** — there is then no key-usage
    restriction and `cA:TRUE` authorizes signing.

  ```text
  cA:FALSE / absent            -> reject ("not a CA")
  keyUsage present, keyCertSign set    -> accept
  keyUsage present, no keyCertSign     -> reject
  keyUsage absent                      -> accept (RFC 5280 §4.2.1.3)
  ```

- The richer `ltv::x509_ext::validate_extensions_for_role` is retained for the
  OCSP/CRL responder role checks it still serves; it is no longer the
  intermediate-CA gate for chain building.

## Consequences

### Positive

- Intermediate CA validation is enforced for the RFC 3161 token path and any
  other `tsp`-only consumer, not just `ltv` builds — no feature-dependent gap.
- The check matches RFC 5280: conforming CAs without a `keyUsage` extension are
  accepted, while a present-but-wrong `keyUsage` (no `keyCertSign`) and a non-CA
  issuer are still rejected.
- One feature-independent implementation; no divergence between build
  configurations.

### Negative / trade-offs

- Behavioural change for `ltv` builds and for previously-unchecked `tsp`-only /
  `default-features = false` builds: a non-CA interposed as an issuer, or a CA
  whose `keyUsage` omits `keyCertSign`, is now rejected where it might have been
  accepted before.
- The intermediate check is intentionally **less strict** than the old `ltv`
  role check (missing `keyUsage` is no longer fatal). This is the RFC-correct
  behaviour and was necessary to avoid over-rejecting real-world CAs.

## bergshamra usage

- `bergshamra` reaches this code through
  `bergshamra-keys::x509::validate_cert_chain` →
  `build_chain_from_pool` + `TrustStore::verify_chain`, with
  `default-features = false`, so this is now the *only* intermediate-CA check it
  performs.
- Its `aleksey-xmldsig-01` X.509 interop chains use intermediates with
  `cA:TRUE` and no `keyUsage`; the RFC-correct "keyUsage optional" rule keeps
  them valid. The full XML-DSig interop suite (`just test-dsig`, 447 OK / 0
  FAIL) passes against the updated crate.
- **Process note:** the regression that motivated the relaxation was not visible
  from `cargo test` alone — it surfaced only when running `bergshamra`'s shell
  interop suites (`test-data/testrun.sh` + `tests/xmlsec1-shim.py`) against the
  local crate. Run those when changing chain-validation behaviour.

## Related

- ADR 0003 — reject weak signature algorithms (the other `verify_chain` policy
  surface; also describes the `bergshamra` legacy opt-in).
- ADR 0007 — pathLenConstraint enforcement (the other CA-extension check in the
  same `verify_chain` walk, likewise feature-independent).
- `SECURITY_AUDIT_REPORT.md` — finding L-3.
- RFC 5280 §4.2.1.3 (Key Usage), §4.2.1.9 (Basic Constraints).
