# 9. Reject delta and partitioned CRLs

Date: 2026-05-31

## Status

Accepted

## Context

`parse_crl` (`ltv/crl.rs`) parses a `CertificateList` and `check_revocation`
treats it as the **complete** set of revocations for the issuer: a serial number
absent from the CRL is concluded to be not revoked.

A security audit (finding **M-1**, Medium) found that the optional
`crlExtensions [0]` trailer of the TBSCertList was parsed and discarded
("skip for now"). Two CRL variants make the completeness assumption false:

- **Delta CRLs** (delta CRL indicator, OID `2.5.29.27`) carry only the *changes*
  since a referenced base CRL. A serial revoked in the base but unchanged since
  is absent from the delta — treating a delta as a full CRL would report a
  revoked certificate as good.
- **Partitioned CRLs** (`IssuingDistributionPoint`, OID `2.5.29.28`) cover only
  a subset of the issuer's certificates (e.g. only CA certs, only user certs, or
  a named distribution point / reason subset). A serial may legitimately be
  absent simply because it belongs to a different partition.

In both cases a certificate's absence from the list does **not** prove it is
unrevoked, so neither can serve as a complete revocation source on its own.

## Decision

Parse the `crlExtensions [0]` trailer in `parse_crl` and **reject** the CRL when
it carries either marker. The `[0]` is `EXPLICIT`, so its body is the inner
`Extensions ::= SEQUENCE OF Extension` TLV; that SEQUENCE is unwrapped first so
the OID scan iterates over individual `Extension` entries rather than mistaking
the wrapping SEQUENCE for a single (OID-less) extension. A small helper,
`extensions_contain_oid`, then walks the extension list and treats a matched
marker OID as present based on the OID alone, so a malformed or missing
`extnValue` still fails closed:

```rust
let (seq_tag, extensions_body, _) = parse_tlv_with_rest(wrap_body)?; // unwrap [0] EXPLICIT
if seq_tag == 0x30 {
  if extensions_contain_oid(extensions_body, DELTA_CRL_INDICATOR_OID)? {
        return Err(LtvError::Crl("delta CRL (2.5.29.27) not supported; ...".into()));
    }
  if extensions_contain_oid(extensions_body, ISSUING_DIST_POINT_OID)? {
        return Err(LtvError::Crl("partitioned CRL (IssuingDistributionPoint) not supported; ...".into()));
    }
}
```

Rejection happens at parse time, so every consumer of `parse_crl` inherits the
guard. The decision is deliberately conservative: rather than attempt to combine
a delta with its base, or to match a partition's `onlyContainsUserCerts` /
`onlyContainsCACerts` / DP scope against the certificate under test, we treat
both as unsupported. Only a full, unpartitioned CRL is accepted as a complete
revocation source.

## Consequences

- A delta or partitioned CRL now produces a parse error. Under the orchestrator
  (`ltv/revocation.rs`) an error from a CRL that was actually received is a
  definitive negative (`Invalid`) — consistent with ADR 0002 / ADR 0005 — rather
  than a silent fail-open "absent ⇒ good".
- Issuers that publish *only* delta or partitioned CRLs are not supported via
  CRL; revocation for such issuers must come from OCSP (or a full CRL at another
  distribution point). Adding base+delta combination or partition-scope matching
  is possible future work but is intentionally out of scope here.
- The completeness assumption underpinning `check_revocation` is now sound: a
  CRL that reaches the revocation check genuinely lists all of the issuer's
  revocations.

## Related

- ADR 0002 — fail-closed revocation policy (the `Invalid` ⇒ hard-fail behaviour
  a rejected CRL relies on).
- ADR 0005 — CRL freshness (the adjacent CRL-validity decision; together they
  ensure a relied-upon CRL is both *complete* and *current*).
