# 5. CRL freshness (RFC 5280 §6.3.3)

Date: 2026-05-30

## Status

Accepted

## Context

`crl::check_revocation` (`ltv/crl.rs`) decides whether a certificate is revoked
from a single CRL. A `CertificateList` carries a validity window: it asserts
revocation status as of `thisUpdate`, and the issuer promises a fresher list by
`nextUpdate` (which RFC 5280 makes optional).

A security audit (finding **H-3**, High) found that this window was never
enforced:

- `this_update` and `next_update` were parsed into `ParsedCrl` but the staleness
  branch only emitted a `log::warn!` and continued to produce a `Valid` verdict.
- When `next_update` was `None` (the parser makes it optional) no freshness check
  occurred at all — the CRL was treated as eternally fresh.

RFC 5280 §6.3.3 forbids relying on a CRL whose `nextUpdate` is in the past.
Without this, a legitimately-signed but superseded CRL can be replayed forever:

> A certificate revoked in CRL v2 is presented alongside the still-signed-but-
> expired CRL v1 (served by an on-path attacker or a stale CDN/cache). The CA
> signature on v1 verifies, the staleness branch only warns, the serial is absent
> from v1 → `Valid`. The CRL cache (M-7) widens the window further.

This is the direct CRL analogue of the OCSP good-path replay gap closed in ADR
0004, and the fix mirrors that decision.

## Decision

Validate CRL freshness in `check_revocation` against the validation time
(`now`), and **fail closed** when the CRL is **stale** as of that instant.

A new `CrlFreshness` policy (`ltv/crl.rs`) parameterises the check:

- `clock_skew` (default **5 minutes**) — tolerance applied to the staleness
  comparison, for issuer/validator clock differences.
- `max_age_without_next_update` (default **24 hours**) — the bound applied to a
  CRL that omits `nextUpdate`, measured from `thisUpdate`. Rather than treat such
  a CRL as eternally fresh, it is rejected once older than this bound.

`validate_crl_freshness` rejects a CRL when, relative to `now` and the skew:

- `nextUpdate` is present and `now` is past it (stale), or `nextUpdate` precedes
  `thisUpdate` (malformed window), or
- `nextUpdate` is absent and `now` is past `thisUpdate + max_age_without_next_update`.

The check runs **after** the CRL signature is verified, so it applies only to a
CRL whose issuer authenticity is already established.

### Later-collected evidence is accepted (not future-dating rejection)

The check deliberately does **not** reject a CRL merely because its `thisUpdate`
is *after* the validation instant. In archival / long-term validation,
`validation_time` is the historical instant being validated (e.g. signing or
timestamp `genTime`), and the revocation evidence is normally collected *shortly
afterwards* — so a valid CRL legitimately has `thisUpdate` after
`validation_time`. Rejecting that would break standard archival flows (a
signature validated "as of signing time" would reject the CRL fetched moments
after signing).

The only freshness failure is **staleness**: the validation instant being past
the CRL's `nextUpdate` (or, lacking `nextUpdate`, past the max-age bound). Forged
"fresh" CRLs are not a concern here — the CRL signature is verified against the
issuer SPKI before this check, so an attacker cannot fabricate a later-dated CRL;
only *replay* of a genuine superseded CRL is in scope, and that is exactly what
the staleness bound prevents.

### Validation time, not wall clock

All comparisons use the caller-supplied `validation_time` (`now`), not
`Utc::now()`. This is required for long-term validation, where the instant being
validated is historical (e.g. when a signature was made). A stored CRL fetched
around signing time is fresh *as of that time*; freshness is therefore a property
checked against the validation time, exactly like the existing time-aware
revocation logic (a `revocationDate` after `now` does not retroactively
invalidate).

### Fail-closed classification

An out-of-range CRL returns `Err(LtvError::Crl(..))`. The revocation
orchestrator (`ltv/revocation.rs`, `run_crl_check`) already classifies any error
from a CRL it actually received — a bad signature, a malformed structure, and now
a stale/expired window — as a definitive negative result →
`ValidationStatus::Invalid`, **not** the non-determinative `Unknown`. Under the
strict revocation default (ADR 0002) `Invalid` hard-fails, so a stale or
forged-window CRL cannot fail open by masquerading as "status undetermined". A
fetch error, timeout, or absent distribution point stays `Unknown` (transient,
non-determinative) and is unaffected.

### API surface

- `check_revocation_with_options(.., policy, freshness)` is the new fully
  parameterised entry point.
- `check_revocation_with_policy` delegates to it with `CrlFreshness::default()`,
  and `check_revocation` delegates to that — so every existing caller becomes
  freshness-enforcing with no edits.
- `RevocationConfig` gains a `crl_freshness` field (default
  `CrlFreshness::default()`), threaded through `run_crl_check`, mirroring how
  `ocsp_freshness` (ADR 0004) and `signature_policy` (ADR 0003) are threaded. A
  `with_crl_freshness()` builder (and `with_ocsp_freshness()`) is added, and the
  type doc steers construction through `..Default::default()` / the builders so
  callers avoid exhaustive struct literals and keep compiling across field
  additions. (The struct is intentionally *not* `#[non_exhaustive]`, which would
  break the common `..Default::default()` struct-update idiom for downstream
  crates — a larger break than simply adding a field.)
- `CrlClient` gains a fetch-time `freshness` policy (with a `freshness()`
  builder, default `CrlFreshness::default()`). `fetch_crl` does not serve a
  cached CRL that has crossed its own `nextUpdate` (it re-fetches), and
  `fetch_crls_for_cert` returns the first distribution point that both downloads
  *and* is current — so a stale cache entry or a lagging endpoint cannot force a
  fail-closed `Invalid` while a fresh CRL is obtainable. This fetch/cache
  currentness check (`crl_is_current`) is wall-clock based and distinct from the
  orchestrator's authoritative `validation_time` check.
- **Single policy source in the orchestrator path.** To avoid the fetch/cache
  layer applying a *different* (e.g. stricter default) freshness than the
  configured one, `fetch_crl`/`fetch_crls_for_cert` have `_with_freshness`
  variants, and `run_crl_check` threads `RevocationConfig::crl_freshness` through
  the selection *and* the authoritative check. A caller who widens
  `crl_freshness` (e.g. to accept `nextUpdate`-less CRLs older than 24h) is then
  never blocked at the fetch layer by a default `CrlClient`. The bare
  `CrlClient::freshness` field only governs direct, non-orchestrated
  `fetch_crl`/`fetch_crls_for_cert` calls.

## Consequences

- A CRL is relied upon only until the validation time passes its `nextUpdate`
  (± skew); indefinite stale-CRL replay is no longer possible.
- Later-collected evidence — a CRL whose `thisUpdate` is after the validation
  instant, the normal archival case — remains acceptable.
- Behavioural change: a previously-accepted **stale** CRL (validation instant
  past `nextUpdate`, or past the max-age bound when `nextUpdate` is absent) now
  resolves to `Invalid` and hard-fails under the default revocation policy.
  Callers relying on CRLs with an unusually long gap between `nextUpdate` and
  their validation instant can widen `CrlFreshness`.
- A `nextUpdate`-less CRL is now bounded rather than eternal; an issuer that
  publishes CRLs without `nextUpdate` and expects reliance beyond 24h must widen
  `max_age_without_next_update`.

## Related

- ADR 0002 — fail-closed revocation policy (the `Invalid` → hard-fail behaviour
  this relies on).
- ADR 0003 — reject weak signature algorithms (the `signature_policy` threading
  pattern this mirrors).
- ADR 0004 — OCSP response freshness (the directly analogous OCSP decision; this
  ADR applies the same model to CRLs).
