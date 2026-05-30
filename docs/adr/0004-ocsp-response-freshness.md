# 4. OCSP response freshness (RFC 6960 §4.2.2.1)

Date: 2026-05-30

## Status

Accepted

## Context

`ocsp::check_revocation` (`ltv/ocsp.rs`) decides whether a certificate is
revoked from a single OCSP response. An OCSP `SingleResponse` carries a validity
window: the status is asserted as of `thisUpdate`, and the responder promises
fresher information will be available by `nextUpdate` (optional). The
`BasicOCSPResponse` also carries `producedAt`.

A security audit (finding **H-2**, High) found that none of these time fields
were ever compared against the validation time:

- `this_update`, `next_update`, and `produced_at` were parsed into
  `SingleResponse`/`ParsedBasicOcspResponse` but used only by test builders.
- `check_revocation` used `now` solely to compare against a `revocationTime`
  (the time-aware historical-revocation check). The good path never inspected
  the response's own validity window.

RFC 6960 §4.2.2.1 requires a client to reject a response whose current time is
outside `[thisUpdate, nextUpdate]`. Without this, a legitimately-issued "good"
response can be replayed forever:

> A "good" response issued in January is replayed after the certificate is
> compromised and revoked in March. `check_revocation` returns `Valid` because
> it never inspects the time fields. Combined with the weak nonce (M-3), there
> is effectively no freshness guarantee on the good path.

## Decision

Validate response freshness in `check_revocation` against the validation time
(`now`), and **fail closed** when the response is **stale** as of that instant.

A new `OcspFreshness` policy (`ltv/ocsp.rs`) parameterises the check:

- `clock_skew` (default **5 minutes**) — tolerance applied to the staleness
  comparison, for responder/validator clock differences.
- `max_age_without_next_update` (default **24 hours**) — the bound applied to a
  response that omits `nextUpdate`, measured from `thisUpdate`. RFC 6960 permits
  an absent `nextUpdate` ("fresher information is always available"); rather than
  treat such a response as eternally fresh, it is rejected once older than this
  bound.

`validate_response_freshness` rejects a response when, relative to `now` and the
skew:

- `nextUpdate` is present and `now` is past it (stale), or `nextUpdate` precedes
  `thisUpdate` (malformed window), or
- `nextUpdate` is absent and `now` is past `thisUpdate + max_age_without_next_update`.

The check runs **after** the matching `SingleResponse` is located, so it applies
to the specific cert's status, using that response's `thisUpdate`/`nextUpdate`.

### Later-collected evidence is accepted (not future-dating rejection)

The check deliberately does **not** reject a response merely because its
`thisUpdate` or `producedAt` is *after* the validation instant. In archival /
long-term validation, `validation_time` is the historical instant being
validated (e.g. signing or timestamp `genTime`), and the revocation evidence is
normally collected *shortly afterwards* — so a valid response legitimately has
`thisUpdate`/`producedAt` after `validation_time`. Rejecting that would break
standard archival flows (a signature validated "as of signing time" would reject
the OCSP response fetched moments after signing).

`producedAt` is the time the responder *signed* the response, not a status
assertion time, so it is not used to gate freshness at all. The only freshness
failure is **staleness**: the validation instant being past the response's
`nextUpdate` (or, lacking `nextUpdate`, past the max-age bound). Forged "fresh"
responses are not a concern here — the response signature is verified against a
trusted responder/issuer before this check, so an attacker cannot fabricate a
later-dated good response; only *replay* of a genuine old response is in scope,
and that is exactly what the staleness bound prevents.

### Validation time, not wall clock

All comparisons use the caller-supplied `validation_time` (`now`), not
`Utc::now()`. This is required for long-term validation, where the instant being
validated is historical (e.g. when a signature was made). A stored OCSP response
fetched around signing time is fresh *as of that time*; freshness is therefore a
property checked against the validation time, exactly like the existing
time-aware revocation logic.

### Fail-closed classification

An out-of-range response returns `Err(LtvError::Ocsp(..))`. The revocation
orchestrator (`ltv/revocation.rs`, `ocsp_check_error_to_status`) classifies this
— like a bad signature, malformed structure, or nonce mismatch — as a definitive
integrity failure → `ValidationStatus::Invalid`, **not** the non-determinative
`Unknown`. Under the strict revocation default (ADR 0002) `Invalid` hard-fails,
so a stale or forged-window response cannot fail open. This is consistent with
ADR 0002, which already lists an "expired" response among the `Invalid` cases.
A responder-side transient status (`tryLater`, ...) is unaffected — it is raised
earlier as `OcspResponderStatus` and still maps to `Unknown`.

### API surface

- `check_revocation_with_options(.., policy, freshness)` is the new fully
  parameterised entry point.
- `check_revocation_with_policy` delegates to it with `OcspFreshness::default()`,
  and `check_revocation` delegates to that — so every existing caller becomes
  freshness-enforcing with no edits.
- `RevocationConfig` gains an `ocsp_freshness` field (default
  `OcspFreshness::default()`), threaded through `run_ocsp_check`, mirroring how
  `signature_policy` (ADR 0003) is threaded.

## Consequences

- A "good" OCSP response is accepted only until the validation time passes its
  `nextUpdate` (± skew); indefinite stale-good replay is no longer possible.
- Later-collected evidence — a response whose `thisUpdate`/`producedAt` is after
  the validation instant, the normal archival case — remains acceptable.
- Behavioural change: a previously-accepted **stale** response (validation
  instant past `nextUpdate`, or past the max-age bound when `nextUpdate` is
  absent) now resolves to `Invalid` and hard-fails under the default revocation
  policy. Callers relying on responses with an unusually long gap between
  `nextUpdate` and their validation instant can widen `OcspFreshness`.
- The staleness bound does not depend on the nonce, so it closes the good-path
  replay gap independently of M-3 (predictable nonce).

## Related

- ADR 0002 — fail-closed revocation policy (the `Invalid` → hard-fail behaviour
  this relies on).
- ADR 0003 — reject weak signature algorithms (the `signature_policy` threading
  pattern this mirrors).
- The analogous CRL freshness gap (stale CRL accepted with only a warning) is
  tracked separately as finding H-3.
