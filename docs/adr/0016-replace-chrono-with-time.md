# 16. Replace `chrono` with `time`

Date: 2026-11-27

## Status

Accepted

## Context

`chrono` is marked unmaintained (RUSTSEC-2026-0543). There is no patched
version and no vulnerability, but `cargo audit --deny warnings` (the `audit`
workflow) fails on it, and so do the audits of crates that depend on tsp-ltv.

`chrono` is part of the public API, so removing it is a breaking change. It
appears in:

- the return types of `der_utils::parse_generalized_time`, `parse_utc_time` and
  `parse_x509_time`;
- the timestamp fields of `RevokedEntry`, `ParsedCrl`, `SingleResponse`,
  `ParsedBasicOcspResponse` and `CertStatus::Revoked`, and the `checked_at` /
  `revocation_time` fields of `ValidationStatus`;
- the `validation_time: Option<...>` parameters of the CRL, OCSP and combined
  revocation checks;
- `clock_skew` and `max_age_without_next_update` in `CrlFreshness` and
  `OcspFreshness`.

The crate only needs a UTC instant, a signed duration, a way to build one from
calendar fields (DER `UTCTime` / `GeneralizedTime`) and the current time. It
does not need time zones, local time or calendar arithmetic beyond that.

## Decision

Use the `time` crate: `time::UtcDateTime` for instants and `time::Duration` for
durations.

- `time` is already in the dependency tree. It was a dev-dependency (pinned for
  `rcgen`) and several downstream crates use it, so it adds no new crate to
  review. The dependency is `time = { version = "0.3.53", default-features =
  false, features = ["std"] }`; only the tests enable `parsing` and
  `formatting`, and no `macros` feature is needed.
- The exact `=0.3.53` dev-dependency pin, which keeps `rcgen`'s transitive
  `time` on an audited release, is kept unchanged. Because that pin applies to
  this crate's own builds, the lockfile stays on `time` 0.3.53, and the shipped
  dependency's minimum is set to the same version.
- DER time parsing builds the instant through one helper
  (`der_utils::utc_from_parts`), which rejects out-of-range months, days,
  hours, minutes and seconds, including a leap second (`:60`), as before.
  `der_utils::der_datetime_to_utc` converts a certificate validity
  `der::DateTime` directly, replacing a format-then-parse round trip in the
  OCSP responder certificate check.
- DER parsing, GeneralizedTime construction and every validity comparison are
  unchanged.

## Alternatives considered

- **`jiff`** (proposed in issue #24, with a working branch). A good fit
  technically, with `Timestamp` and `SignedDuration` as direct equivalents. It
  is a new dependency for every consumer, whereas `time` is already present in
  this tree and in several downstream crates. The two are otherwise close, so
  the deciding factor is the existing presence of `time`.
- **`std::time::SystemTime` / `Duration`.** No new dependency, but no calendar
  fields, so DER time parsing and the fixed-date tests would need hand-written
  date arithmetic.
- **Keep `chrono` and ignore the advisory.** Nothing changes for consumers, but
  the warning stays and every downstream audit has to carry the same ignore.

## Consequences

- **Breaking change** for every item listed in the context; the next release
  must be a minor-version bump (pre-1.0). The CHANGELOG lists the changed types.
- Raw `Display` and `Debug` output of the `time` types differs from `chrono`'s
  (for example `2026-06-01 0:00:00.0 +00` for an instant, `1d` for a duration).
  Messages that embed an instant (the `ValidationStatus` display and the CRL/OCSP
  stale-response and responder-validity errors) go through
  `der_utils::fmt_instant`, which prints `YYYY-MM-DDThh:mm:ssZ`, so they stay
  readable. Durations in those messages print in `time`'s form (`1d` rather than
  `PT86400S`). Nothing in this crate depends on that text.
- `time`'s default date range is years -9999 to 9999. DER `GeneralizedTime`
  carries a four-digit year and `UTCTime` maps to 1950-2049, so every parsed
  value fits. Adding a clock-skew or max-age allowance to a value near year 9999
  can leave the range, and `time`'s `+` panics there. The freshness checks
  therefore add durations through `der_utils::saturating_add`, which clamps to
  the representable range. This matches `chrono`, where such a sum was just a
  very distant instant, and means a hostile `nextUpdate` of `9999-12-31` cannot
  panic the CRL fetch path (which reads bytes before any signature check).
- `time` moves from a dev-dependency to a shipped dependency. It is declared as
  a floating minimum (`0.3.53`) rather than an exact pin: an exact pin on a
  library dependency forces every consumer onto that one release, and the
  consumer's lockfile is where an audited version belongs. The test-only
  `[dev-dependencies]` entry keeps its exact pin (`=0.3.53`), as before, because
  dev-dependencies are not passed on to consumers; it holds `rcgen`'s transitive
  `time` on the audited release for this crate's own builds.
- `chrono` and its platform dependencies (`iana-time-zone` and the `windows-*`
  crates) leave the lockfile.
- Downstream crates that convert these values must move to `time` as well, or
  convert at the boundary.
