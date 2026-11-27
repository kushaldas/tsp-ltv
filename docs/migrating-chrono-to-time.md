# Migrating from `chrono` to `time`

tsp-ltv no longer depends on `chrono` (RUSTSEC-2026-0543: `chrono` is
unmaintained). Instants are now `time::UtcDateTime` and durations
`time::Duration`. The list of changed public items is in `CHANGELOG.md`; the
reasoning is in `docs/adr/0016-replace-chrono-with-time.md`. This page is for
code that reads or builds those values.

Any crate that re-exports these types (for example `ValidationStatus`) changes
with them. Parsing and formatting need your own `time` dependency to enable the
`parsing` / `formatting` features.

## Conversions

| `chrono` | `time` |
|---|---|
| `chrono::DateTime<chrono::Utc>` | `time::UtcDateTime` |
| `chrono::Utc::now()` | `time::UtcDateTime::now()` |
| `chrono::Duration::minutes(5)` (and `hours`, `days`, `seconds`) | `time::Duration::minutes(5)` (same names) |
| `d.num_seconds()` | `d.whole_seconds()` |
| `a.signed_duration_since(b)` | `a - b` (a `time::Duration`) |
| `DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc)` | `UtcDateTime::parse(s, &Rfc3339)?` |
| `dt.to_rfc3339()` (`...+00:00`) | `dt.format(&Rfc3339)?` (`...Z`) |
| `dt.timestamp()` / `DateTime::from_timestamp(secs, nanos)` | `dt.unix_timestamp()` / `UtcDateTime::from_unix_timestamp(secs)` (nanoseconds: `from_unix_timestamp_nanos`) |

`Rfc3339` is `time::format_description::well_known::Rfc3339`.

To convert an existing `chrono` value at a boundary:

```rust
// chrono -> time
let t = time::UtcDateTime::from_unix_timestamp_nanos(dt.timestamp_nanos_opt()? as i128)?;
// time -> chrono
let dt = chrono::DateTime::from_timestamp(t.unix_timestamp(), t.nanosecond())?;
```

## Overflow

`time` covers years -9999 to 9999, and its `+` and `-` panic when the result
leaves that range; `chrono` reached much further. A parsed `nextUpdate` or
`thisUpdate` can be as late as year 9999, so adding a duration to one with `+`
can panic. Use `checked_add`, which returns `None` on overflow, or clamp:

```rust
let limit = next_update
    .checked_add(skew)
    .unwrap_or(time::UtcDateTime::MAX);
```

tsp-ltv's own freshness checks clamp this way, so a far-future `nextUpdate`
counts as fresh, as it did under `chrono`.

## Message text

Instants in `ValidationStatus`'s display and in the CRL and OCSP freshness and
responder errors are printed as RFC 3339. For example:

| | Before | After |
|---|---|---|
| `ValidationStatus` display | `VALID (via OCSP, checked at 2026-06-01 12:03:07 UTC)` | `VALID (via OCSP, checked at 2026-06-01T12:03:07Z)` |
| duration in a message | `max age PT86400S` | `max age 1d` |

The raw types print differently from `chrono`'s: an instant displays as
`2026-06-01 12:03:07.0 +00` and a duration as `5m` (previously `PT300S`). Code
that matches on these strings needs updating.
