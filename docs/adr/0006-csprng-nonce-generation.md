# 6. CSPRNG-based nonce generation for OCSP and TSP

Date: 2026-05-31

## Status

Accepted

## Context

Two request paths attach a nonce to bind a response to the request that
provoked it and to defeat replay:

- OCSP requests (`ltv/ocsp.rs`, `generate_nonce`) — a `NONCE_SIZE`-byte (30 B)
  nonce carried in the OCSP nonce extension.
- TSP timestamp requests (`tsp/...`) — a 64-bit nonce echoed back in `TSTInfo`.

A security audit (finding **M-3**, Medium) found that both nonces were derived
from `SystemTime::now()` mixed with a hand-rolled, non-cryptographic bit-shuffle:

```rust
let seed = now.as_nanos();
let byte = ((seed >> ((i * 7) % 64)) ^ (seed >> ((i * 3) % 64))) as u8;
nonce.push(byte.wrapping_add(i as u8));
```

The original comment rationalised this as "nonces only need uniqueness, not
unpredictability". That reasoning is wrong for a security protocol: a nonce
derived from a readable clock is **predictable**. An attacker who can estimate
the request time (network timing, log correlation) can precompute the nonce and
pre-sign or pre-fetch a response, collapsing the anti-replay guarantee the nonce
exists to provide. The derivation also had low entropy — all `NONCE_SIZE` bytes
were a deterministic function of a single nanosecond timestamp.

## Decision

Generate every nonce from the operating-system CSPRNG via
`getrandom::getrandom`, filling the full nonce buffer with cryptographically
random bytes:

```rust
let mut nonce = vec![0u8; NONCE_SIZE];
getrandom::getrandom(&mut nonce).expect("OS random number generator");
nonce
```

The TSP 64-bit nonce is generated the same way (8 random bytes). The
`getrandom` crate is added to `Cargo.toml` with the `std` feature; it is a thin,
well-audited shim over the platform RNG (`getrandom(2)` / `getentropy` /
`BCryptGenRandom`) and pulls in no heavyweight transitive dependencies.

### Why `expect` on the RNG

A failure of the OS CSPRNG is a non-recoverable environmental fault (no entropy
source). Continuing with a degraded or zero nonce would silently reintroduce the
very weakness being fixed, so the call panics rather than failing open. In
practice `getrandom` only errors on platforms without an entropy source, which
this library does not target.

## Consequences

- OCSP and TSP nonces are now unpredictable, restoring the anti-replay property.
- A new runtime dependency on the OS entropy source. Environments without one
  (extremely early boot, exotic sandboxes) will panic at nonce generation rather
  than emit a weak nonce — a deliberate fail-closed posture.
- `getrandom` is added to the dependency tree.

## Related

- ADR 0002 — fail-closed revocation policy (the same "fail closed on a security
  primitive failure rather than degrade silently" posture).
