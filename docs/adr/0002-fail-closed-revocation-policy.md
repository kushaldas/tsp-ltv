# 2. Fail-closed revocation policy and revocation status priority

Date: 2026-05-30

## Status

Accepted

## Context

`check_certificate_revocation` (`ltv/revocation.rs`) is the high-level entry
point that determines whether a certificate is revoked. It runs OCSP and CRL
checks concurrently and merges their results into a single four-valued
`ValidationStatus` (`Valid`, `Revoked`, `Invalid`, `Unknown`) via
`resolve_priority` (`ltv/status.rs`).

A security audit (finding **C-2**, Critical) found this layer to be systemically
**fail-open**:

- `RevocationConfig::require_revocation_check` was dead code. It was set by the
  constructors (`default()`/`strict()` = `true`, `disabled()` = `false`) and
  asserted in tests, but **read by no logic**. The library documented a
  "revocation required" guarantee that did not exist.
- Every failure mode — no OCSP/CRL endpoint, fetch error, per-source timeout,
  per-certificate timeout, malformed response, **signature-verification
  failure** — collapsed to `Unknown`. `check_certificate_revocation` returned
  that `Unknown` to the caller unchanged, and `Unknown` is indistinguishable
  from "no revocation information configured."
- `resolve_priority` ranked `Unknown(1)` **above** `Invalid(0)`, so a definitive
  rejection (e.g. a forged CRL whose signature failed) could be masked behind
  the other source's `Unknown`.

Attack scenario: an attacker holding a revoked certificate blocks egress to the
OCSP responder and the CRL distribution point (on-path, or by DoSing the
responder), or serves a forged CRL. Both checks resolve to `Unknown` (or
`Invalid` masked by `Unknown`); the merged result is `Unknown`; nothing enforces
`require_revocation_check`; the caller proceeds. The revoked certificate is
accepted.

`check_certificate_revocation` and `ValidationStatus` have no in-tree consumers
beyond this module — the enforcement decision is made by downstream AdES crates,
which are out of scope. The returned status must therefore be **self-describing
and unambiguous**: the policy has to be applied here, not left to the caller.

## Decision

Make the merge order safe, classify definitive failures correctly, and actually
enforce the policy flag inside `check_certificate_revocation`.

1. **Re-order `resolve_priority`** to `Revoked(3) > Valid(2) > Invalid(1) >
   Unknown(0)`.
   - `Invalid` now dominates `Unknown`: a source that served malformed or forged
     data cannot be hidden behind the other source's "couldn't determine".
   - `Valid` still dominates `Invalid`: a genuine, cryptographically verified
     "good" from one source cannot be forged, so a bogus result from the other
     source must not turn a genuinely valid certificate into a hard failure
     (this would be an availability/DoS regression, and it buys no security —
     the attacker cannot manufacture a `Valid`).

2. **Classify definitive failures as `Invalid`, not `Unknown`.** In
   `run_ocsp_check`/`run_crl_check`, separate *fetch* outcomes from *validation*
   outcomes:
   - no endpoint, fetch/network error, timeout → `Unknown` (status genuinely
     undetermined);
   - a response/CRL was received but failed validation (bad signature,
     malformed, expired, nonce mismatch, untrusted responder) → `Invalid` (a
     definitive negative result and an attack indicator).

   The distinction is by *kind of failure*, not merely by stage. A non-successful
   OCSP `responseStatus` (tryLater, internalError, malformedRequest, sigRequired,
   unauthorized) is reported **by the responder** and is transient/responder-side,
   not proof of a forged or malformed response — so it maps to `Unknown`, never
   `Invalid`. This is carried by a dedicated `LtvError::OcspResponderStatus`
   variant and the `ocsp_check_error_to_status` mapping, so a temporary responder
   outage cannot escalate into a dominating `Invalid` (which would otherwise turn
   a best-effort/offline check into a hard failure). CRLs have no responder-status
   concept; all `crl::check_revocation` errors are integrity failures and stay
   `Invalid`.

3. **Enforce `require_revocation_check`** via a new `enforce_revocation_policy`,
   applied to the merged result in `check_certificate_revocation`:
   - strict (`true`, the default): `Unknown` is upgraded to `Invalid` so the
     returned status is unambiguously non-acceptable; `Invalid` is left blocking;
     `Valid` and `Revoked` pass through. Only a verified `Valid` (or a
     `Revoked`) is a non-`Unknown`/non-`Invalid` outcome.
   - relaxed (`false`, via `RevocationConfig::disabled()`): the merged status is
     returned unchanged, so `Unknown` is acceptable for offline/best-effort use.

With (1)–(3), an attacker holding a revoked certificate cannot produce a `Valid`
result: genuine sources report `Revoked` (which dominates), and everything the
attacker controls is `Unknown` (blocked) or `Invalid` (forged) — both hard-fail
under the strict default.

## Consequences

### Positive

- The documented "revocation required" guarantee now holds; the default config
  is fail-closed.
- Blocked, unreachable, or forged revocation sources can no longer be laundered
  into an acceptable result.
- Callers get a self-describing status: under the strict default, only `Valid`
  means "proceed"; `Revoked`/`Invalid` both mean "do not accept"; `Unknown`
  only occurs when the policy is relaxed.

### Negative / trade-offs

- **Behavioural change to the default.** A certificate that offers no usable
  revocation source (no OCSP AIA URL and no CRL distribution point) now
  hard-fails (`Invalid`) under `RevocationConfig::default()`, where it
  previously returned `Unknown`. Callers that need the old behaviour must opt in
  via `RevocationConfig::disabled()` (or set `require_revocation_check = false`).
  The "no endpoints" and "endpoints blocked" cases are both treated as
  hard-fail under strict policy; they are distinguished only by the human-
  readable reason string, not by the status variant.
- `Unknown` produced under a strict policy is surfaced as `Invalid` with a
  wrapped reason (`"revocation check required but status could not be
  established: ..."`), so the original cause is preserved in text but not in the
  type.

### Follow-ups

- This addresses the orchestration/policy layer only. Related audit findings
  remain open and are tracked separately: OCSP `thisUpdate`/`nextUpdate`
  freshness is not checked (stale-replay), stale CRLs are accepted with only a
  warning, and the `AlgorithmRegistry` weak-hash allowlist is dead code
  (MD5/SHA-1 still accepted).

## References

- RFC 6960 — Online Certificate Status Protocol (OCSP)
- RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
- Security audit finding C-2 (`SECURITY_AUDIT_REPORT.md`)
- ADR 0001 — Strict RSASSA-PSS parameter handling and signature/digest hash
  consistency
