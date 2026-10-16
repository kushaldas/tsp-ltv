# Dependency ecosystem status

**Last reviewed:** 2026-10-16 (previous: 2026-06-27)
**Tool:** `cargo outdated --depth 1` against the top-level `Cargo.toml`
**Scope:** direct deps only (transitives are `cargo audit`'s job)

This document records which direct-dep major bumps are *ecosystem-blocked* — the
new major exists, but taking it would require pulling **pre-release** crypto
crates into this security library, because the stable consumers (`cms`,
`x509-cert`, `rsa`, `ecdsa`, the P-curves, `ed25519-dalek`) still pin the old
majors. It exists so future `cargo outdated` runs don't re-litigate the same
investigation.

## Decision (2026-10-16, unchanged from 2026-06-27)

**Stay on stable for tsp-ltv's own dependencies.** `x509-cert` 0.3.0, `ecdsa`
0.17.0, `p256`/`p384`/`p521` 0.14.0, `ed25519-dalek` 3.0.0, `dsa` 0.7.0,
`base64` 0.23 and `rcgen` 0.14 have shipped stable since the last review, but
`cms` is still `0.3.0-rc.0` and `rsa` is still `0.10.0-rc.19`. `cms` anchors
the format wave and `rsa` anchors the digest and signature waves, so none of
the waves below can be taken whole yet (see "Never take partial waves").

Kryptering 0.7.0, which tsp-ltv now depends on, already moved its RustCrypto
provider to the new trait line (`der` 0.8, `digest` 0.11, `signature` 3,
`rand_core` 0.10, `rsa` pinned at `=0.10.0-rc.19`; rationale in Kryptering's
own `docs/ecosystem.md`). tsp-ltv exchanges only bytes and plain enums with
Kryptering, so both lines coexist in `Cargo.lock` without a trait-identity
clash. Every production cryptographic operation goes through Kryptering, so
the pre-release `rsa` in the tree is the one Kryptering chose and audited;
tsp-ltv's own `rsa 0.9` / `digest 0.10` line is used for CMS and X.509 parsing
and for test fixture generation.

Previous decision text follows.

**Stay on stable.** The entire RustCrypto stack is mid-migration: the trait
crates (`der` 0.8, `digest` 0.11, `signature` 3, `sha2/sha1/sha3/md-5`,
`const-oid` 0.10, `spki` 0.8, `pem-rfc7468` 1.0) have shipped stable, but every
high-level consumer that adopts them is **pre-release / rc**. We do not depend on
pre-release crypto in a security library, so the bumps below are deferred until
the consumers ship stable majors. Only in-range patches were taken (see the end).

## Status at a glance

| Crate | Current | Latest stable usable | Newest (pre-release) | Wave |
|---|---|---|---|---|
| `der` | 0.7.10 | — | 0.8.0 | formats |
| `spki` | 0.7.3 | — | 0.8.0 | formats |
| `const-oid` | 0.9.6 | — | 0.10.2 | formats |
| `pem-rfc7468` | 0.7.0 | — | 1.0.0 | formats |
| `digest` | 0.10.7 | — | 0.11.3 | digest |
| `sha2` | 0.10.9 | — | 0.11.0 | digest |
| `sha1` | 0.10.6 | — | 0.11.0 | digest |
| `sha3` | 0.10.9 | — | 0.12.0 | digest |
| `md-5` | 0.10.6 | — | 0.11.0 | digest |
| `signature` | 2.2.0 | — | 3.0.0 | signature |
| `getrandom` | 0.2.17 | — | 0.4.3 | rand_core |

The trait-crate majors above are *stable*, but they cannot be taken in
isolation: bumping them while `cms`/`x509-cert`/`rsa`/`ecdsa` still know only the
old trait major produces trait-bound cascades. The consumer majors that adopt
them exist only as pre-releases:

| Consumer | Current (stable, in tree) | Newest available |
|---|---|---|
| `cms` | 0.2.3 | 0.3.0-**pre**.2 |
| `x509-cert` | 0.2.5 | 0.3.0-rc.4 |
| `rsa` | 0.9.10 | 0.10.0-rc.18 |
| `ecdsa` | 0.16.9 | 0.17.0-rc.22 |
| `p256` / `p384` / `p521` | 0.13.x | 0.14.0-rc.14 |
| `ed25519-dalek` | 2.2.0 | 3.0.0-rc.1 |

---

## Wave 1 — formats: `der` 0.7 -> 0.8 (with `spki`, `const-oid`, `pem-rfc7468`)

`der` is the RustCrypto ASN.1 DER framework; `spki`, `const-oid`, and
`pem-rfc7468` move with it. `cms` and `x509-cert` — our two top-level encoding
crates — are built directly on these, so the whole encoding stack must move
together. A `der` major changes the `Decode`/`Encode`/`Sequence` trait
identities, so a consumer pinned to `der 0.7` cannot accept types from
`der 0.8`.

### Direct deps that pin the old major

| Consumer | Exact pin (from registry Cargo.toml) |
|---|---|
| `cms@0.2.3` | `der = "0.7.7"`, `spki = "0.7"`, `const-oid = "0.9.4"` |
| `x509-cert@0.2.5` | `der = "0.7.6"`, `spki = "0.7.3"`, `const-oid = "0.9.3"` |
| `rsa@0.9.10` | `spki = "0.7.3"`, `const-oid = "0.9"`, `pkcs8 = "0.10.2"` |
| `ecdsa@0.16.9` | `der = "0.7"`, `spki = "0.7.2"` |

`cms`/`x509-cert` 0.3 (which adopt `der 0.8`) exist only as `0.3.0-pre.2` /
`0.3.0-rc.4`.

### Unblock-condition

Stable `cms` 0.3 and `x509-cert` 0.3 (plus `rsa` 0.10 / `ecdsa` 0.17, whose
`spki`/`const-oid` track the same wave). Then bump
`cms`/`x509-cert`/`rsa`/`ecdsa` first, then `der`/`spki`/`const-oid`/`pem-rfc7468`
together, then rebuild and fix API fallout.

---

## Wave 2 — digest: `digest` 0.10 -> 0.11 (with `sha2`, `sha1`, `sha3`, `md-5`)

`digest` defines `Digest`/`FixedOutput`/`HashMarker`. Every hash crate
implements it and `rsa`/`ecdsa` consume it (for signature hashing), so all must
share one major.

### Direct deps that pin the old major

| Consumer | Exact pin (from registry Cargo.toml) |
|---|---|
| `rsa@0.9.10` | `digest = "0.10.5"` |
| `ecdsa@0.16.9` | `digest = "0.10.7"` |

Bumping the hash crates + `digest` to 0.11 while `rsa 0.9` / `ecdsa 0.16` know
only `digest 0.10` yields `T: digest::Digest is not satisfied` cascades at
`rsa`/`ecdsa` call sites.

### Unblock-condition

Stable `rsa` 0.10 and `ecdsa` 0.17 on `digest 0.11` (today only `rsa
0.10.0-rc.18` / `ecdsa 0.17.0-rc.22`). Then bump the hash crates + `digest`
together.

---

## Wave 3 — `signature` 2 -> 3

`signature` defines `Signer`/`Verifier`/`Keypair`. Bumping it requires every
signature consumer to adopt the new major simultaneously.

### Direct deps that pin the old major

| Consumer | Exact pin (from registry Cargo.toml) |
|---|---|
| `cms@0.2.3` | `signature = "2.1.0"` |
| `x509-cert@0.2.5` | `signature = "2.1.0"` |
| `rsa@0.9.10` | `signature = ">2.0, <2.3"` |
| `ecdsa@0.16.9` | `signature = "2.0, <2.3"` |
| `ed25519-dalek@2.2.0` | `signature = ">=2.0, <2.3"` |

Every consumer caps `signature < 2.3`, i.e. requires the 2.x trait identities.

### Unblock-condition

Stable `cms`/`x509-cert`/`rsa`/`ecdsa`/`ed25519-dalek` majors built on
`signature 3` (today only pre-release: `ed25519-dalek 3.0.0-rc.1`, etc.).

---

## Wave 4 — rand_core: `getrandom` 0.2 -> 0.4

`getrandom` sits under `rand_core`; a `getrandom` major arrives via a `rand_core`
major. `rsa` and `ed25519-dalek` pin `rand_core 0.6` (which uses `getrandom
0.2`), so taking `getrandom 0.4` directly would create a duplicate/mismatched
`getrandom` in the tree.

### Direct deps that pin the old major

| Consumer | Exact pin (from registry Cargo.toml) |
|---|---|
| `rsa@0.9.10` | `rand_core = "0.6.4"` |
| `ed25519-dalek@2.2.0` | `rand_core = "0.6.4"` |

### Unblock-condition

Stable `rsa` and `ed25519-dalek` majors on `rand_core 0.10` (→ `getrandom 0.4`);
today only pre-release.

---

## reqwest 0.12 -> 0.13 (deferred, not wave-blocked)

`reqwest` is a standalone HTTP client (optional, `tsp` feature) with no shared
trait crate, so it is bumpable independently. The only blocker is a **feature
rename**: 0.12's `rustls-tls` is split in 0.13 into `rustls` plus a roots
feature (`webpki-roots` for bundled Mozilla roots, or `rustls-native-certs` for
the OS trust store). Probe on 2026-06-27:

```
package `tsp-ltv` depends on `reqwest` with feature `rustls-tls`
but `reqwest` does not have that feature.
```

Deferred to a dedicated change: choosing the TLS root source is a deliberate
decision for this security library, and the current test suite makes no live
HTTPS calls, so a wrong roots choice would not be caught here. The closest
behavior-preserving config is `features = ["rustls", "webpki-roots"]`.

---

## What was actually pulled on 2026-10-16

`cargo outdated --depth 1` on 2026-10-16 (direct deps a major behind, all
deferred per the decision above):

| Crate | Current | Latest | Why not taken |
|---|---|---|---|
| `der` / `spki` / `const-oid` / `pem-rfc7468` | 0.7.10 / 0.7.3 / 0.9.6 / 0.7.0 | 0.8.2 / 0.8.1 / 0.10.2 / 1.0.0 | format wave, `cms` 0.3 still rc |
| `x509-cert` | 0.2.5 | 0.3.0 (stable) | format wave, moves with `cms` |
| `digest` / `sha1` / `sha2` / `sha3` / `md-5` (dev) | 0.10.x | 0.11.x / 0.12.0 | digest wave, `rsa` 0.10 still rc |
| `ecdsa` / `p256` / `p384` / `p521` / `dsa` (dev) | 0.16.9 / 0.13.x / 0.6.3 | 0.17.0 / 0.14.0 / 0.7.0 (stable) | digest and signature waves, `rsa` 0.10 still rc |
| `ed25519-dalek` / `signature` (dev) | 2.2.0 / 2.2.0 | 3.0.0 (stable) | signature wave, `cms`/`rsa` |
| `rand` (dev) | 0.8.8 | 0.10.3 | rand_core wave, `rsa` 0.10 still rc |
| `base64` | 0.22.1 | 0.23.1 | standalone; defer to a dedicated change, API review needed |
| `rcgen` / `time` (dev) | 0.13.2 / 0.3.53 | 0.14.10 / 0.3.55 | pinned exactly for Rust 1.88; revisit with MSRV |
| `reqwest` | 0.12.28 | 0.13.5 | feature rename, see the reqwest section |

Direct deps rolled forward in range by `cargo update` (through `sfw`):

```
kryptering     0.6.0   -> 0.7.0   (manifest bump)
thiserror      2.0.18  -> 2.0.21
log            0.4.33  -> 0.4.34
rustls         0.23.45 -> 0.23.46
webpki-roots   1.0.8   -> 1.0.9
tokio          1.52.3  -> 1.53.3
tokio-rustls   0.26.4  -> 0.26.6   (dev-dependency)
rand           0.8.6   -> 0.8.8    (dev-dependency)
sha1           0.10.6  -> 0.10.7   (dev-dependency)
```

The manifest now sets `resolver = "3"`. The first `cargo update` of the day,
under the edition-2021 default resolver, selected `aes` 0.9.3 (`rust-version =
1.89`) behind Kryptering; the MSRV-aware resolver downgraded it to 0.9.2, the
version Kryptering's own lockfile pins. Always run `cargo update` with this
resolver in place; the "Rust 1.88 MSRV" CI job (`cargo +1.88.0 check --locked`)
is the backstop.

Kryptering 0.7.0 adds `k256`, `bp256`, `bp384`, `x448`, `primefield` and `wnaf`
to the tree and drops `either` and `itertools`. The duplicated majors now in
the lockfile, all from the Kryptering line next to tsp-ltv's own line:
`const-oid`, `der`, `digest`, `getrandom`, `md-5`, `pem-rfc7468`, `pkcs8`,
`rand_core`, `rsa`, `sha1`, `sha2`, `sha3`, `signature`, `spki`. They collapse
when the waves above are taken.

Verification on 2026-10-16, against `kryptering 0.7.0` from crates.io (its
packaged sources are byte-identical to the tree tested beforehand):
- `cargo build --locked` and `cargo clippy --locked --tests -- -D warnings`: clean
- `cargo test --locked` (default features): 247 + 8 tests passed
- `cargo test --locked --no-default-features --features rustcrypto,legacy-algorithms`: 71 + 3 passed
- `cargo test --locked --no-default-features --features tsp,ltv,blocking,aws-lc,tls-aws-lc,legacy-algorithms`: 247 + 8 passed
- `cargo audit`: exit 0 (RUSTSEC-2023-0071 remains allow-listed in `.cargo/audit.toml`)
- `cargo publish --dry-run --locked`: packages and builds

## What was actually pulled on 2026-06-27

`cargo update` picked up these compat-range patches (no `Cargo.toml` changes
required); direct deps shown, plus the usual transitive roll-forward:

```
chrono   0.4.44 -> 0.4.45
log      0.4.29 -> 0.4.33
sha3     0.10.8 -> 0.10.9
tokio    1.50.0 -> 1.52.3
rand     0.8.5  -> 0.8.6   (dev-dependency)
```

After the update:
- the then-current complete feature set built cleanly
- the library suite passed 231 tests
- clippy with all targets was clean
- `cargo audit` — exits non-zero on **RUSTSEC-2023-0071** (Marvin attack,
  `rsa 0.9.10`, "no fixed upgrade available"). Pre-existing and ecosystem-wide;
  resolved only when `rsa` ships a stable fix (tracked with the digest/signature
  waves).

## How to re-evaluate

```bash
cargo outdated --depth 1
cargo search cms x509-cert rsa ecdsa ed25519-dalek   # are the consumers stable yet?
```

For each crate still shown a major behind, check whether the blocker consumers
above have shipped their next major **as a stable release** (not rc/pre). If not,
the wave hasn't moved. When an upstream stable release finally unblocks a wave,
bump every crate in that wave in a single commit, rebuild, and delete the
corresponding section here.
