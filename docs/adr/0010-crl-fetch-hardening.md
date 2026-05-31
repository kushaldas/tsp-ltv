# 10. CRL fetch hardening: SSRF address filtering and response size cap

Date: 2026-05-31

## Status

Accepted

## Context

`CrlClient::fetch_crl` (`ltv/crl.rs`) downloads a CRL from a distribution-point
URL extracted from the certificate under validation (`extract_crl_urls`). The
URL is therefore **attacker-influenced**: a certificate presented for validation
carries its own CRL distribution points.

A security audit (finding **M-7**, Medium) flagged the fetch path for two
unbounded behaviours (the cache-TTL portion of M-7 is addressed separately by
ADR 0005, whose `crl_is_current` check already bounds cache reuse by the CRL's
own `nextUpdate`):

- **SSRF via attacker-controlled target.** The distribution-point URL was passed
  straight to the HTTP client. A crafted certificate could point at non-web
  schemes (`file://`, `gopher://`) *or* at internal hosts —
  `http://127.0.0.1/...`, `http://169.254.169.254/...` (cloud metadata), or any
  RFC 1918 address — turning the validator into an SSRF gadget. **A scheme
  allowlist alone does not close this**: `http://169.254.169.254/` passes a
  scheme check yet still reaches an internal endpoint.
- **No response size limit.** The full response body was read into memory with
  no cap, so a malicious or compromised distribution point could return an
  arbitrarily large body and exhaust the validator's memory.

## Decision

Add an address-aware SSRF guard and a streaming size cap to the fetch path.

**SSRF guard: scheme allowlist *and* destination address filtering.**
`validate_url` (async) enforces an `http`/`https` scheme allowlist and then
checks the *destination address*, not just the scheme:

- A literal-IP host is checked directly (no DNS).
- A hostname is resolved (off the async executor via `spawn_blocking`) and
  **every** resolved address is checked.
- `is_disallowed_ip` rejects loopback, private (RFC 1918), link-local
  (including `169.254.0.0/16` metadata), unique-local IPv6 (`fc00::/7`),
  link-local IPv6 (`fe80::/10`), unspecified, broadcast, documentation,
  multicast, and CGNAT shared space (`100.64.0.0/10`); IPv4-mapped IPv6 is
  unwrapped and re-checked.

```rust
match parsed.scheme() { "http" | "https" => {}, other => return Err(/* scheme */) }
if let Ok(ip) = host_bare.parse::<IpAddr>() {        // literal IP, no DNS
    if is_disallowed_ip(ip) { return Err(/* non-public (SSRF guard) */); }
    return Ok(());
}
let addrs = spawn_blocking(move || (host, port).to_socket_addrs()...).await?...;  // hostname
for addr in &addrs { if is_disallowed_ip(addr.ip()) { return Err(/* non-public */); } }
```

The guard runs **after** the cache lookup (a cache hit makes no network request,
so it needs no DNS) and **before** any network egress. The default HTTP client
is additionally built with a bounded redirect policy (`MAX_REDIRECTS = 5`) that
refuses to follow redirects to literal non-public addresses, closing the
redirect-to-internal bypass.

**Residual limitation (documented, not silently ignored).** Resolution here and
`reqwest`'s connect-time resolution are two separate lookups, so a DNS-rebinding
attacker who flips the record between them is not fully prevented, and a redirect
to a *hostname* that resolves internally is only caught for literal-IP targets.
Fully closing these would require pinning the validated IP into the connection
(custom resolver / per-request client). The guard as implemented closes the
attacks in the finding (literal internal IPs and hostnames that statically
resolve internally) without over-claiming complete SSRF immunity.

**Response size cap.** A `max_body_size` field on `CrlClient` (default
`MAX_BODY_SIZE` = 10 MiB, overridable via the `max_body_size()` builder) bounds
the downloaded body. The cap is enforced *before* and *during* download, never
by buffering the whole body first:

```rust
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
// 1. Reject up front on an advertised Content-Length over the cap.
if let Some(len) = response.content_length() {
    if len > self.max_body_size as u64 { return Err(/* exceeds max body size */); }
}
// 2. Stream chunks, aborting as soon as the accumulated bytes exceed the cap —
//    bounds peak memory even when Content-Length is absent or lies.
let mut crl_bytes = Vec::new();
while let Some(chunk) = response.chunk().await? {
    if crl_bytes.len() + chunk.len() > self.max_body_size { return Err(/* exceeds */); }
    crl_bytes.extend_from_slice(&chunk);
}
```

The `Content-Length` pre-check rejects an honestly-oversized body without
downloading it; the streaming accumulation caps peak memory at one chunk over
the limit when the header is missing or dishonest. 10 MiB is far above any
legitimate CRL while still bounding the blast radius.

## Consequences

- A CRL fetch whose host resolves to a non-public address is refused before any
  connection is made, removing the practical SSRF surface (internal services,
  cloud metadata) that an attacker-supplied distribution-point URL opened — not
  merely the non-web schemes a scheme check would catch.
- A single CRL response cannot consume more than `max_body_size` of memory;
  operators with unusually large legitimate CRLs can raise the bound via the
  builder.
- The SSRF guard runs after the cache lookup (cache hits stay network-free) and
  before egress; the default client additionally blocks redirects to literal
  non-public addresses.
- DNS-rebinding and redirect-to-internal-hostname remain residual (see Decision);
  the limitation is documented rather than papered over.
- The third M-7 concern — serving a stale CRL from cache past its `nextUpdate` —
  is handled by the fetch-time freshness check introduced in ADR 0005, not here.

## Related

- ADR 0005 — CRL freshness (covers the cache-currentness half of M-7).
- ADR 0009 — reject delta and partitioned CRLs (the adjacent CRL-content guard;
  together they harden the full CRL acquisition and parsing path).
