# Provider-specific expected unsupported cases

Provider matrix tests execute every case below and assert an explicit
`UnsupportedAlgorithm` result. They are not silently skipped.

| Provider | Operation | Reason |
|---|---|---|
| AWS-LC | DSA-SHA1 and DSA-SHA256 certificate verification | AWS-LC's stable Rust API does not expose DSA. |
| AWS-LC | RSA-PSS verification with a salt length different from the digest length | AWS-LC's stable verification parameters bind PSS salt length to the digest length. Parameter-aware TSP/CMS verification rejects other declared lengths before key use. |

These interoperability cases do not weaken the default signature policy:
legacy SHA-1 remains rejected unless the caller explicitly enables the legacy
policy.
