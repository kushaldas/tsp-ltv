//! RFC 5280 §4.2.1.10 name-constraints (`2.5.29.30`) processing.
//!
//! A CA certificate may carry a `NameConstraints` extension that restricts the
//! name space all subordinate certificates may use (permitted subtrees) and/or
//! forbids parts of it (excluded subtrees). Without enforcement, a constrained
//! sub-CA — e.g. one a parent CA technically constrained to `*.example.com` —
//! could mint a certificate for *any* name and a verifier would accept it: the
//! constraint would be silently un-enforced (a fail-**open** chain-validation
//! bug).
//!
//! # What is implemented
//!
//! Permitted/excluded subtree enforcement for the four common
//! [`GeneralName`](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6) types:
//!
//! - **dNSName** (`[2]`) — case-insensitive suffix match, RFC 5280 label-boundary
//!   semantics (a constraint of `example.com` matches `host.example.com` and
//!   `example.com`, but not `notexample.com`; `.example.com` matches
//!   subdomains only).
//! - **rfc822Name** (`[1]`) — host-part / domain / sub-domain matching.
//! - **iPAddress** (`[7]`) — CIDR (`address/netmask`) containment for IPv4 and
//!   IPv6.
//! - **directoryName** (`[4]`) — RDN-prefix containment over the DER-encoded
//!   `Name`, with attribute values in the interchangeable directory string
//!   types (PrintableString / UTF8String / IA5String) compared under RFC 5280
//!   §7.1 `caseIgnoreMatch` semantics rather than raw byte-equality, so a
//!   re-encoded or re-cased RDN cannot evade an excluded subtree.
//!
//! Both the certificate **subject** directoryName and every applicable
//! **subjectAltName** GeneralName of each subordinate certificate are checked
//! against the accumulated constraints of the CAs above it.
//!
//! # Fail-closed for unsupported constraint types
//!
//! If a CA asserts a `NameConstraints` extension that constrains a GeneralName
//! type this module does not implement (e.g. `x400Address`, `ediPartyName`,
//! `otherName`, `uniformResourceIdentifier`, `registeredID`), the constraint
//! cannot be honoured and the chain is **rejected** ([`NameConstraintError::Unsupported`])
//! rather than silently ignored — a critical name constraint must never be
//! bypassed. (A constraint over a type we *do* support but that the subject
//! certificate does not assert simply does not match, per the type-specific
//! rules in RFC 5280 §4.2.1.10.)

use x509_cert::Certificate;

use crate::der_utils::{parse_tlv, parse_tlv_with_rest};

/// NameConstraints extension OID (`2.5.29.30`), raw DER OID body bytes.
pub const NAME_CONSTRAINTS_OID: &str = "2.5.29.30";

/// Subject Alternative Name OID (`2.5.29.17`).
const SAN_OID: &str = "2.5.29.17";

// GeneralName context-specific tags (RFC 5280 §4.2.1.6).
const GN_RFC822: u8 = 0x81; // [1] IA5String, primitive
const GN_DNS: u8 = 0x82; // [2] IA5String, primitive
const GN_DIRECTORY: u8 = 0xA4; // [4] Name, constructed (EXPLICIT — Name is a CHOICE)
const GN_IP: u8 = 0x87; // [7] OCTET STRING, primitive

/// An error from name-constraints processing.
#[derive(Debug)]
pub enum NameConstraintError {
    /// A subordinate certificate's name violates a permitted/excluded subtree.
    Violation(String),
    /// A constraint (or asserted name) used a GeneralName type that is not
    /// implemented — the chain is rejected (fail closed).
    Unsupported(String),
    /// The NameConstraints extension (or a name) was malformed.
    Parse(String),
}

impl std::fmt::Display for NameConstraintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameConstraintError::Violation(m) => write!(f, "name constraint violation: {m}"),
            NameConstraintError::Unsupported(m) => {
                write!(f, "unsupported name constraint (fail closed): {m}")
            }
            NameConstraintError::Parse(m) => write!(f, "malformed name constraints: {m}"),
        }
    }
}

/// One permitted-or-excluded GeneralName base, decoded into a typed form.
#[derive(Debug, Clone)]
enum GeneralNameBase {
    Dns(String),
    Rfc822(String),
    /// CIDR base: (address bytes, mask bytes). Lengths are 4 (IPv4) or 16 (IPv6).
    Ip(Vec<u8>, Vec<u8>),
    /// DER of the directoryName `Name` (the inner sequence, tag 0x30..).
    Directory(Vec<u8>),
}

/// A typed GeneralName asserted *by a subordinate certificate* (subject DN or a
/// SAN entry), to be matched against constraints.
#[derive(Debug, Clone)]
enum AssertedName {
    Dns(String),
    Rfc822(String),
    Ip(Vec<u8>),
    Directory(Vec<u8>),
}

/// Accumulated name constraints gathered from the CA certificates above the
/// certificate currently being checked.
///
/// Per RFC 5280 §6.1.4 constraints accumulate down the chain: every certificate
/// is checked against the union of all CAs' constraints above it.
#[derive(Debug, Default, Clone)]
pub struct NameConstraintState {
    permitted: Vec<GeneralNameBase>,
    excluded: Vec<GeneralNameBase>,
    /// Whether any permitted subtree of a given type was seen. RFC 5280: if a
    /// type has permitted subtrees, a name of that type must match at least one.
    permitted_dns: bool,
    permitted_rfc822: bool,
    permitted_ip: bool,
    permitted_directory: bool,
}

impl NameConstraintState {
    /// Fold the `NameConstraints` extension of an issuing CA `cert` (if any)
    /// into the accumulated state.
    ///
    /// Returns `Unsupported` (fail closed) if the extension constrains a
    /// GeneralName type this module does not implement.
    pub fn add_from_cert(&mut self, cert: &Certificate) -> Result<(), NameConstraintError> {
        let nc_oid = const_oid::ObjectIdentifier::new_unwrap(NAME_CONSTRAINTS_OID);
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return Ok(());
        };
        let Some(ext) = extensions.iter().find(|e| e.extn_id == nc_oid) else {
            return Ok(());
        };
        self.add_from_extension_value(ext.extn_value.as_bytes())
    }

    fn add_from_extension_value(&mut self, value: &[u8]) -> Result<(), NameConstraintError> {
        // NameConstraints ::= SEQUENCE { permittedSubtrees [0] OPTIONAL,
        //                                 excludedSubtrees  [1] OPTIONAL }
        let (tag, body) =
            parse_tlv(value).map_err(|e| NameConstraintError::Parse(format!("outer: {e}")))?;
        if tag != 0x30 {
            return Err(NameConstraintError::Parse(format!(
                "expected SEQUENCE (0x30), got 0x{tag:02x}"
            )));
        }
        let mut pos = &body[..];
        while !pos.is_empty() {
            let (t, sub_body, rest) = parse_tlv_with_rest(pos)
                .map_err(|e| NameConstraintError::Parse(format!("subtrees: {e}")))?;
            match t {
                // permittedSubtrees [0]
                0xA0 => {
                    let bases = parse_general_subtrees(sub_body)?;
                    for b in bases {
                        match &b {
                            GeneralNameBase::Dns(_) => self.permitted_dns = true,
                            GeneralNameBase::Rfc822(_) => self.permitted_rfc822 = true,
                            GeneralNameBase::Ip(..) => self.permitted_ip = true,
                            GeneralNameBase::Directory(_) => self.permitted_directory = true,
                        }
                        self.permitted.push(b);
                    }
                }
                // excludedSubtrees [1]
                0xA1 => {
                    let bases = parse_general_subtrees(sub_body)?;
                    self.excluded.extend(bases);
                }
                other => {
                    return Err(NameConstraintError::Parse(format!(
                        "unexpected NameConstraints member tag 0x{other:02x}"
                    )));
                }
            }
            pos = rest;
        }
        Ok(())
    }

    /// Whether any constraints are present (so callers can skip the (cheap)
    /// per-certificate name extraction when there is nothing to enforce).
    pub fn is_empty(&self) -> bool {
        self.permitted.is_empty() && self.excluded.is_empty()
    }

    /// Check a subordinate `cert`'s names (subject DN + subjectAltName entries)
    /// against the accumulated constraints.
    pub fn check_cert(&self, cert: &Certificate) -> Result<(), NameConstraintError> {
        if self.is_empty() {
            return Ok(());
        }
        let names = collect_asserted_names(cert)?;
        for name in &names {
            self.check_name(name)?;
        }
        Ok(())
    }

    fn check_name(&self, name: &AssertedName) -> Result<(), NameConstraintError> {
        // 1. Excluded subtrees: any match is a violation.
        for ex in &self.excluded {
            if base_matches(ex, name)? {
                return Err(NameConstraintError::Violation(format!(
                    "{name:?} falls within an excluded subtree"
                )));
            }
        }
        // 2. Permitted subtrees: if any permitted subtree of this name's type
        //    exists, the name must match at least one of them.
        let (has_permitted_of_type, type_label) = match name {
            AssertedName::Dns(_) => (self.permitted_dns, "dNSName"),
            AssertedName::Rfc822(_) => (self.permitted_rfc822, "rfc822Name"),
            AssertedName::Ip(_) => (self.permitted_ip, "iPAddress"),
            AssertedName::Directory(_) => (self.permitted_directory, "directoryName"),
        };
        if has_permitted_of_type {
            let mut matched = false;
            for p in &self.permitted {
                if base_matches(p, name)? {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err(NameConstraintError::Violation(format!(
                    "{type_label} {name:?} is outside every permitted subtree"
                )));
            }
        }
        Ok(())
    }
}

/// Parse a `GeneralSubtrees ::= SEQUENCE OF GeneralSubtree` body into the typed
/// bases, rejecting (fail closed) any unsupported GeneralName type.
fn parse_general_subtrees(body: &[u8]) -> Result<Vec<GeneralNameBase>, NameConstraintError> {
    let mut out = Vec::new();
    let mut pos = body;
    while !pos.is_empty() {
        // GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] ..., maximum [1] ... }
        let (t, st_body, rest) = parse_tlv_with_rest(pos)
            .map_err(|e| NameConstraintError::Parse(format!("GeneralSubtree: {e}")))?;
        if t != 0x30 {
            return Err(NameConstraintError::Parse(format!(
                "expected GeneralSubtree SEQUENCE, got 0x{t:02x}"
            )));
        }
        // The base GeneralName is the first element; the optional
        // `minimum [0]`/`maximum [1]` BaseDistance fields follow. RFC 5280
        // §4.2.1.10 mandates `minimum` be 0 and `maximum` be absent within this
        // profile, so we validate (fail closed) rather than silently ignore
        // them: a constraint carrying a non-zero minimum or any maximum encodes
        // semantics we do not implement.
        let (gn_tag, gn_body, gn_rest) = parse_tlv_with_rest(st_body)
            .map_err(|e| NameConstraintError::Parse(format!("base GeneralName: {e}")))?;
        validate_subtree_min_max(gn_rest)?;
        out.push(decode_base_general_name(gn_tag, gn_body)?);
        pos = rest;
    }
    Ok(out)
}

/// Validate the bytes following the base `GeneralName` inside a `GeneralSubtree`.
///
/// RFC 5280 §4.2.1.10: "the minimum and maximum fields are not used with any
/// name forms, thus, the minimum MUST be zero, and maximum MUST be absent." In
/// canonical DER `minimum` (DEFAULT 0) is omitted and `maximum` is absent, so a
/// well-formed subtree has nothing here. We accept only an explicitly encoded
/// `minimum [0] = 0` and reject everything else (non-zero minimum, any maximum,
/// or unexpected trailing content) — fail closed.
fn validate_subtree_min_max(mut rest: &[u8]) -> Result<(), NameConstraintError> {
    while !rest.is_empty() {
        let (tag, body, next) = parse_tlv_with_rest(rest)
            .map_err(|e| NameConstraintError::Parse(format!("GeneralSubtree min/max: {e}")))?;
        match tag {
            // minimum [0] IMPLICIT BaseDistance (INTEGER). Accept only 0.
            0x80 => {
                if body.len() != 1 || body[0] != 0 {
                    return Err(NameConstraintError::Violation(
                        "NameConstraints GeneralSubtree.minimum must be 0 (RFC 5280 §4.2.1.10)"
                            .into(),
                    ));
                }
            }
            // maximum [1] MUST be absent.
            0x81 => {
                return Err(NameConstraintError::Violation(
                    "NameConstraints GeneralSubtree.maximum must be absent (RFC 5280 §4.2.1.10)"
                        .into(),
                ));
            }
            other => {
                return Err(NameConstraintError::Parse(format!(
                    "unexpected field [tag 0x{other:02x}] in GeneralSubtree"
                )));
            }
        }
        rest = next;
    }
    Ok(())
}

/// Decode a base GeneralName from a constraint, failing closed on unsupported
/// types.
fn decode_base_general_name(tag: u8, body: &[u8]) -> Result<GeneralNameBase, NameConstraintError> {
    match tag {
        GN_DNS => Ok(GeneralNameBase::Dns(ia5_string(body)?.to_ascii_lowercase())),
        GN_RFC822 => Ok(GeneralNameBase::Rfc822(
            ia5_string(body)?.to_ascii_lowercase(),
        )),
        GN_DIRECTORY => {
            // [4] is EXPLICIT: the body is the inner Name (a SEQUENCE).
            let (inner_tag, _inner) = parse_tlv(body)
                .map_err(|e| NameConstraintError::Parse(format!("directoryName: {e}")))?;
            if inner_tag != 0x30 {
                return Err(NameConstraintError::Parse(format!(
                    "directoryName base inner tag 0x{inner_tag:02x}, expected SEQUENCE"
                )));
            }
            Ok(GeneralNameBase::Directory(body.to_vec()))
        }
        GN_IP => {
            // For a constraint, iPAddress is address || subnet-mask: 8 bytes
            // (IPv4) or 32 bytes (IPv6).
            match body.len() {
                8 => Ok(GeneralNameBase::Ip(body[..4].to_vec(), body[4..].to_vec())),
                32 => Ok(GeneralNameBase::Ip(
                    body[..16].to_vec(),
                    body[16..].to_vec(),
                )),
                n => Err(NameConstraintError::Parse(format!(
                    "iPAddress constraint must be 8 or 32 bytes (addr||mask), got {n}"
                ))),
            }
        }
        other => Err(NameConstraintError::Unsupported(format!(
            "GeneralName type [tag 0x{other:02x}] in NameConstraints is not supported"
        ))),
    }
}

/// Gather the names a subordinate certificate asserts: its subject
/// directoryName (always, when non-empty) and each supported subjectAltName
/// entry. A SAN entry of an unsupported type is ignored *for matching* (it is
/// not constrainable by the types we implement); a *constraint* of an
/// unsupported type is what fails closed (handled in `decode_base_general_name`).
fn collect_asserted_names(cert: &Certificate) -> Result<Vec<AssertedName>, NameConstraintError> {
    let mut names = Vec::new();

    // Subject directoryName: the raw DER of the subject Name SEQUENCE. An empty
    // subject (all-empty RDNSequence) does not assert a directoryName.
    use der::Encode;
    let subject_der = cert
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| NameConstraintError::Parse(format!("subject DER: {e}")))?;
    // An empty Name is `30 00` (SEQUENCE, length 0).
    if subject_der.len() > 2 {
        names.push(AssertedName::Directory(subject_der));
    }

    // subjectAltName entries.
    let san_oid = const_oid::ObjectIdentifier::new_unwrap(SAN_OID);
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        if let Some(ext) = extensions.iter().find(|e| e.extn_id == san_oid) {
            collect_san_names(ext.extn_value.as_bytes(), &mut names)?;
        }
    }

    Ok(names)
}

/// Parse a `SubjectAltName ::= GeneralNames` extension value into asserted
/// names of the supported types.
fn collect_san_names(
    value: &[u8],
    names: &mut Vec<AssertedName>,
) -> Result<(), NameConstraintError> {
    let (tag, body) =
        parse_tlv(value).map_err(|e| NameConstraintError::Parse(format!("SAN: {e}")))?;
    if tag != 0x30 {
        return Err(NameConstraintError::Parse(format!(
            "SAN expected SEQUENCE, got 0x{tag:02x}"
        )));
    }
    let mut pos = &body[..];
    while !pos.is_empty() {
        let (gn_tag, gn_body, rest) = parse_tlv_with_rest(pos)
            .map_err(|e| NameConstraintError::Parse(format!("SAN entry: {e}")))?;
        match gn_tag {
            GN_DNS => names.push(AssertedName::Dns(ia5_string(gn_body)?.to_ascii_lowercase())),
            GN_RFC822 => names.push(AssertedName::Rfc822(
                ia5_string(gn_body)?.to_ascii_lowercase(),
            )),
            GN_IP => {
                // In a SAN, iPAddress is the bare address (4 or 16 bytes).
                match gn_body.len() {
                    4 | 16 => names.push(AssertedName::Ip(gn_body.to_vec())),
                    n => {
                        return Err(NameConstraintError::Parse(format!(
                            "SAN iPAddress must be 4 or 16 bytes, got {n}"
                        )));
                    }
                }
            }
            GN_DIRECTORY => {
                // [4] EXPLICIT Name.
                names.push(AssertedName::Directory(gn_body.to_vec()));
            }
            // Other SAN types (URI, otherName, ...) are not matched by the
            // constraint types we implement; ignore them for matching.
            _ => {}
        }
        pos = rest;
    }
    Ok(())
}

/// Decode an IA5String body to a `String`. IA5 is ASCII; reject non-ASCII.
fn ia5_string(body: &[u8]) -> Result<String, NameConstraintError> {
    if body.is_ascii() {
        Ok(String::from_utf8_lossy(body).into_owned())
    } else {
        Err(NameConstraintError::Parse(
            "IA5String contains non-ASCII bytes".into(),
        ))
    }
}

/// Does the constraint `base` match the asserted `name`? A type mismatch is
/// simply "no match" (returns `Ok(false)`), not an error.
fn base_matches(base: &GeneralNameBase, name: &AssertedName) -> Result<bool, NameConstraintError> {
    match (base, name) {
        (GeneralNameBase::Dns(b), AssertedName::Dns(n)) => Ok(dns_matches(b, n)),
        (GeneralNameBase::Rfc822(b), AssertedName::Rfc822(n)) => Ok(rfc822_matches(b, n)),
        (GeneralNameBase::Ip(addr, mask), AssertedName::Ip(n)) => Ok(ip_matches(addr, mask, n)),
        (GeneralNameBase::Directory(b), AssertedName::Directory(n)) => directory_matches(b, n),
        _ => Ok(false),
    }
}

/// RFC 5280 §4.2.1.10 dNSName matching: the constraint matches the name if it is
/// equal to, or a (label-boundary) suffix of, the name. An empty constraint
/// matches all (permitted-all / excluded-all).
fn dns_matches(base: &str, name: &str) -> bool {
    if base.is_empty() {
        return true;
    }
    if let Some(suffix) = base.strip_prefix('.') {
        return name.len() > suffix.len()
            && name.ends_with(suffix)
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.';
    }
    if name == base {
        return true;
    }
    // host.example.com matches example.com (suffix on a label boundary).
    name.len() > base.len()
        && name.ends_with(base)
        && name.as_bytes()[name.len() - base.len() - 1] == b'.'
}

/// rfc822Name matching: a bare host (`host.example.com`) matches that mailbox
/// host exactly; a domain (`example.com`) matches any mailbox in that domain or
/// a sub-domain; a leading-dot form (`.example.com`) matches sub-domains only.
fn rfc822_matches(base: &str, name: &str) -> bool {
    if base.is_empty() {
        return true;
    }
    // Mailbox local-part@host.
    let host = match name.rsplit_once('@') {
        Some((_local, host)) => host,
        None => name, // already a host (some encoders omit the local part)
    };
    if let Some(suffix) = base.strip_prefix('.') {
        // ".example.com" — sub-domains only.
        return host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    if base.contains('@') {
        // Full mailbox constraint — exact (case-insensitive) match.
        return name == base;
    }
    // A host or domain. Exact host match, or domain suffix on a label boundary.
    host == base
        || (host.len() > base.len()
            && host.ends_with(base)
            && host.as_bytes()[host.len() - base.len() - 1] == b'.')
}

/// iPAddress constraint matching: `(name & mask) == (addr & mask)` for matching
/// address families and lengths.
fn ip_matches(addr: &[u8], mask: &[u8], name: &[u8]) -> bool {
    if name.len() != addr.len() || mask.len() != addr.len() {
        return false;
    }
    addr.iter()
        .zip(mask.iter())
        .zip(name.iter())
        .all(|((a, m), n)| (a & m) == (n & m))
}

/// directoryName constraint matching: the constraint matches if its RDN
/// sequence is a prefix of the asserted name's RDN sequence (RFC 5280
/// §4.2.1.10). Both inputs are the DER of the `[4]`-EXPLICIT wrapper or the bare
/// Name; we normalise to the inner Name SEQUENCE then compare RDN-by-RDN.
///
/// RDN comparison is **not** raw byte-equality: attribute values carried in the
/// interchangeable directory string types (PrintableString, UTF8String,
/// IA5String) are compared per RFC 5280 §7.1 `caseIgnoreMatch` semantics
/// (case-insensitive, leading/trailing whitespace stripped, internal whitespace
/// runs collapsed). Byte-equality alone would let a sub-CA escape an
/// *excludedSubtrees* directoryName by re-encoding the same logical RDN with a
/// different string type or letter case. Values of any other ASN.1 type fall
/// back to exact tag + byte equality, and malformed RDNs are a parse error
/// (fail closed).
fn directory_matches(
    base_wrapped: &[u8],
    name_wrapped: &[u8],
) -> Result<bool, NameConstraintError> {
    let base_rdns = inner_name_rdns(base_wrapped)?;
    let name_rdns = inner_name_rdns(name_wrapped)?;
    if base_rdns.len() > name_rdns.len() {
        return Ok(false);
    }
    // Prefix match: each of the base's RDNs must match the corresponding RDN of
    // the asserted name under caseIgnoreMatch-normalised comparison.
    for (b, n) in base_rdns.iter().zip(name_rdns.iter()) {
        if !rdn_matches(b, n)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// ASN.1 string tags treated as interchangeable "directory string" types for
/// caseIgnoreMatch comparison: UTF8String (0x0c), PrintableString (0x13),
/// IA5String (0x16).
const DIRECTORY_STRING_TAGS: [u8; 3] = [0x0c, 0x13, 0x16];

/// One `AttributeTypeAndValue`: `(type OID body, value tag, value body)`.
type Atv = (Vec<u8>, u8, Vec<u8>);

/// Parse one RDN (SET, `0x31`) into its `AttributeTypeAndValue` components.
fn rdn_atvs(rdn_der: &[u8]) -> Result<Vec<Atv>, NameConstraintError> {
    let (tag, body) = parse_tlv(rdn_der)
        .map_err(|e| NameConstraintError::Parse(format!("directoryName RDN: {e}")))?;
    if tag != 0x31 {
        return Err(NameConstraintError::Parse(format!(
            "directoryName RDN tag 0x{tag:02x}, expected SET"
        )));
    }
    let mut atvs = Vec::new();
    let mut pos = &body[..];
    while !pos.is_empty() {
        let (atv_tag, atv_body, rest) = parse_tlv_with_rest(pos)
            .map_err(|e| NameConstraintError::Parse(format!("AttributeTypeAndValue: {e}")))?;
        if atv_tag != 0x30 {
            return Err(NameConstraintError::Parse(format!(
                "AttributeTypeAndValue tag 0x{atv_tag:02x}, expected SEQUENCE"
            )));
        }
        let (oid_tag, oid_body, val_rest) = parse_tlv_with_rest(atv_body)
            .map_err(|e| NameConstraintError::Parse(format!("attribute type: {e}")))?;
        if oid_tag != 0x06 {
            return Err(NameConstraintError::Parse(format!(
                "attribute type tag 0x{oid_tag:02x}, expected OID"
            )));
        }
        let (val_tag, val_body, trailing) = parse_tlv_with_rest(val_rest)
            .map_err(|e| NameConstraintError::Parse(format!("attribute value: {e}")))?;
        if !trailing.is_empty() {
            return Err(NameConstraintError::Parse(
                "trailing data in AttributeTypeAndValue".into(),
            ));
        }
        atvs.push((oid_body.to_vec(), val_tag, val_body.to_vec()));
        pos = rest;
    }
    Ok(atvs)
}

/// RFC 5280 §7.1 `caseIgnoreMatch` approximation for directory string values:
/// require valid UTF-8, fold case, strip leading/trailing whitespace, collapse
/// internal whitespace runs to a single space. Returns `None` for invalid
/// UTF-8 (caller falls back to exact comparison).
fn normalize_directory_string(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            pending_space = !out.is_empty();
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.extend(c.to_lowercase());
        }
    }
    Some(out)
}

/// Compare two attribute values. Directory-string types compare under
/// caseIgnoreMatch normalisation (across the interchangeable string tags);
/// anything else requires exact tag + byte equality.
fn atv_value_matches(b_tag: u8, b_val: &[u8], n_tag: u8, n_val: &[u8]) -> bool {
    if DIRECTORY_STRING_TAGS.contains(&b_tag) && DIRECTORY_STRING_TAGS.contains(&n_tag) {
        if let (Some(b), Some(n)) = (
            normalize_directory_string(b_val),
            normalize_directory_string(n_val),
        ) {
            return b == n;
        }
    }
    b_tag == n_tag && b_val == n_val
}

/// Compare two RDNs (SETs of AttributeTypeAndValue) as multisets: same number
/// of attributes, and every base attribute pairs with a distinct name attribute
/// of the same type OID and a matching value. Multiset comparison (rather than
/// positional) tolerates encoder differences in SET ordering.
fn rdn_matches(base_rdn: &[u8], name_rdn: &[u8]) -> Result<bool, NameConstraintError> {
    let base = rdn_atvs(base_rdn)?;
    let name = rdn_atvs(name_rdn)?;
    if base.len() != name.len() {
        return Ok(false);
    }
    let mut used = vec![false; name.len()];
    for (b_oid, b_tag, b_val) in &base {
        let mut found = false;
        for (i, (n_oid, n_tag, n_val)) in name.iter().enumerate() {
            if used[i] || n_oid != b_oid {
                continue;
            }
            if atv_value_matches(*b_tag, b_val, *n_tag, n_val) {
                used[i] = true;
                found = true;
                break;
            }
        }
        if !found {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Given the DER of a directoryName (either the bare `Name` SEQUENCE `30..` or
/// the `[4]`-EXPLICIT wrapper `A4..`), return the list of raw DER-encoded RDNs
/// (each `31..`), or a parse error if malformed.
fn inner_name_rdns(der: &[u8]) -> Result<Vec<Vec<u8>>, NameConstraintError> {
    let (tag, body) =
        parse_tlv(der).map_err(|e| NameConstraintError::Parse(format!("directoryName: {e}")))?;
    let name_body = if tag == GN_DIRECTORY {
        // EXPLICIT [4] wrapper: unwrap to the inner Name SEQUENCE.
        let (inner_tag, inner_body) = parse_tlv(&body)
            .map_err(|e| NameConstraintError::Parse(format!("directoryName inner Name: {e}")))?;
        if inner_tag != 0x30 {
            return Err(NameConstraintError::Parse(format!(
                "directoryName inner tag 0x{inner_tag:02x}, expected SEQUENCE"
            )));
        }
        inner_body
    } else if tag == 0x30 {
        body
    } else {
        return Err(NameConstraintError::Parse(format!(
            "directoryName tag 0x{tag:02x}, expected [4] or SEQUENCE"
        )));
    };
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName (each a SET, 0x31).
    let mut rdns = Vec::new();
    let mut pos = &name_body[..];
    while !pos.is_empty() {
        let (rdn_tag, _rdn_body, rest) = parse_tlv_with_rest(pos)
            .map_err(|e| NameConstraintError::Parse(format!("directoryName RDN: {e}")))?;
        let consumed = pos.len() - rest.len();
        if rdn_tag != 0x31 {
            return Err(NameConstraintError::Parse(format!(
                "directoryName RDN tag 0x{rdn_tag:02x}, expected SET"
            )));
        }
        rdns.push(pos[..consumed].to_vec());
        pos = rest;
    }
    Ok(rdns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_label_boundary() {
        assert!(dns_matches("example.com", "host.example.com"));
        assert!(dns_matches("example.com", "example.com"));
        assert!(dns_matches(".example.com", "host.example.com"));
        assert!(!dns_matches(".example.com", "example.com"));
        assert!(!dns_matches("example.com", "notexample.com"));
        assert!(!dns_matches("example.com", "example.com.evil.com"));
        assert!(dns_matches("", "anything.test")); // empty base = all
    }

    #[test]
    fn rfc822_rules() {
        assert!(rfc822_matches("example.com", "alice@example.com"));
        assert!(rfc822_matches("example.com", "bob@sub.example.com"));
        assert!(!rfc822_matches("example.com", "bob@notexample.com"));
        assert!(rfc822_matches("host.example.com", "carol@host.example.com"));
        assert!(!rfc822_matches(
            "host.example.com",
            "carol@other.example.com"
        ));
        assert!(rfc822_matches(".example.com", "dan@sub.example.com"));
        assert!(!rfc822_matches(".example.com", "dan@example.com"));
        assert!(rfc822_matches("alice@example.com", "alice@example.com"));
    }

    #[test]
    fn ipv4_cidr() {
        // 10.0.0.0/8
        let addr = vec![10, 0, 0, 0];
        let mask = vec![0xff, 0, 0, 0];
        assert!(ip_matches(&addr, &mask, &[10, 1, 2, 3]));
        assert!(!ip_matches(&addr, &mask, &[11, 0, 0, 1]));
        // Wrong family/length → no match.
        assert!(!ip_matches(&addr, &mask, &[0u8; 16]));
    }

    #[test]
    fn unsupported_constraint_fails_closed() {
        // GeneralName [6] uniformResourceIdentifier (0x86) is not supported.
        let err = decode_base_general_name(0x86, b"http://x/").unwrap_err();
        assert!(matches!(err, NameConstraintError::Unsupported(_)));
    }

    #[test]
    fn malformed_ip_san_fails_closed() {
        use crate::der_utils::{encode_sequence_raw, encode_tlv};

        let san_value = encode_sequence_raw(&encode_tlv(GN_IP, &[192, 0, 2]));
        let mut names = Vec::new();
        let err = collect_san_names(&san_value, &mut names).unwrap_err();

        assert!(matches!(err, NameConstraintError::Parse(ref m) if m.contains("iPAddress")));
        assert!(names.is_empty());
    }

    #[test]
    fn malformed_directory_name_fails_closed() {
        let valid_name = [0x30, 0x00];
        let invalid_name = [0x04, 0x00];

        let err = base_matches(
            &GeneralNameBase::Directory(valid_name.to_vec()),
            &AssertedName::Directory(invalid_name.to_vec()),
        )
        .unwrap_err();

        assert!(matches!(err, NameConstraintError::Parse(ref m) if m.contains("directoryName")));
    }

    /// Encode a single-RDN `Name` SEQUENCE: `SEQ { SET { SEQ { OID, value } } }`.
    /// `oid_body` is the raw OID content bytes (e.g. `[0x55, 0x04, 0x03]` = CN).
    fn dir_name(oid_body: &[u8], value_tag: u8, value: &[u8]) -> Vec<u8> {
        use crate::der_utils::{encode_sequence_raw, encode_tlv};
        let atv = encode_sequence_raw(
            &[encode_tlv(0x06, oid_body), encode_tlv(value_tag, value)].concat(),
        );
        let rdn = encode_tlv(0x31, &atv);
        encode_sequence_raw(&rdn)
    }

    const CN_OID: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3
    const O_OID: &[u8] = &[0x55, 0x04, 0x0A]; // 2.5.4.10

    #[test]
    fn directory_name_case_and_string_type_insensitive() {
        // PrintableString "Example CA" must match UTF8String "example ca":
        // an excluded-subtree constraint cannot be evaded by re-encoding the
        // same logical RDN with a different string type or letter case.
        let printable = dir_name(CN_OID, 0x13, b"Example CA");
        let utf8_lower = dir_name(CN_OID, 0x0c, b"example ca");
        assert!(directory_matches(&printable, &utf8_lower).unwrap());
        assert!(directory_matches(&utf8_lower, &printable).unwrap());

        // Whitespace runs collapse; leading/trailing whitespace is stripped.
        let padded = dir_name(CN_OID, 0x0c, b"  Example   CA ");
        assert!(directory_matches(&printable, &padded).unwrap());
    }

    #[test]
    fn directory_name_still_distinguishes_different_values() {
        let a = dir_name(CN_OID, 0x13, b"Example CA");
        let b = dir_name(CN_OID, 0x13, b"Other CA");
        assert!(!directory_matches(&a, &b).unwrap());

        // Same value under a different attribute type must not match.
        let cn = dir_name(CN_OID, 0x13, b"Example CA");
        let o = dir_name(O_OID, 0x13, b"Example CA");
        assert!(!directory_matches(&cn, &o).unwrap());
    }

    #[test]
    fn directory_name_non_string_values_exact_match_only() {
        // Non directory-string types (here OCTET STRING) compare byte-exact.
        let a = dir_name(CN_OID, 0x04, b"AB");
        let b = dir_name(CN_OID, 0x04, b"ab");
        assert!(!directory_matches(&a, &b).unwrap());
        assert!(directory_matches(&a, &a).unwrap());
    }

    #[test]
    fn general_subtree_min_max_fail_closed() {
        use crate::der_utils::{encode_sequence_raw, encode_tlv};

        let base = encode_tlv(GN_DNS, b"example.com");

        // Bare base (no minimum/maximum) -> accepted.
        let ok = encode_sequence_raw(&base);
        assert!(parse_general_subtrees(&ok).is_ok());

        // Explicitly encoded minimum [0] = 0 -> accepted (RFC 5280 requires 0).
        let mut st = base.clone();
        st.extend(encode_tlv(0x80, &[0x00]));
        assert!(parse_general_subtrees(&encode_sequence_raw(&st)).is_ok());

        // Non-zero minimum -> rejected (fail closed).
        let mut st = base.clone();
        st.extend(encode_tlv(0x80, &[0x05]));
        assert!(matches!(
            parse_general_subtrees(&encode_sequence_raw(&st)).unwrap_err(),
            NameConstraintError::Violation(ref m) if m.contains("minimum")
        ));

        // maximum [1] present -> rejected (RFC 5280 requires it absent).
        let mut st = base.clone();
        st.extend(encode_tlv(0x81, &[0x05]));
        assert!(matches!(
            parse_general_subtrees(&encode_sequence_raw(&st)).unwrap_err(),
            NameConstraintError::Violation(ref m) if m.contains("maximum")
        ));
    }
}
