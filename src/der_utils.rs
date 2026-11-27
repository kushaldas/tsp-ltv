//! Shared DER/ASN.1 parsing and encoding utilities.
//!
//! These helpers work directly with raw DER byte slices, providing
//! low-level TLV (Tag-Length-Value) operations used across multiple
//! modules (CRL, OCSP, TSP, X.509 extension parsing).
//!
//! All functions work on `&[u8]` slices and return owned `Vec<u8>`
//! or borrowed sub-slices as appropriate. Error messages include
//! context about what was being parsed.

/// Parse a DER TLV and return `(tag, value_bytes)`.
///
/// Ignores any trailing data after the first complete TLV.
pub fn parse_tlv(data: &[u8]) -> Result<(u8, Vec<u8>), String> {
    let (tag, body, _rest) = parse_tlv_with_rest(data)?;
    Ok((tag, body.to_vec()))
}

/// Parse a DER TLV and return `(tag, value_slice, remaining_bytes)`.
pub fn parse_tlv_with_rest(data: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    if data.is_empty() {
        return Err("empty input".into());
    }

    let tag = data[0];
    let (len, header_len) = parse_der_length(&data[1..])?;
    let total_header = 1 + header_len;

    if total_header + len > data.len() {
        return Err(format!(
            "TLV length exceeds data: header={total_header}, len={len}, available={}",
            data.len()
        ));
    }

    let value = &data[total_header..total_header + len];
    let rest = &data[total_header + len..];
    Ok((tag, value, rest))
}

/// Parse DER definite-form length.
///
/// Returns `(length_value, number_of_bytes_consumed)`.
pub fn parse_der_length(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("empty length".into());
    }

    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else if first == 0x80 {
        Err("indefinite length not supported".into())
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 {
            return Err(format!("length too large: {num_bytes} bytes"));
        }
        if 1 + num_bytes > data.len() {
            return Err("insufficient data for length".into());
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((len, 1 + num_bytes))
    }
}

/// Encode a DER TLV from tag and value bytes.
pub fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 5 + value.len());
    out.push(tag);
    encode_der_length(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// Encode a DER SEQUENCE wrapping the concatenation of `parts`.
pub fn encode_sequence_from_parts(parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = parts.iter().map(|p| p.len()).sum();
    let mut body = Vec::with_capacity(total_len);
    for part in parts {
        body.extend_from_slice(part);
    }
    encode_sequence_raw(&body)
}

/// Encode a DER SEQUENCE from a pre-assembled body.
pub fn encode_sequence_raw(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 5 + body.len());
    out.push(0x30); // SEQUENCE tag
    encode_der_length(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// Encode DER definite-form length into `out`.
pub fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len <= 0xFF_FFFF {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Encode a non-negative integer as DER INTEGER.
pub fn encode_integer_u64(val: u64) -> Vec<u8> {
    let be_bytes = val.to_be_bytes();
    let start = be_bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let significant = &be_bytes[start..];

    let needs_padding = significant.is_empty() || (significant[0] & 0x80) != 0;
    let mut value_bytes = Vec::with_capacity(significant.len() + 1);
    if needs_padding {
        value_bytes.push(0x00);
    }
    value_bytes.extend_from_slice(significant);

    encode_tlv(0x02, &value_bytes)
}

/// Decode a DER INTEGER body (no tag/length) to `u64`.
///
/// Handles leading zero padding. Returns an error if the integer is negative
/// (high bit of the first significant byte set) or exceeds 64 bits (> 8 bytes
/// of significant data after stripping leading-zero padding).
pub fn decode_integer_u64(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() {
        return Err("empty INTEGER body".into());
    }
    // Check for negative: MSB of first byte set.
    // But the first byte may be a leading 0x00 pad for positive sign; skip it.
    // A negative INTEGER has MSB=1 in its actual value byte, without a leading pad.
    let (significant, _overflow) = if bytes.len() > 1 && bytes[0] == 0x00 {
        (&bytes[1..], false)
    } else if bytes[0] & 0x80 != 0 {
        return Err(format!(
            "negative INTEGER body not representable as u64: 0x{:02x}...",
            bytes[0]
        ));
    } else {
        (bytes, false)
    };

    if significant.len() > 8 {
        return Err(format!(
            "INTEGER body too large for u64: {} significant bytes",
            significant.len()
        ));
    }

    let mut val: u64 = 0;
    for &b in significant {
        val = (val << 8) | (b as u64);
    }
    Ok(val)
}

/// Encode a DER BOOLEAN value.
pub fn encode_boolean(val: bool) -> Vec<u8> {
    encode_tlv(0x01, &[if val { 0xFF } else { 0x00 }])
}

/// Extract the raw body bytes of an INTEGER from a DER-encoded integer.
///
/// Strips the leading zero byte used for positive sign encoding.
/// Useful for comparing serial numbers.
pub fn parse_integer_body(body: &[u8]) -> Vec<u8> {
    // Skip leading 0x00 padding used to indicate positive sign
    if body.len() > 1 && body[0] == 0x00 {
        body[1..].to_vec()
    } else {
        body.to_vec()
    }
}

/// Parse a DER-encoded `BasicConstraints` extension value.
///
/// Returns `(is_ca, path_len_constraint)`. An empty SEQUENCE body yields
/// `(false, None)`. This is a pure byte-level parser (no `x509-cert` or feature
/// dependency) so trust-chain code can enforce `pathLenConstraint` in every
/// build configuration, not only when the `ltv` feature is enabled.
///
/// ```text
/// BasicConstraints ::= SEQUENCE {
///     cA                      BOOLEAN DEFAULT FALSE,
///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
/// }
/// ```
pub fn parse_basic_constraints(ext_value: &[u8]) -> Result<(bool, Option<u64>), String> {
    let (tag, seq_body) = parse_tlv(ext_value)?;
    if tag != 0x30 {
        return Err(format!(
            "basicConstraints: expected SEQUENCE (0x30), got 0x{tag:02x}"
        ));
    }
    let mut is_ca = false;
    let mut path_len: Option<u64> = None;
    let mut pos = &seq_body[..];

    // cA BOOLEAN (optional, DEFAULT FALSE). A malformed TLV here is a hard
    // error, not a silently-skipped field — otherwise a truncated cA/pathLen
    // could bypass pathLen enforcement.
    if !pos.is_empty() {
        let (t, value, rest) =
            parse_tlv_with_rest(pos).map_err(|e| format!("basicConstraints cA: {e}"))?;
        if t == 0x01 {
            // A BOOLEAN's contents are exactly one byte; zero or multiple bytes
            // is malformed and must fail closed (else a CA flag could be
            // mis-counted by the trust-chain pathLen logic).
            if value.len() != 1 {
                return Err(format!(
                    "basicConstraints cA: BOOLEAN must be 1 byte, got {}",
                    value.len()
                ));
            }
            is_ca = value[0] != 0x00;
            pos = rest;
        }
    }

    // pathLenConstraint INTEGER (optional). Any remaining child here MUST be the
    // pathLenConstraint INTEGER — a different tag (or trailing data) is malformed
    // and must fail closed, not be silently ignored, otherwise a bogus
    // BasicConstraints on a subordinate CA could be undercounted.
    if !pos.is_empty() {
        let (t, value, rest) = parse_tlv_with_rest(pos)
            .map_err(|e| format!("basicConstraints pathLenConstraint: {e}"))?;
        if t != 0x02 {
            return Err(format!(
                "basicConstraints: unexpected element 0x{t:02x} (expected pathLenConstraint INTEGER)"
            ));
        }
        // RFC 5280 §4.2.1.9: pathLenConstraint is meaningful only when cA is
        // asserted. Reject `pathLenConstraint` without `cA:TRUE` rather than
        // returning a constraint for a non-CA certificate.
        if !is_ca {
            return Err("basicConstraints: pathLenConstraint present without cA:TRUE".to_string());
        }
        path_len = Some(decode_integer_u64(value).map_err(|e| format!("pathLenConstraint: {e}"))?);
        if !rest.is_empty() {
            return Err("basicConstraints: trailing data after pathLenConstraint".to_string());
        }
    }

    Ok((is_ca, path_len))
}

/// Find the first child element with a specific tag inside a SEQUENCE body.
///
/// Searches the immediate children (not recursive) of the given body bytes.
/// Returns the value bytes of the first match, or `None`.
pub fn find_tagged_value(body: &[u8], target_tag: u8) -> Option<&[u8]> {
    let mut pos = body;
    while !pos.is_empty() {
        match parse_tlv_with_rest(pos) {
            Ok((tag, value, rest)) => {
                if tag == target_tag {
                    return Some(value);
                }
                pos = rest;
            }
            Err(_) => break,
        }
    }
    None
}

/// Iterate over child TLVs in a body, calling `f` for each `(tag, value, rest)`.
///
/// Stops at the first parse error or when body is exhausted.
pub fn for_each_tlv<F>(body: &[u8], mut f: F)
where
    F: FnMut(u8, &[u8]),
{
    let mut pos = body;
    while !pos.is_empty() {
        match parse_tlv_with_rest(pos) {
            Ok((tag, value, rest)) => {
                f(tag, value);
                pos = rest;
            }
            Err(_) => break,
        }
    }
}

/// Compare two DER INTEGER bodies for equality, ignoring leading zero padding.
pub fn integer_bodies_equal(a: &[u8], b: &[u8]) -> bool {
    parse_integer_body(a) == parse_integer_body(b)
}

/// Build a UTC instant from calendar fields, rejecting out-of-range values
/// (including a leap second, which DER time types do not allow here).
fn utc_from_parts(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
) -> Result<time::UtcDateTime, String> {
    let month_name = u8::try_from(month)
        .ok()
        .and_then(|m| time::Month::try_from(m).ok())
        .ok_or_else(|| format!("invalid date: {year}-{month}-{day}"))?;
    let date = u8::try_from(day)
        .ok()
        .and_then(|d| time::Date::from_calendar_date(year, month_name, d).ok())
        .ok_or_else(|| format!("invalid date: {year}-{month}-{day}"))?;
    let tod = match (u8::try_from(hour), u8::try_from(min), u8::try_from(sec)) {
        (Ok(h), Ok(m), Ok(sec)) => time::Time::from_hms(h, m, sec).ok(),
        _ => None,
    }
    .ok_or_else(|| format!("invalid time: {hour}:{min}:{sec}"))?;
    Ok(time::PrimitiveDateTime::new(date, tod)
        .assume_utc()
        .to_utc())
}

/// Add a duration to an instant, clamping to the representable range instead of
/// panicking.
///
/// `time::UtcDateTime` covers years -9999 to 9999, narrower than `chrono`, so a
/// DER time near year 9999 plus a clock-skew allowance can leave the range. The
/// comparisons in the freshness checks only need "later than anything we could
/// hold" or "earlier than anything we could hold", which the clamped value
/// gives: it matches `chrono`'s behavior, where such a sum was simply a very
/// distant instant.
pub(crate) fn saturating_add(dt: time::UtcDateTime, d: time::Duration) -> time::UtcDateTime {
    dt.checked_add(d).unwrap_or(if d.is_negative() {
        time::UtcDateTime::MIN
    } else {
        time::UtcDateTime::MAX
    })
}

/// Format an instant as `YYYY-MM-DDThh:mm:ssZ` (RFC 3339, whole seconds) for
/// log and error messages.
pub(crate) fn fmt_instant(dt: time::UtcDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// Convert a `der::DateTime` (as found in certificate validity periods) to a
/// UTC instant.
pub(crate) fn der_datetime_to_utc(dt: &der::DateTime) -> Result<time::UtcDateTime, String> {
    utc_from_parts(
        i32::from(dt.year()),
        u32::from(dt.month()),
        u32::from(dt.day()),
        u32::from(dt.hour()),
        u32::from(dt.minutes()),
        u32::from(dt.seconds()),
    )
}

/// Parse a DER-encoded GeneralizedTime body (no tag/length) to a [`time::UtcDateTime`].
///
/// Format: `YYYYMMDDHHMMSSZ` or `YYYYMMDDHHMMSS.fracZ`
///
/// # Panic safety
///
/// The string is checked to be ASCII before any indexing on the `&str`, so a
/// multi-byte UTF-8 character cannot cause a mid-character slice panic.
pub fn parse_generalized_time(body: &[u8]) -> Result<time::UtcDateTime, String> {
    let s =
        std::str::from_utf8(body).map_err(|e| format!("GeneralizedTime: invalid UTF-8: {e}"))?;

    if !s.is_ascii() {
        return Err("GeneralizedTime: non-ASCII characters".to_string());
    }

    // Strip trailing 'Z'
    let s = s.strip_suffix('Z').unwrap_or(s);

    // Strip fractional seconds if present
    let s = if let Some(dot_pos) = s.find('.') {
        &s[..dot_pos]
    } else {
        s
    };

    if s.len() < 14 {
        return Err(format!("GeneralizedTime too short: {s}"));
    }

    let year: i32 = s[0..4].parse().map_err(|e| format!("year: {e}"))?;
    let month: u32 = s[4..6].parse().map_err(|e| format!("month: {e}"))?;
    let day: u32 = s[6..8].parse().map_err(|e| format!("day: {e}"))?;
    let hour: u32 = s[8..10].parse().map_err(|e| format!("hour: {e}"))?;
    let min: u32 = s[10..12].parse().map_err(|e| format!("minute: {e}"))?;
    let sec: u32 = s[12..14].parse().map_err(|e| format!("second: {e}"))?;

    utc_from_parts(year, month, day, hour, min, sec)
}

/// Parse a DER-encoded UTCTime body (no tag/length) to a [`time::UtcDateTime`].
///
/// Format: `YYMMDDHHMMSSZ`
///
/// # Panic safety
///
/// The string is checked to be ASCII before any indexing on the `&str`, so a
/// multi-byte UTF-8 character cannot cause a mid-character slice panic.
pub fn parse_utc_time(body: &[u8]) -> Result<time::UtcDateTime, String> {
    let s = std::str::from_utf8(body).map_err(|e| format!("UTCTime: invalid UTF-8: {e}"))?;

    if !s.is_ascii() {
        return Err("UTCTime: non-ASCII characters".to_string());
    }

    let s = s.strip_suffix('Z').unwrap_or(s);

    if s.len() < 12 {
        return Err(format!("UTCTime too short: {s}"));
    }

    let yy: i32 = s[0..2].parse().map_err(|e| format!("year: {e}"))?;
    // RFC 5280 §4.1.2.5.1: values 0-49 → 2000-2049, 50-99 → 1950-1999
    let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
    let month: u32 = s[2..4].parse().map_err(|e| format!("month: {e}"))?;
    let day: u32 = s[4..6].parse().map_err(|e| format!("day: {e}"))?;
    let hour: u32 = s[6..8].parse().map_err(|e| format!("hour: {e}"))?;
    let min: u32 = s[8..10].parse().map_err(|e| format!("minute: {e}"))?;
    let sec: u32 = s[10..12].parse().map_err(|e| format!("second: {e}"))?;

    utc_from_parts(year, month, day, hour, min, sec)
}

/// Parse a time value that could be either UTCTime (tag 0x17) or
/// GeneralizedTime (tag 0x18).
pub fn parse_x509_time(tag: u8, body: &[u8]) -> Result<time::UtcDateTime, String> {
    match tag {
        0x17 => parse_utc_time(body),
        0x18 => parse_generalized_time(body),
        _ => Err(format!(
            "expected UTCTime (0x17) or GeneralizedTime (0x18), got 0x{tag:02x}"
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_roundtrip() {
        let value = b"hello";
        let encoded = encode_tlv(0x04, value); // OCTET STRING
        let (tag, body) = parse_tlv(&encoded).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(body, value);
    }

    #[test]
    fn test_sequence_encoding() {
        let int1 = encode_integer_u64(42);
        let int2 = encode_integer_u64(100);
        let seq = encode_sequence_from_parts(&[&int1, &int2]);
        let (tag, _body) = parse_tlv(&seq).unwrap();
        assert_eq!(tag, 0x30);
    }

    #[test]
    fn test_der_length_roundtrip() {
        for len in [0, 1, 127, 128, 255, 256, 65535, 65536] {
            let mut buf = Vec::new();
            encode_der_length(&mut buf, len);
            let (parsed_len, consumed) = parse_der_length(&buf).unwrap();
            assert_eq!(parsed_len, len, "length roundtrip failed for {len}");
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_encode_decode_integer() {
        assert_eq!(encode_integer_u64(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(encode_integer_u64(1), vec![0x02, 0x01, 0x01]);
        assert_eq!(encode_integer_u64(128), vec![0x02, 0x02, 0x00, 0x80]);

        // Decode back
        assert_eq!(decode_integer_u64(&[0x01]).unwrap(), 1);
        assert_eq!(decode_integer_u64(&[0x00, 0x80]).unwrap(), 128);
        // Negative values rejected
        assert!(decode_integer_u64(&[0x80]).is_err());
        // Too large (>8 bytes of significant data)
        assert!(
            decode_integer_u64(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]).is_err()
        );
    }

    #[test]
    fn test_parse_basic_constraints_ok() {
        // SEQUENCE { BOOLEAN TRUE, INTEGER 2 }
        let bc = encode_sequence_from_parts(&[&encode_boolean(true), &encode_integer_u64(2)]);
        assert_eq!(parse_basic_constraints(&bc).unwrap(), (true, Some(2)));
        // Empty SEQUENCE → CA:FALSE, no pathlen.
        assert_eq!(
            parse_basic_constraints(&[0x30, 0x00]).unwrap(),
            (false, None)
        );
        // cA only.
        let bc = encode_sequence_from_parts(&[&encode_boolean(true)]);
        assert_eq!(parse_basic_constraints(&bc).unwrap(), (true, None));
    }

    #[test]
    fn test_parse_basic_constraints_rejects_malformed_child() {
        // SEQUENCE (len 3) { BOOLEAN tag+len but value byte truncated }.
        // A swallowed parse error here would let cA/pathLen bypass enforcement.
        let malformed = [0x30, 0x02, 0x01, 0x01];
        assert!(parse_basic_constraints(&malformed).is_err());
        // Truncated pathLen INTEGER after a valid cA BOOLEAN.
        let mut body = encode_boolean(true);
        body.extend_from_slice(&[0x02, 0x04, 0x00]); // INTEGER len 4, only 1 byte
        let seq = encode_sequence_raw(&body);
        assert!(parse_basic_constraints(&seq).is_err());
    }

    #[test]
    fn test_parse_basic_constraints_rejects_pathlen_without_ca() {
        // RFC 5280: pathLenConstraint is only valid with cA:TRUE. A non-CA cert
        // (cA absent/FALSE) carrying a pathLen is malformed and must be rejected.
        let bc = encode_sequence_from_parts(&[&encode_integer_u64(0)]); // INTEGER only
        assert!(parse_basic_constraints(&bc).is_err());
        let bc = encode_sequence_from_parts(&[&encode_boolean(false), &encode_integer_u64(1)]);
        assert!(parse_basic_constraints(&bc).is_err());
    }

    #[test]
    fn test_parse_basic_constraints_rejects_unexpected_child() {
        // A child after cA that is not a pathLenConstraint INTEGER is malformed
        // and must fail closed (not be silently ignored, leaving path_len=None).
        let bc = encode_sequence_from_parts(&[
            &encode_boolean(true),
            &encode_tlv(0x05, &[]), // NULL where pathLen INTEGER is expected
        ]);
        assert!(parse_basic_constraints(&bc).is_err());
        // Trailing data after a valid pathLenConstraint is also rejected.
        let bc = encode_sequence_from_parts(&[
            &encode_boolean(true),
            &encode_integer_u64(1),
            &encode_tlv(0x05, &[]),
        ]);
        assert!(parse_basic_constraints(&bc).is_err());
    }

    #[test]
    fn test_parse_basic_constraints_rejects_malformed_ca_boolean() {
        // BOOLEAN contents must be exactly one byte.
        let bc = encode_sequence_from_parts(&[&encode_tlv(0x01, &[])]); // zero-length
        assert!(parse_basic_constraints(&bc).is_err());
        let bc = encode_sequence_from_parts(&[&encode_tlv(0x01, &[0xFF, 0xFF])]); // two bytes
        assert!(parse_basic_constraints(&bc).is_err());
    }

    #[test]
    fn test_parse_basic_constraints_large_pathlen_not_truncated() {
        // pathLenConstraint that exceeds u32 must survive as a full u64 (the
        // u32 narrowing/rejection is the caller's concern, not this parser's).
        let big = encode_sequence_from_parts(&[
            &encode_boolean(true),
            &encode_integer_u64(0x1_0000_0001),
        ]);
        assert_eq!(
            parse_basic_constraints(&big).unwrap(),
            (true, Some(0x1_0000_0001))
        );
    }

    #[test]
    fn test_parse_integer_body_strips_padding() {
        assert_eq!(parse_integer_body(&[0x00, 0x80]), vec![0x80]);
        assert_eq!(parse_integer_body(&[0x42]), vec![0x42]);
        assert_eq!(parse_integer_body(&[0x00, 0x01, 0x02]), vec![0x01, 0x02]);
    }

    #[test]
    fn test_integer_bodies_equal() {
        assert!(integer_bodies_equal(&[0x00, 0x80], &[0x80]));
        assert!(integer_bodies_equal(&[0x42], &[0x42]));
        assert!(!integer_bodies_equal(&[0x42], &[0x43]));
    }

    #[test]
    fn test_find_tagged_value() {
        // Build: SEQUENCE { INTEGER 42, OCTET STRING "hi", BOOLEAN true }
        let int = encode_integer_u64(42);
        let oct = encode_tlv(0x04, b"hi");
        let boolean = encode_boolean(true);
        let mut body = Vec::new();
        body.extend_from_slice(&int);
        body.extend_from_slice(&oct);
        body.extend_from_slice(&boolean);

        // Find OCTET STRING (0x04)
        let found = find_tagged_value(&body, 0x04);
        assert_eq!(found, Some(b"hi".as_slice()));

        // Find BOOLEAN (0x01)
        let found = find_tagged_value(&body, 0x01);
        assert_eq!(found, Some(&[0xFF][..]));

        // Not found
        assert!(find_tagged_value(&body, 0x06).is_none());
    }

    #[test]
    fn test_time_parsers_reject_out_of_range_fields() {
        for bad in [
            b"20261301000000Z".as_slice(), // month 13
            b"20260230000000Z".as_slice(), // February 30
            b"20260001000000Z".as_slice(), // month 0
            b"20260600000000Z".as_slice(), // day 0
            b"20260601240000Z".as_slice(), // hour 24
            b"20260601126000Z".as_slice(), // minute 60
            b"20260601235960Z".as_slice(), // leap second
        ] {
            assert!(
                parse_generalized_time(bad).is_err(),
                "GeneralizedTime must reject {}",
                String::from_utf8_lossy(bad)
            );
        }
        for bad in [
            b"261301000000Z".as_slice(),
            b"260230000000Z".as_slice(),
            b"260601240000Z".as_slice(),
            b"260601235960Z".as_slice(),
        ] {
            assert!(
                parse_utc_time(bad).is_err(),
                "UTCTime must reject {}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn test_der_datetime_to_utc() {
        let dt = der::DateTime::new(2026, 6, 1, 12, 3, 7).unwrap();
        let utc = der_datetime_to_utc(&dt).unwrap();
        assert_eq!(fmt_instant(utc), "2026-06-01T12:03:07Z");

        // The extremes of a four-digit year convert without error.
        let last = der::DateTime::new(9999, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(
            fmt_instant(der_datetime_to_utc(&last).unwrap()),
            "9999-12-31T23:59:59Z"
        );
    }

    #[test]
    fn test_saturating_add_clamps_instead_of_panicking() {
        let last = parse_generalized_time(b"99991231235959Z").unwrap();
        assert_eq!(
            saturating_add(last, time::Duration::minutes(5)),
            time::UtcDateTime::MAX
        );
        assert_eq!(
            saturating_add(time::UtcDateTime::MIN, time::Duration::minutes(-5)),
            time::UtcDateTime::MIN
        );
        let mid = parse_generalized_time(b"20260601000000Z").unwrap();
        assert_eq!(
            fmt_instant(saturating_add(mid, time::Duration::hours(1))),
            "2026-06-01T01:00:00Z"
        );
    }

    #[test]
    fn test_fmt_instant() {
        let dt = parse_generalized_time(b"20260601000007Z").unwrap();
        assert_eq!(fmt_instant(dt), "2026-06-01T00:00:07Z");
        let dt = parse_utc_time(b"990101235959Z").unwrap();
        assert_eq!(fmt_instant(dt), "1999-01-01T23:59:59Z");
    }

    #[test]
    fn test_parse_generalized_time() {
        let dt = parse_generalized_time(b"20260303120000Z").unwrap();
        assert_eq!(
            dt.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            "2026-03-03T12:00:00Z"
        );

        // With fractional seconds
        let dt = parse_generalized_time(b"20260303120000.5Z").unwrap();
        assert_eq!(
            dt.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            "2026-03-03T12:00:00Z"
        );
    }

    #[test]
    fn test_parse_utc_time() {
        // 26 → 2026
        let dt = parse_utc_time(b"260303120000Z").unwrap();
        assert_eq!(
            dt.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            "2026-03-03T12:00:00Z"
        );

        // 99 → 1999
        let dt = parse_utc_time(b"990101000000Z").unwrap();
        assert_eq!(
            dt.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            "1999-01-01T00:00:00Z"
        );
    }

    #[test]
    fn test_parse_x509_time() {
        let dt = parse_x509_time(0x17, b"260303120000Z").unwrap();
        assert_eq!(
            dt.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            "2026-03-03T12:00:00Z"
        );

        let dt = parse_x509_time(0x18, b"20260303120000Z").unwrap();
        assert_eq!(
            dt.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            "2026-03-03T12:00:00Z"
        );

        assert!(parse_x509_time(0x04, b"whatever").is_err());
    }

    #[test]
    fn test_for_each_tlv() {
        let int = encode_integer_u64(1);
        let oct = encode_tlv(0x04, b"test");
        let mut body = Vec::new();
        body.extend_from_slice(&int);
        body.extend_from_slice(&oct);

        let mut tags = Vec::new();
        for_each_tlv(&body, |tag, _value| {
            tags.push(tag);
        });
        assert_eq!(tags, vec![0x02, 0x04]);
    }

    #[test]
    fn test_empty_input_errors() {
        assert!(parse_tlv(&[]).is_err());
        assert!(parse_tlv_with_rest(&[]).is_err());
        assert!(parse_der_length(&[]).is_err());
    }
}
