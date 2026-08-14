//! Parse dates.
//!
//! The wire form is `{"__type":"Date","iso":"YYYY-MM-DDTHH:MM:SS.mmmZ"}`: ISO 8601, always UTC,
//! always a literal `Z`, always exactly three fractional digits. Round trips must be lossless.
//!
//! **The same logical value has two wire forms depending on position**, and conflating them is a
//! real bug that a published Rust Parse client shipped:
//! top-level `createdAt` and `updatedAt` are **bare ISO strings**, while a user-defined Date
//! field is the `__type` envelope above. `ParseDate` models the value; the encoder decides the
//! form from where it sits.

use chrono::{DateTime, SecondsFormat, Utc};

use crate::error::ParseError;

/// A Parse date. Millisecond precision, UTC.
///
/// Precision is truncated to milliseconds on construction rather than at serialization, so that
/// two values that will serialize identically also compare equal. Doing it the other way round
/// makes `a == b` disagree with `encode(a) == encode(b)`, which is the kind of thing that
/// produces an intermittent conformance failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParseDate(DateTime<Utc>);

impl ParseDate {
    /// Truncates sub-millisecond precision.
    ///
    /// Total by construction. The millisecond count came from a `DateTime`, so reconstructing
    /// one from it cannot fail, but this is a request path and "cannot fail" is not a reason to
    /// write a panic. Falling back to the untruncated value degrades precision on a date no
    /// client can construct, which is a strictly better failure than taking down a worker.
    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        let ms = dt.timestamp_millis();
        Self(DateTime::from_timestamp_millis(ms).unwrap_or(dt))
    }

    pub fn now() -> Self {
        Self::from_datetime(Utc::now())
    }

    pub fn timestamp_millis(&self) -> i64 {
        self.0.timestamp_millis()
    }

    pub fn as_datetime(&self) -> DateTime<Utc> {
        self.0
    }

    /// The ISO form Parse emits: exactly three fractional digits, `Z`, never `+00:00`.
    pub fn to_iso(&self) -> String {
        self.0.to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    /// Parse an ISO 8601 string.
    ///
    /// Deliberately permissive on input and strict on output, which matches Node: `new Date(s)`
    /// accepts offsets and varying fractional precision, and `toISOString()` always emits
    /// millisecond `Z`. So a value read from a database written by another client may carry an
    /// offset, and it must normalize rather than fail.
    pub fn parse_iso(s: &str) -> Result<Self, ParseError> {
        DateTime::parse_from_rfc3339(s)
            .map(|dt| Self::from_datetime(dt.with_timezone(&Utc)))
            .map_err(|e| ParseError::invalid_json(format!("invalid date: {s}: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_form_is_exactly_upstreams() {
        let d = ParseDate::parse_iso("2026-08-14T13:34:33.581Z").unwrap();
        assert_eq!(d.to_iso(), "2026-08-14T13:34:33.581Z");
    }

    #[test]
    fn always_three_fractional_digits() {
        // Whole seconds still carry .000, which is what Node's toISOString does.
        let d = ParseDate::parse_iso("2026-01-02T03:04:05Z").unwrap();
        assert_eq!(d.to_iso(), "2026-01-02T03:04:05.000Z");
        // One and two digit fractions are padded, not truncated to nothing.
        assert_eq!(
            ParseDate::parse_iso("2026-01-02T03:04:05.5Z")
                .unwrap()
                .to_iso(),
            "2026-01-02T03:04:05.500Z"
        );
    }

    #[test]
    fn offsets_normalize_to_utc_z() {
        let d = ParseDate::parse_iso("2026-08-14T15:34:33.581+02:00").unwrap();
        assert_eq!(d.to_iso(), "2026-08-14T13:34:33.581Z");
        assert!(!d.to_iso().contains("+00:00"), "must emit Z, never +00:00");
    }

    #[test]
    fn sub_millisecond_input_truncates_at_construction() {
        let a = ParseDate::parse_iso("2026-01-01T00:00:00.123456Z").unwrap();
        let b = ParseDate::parse_iso("2026-01-01T00:00:00.123Z").unwrap();
        // Equality must agree with encoded equality.
        assert_eq!(a, b);
        assert_eq!(a.to_iso(), b.to_iso());
    }

    #[test]
    fn round_trips_losslessly() {
        for s in [
            "1970-01-01T00:00:00.000Z",
            "2026-08-14T13:34:33.581Z",
            "1969-12-31T23:59:59.999Z", // pre-epoch, negative millis
            "2100-12-31T23:59:59.999Z",
        ] {
            let d = ParseDate::parse_iso(s).unwrap();
            assert_eq!(d.to_iso(), s);
            assert_eq!(ParseDate::parse_iso(&d.to_iso()).unwrap(), d);
        }
    }

    #[test]
    fn rejects_garbage_with_a_parse_error() {
        let e = ParseDate::parse_iso("not a date").unwrap_err();
        assert_eq!(e.code, crate::error::ErrorCode::InvalidJson);
        assert!(ParseDate::parse_iso("").is_err());
        // A bare date with no time is not RFC 3339 and must not silently become midnight.
        assert!(ParseDate::parse_iso("2026-08-14").is_err());
    }
}
