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

    /// A stored date, from its millisecond count. `None` outside years 0 through 9999, the range
    /// an ISO 8601 string with a four-digit year can carry, which is what refused such a value
    /// when it was read through its text form.
    pub fn from_timestamp_millis(ms: i64) -> Option<Self> {
        use chrono::Datelike;
        DateTime::from_timestamp_millis(ms)
            .filter(|dt| (0..=9999).contains(&dt.year()))
            .map(Self)
    }

    pub fn now() -> Self {
        Self::from_datetime(Utc::now())
    }

    pub fn timestamp_millis(&self) -> i64 {
        self.0.timestamp_millis()
    }

    /// This date moved by a whole number of milliseconds, as `new Date(t + ms)` moves it. Saturates
    /// at the representable range rather than failing, for the same reason as above.
    #[must_use]
    pub fn plus_millis(&self, ms: i64) -> Self {
        let target = self.0.timestamp_millis().saturating_add(ms);
        Self(DateTime::from_timestamp_millis(target).unwrap_or(self.0))
    }

    pub fn as_datetime(&self) -> DateTime<Utc> {
        self.0
    }

    /// The ISO form Parse emits: exactly three fractional digits, `Z`, never `+00:00`.
    ///
    /// Written digit by digit for years 0 through 9999, which is every date a stored value or a
    /// client's ISO string can carry. A response pays this once per date, and chrono's general
    /// formatter costs several times as much. Any other year takes chrono's form, as before.
    pub fn to_iso(&self) -> String {
        use chrono::{Datelike, Timelike};
        let dt = &self.0;
        let year = dt.year();
        if !(0..=9999).contains(&year) {
            return dt.to_rfc3339_opts(SecondsFormat::Millis, true);
        }
        let mut out = [0u8; 24];
        let mut put = |at: usize, value: u32, width: usize| {
            let mut v = value;
            for i in (0..width).rev() {
                out[at + i] = b'0' + (v % 10) as u8;
                v /= 10;
            }
        };
        put(0, year as u32, 4);
        put(5, dt.month(), 2);
        put(8, dt.day(), 2);
        put(11, dt.hour(), 2);
        put(14, dt.minute(), 2);
        put(17, dt.second(), 2);
        put(20, dt.timestamp_subsec_millis(), 3);
        out[4] = b'-';
        out[7] = b'-';
        out[10] = b'T';
        out[13] = b':';
        out[16] = b':';
        out[19] = b'.';
        out[23] = b'Z';
        // Every byte is an ASCII digit or separator.
        String::from_utf8_lossy(&out).into_owned()
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
    fn a_stored_millisecond_count_reads_as_its_text_form_did() {
        let ms = 1_728_051_862_287;
        let direct = ParseDate::from_timestamp_millis(ms).expect("in range");
        assert_eq!(direct.to_iso(), "2024-10-04T14:24:22.287Z");
        assert_eq!(
            ParseDate::parse_iso(&direct.to_iso()).expect("parses"),
            direct
        );
        // Year 10000 and year -1 have no four-digit form.
        assert!(ParseDate::from_timestamp_millis(253_402_300_800_000).is_none());
        assert!(ParseDate::from_timestamp_millis(-62_167_219_200_001).is_none());
        assert!(ParseDate::from_timestamp_millis(-62_167_219_200_000).is_some());
    }

    #[test]
    fn the_hand_written_form_is_chronos_across_the_range() {
        // Every boundary that changes a digit's width or a field's carry, plus a spread.
        let mut ms: Vec<i64> = vec![
            -62_167_219_200_000, // 0000-01-01T00:00:00.000Z
            0,
            951_782_399_999,     // 2000-02-28T23:59:59.999Z
            951_868_800_000,     // 2000-03-01
            253_402_300_799_999, // 9999-12-31T23:59:59.999Z
        ];
        let mut x: i64 = 1;
        for _ in 0..10_000 {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ms.push(x.rem_euclid(253_402_300_800_000));
        }
        for m in ms {
            let date = ParseDate::from_timestamp_millis(m).expect("in range");
            assert_eq!(
                date.to_iso(),
                date.0.to_rfc3339_opts(SecondsFormat::Millis, true),
                "{m}"
            );
        }
    }

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
