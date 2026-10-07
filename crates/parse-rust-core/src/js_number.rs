//! ECMAScript `Number::toString(x, 10)`, which is what `JSON.stringify` uses for numbers.
//!
//! This exists because `serde_json` formats `f64` with ryu, producing the shortest
//! round-tripping decimal, and that is **not** the same string ECMAScript produces. Parse
//! Server is a Node server, so its number output is ECMAScript's, and wire compatibility
//! means matching it byte for byte.
//!
//! Measured divergences between ryu and `JSON.stringify`, all reproduced in the tests below:
//!
//! | Value    | `JSON.stringify` | `serde_json` |
//! |----------|------------------|--------------|
//! | `100.0`  | `100`            | `100.0`      |
//! | `1e20`   | `100000000000000000000` | `1e20` |
//! | `1e-6`   | `0.000001`       | `1e-6`       |
//! | `-0.0`   | `0`              | `-0.0`       |
//!
//! Not a divergence, despite looking like one: both emit `+` in a positive exponent, so
//! `1.5e+300` already matches. Do not "fix" that.
//!
//! Spec: ECMA-262 §6.1.6.1.20, `Number::toString`.
//!
//! Note the distinction this module does *not* cover: number **representation**, meaning which
//! BSON type a value is stored as, is a separate problem handled at the storage boundary in
//! `parse-rust-mongo`. Conflating the two is a mistake this project made once.

use std::fmt::Write as _;

/// Format an `f64` exactly as ECMAScript's `String(x)` / `JSON.stringify(x)` would.
///
/// Note `NaN` and the infinities: this returns their ECMAScript *string* forms, which is
/// correct for `String(x)` but is **not** valid JSON. `JSON.stringify` emits `null` for all
/// three. Callers serializing to JSON must handle that before calling here; the encoder in
/// `crate::value` does.
pub fn to_ecma_string(x: f64) -> String {
    if x.is_nan() {
        return "NaN".to_string();
    }
    // Step 2: both zeros render as "0". The sign of -0.0 is deliberately dropped.
    if x == 0.0 {
        return "0".to_string();
    }
    if x < 0.0 {
        return format!("-{}", to_ecma_string(-x));
    }
    if x.is_infinite() {
        return "Infinity".to_string();
    }

    let (digits, n) = shortest_digits(x);
    let k = digits.len() as i32;
    render(&digits, k, n)
}

/// Decompose a positive, finite `f64` into its shortest round-tripping decimal digits and the
/// position of the decimal point.
///
/// Returns `(digits, n)` with no trailing zeros, such that `0.<digits> * 10^n == x`. This is
/// `s` and `n` from the spec, with `k = digits.len()`.
///
/// **Uses ryu, not `format!("{:e}")`, and the difference is not cosmetic.** Spec step 5 does not
/// merely ask for a shortest representation, it asks for a specific one: among candidates of
/// minimal length, the one closest in value to `x`, breaking a remaining tie toward the even
/// digit. Rust's `Display`/`LowerExp` guarantee only that the result round-trips, which is a
/// weaker property, and the two disagree in practice.
///
/// Found by the differential test in `tests/js_number_differential.rs`, not by reading:
/// `f64::from_bits(4829166033435530498)` renders as `726354065216160.3` via `{:e}` and
/// `726354065216160.2` via ryu and Node. Both strings parse back to the identical bit pattern,
/// so both are "shortest round-tripping"; only ryu's is the closest to the true value.
fn shortest_digits(x: f64) -> (String, i32) {
    let mut buf = ryu::Buffer::new();
    let s = buf.format_finite(x); // "100.0", "0.1", "1e20", "1.5e300", "726354065216160.2"

    let (mantissa, exp10) = match s.split_once('e') {
        // Scientific: mantissa is d[.ddd], exponent has no explicit '+'.
        Some((m, e)) => (m, e.parse::<i32>().unwrap_or(0)),
        None => (s, 0),
    };

    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));

    // n counts digits before the decimal point. For a pure fraction ryu emits "0.000ddd", and
    // each leading zero in the fraction pushes the point one place further right.
    let (digits, n) = if int_part == "0" {
        let lead_zeros = frac_part.len() - frac_part.trim_start_matches('0').len();
        (frac_part[lead_zeros..].to_string(), -(lead_zeros as i32))
    } else {
        let mut d = String::with_capacity(int_part.len() + frac_part.len());
        d.push_str(int_part);
        d.push_str(frac_part);
        (d, int_part.len() as i32)
    };

    // ryu writes "100.0" for an integer, so the combined digits can carry trailing zeros that
    // inflate k and would push a value into the wrong rendering branch.
    let trimmed = digits.trim_end_matches('0');
    let digits = if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    };

    (digits, n + exp10)
}

/// Steps 6 through 10 of ECMA-262 §6.1.6.1.20, given the digits, their count `k`, and the
/// decimal point position `n`.
fn render(digits: &str, k: i32, n: i32) -> String {
    // Step 6: k <= n <= 21. Integer, padded with n-k trailing zeros, no fractional part.
    if k <= n && n <= 21 {
        let mut s = String::with_capacity(n as usize);
        s.push_str(digits);
        for _ in 0..(n - k) {
            s.push('0');
        }
        return s;
    }
    // Step 7: 0 < n <= 21. Decimal point falls inside the digits.
    if 0 < n && n <= 21 {
        let (int_part, frac_part) = digits.split_at(n as usize);
        return format!("{int_part}.{frac_part}");
    }
    // Step 8: -6 < n <= 0. Leading "0." then -n zeros then the digits.
    if -6 < n && n <= 0 {
        let mut s = String::with_capacity((2 - n) as usize + digits.len());
        s.push_str("0.");
        for _ in 0..(-n) {
            s.push('0');
        }
        s.push_str(digits);
        return s;
    }
    // Steps 9 and 10: exponential. The exponent is n-1, and its sign is always explicit.
    let e = n - 1;
    let sign = if e >= 0 { '+' } else { '-' };
    let mut s = String::new();
    if k == 1 {
        // Step 9: single digit, no decimal point.
        let _ = write!(s, "{digits}e{sign}{}", e.abs());
    } else {
        // Step 10: first digit, point, remainder.
        let (first, rest) = digits.split_at(1);
        let _ = write!(s, "{first}.{rest}e{sign}{}", e.abs());
    }
    s
}

/// `String(value)`, the coercion a JavaScript template literal or `+` performs.
///
/// Upstream builds several client-visible error messages by concatenating a value into a string,
/// so the rendering is part of the wire contract rather than a debugging convenience:
/// `You cannot use ${value} as a query parameter.` (`MongoTransform.js:352`) and
/// `'This is not a valid ' + obj.__type` (`SchemaController.js`) both reach a client.
///
/// The two cases worth naming: an array joins its elements on commas **after** coercing each one,
/// so nesting flattens and `null` renders as the empty string; and every other object is the
/// literal `[object Object]`, which is why a malformed operand's message says nothing about it.
pub fn to_ecma_display(value: &crate::value::ParseValue) -> String {
    use crate::value::ParseValue;
    match value {
        ParseValue::String(s) => s.clone(),
        ParseValue::Number(n) => to_ecma_string(*n),
        ParseValue::Bool(b) => b.to_string(),
        ParseValue::Null => "null".to_string(),
        ParseValue::Array(items) => items
            .iter()
            .map(|item| match item {
                // `Array.prototype.join` renders null and undefined as empty, which is not what
                // `String(null)` does. The difference is only visible inside an array.
                ParseValue::Null => String::new(),
                other => to_ecma_display(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        _ => "[object Object]".to_string(),
    }
}

/// ECMAScript `StringToNumber`: surrounding whitespace ignored, empty is zero, `Infinity` and the
/// `0x`, `0o` and `0b` prefixes recognised, anything else that is not a decimal literal `NaN`.
pub fn string_to_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    // `from_str_radix` accepts a leading sign, which `Number("0x+10")` does not: `NaN`.
    let radix = |digits: &str, base: u32| {
        if digits.is_empty() || !digits.chars().all(|c| c.is_digit(base)) {
            return f64::NAN;
        }
        u64::from_str_radix(digits, base).map_or(f64::NAN, |n| n as f64)
    };
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return radix(h, 16);
    }
    if let Some(o) = t.strip_prefix("0o").or_else(|| t.strip_prefix("0O")) {
        return radix(o, 8);
    }
    if let Some(b) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
        return radix(b, 2);
    }
    let decimal = t
        .bytes()
        .all(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'));
    if !decimal || t.contains("inf") || t.contains("nan") {
        return f64::NAN;
    }
    t.parse().unwrap_or(f64::NAN)
}

/// JavaScript's `Number(value)`, which the arithmetic and comparison operators apply implicitly:
/// `"100" / 6371` divides, `isNaN(null)` is false because `null` is 0.
pub fn to_number(value: &crate::value::ParseValue) -> f64 {
    use crate::value::ParseValue;
    match value {
        ParseValue::Number(n) => *n,
        ParseValue::Null => 0.0,
        ParseValue::Bool(b) => f64::from(u8::from(*b)),
        ParseValue::String(s) => string_to_number(s),
        // Through `String()`, so `[5]` is 5, `[]` is 0 and `[1,2]` is `NaN`.
        ParseValue::Array(_) => string_to_number(&to_ecma_display(value)),
        _ => f64::NAN,
    }
}

/// JavaScript truthiness.
///
/// Upstream guards several schema decisions with a bare `if (obj.key)`, which is **not** a presence
/// test: `""`, `0`, `false` and `NaN` are all present and all falsy, and an empty array or object
/// is falsy in neither JavaScript nor here. Reading those guards as "is the key set" accepts
/// metadata upstream refuses, and reading them as "is the key a string" refuses metadata upstream
/// accepts.
pub fn is_truthy(value: &crate::value::ParseValue) -> bool {
    use crate::value::ParseValue;
    match value {
        ParseValue::Null => false,
        ParseValue::Bool(b) => *b,
        ParseValue::Number(n) => *n != 0.0 && !n.is_nan(),
        ParseValue::String(s) => !s.is_empty(),
        // Every object is truthy in JavaScript, an empty array and an empty object included.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every expectation here was produced by running the value through Node and pasting the
    /// output, not by reasoning about the spec. `tests/js_number_differential.rs`, driving `tools/js-number-oracle.js`, re-derives
    /// them at scale against a live Node.
    #[test]
    fn matches_node_on_the_known_divergences() {
        // The four rules where ryu and ECMAScript disagree.
        assert_eq!(to_ecma_string(100.0), "100"); // ryu: 100.0
        assert_eq!(to_ecma_string(3_000_000_000.0), "3000000000"); // ryu: 3000000000.0
        assert_eq!(to_ecma_string(1e20), "100000000000000000000"); // ryu: 1e20
        assert_eq!(to_ecma_string(1e-6), "0.000001"); // ryu: 1e-6
        assert_eq!(to_ecma_string(-0.0), "0"); // ryu: -0.0
    }

    #[test]
    fn agrees_with_ryu_where_it_already_agreed() {
        // Guards against "fixing" the exponent sign, which ryu already gets right.
        assert_eq!(to_ecma_string(1.5e300), "1.5e+300");
        assert_eq!(to_ecma_string(1e21), "1e+21");
        assert_eq!(to_ecma_string(1e-7), "1e-7");
        assert_eq!(to_ecma_string(0.1), "0.1");
        assert_eq!(to_ecma_string(5e-324), "5e-324");
        assert_eq!(to_ecma_string(f64::MAX), "1.7976931348623157e+308");
    }

    #[test]
    fn boundaries_are_exact() {
        // Upper switch to exponential is at 1e21, not before.
        assert_eq!(to_ecma_string(1e20), "100000000000000000000");
        assert_eq!(to_ecma_string(1e21), "1e+21");
        // Lower switch is at 1e-7, not 1e-6.
        assert_eq!(to_ecma_string(1e-6), "0.000001");
        assert_eq!(to_ecma_string(1e-7), "1e-7");
        // 21 significant digits still renders as an integer below 1e21.
        assert_eq!(
            to_ecma_string(123456789012345678901.0),
            "123456789012345680000"
        );
    }

    #[test]
    fn integers_and_fractions() {
        assert_eq!(to_ecma_string(0.0), "0");
        assert_eq!(to_ecma_string(1.0), "1");
        assert_eq!(to_ecma_string(-1.0), "-1");
        assert_eq!(to_ecma_string(1.5), "1.5");
        assert_eq!(to_ecma_string(-1.5), "-1.5");
        assert_eq!(to_ecma_string(9007199254740992.0), "9007199254740992"); // 2^53
        assert_eq!(to_ecma_string(-1e21), "-1e+21");
    }

    #[test]
    fn non_finite_are_ecmascript_strings_not_json() {
        // Documented above: these are String(x), not JSON. The value encoder maps them to null.
        assert_eq!(to_ecma_string(f64::NAN), "NaN");
        assert_eq!(to_ecma_string(f64::INFINITY), "Infinity");
        assert_eq!(to_ecma_string(f64::NEG_INFINITY), "-Infinity");
    }

    #[test]
    fn round_trips_through_parse() {
        // Whatever we emit must parse back to the same bits, since the digits are shortest
        // round-tripping by construction. Catches an error in the rendering steps.
        let vals = [
            1.0,
            100.0,
            0.1,
            1e20,
            1e21,
            1e-6,
            1e-7,
            1.5e300,
            5e-324,
            f64::MAX,
            9007199254740992.0,
            123456789012345678901.0,
            -42.75,
            2.2250738585072014e-308,
        ];
        for v in vals {
            let s = to_ecma_string(v);
            let back: f64 = s
                .parse()
                .unwrap_or_else(|e| panic!("{s} did not reparse: {e}"));
            assert_eq!(back.to_bits(), v.to_bits(), "round trip failed for {s}");
        }
    }
}
