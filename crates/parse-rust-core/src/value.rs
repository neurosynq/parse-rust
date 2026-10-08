//! The `ParseValue` model: every JSON value a client can send or receive in an object body.
//!
//! Two decisions here are load-bearing, and both look like mistakes until the reason is stated.
//!
//! **`ParseMap` preserves key order.** Several upstream behaviors iterate object keys, and the
//! resulting order is observable in golden-file comparison even where it is not semantically
//! meaningful. A `HashMap` destroys it on every round trip and makes snapshot testing impossible.
//!
//! **Nothing here derives `PartialEq`.** A derived one would compile, read as correct, and get
//! both float edge cases backwards at the one call site that decides which keys a client is told
//! about. Use [`deep_strict_eq`], which implements Node's `util.isDeepStrictEqual` semantics.

use indexmap::IndexMap;

use crate::date::ParseDate;
use crate::js_number;

/// An order-preserving string-keyed map. See the module note.
pub type ParseMap = IndexMap<String, ParseValue>;

/// A Parse value.
///
/// The data plane stays dynamic on purpose. There is no compile-time struct per application
/// class, because the schema does not exist at compile time. `Object` and `Array` contents are
/// deliberately opaque.
///
/// Deliberately no `PartialEq`. See the module note.
///
/// **Deliberately not `#[non_exhaustive]`, either**, and that is the opposite of the usual
/// advice. `non_exhaustive` lets a downstream crate keep compiling when a variant is added, by
/// forcing it to carry a wildcard arm. For this type that is precisely the wrong trade: every
/// consumer is a *total* function over the value space, an encoder, a decoder, a storage
/// transform, an equality predicate, and a wildcard arm in any of them is a silent data-loss bug
/// waiting for the next variant. The whole premise of writing this in Rust is that forgetting a
/// case is a compile error; `non_exhaustive` on this enum would make that false across exactly
/// the crate boundary that matters.
///
/// Adding a variant here is a breaking change on purpose. `ErrorCode` keeps `non_exhaustive`,
/// because nobody exhaustively matches sixty error codes and a new one genuinely is additive.
#[derive(Debug, Clone)]
pub enum ParseValue {
    Null,
    Bool(bool),
    /// JavaScript has exactly one number type. Matching its lossiness above 2^53 is the goal,
    /// not avoiding it.
    Number(f64),
    String(String),
    Array(Vec<ParseValue>),
    Object(ParseMap),
    /// `{"__type":"Date","iso":"..."}`, or a bare ISO string at `createdAt`/`updatedAt`.
    Date(ParseDate),
    /// `{"__type":"Pointer","className":"...","objectId":"..."}`
    Pointer {
        class_name: String,
        object_id: String,
    },
    /// `{"__type":"GeoPoint","latitude":n,"longitude":n}`
    GeoPoint {
        latitude: f64,
        longitude: f64,
    },
    /// `{"__type":"Bytes","base64":"..."}`. Held decoded, because Mongo stores BSON Binary and
    /// re-encoding from a canonical byte slice is what keeps the two backends agreeing.
    Bytes(Vec<u8>),
    /// `{"__type":"File","name":"...","url":"..."}`. `url` is absent on a file pointer that has
    /// not been through `expandFilesInObject`, so it is optional rather than defaulted.
    File {
        name: String,
        url: Option<String>,
    },
    /// `{"__type":"Polygon","coordinates":[[lat,lng],...]}`
    ///
    /// Note the axis order: Parse's wire form is **latitude first**, the reverse of GeoJSON.
    /// `PolygonCoder.databaseToJSON` swaps on the way out (`MongoTransform.js:1362-1372`), so
    /// holding it in wire order keeps that swap confined to the Mongo boundary.
    Polygon(Vec<(f64, f64)>),
    /// `{"__type":"Relation","className":"..."}`
    Relation {
        class_name: String,
    },
}

impl ParseValue {
    /// Serialize to the exact bytes Parse Server would emit.
    ///
    /// Numbers go through [`js_number::to_ecma_string`] rather than any Rust float formatter,
    /// for the reasons in that module. Non-finite numbers become `null`, which is what
    /// `JSON.stringify` does; `to_ecma_string` alone would emit `NaN`, which is not valid JSON.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        self.write_json(&mut s);
        s
    }

    /// The length of an object's JSON, without copying the object into a [`ParseValue`].
    pub fn object_json_len(map: &ParseMap) -> usize {
        let mut out = String::new();
        out.push('{');
        for (i, (k, v)) in map.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            write_json_string(k, &mut out);
            out.push(':');
            v.write_json(&mut out);
        }
        out.push('}');
        out.len()
    }

    fn write_json(&self, out: &mut String) {
        match self {
            ParseValue::Null => out.push_str("null"),
            ParseValue::Bool(true) => out.push_str("true"),
            ParseValue::Bool(false) => out.push_str("false"),
            ParseValue::Number(n) => {
                if n.is_finite() {
                    out.push_str(&js_number::to_ecma_string(*n));
                } else {
                    // JSON.stringify(NaN) === "null", same for both infinities.
                    out.push_str("null");
                }
            }
            ParseValue::String(s) => write_json_string(s, out),
            ParseValue::Array(items) => {
                out.push('[');
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write_json(out);
                }
                out.push(']');
            }
            ParseValue::Object(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_string(k, out);
                    out.push(':');
                    v.write_json(out);
                }
                out.push('}');
            }
            ParseValue::Date(d) => {
                out.push_str(r#"{"__type":"Date","iso":"#);
                write_json_string(&d.to_iso(), out);
                out.push('}');
            }
            ParseValue::Pointer {
                class_name,
                object_id,
            } => {
                out.push_str(r#"{"__type":"Pointer","className":"#);
                write_json_string(class_name, out);
                out.push_str(r#","objectId":"#);
                write_json_string(object_id, out);
                out.push('}');
            }
            ParseValue::GeoPoint {
                latitude,
                longitude,
            } => {
                out.push_str(r#"{"__type":"GeoPoint","latitude":"#);
                out.push_str(&js_number::to_ecma_string(*latitude));
                out.push_str(r#","longitude":"#);
                out.push_str(&js_number::to_ecma_string(*longitude));
                out.push('}');
            }
            ParseValue::Bytes(raw) => {
                out.push_str(r#"{"__type":"Bytes","base64":"#);
                write_json_string(&base64_encode(raw), out);
                out.push('}');
            }
            ParseValue::File { name, url } => {
                out.push_str(r#"{"__type":"File","name":"#);
                write_json_string(name, out);
                if let Some(u) = url {
                    out.push_str(r#","url":"#);
                    write_json_string(u, out);
                }
                out.push('}');
            }
            ParseValue::Polygon(coords) => {
                out.push_str(r#"{"__type":"Polygon","coordinates":["#);
                for (i, (lat, lng)) in coords.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('[');
                    out.push_str(&js_number::to_ecma_string(*lat));
                    out.push(',');
                    out.push_str(&js_number::to_ecma_string(*lng));
                    out.push(']');
                }
                out.push_str("]}");
            }
            ParseValue::Relation { class_name } => {
                out.push_str(r#"{"__type":"Relation","className":"#);
                write_json_string(class_name, out);
                out.push('}');
            }
        }
    }
}

impl ParseValue {
    /// The value as a `serde_json::Value`, for a response body.
    ///
    /// **The same value [`Self::to_json`] text parses to, built without the text.** Responses used
    /// to go through the string and back, which costs a full encode and a full parse per row and
    /// changes nothing: without serde_json's `arbitrary_precision` feature a parsed number keeps
    /// its value and not its spelling, so the ECMAScript formatting never reached the wire through
    /// that path either. The number rule below is the parse's: an integral value that fits `u64`,
    /// or a negative one that fits `i64`, is an integer, and anything else is an `f64`. The
    /// equivalence is tested, not argued.
    pub fn to_serde_json(&self) -> serde_json::Value {
        use serde_json::Value as J;
        let object = |pairs: Vec<(&str, J)>| {
            J::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
        };
        match self {
            ParseValue::Null => J::Null,
            ParseValue::Bool(b) => J::Bool(*b),
            ParseValue::Number(n) => json_number(*n),
            ParseValue::String(s) => J::String(s.clone()),
            ParseValue::Array(items) => J::Array(items.iter().map(Self::to_serde_json).collect()),
            ParseValue::Object(map) => J::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), v.to_serde_json()))
                    .collect(),
            ),
            ParseValue::Date(d) => object(vec![
                ("__type", J::String("Date".into())),
                ("iso", J::String(d.to_iso())),
            ]),
            ParseValue::Pointer {
                class_name,
                object_id,
            } => object(vec![
                ("__type", J::String("Pointer".into())),
                ("className", J::String(class_name.clone())),
                ("objectId", J::String(object_id.clone())),
            ]),
            ParseValue::GeoPoint {
                latitude,
                longitude,
            } => object(vec![
                ("__type", J::String("GeoPoint".into())),
                ("latitude", json_number(*latitude)),
                ("longitude", json_number(*longitude)),
            ]),
            ParseValue::Bytes(raw) => object(vec![
                ("__type", J::String("Bytes".into())),
                ("base64", J::String(base64_encode(raw))),
            ]),
            ParseValue::File { name, url } => {
                let mut pairs = vec![
                    ("__type", J::String("File".into())),
                    ("name", J::String(name.clone())),
                ];
                if let Some(u) = url {
                    pairs.push(("url", J::String(u.clone())));
                }
                object(pairs)
            }
            ParseValue::Polygon(coords) => object(vec![
                ("__type", J::String("Polygon".into())),
                (
                    "coordinates",
                    J::Array(
                        coords
                            .iter()
                            .map(|(lat, lng)| J::Array(vec![json_number(*lat), json_number(*lng)]))
                            .collect(),
                    ),
                ),
            ]),
            ParseValue::Relation { class_name } => object(vec![
                ("__type", J::String("Relation".into())),
                ("className", J::String(class_name.clone())),
            ]),
        }
    }
}

/// A number as serde_json would hold it after parsing [`js_number::to_ecma_string`]'s text.
///
/// Below 2^53 an integral value's text is its exact digits, so it converts directly. At and above
/// it, JavaScript prints the shortest round-trip digits padded with zeros, `2**60` as
/// `1152921504606847000` rather than its exact `1152921504606846976`, so those few go through the
/// text, which is the only way to get the same integer.
fn json_number(n: f64) -> serde_json::Value {
    const EXACT: f64 = 9_007_199_254_740_992.0; // 2^53
    if !n.is_finite() {
        return serde_json::Value::Null;
    }
    if n.fract() == 0.0 && n.abs() < EXACT {
        // `-0` prints as `0`, and `0` parses as an unsigned integer.
        return if n >= 0.0 {
            serde_json::Value::Number((n as u64).into())
        } else {
            serde_json::Value::Number((n as i64).into())
        };
    }
    if n.fract() == 0.0 {
        if let Ok(parsed) = serde_json::from_str(&js_number::to_ecma_string(n)) {
            return parsed;
        }
    }
    serde_json::Number::from_f64(n).map_or(serde_json::Value::Null, serde_json::Value::Number)
}

/// Standard base64 with padding, matching what `BytesCoder` accepts
/// (`MongoTransform.js:1306`). Hand-rolled to keep `parse-rust-core` dependency-light; it is 20 lines
/// and the alphabet is fixed by the wire format.
/// Base64, as the `{"__type":"Bytes","base64":...}` envelope spells it.
///
/// Public because the Mongo adapter needs the same spelling when it stores a value verbatim: schema
/// metadata and query atoms both keep a `Bytes` in envelope form rather than as BSON Binary.
pub fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The inverse. Rejects any character outside the alphabet rather than skipping it, because a
/// lenient decoder would silently accept a corrupted payload from an untrusted client.
/// Does this string match `BytesCoder.base64Pattern`?
///
/// ```text
/// ^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$
/// ```
///
/// Written out rather than pulled in as a regex because the shape is simple and the rule is exact:
/// the total length is always a multiple of four, since the optional trailing group is four
/// characters either way, and padding may only be the final one or two characters. The empty string
/// matches, which upstream's pattern also allows.
///
/// **This decides whether a plain string stored in a `Bytes` column is a legacy Bytes value.**
/// `isValidDatabaseObject` is `object instanceof mongodb.Binary || this.isBase64Value(object)`, so
/// a column written by an older parse-server holds the string form and still has to raise to the
/// envelope.
pub fn is_base64_value(s: &str) -> bool {
    if !s.len().is_multiple_of(4) {
        return false;
    }
    let padding = s.bytes().rev().take_while(|b| *b == b'=').count();
    if padding > 2 {
        return false;
    }
    s.as_bytes()[..s.len() - padding]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// JSON string escaping, matching `JSON.stringify`: the two mandatory escapes, the five
/// short forms, and `\u00XX` for the rest of the C0 range. Characters above 0x1F are emitted
/// as-is, including non-ASCII, which is what Node does.
pub(crate) fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Deep equality with Node's `util.isDeepStrictEqual` semantics.
///
/// Two float cases differ from what a derived `PartialEq` would do, and both are reachable:
/// Node compares primitives with `Object.is`, so **`NaN` equals `NaN`** and **`+0.0` does not
/// equal `-0.0`**. `JSON.parse("-0")` yields `-0`, and a stored BSON double can be `-0`, so this
/// is not theoretical.
///
/// Note the deliberate tension with the encoder: `-0.0` and `0.0` compare as distinct here and
/// serialize identically (both as `0`). Both are correct, and both must hold at once.
pub fn deep_strict_eq(a: &ParseValue, b: &ParseValue) -> bool {
    use ParseValue::*;
    match (a, b) {
        (Null, Null) => true,
        (Bool(x), Bool(y)) => x == y,
        (Number(x), Number(y)) => js_object_is(*x, *y),
        (String(x), String(y)) => x == y,
        (Array(x), Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(i, j)| deep_strict_eq(i, j))
        }
        (Object(x), Object(y)) => {
            // Key *order* is preserved by ParseMap but is not part of equality, matching Node,
            // where two objects with the same keys in different orders are deep-strict-equal.
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| deep_strict_eq(v, w)))
        }
        (Date(x), Date(y)) => x == y,
        (
            Pointer {
                class_name: c1,
                object_id: o1,
            },
            Pointer {
                class_name: c2,
                object_id: o2,
            },
        ) => c1 == c2 && o1 == o2,
        (
            GeoPoint {
                latitude: la1,
                longitude: lo1,
            },
            GeoPoint {
                latitude: la2,
                longitude: lo2,
            },
        ) => js_object_is(*la1, *la2) && js_object_is(*lo1, *lo2),
        (Bytes(x), Bytes(y)) => x == y,
        (File { name: n1, url: u1 }, File { name: n2, url: u2 }) => n1 == n2 && u1 == u2,
        (Polygon(x), Polygon(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y)
                    .all(|(a, b)| js_object_is(a.0, b.0) && js_object_is(a.1, b.1))
        }
        (Relation { class_name: c1 }, Relation { class_name: c2 }) => c1 == c2,
        _ => false,
    }
}

/// `Object.is` for f64: NaN equals NaN, and zeros differ by sign.
fn js_object_is(x: f64, y: f64) -> bool {
    if x.is_nan() && y.is_nan() {
        return true;
    }
    x == y && x.is_sign_negative() == y.is_sign_negative()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The direct conversion against the text round trip it replaces, over the values most likely
    /// to differ: number edges, escapes, every typed envelope, nesting.
    #[test]
    fn to_serde_json_is_the_parse_of_to_json() {
        let numbers = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            0.1,
            1.5,
            -2.25,
            1e-7,
            1e21,
            1e20,
            123456789012.0,
            9_007_199_254_740_993.0,
            9.3e18,
            1.8e19,
            1.9e19,
            -9.3e18,
            -9.3e19,
            5e-324,
            1.7e308,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            4294967295.0,
            0.30000000000000004,
        ];
        let mut values: Vec<ParseValue> = numbers.iter().map(|n| ParseValue::Number(*n)).collect();
        values.extend([
            ParseValue::Null,
            ParseValue::Bool(true),
            ParseValue::String(
                "quote \" slash \\ nl \n tab \t ctrl \u{1} uni \u{2028} é \u{1F600}".into(),
            ),
            ParseValue::Date(ParseDate::from_timestamp_millis(1_728_051_862_287).expect("date")),
            ParseValue::Pointer {
                class_name: "C".into(),
                object_id: "x".into(),
            },
            ParseValue::GeoPoint {
                latitude: -33.5,
                longitude: 151.0,
            },
            ParseValue::Bytes(vec![0, 1, 2, 250, 251]),
            ParseValue::File {
                name: "f.png".into(),
                url: None,
            },
            ParseValue::File {
                name: "f.png".into(),
                url: Some("http://x/f.png".into()),
            },
            ParseValue::Polygon(vec![(1.0, 2.5), (-3.0, 4.0)]),
            ParseValue::Relation {
                class_name: "R".into(),
            },
        ]);
        let mut nested = ParseMap::new();
        nested.insert("z".into(), ParseValue::Array(values.clone()));
        nested.insert("a".into(), ParseValue::Number(1e21));
        values.push(ParseValue::Object(nested));
        for v in values {
            let via_text: serde_json::Value =
                serde_json::from_str(&v.to_json()).expect("valid JSON");
            let direct = v.to_serde_json();
            assert_eq!(direct, via_text, "{}", v.to_json());
            assert_eq!(
                serde_json::to_string(&direct).expect("encodes"),
                serde_json::to_string(&via_text).expect("encodes")
            );
        }
    }

    fn n(v: f64) -> ParseValue {
        ParseValue::Number(v)
    }
    fn s(v: &str) -> ParseValue {
        ParseValue::String(v.to_string())
    }

    #[test]
    fn numbers_serialize_through_the_ecmascript_formatter() {
        assert_eq!(n(100.0).to_json(), "100");
        assert_eq!(n(1e20).to_json(), "100000000000000000000");
        assert_eq!(n(1e-6).to_json(), "0.000001");
        assert_eq!(n(-0.0).to_json(), "0");
    }

    #[test]
    fn non_finite_numbers_become_null_not_nan() {
        assert_eq!(n(f64::NAN).to_json(), "null");
        assert_eq!(n(f64::INFINITY).to_json(), "null");
        assert_eq!(n(f64::NEG_INFINITY).to_json(), "null");
    }

    #[test]
    fn object_key_order_survives_serialization() {
        let mut m = ParseMap::new();
        m.insert("zebra".into(), n(1.0));
        m.insert("apple".into(), n(2.0));
        m.insert("mango".into(), n(3.0));
        assert_eq!(
            ParseValue::Object(m).to_json(),
            r#"{"zebra":1,"apple":2,"mango":3}"#,
            "insertion order must be preserved, not sorted"
        );
    }

    #[test]
    fn tagged_types_have_the_upstream_key_order() {
        let d = ParseDate::parse_iso("2026-08-14T13:34:33.581Z").unwrap();
        assert_eq!(
            ParseValue::Date(d).to_json(),
            r#"{"__type":"Date","iso":"2026-08-14T13:34:33.581Z"}"#
        );
        assert_eq!(
            ParseValue::Pointer {
                class_name: "_User".into(),
                object_id: "abc123".into()
            }
            .to_json(),
            r#"{"__type":"Pointer","className":"_User","objectId":"abc123"}"#
        );
        assert_eq!(
            ParseValue::GeoPoint {
                latitude: 40.0,
                longitude: -75.5
            }
            .to_json(),
            r#"{"__type":"GeoPoint","latitude":40,"longitude":-75.5}"#
        );
    }

    #[test]
    fn string_escaping_matches_json_stringify() {
        assert_eq!(s(r#"a"b"#).to_json(), r#""a\"b""#);
        assert_eq!(s("a\\b").to_json(), r#""a\\b""#);
        assert_eq!(s("a\nb").to_json(), r#""a\nb""#);
        // C0 controls take the \u00xx form, lowercase hex. Verified against Node:
        //   JSON.stringify("a" + String.fromCharCode(1) + "b")  ->  "a\\u0001b"
        assert_eq!(s("a\u{1}b").to_json(), "\"a\\u0001b\"");
        assert_eq!(s("a\u{1f}b").to_json(), "\"a\\u001fb\"");
        // Non-ASCII is emitted raw, as Node does.
        assert_eq!(s("héllo").to_json(), "\"héllo\"");
    }

    #[test]
    fn deep_strict_eq_follows_object_is_on_floats() {
        // The two cases a derived PartialEq gets backwards.
        assert!(
            deep_strict_eq(&n(f64::NAN), &n(f64::NAN)),
            "NaN must equal NaN"
        );
        assert!(!deep_strict_eq(&n(0.0), &n(-0.0)), "+0 must not equal -0");
        assert!(deep_strict_eq(&n(0.0), &n(0.0)));
        assert!(deep_strict_eq(&n(-0.0), &n(-0.0)));
    }

    #[test]
    fn minus_zero_compares_distinct_but_serializes_identically() {
        // Both properties are required at once. This test exists to stop someone "fixing" one.
        assert!(!deep_strict_eq(&n(0.0), &n(-0.0)));
        assert_eq!(n(0.0).to_json(), n(-0.0).to_json());
    }

    #[test]
    fn deep_strict_eq_ignores_key_order_but_not_content() {
        let mut a = ParseMap::new();
        a.insert("x".into(), n(1.0));
        a.insert("y".into(), n(2.0));
        let mut b = ParseMap::new();
        b.insert("y".into(), n(2.0));
        b.insert("x".into(), n(1.0));
        assert!(deep_strict_eq(
            &ParseValue::Object(a.clone()),
            &ParseValue::Object(b)
        ));

        let mut c = ParseMap::new();
        c.insert("x".into(), n(1.0));
        assert!(!deep_strict_eq(
            &ParseValue::Object(a),
            &ParseValue::Object(c)
        ));
    }

    #[test]
    fn deep_strict_eq_is_recursive_and_type_strict() {
        let nested = |v: ParseValue| ParseValue::Array(vec![ParseValue::Array(vec![v])]);
        assert!(deep_strict_eq(&nested(n(1.0)), &nested(n(1.0))));
        assert!(!deep_strict_eq(&nested(n(1.0)), &nested(n(2.0))));
        // No cross-type coercion: 1 is not "1" and not true.
        assert!(!deep_strict_eq(&n(1.0), &s("1")));
        assert!(!deep_strict_eq(&n(1.0), &ParseValue::Bool(true)));
        assert!(!deep_strict_eq(&ParseValue::Null, &ParseValue::Bool(false)));
    }
}
