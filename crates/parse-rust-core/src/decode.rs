//! `classify`: `serde_json::Value` to [`ParseValue`].
//!
//! The inverse of [`ParseValue::to_json`]. Everything above `parse-rust-core` needs this, because a
//! request body arrives as untyped JSON and has to become a typed value before any pipeline can
//! reason about it.
//!
//! Two upstream behaviors shape the signature, and both are easy to get wrong in the safer
//! direction:
//!
//! **Unknown `__type` is rejected at the top level and preserved when nested.**
//! `validateObject` raises `INCORRECT_TYPE` for an unrecognized `__type`, but it does not
//! recurse, so a nested one is stored verbatim as an ordinary object
//! (`SchemaController.js:1304`), and it is reproduced deliberately. A recursive
//! rejection would be tidier and would reject writes parse-server accepts.
//!
//! **A literal `null` is a value, not an absence.** It classifies as [`ParseValue::Null`] here.
//! The rule that writing `null` never creates a field lives in the schema controller, not in the
//! decoder, because it is a schema decision rather than a parsing one.

use serde_json::Value as Json;

use crate::date::ParseDate;
use crate::error::{ErrorCode, ParseError};
use crate::value::{base64_decode, ParseMap, ParseValue};

/// Decode a client-supplied JSON value.
///
/// Top-level semantics: an unrecognized `__type` is an error. Use this for the values of an
/// object body's own fields.
pub fn classify(value: Json) -> Result<ParseValue, ParseError> {
    classify_at(value, true)
}

/// Decode a value that sits inside an array or a plain object.
///
/// Differs from [`classify`] only in that an unrecognized `__type` is kept as a plain object
/// rather than rejected, which is what upstream does.
pub fn classify_nested(value: Json) -> Result<ParseValue, ParseError> {
    classify_at(value, false)
}

/// Which of upstream's two atom transforms applies at a given position.
///
/// **The two recognize different tag lists, and which one applies is a property of the field, not
/// of the value** (`MongoTransform.js:655-662`). That is why this is an argument to
/// [`recognize_atom`] at lowering time rather than a choice made by the parser: the parser does not
/// have the schema, and guessing is wrong in both directions. Guessing top-level makes a GeoPoint
/// compared against an `Array` field match a row upstream does not return, because the extra key
/// upstream would have compared is discarded; guessing interior makes a GeoPoint compared against a
/// `GeoPoint` field fail to match a row upstream does return, for the mirror reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomPosition {
    /// `transformInteriorAtom` (`MongoTransform.js:566-584`): **Pointer, Date and Bytes only.**
    ///
    /// GeoPoint, File, Polygon and Relation are deliberately absent. Upstream leaves them as plain
    /// objects here, so they are compared whole, extra keys included. Its fourth arm is `$regex`,
    /// which is not a `__type` and is handled by the lowering.
    Interior,
    /// `transformTopLevelAtom` (`MongoTransform.js:594-652`): **Pointer, Date, Bytes, GeoPoint,
    /// Polygon and File.**
    ///
    /// Six, not seven. `Relation` has no arm and no coder, so at the top level it is not an atom at
    /// all and the caller refuses it. "Every Parse type" is the summary that reads right and is
    /// wrong by one, and the one it is wrong by is reachable: `{"field": {"__type": "Relation"}}`
    /// answers 107 upstream.
    TopLevel,
}

/// The tags each position recognizes, which is the whole of the difference between them.
const INTERIOR_TAGS: [&str; 3] = ["Pointer", "Date", "Bytes"];
const TOP_LEVEL_TAGS: [&str; 6] = ["Pointer", "Date", "Bytes", "GeoPoint", "Polygon", "File"];

/// Rebuild a recognized `__type` envelope on an otherwise-raw value. Never recurses.
///
/// The asymmetry this preserves is upstream's, measured at the pin against an `$in` over an array
/// field:
///
/// | operand | upstream |
/// |---|---|
/// | element **is** a Pointer | matches |
/// | element **is** a Pointer plus an unknown key | still matches |
/// | Pointer **nested** in a plain object | matches |
/// | Pointer nested in a plain object, plus an unknown key | **does not match** |
///
/// Upstream *reconstructs* a recognized atom from its declared keys, so an extra key on the atom
/// itself is discarded and cannot affect the comparison, while a plain object is returned untouched
/// and is therefore compared whole. Decoding all the way down, which is what [`classify`] does,
/// collapses those two rows into one: the nested extra key is dropped, the operand compares equal,
/// and the query matches a row upstream does not return.
///
/// A value that is already a decoded atom is returned unchanged, so a constraint built in Rust
/// rather than parsed from a request passes through untouched.
///
/// **Payload validation here is stricter than upstream's, deliberately.** Every coder's
/// `isValidJSON` is the tag test and nothing else (`MongoTransform.js`, the five `*Coder` objects),
/// so upstream converts a malformed envelope instead of declining it, and what it converts it to is
/// not worth reproducing. Measured against a running server at the pin: `{"__type":"Date"}` becomes
/// an Invalid Date and matches nothing, `{"__type":"GeoPoint"}` becomes `[null, null]` and matches
/// nothing, `{"__type":"Pointer","className":"C"}` compares against the literal string
/// `C$undefined`, `{"__type":"File"}` yields `undefined` and so compares as `null`, matching rows
/// where the field is null or absent, and `{"__type":"Bytes"}` raises a Node `TypeError` rather
/// than a Parse error, which is a 500. Every one of those is a comparison against a value the
/// client never wrote, or a crash.
///
/// Declining to recognize a malformed envelope leaves it a plain object, which the caller then
/// refuses with upstream's own 107 for a non-atom. **Narrowing in every case**, which is the safe
/// direction: parse-rust refuses where upstream answers with a garbage match. Recorded as a Tier 2
/// divergence.
///
/// An earlier version of this note called the File case a broadening bug that returned every row,
/// and cited the security carve-out. That was wrong, and wrong in an instructive way: it read
/// `JSON.stringify` dropping an `undefined` key as the key being absent from the query. The driver
/// serializes it as `null`, so the constraint is applied and narrows. A rendering is not a
/// behavior. Verified against a live server rather than against a transform's return value.
pub fn recognize_atom(value: ParseValue, position: AtomPosition) -> ParseValue {
    let recognized = match &value {
        ParseValue::Object(map) => match map.get("__type") {
            Some(ParseValue::String(tag)) => match position {
                AtomPosition::Interior => INTERIOR_TAGS.contains(&tag.as_str()),
                AtomPosition::TopLevel => TOP_LEVEL_TAGS.contains(&tag.as_str()),
            },
            _ => false,
        },
        _ => false,
    };
    if !recognized {
        return value;
    }
    let Some(json) = to_json_value(&value) else {
        return value;
    };
    match classify_at(json, false) {
        // Only an actual atom counts. A malformed envelope is not one, and upstream's coders answer
        // the same way: `DateCoder.isValidJSON` is a shape test, and a failed one falls to
        // `return atom`. Listing the variants rather than excluding `Object` also keeps a decode
        // that somehow produced a scalar from silently replacing the operand.
        //
        // **`Relation` is listed here even though no position admits the tag**, and that is
        // deliberate rather than sloppy. This match asks "did the decode produce an atom", which is
        // a different question from "is this tag recognized here", and the tag lists above are the
        // single place the second question is answered. Leaving `Relation` out made the two guards
        // redundant, so a mutation that put `Relation` back on the top-level list changed no
        // observable behavior and the test written to catch it passed. One rule, one place.
        Ok(
            decoded @ (ParseValue::Date(_)
            | ParseValue::Pointer { .. }
            | ParseValue::GeoPoint { .. }
            | ParseValue::Bytes(_)
            | ParseValue::File { .. }
            | ParseValue::Polygon(_)
            | ParseValue::Relation { .. }),
        ) => decoded,
        _ => value,
    }
}

/// The JSON a value encodes to.
///
/// Goes through [`ParseValue::to_json`] rather than restating every envelope form, so it cannot
/// drift from the encoder: it *is* the encoder. Private because the only caller is
/// [`recognize_atom`] and the failure case has no sensible general answer. `None` means
/// `write_json` emitted something that is not JSON, which would be a bug in the encoder rather than
/// in the input, and recognition answers it by declining to recognize.
fn to_json_value(value: &ParseValue) -> Option<Json> {
    serde_json::from_str(&value.to_json()).ok()
}

/// Decode without interpreting a single `__type` envelope, at any depth.
///
/// **For the two places that must keep what the client sent rather than what it meant.**
/// [`classify`] and [`classify_nested`] both recognize `{"__type": "Date", ...}` and turn it into a
/// `Date`, which is right for a column value and destructive everywhere else: the instant is
/// re-rendered in UTC, base64 is re-padded, and any key beyond the ones the envelope declares is
/// dropped, because a `ParseValue::Date` has nowhere to put it.
///
/// That loss is invisible locally, since parse-rust decodes its own storage the same way it encoded
/// it. It is visible to the other node and to the database:
///
/// - **Schema metadata.** A `defaultValue` is stored, never enforced, and read back by whoever asks.
///   Upstream stores the JSON it was sent, so a parse-server node reads back an offset instant, an
///   unpadded base64 string and every extra key. Canonicalizing means it reads something the client
///   never wrote.
/// - **Query operands.** An operand is compared, not stored, and upstream compares it unconverted
///   (`transformInteriorAtom` returns a generic object as-is). Decoding it first builds a *different
///   predicate*: `$in` with a nested pointer carrying an extra key matches a row upstream does not
///   return, because upstream is comparing three keys and parse-rust is comparing two.
///
/// Numbers still go through the same range check, so this is "no interpretation", not "no
/// validation".
pub fn classify_raw(value: Json) -> Result<ParseValue, ParseError> {
    match value {
        Json::Null => Ok(ParseValue::Null),
        Json::Bool(b) => Ok(ParseValue::Bool(b)),
        Json::Number(n) => n
            .as_f64()
            .map(ParseValue::Number)
            .ok_or_else(|| ParseError::invalid_json(format!("number out of range: {n}"))),
        Json::String(s) => Ok(ParseValue::String(s)),
        Json::Array(items) => items
            .into_iter()
            .map(classify_raw)
            .collect::<Result<Vec<_>, _>>()
            .map(ParseValue::Array),
        Json::Object(map) => {
            let mut out = ParseMap::new();
            for (k, v) in map {
                out.insert(k, classify_raw(v)?);
            }
            Ok(ParseValue::Object(out))
        }
    }
}

fn classify_at(value: Json, top_level: bool) -> Result<ParseValue, ParseError> {
    match value {
        Json::Null => Ok(ParseValue::Null),
        Json::Bool(b) => Ok(ParseValue::Bool(b)),
        Json::Number(n) => n
            .as_f64()
            .map(ParseValue::Number)
            .ok_or_else(|| ParseError::invalid_json(format!("number out of range: {n}"))),
        Json::String(s) => Ok(ParseValue::String(s)),
        Json::Array(items) => items
            .into_iter()
            .map(classify_nested)
            .collect::<Result<Vec<_>, _>>()
            .map(ParseValue::Array),
        Json::Object(map) => classify_object(map, top_level),
    }
}

fn classify_object(
    map: serde_json::Map<String, Json>,
    top_level: bool,
) -> Result<ParseValue, ParseError> {
    let tag = match map.get("__type") {
        Some(Json::String(t)) => t.clone(),
        // A non-string `__type` is not a tagged value. Upstream's checks are all string
        // comparisons, so it falls through to being an ordinary object.
        _ => return plain_object(map),
    };

    match tag.as_str() {
        "Date" => {
            let iso = require_str(&map, "iso", "Date")?;
            Ok(ParseValue::Date(ParseDate::parse_iso(iso)?))
        }
        "Pointer" => Ok(ParseValue::Pointer {
            class_name: require_str(&map, "className", "Pointer")?.to_string(),
            object_id: require_str(&map, "objectId", "Pointer")?.to_string(),
        }),
        "GeoPoint" => Ok(ParseValue::GeoPoint {
            latitude: require_f64(&map, "latitude", "GeoPoint")?,
            longitude: require_f64(&map, "longitude", "GeoPoint")?,
        }),
        "Bytes" => {
            let b64 = require_str(&map, "base64", "Bytes")?;
            base64_decode(b64)
                .map(ParseValue::Bytes)
                .ok_or_else(|| ParseError::incorrect_type("invalid base64 in Bytes".to_string()))
        }
        "File" => Ok(ParseValue::File {
            name: require_str(&map, "name", "File")?.to_string(),
            url: match map.get("url") {
                Some(Json::String(u)) => Some(u.clone()),
                _ => None,
            },
        }),
        "Polygon" => {
            let coords = match map.get("coordinates") {
                Some(Json::Array(a)) => a,
                _ => {
                    return Err(ParseError::incorrect_type(
                        "Polygon requires a coordinates array".to_string(),
                    ))
                }
            };
            let mut out = Vec::with_capacity(coords.len());
            for pair in coords {
                match pair {
                    // Latitude first. See the note on ParseValue::Polygon.
                    Json::Array(p) if p.len() == 2 => {
                        let lat = p[0].as_f64();
                        let lng = p[1].as_f64();
                        match (lat, lng) {
                            (Some(a), Some(b)) => out.push((a, b)),
                            _ => {
                                return Err(ParseError::incorrect_type(
                                    "Polygon coordinates must be numbers".to_string(),
                                ))
                            }
                        }
                    }
                    _ => {
                        return Err(ParseError::incorrect_type(
                            "Polygon coordinates must be [latitude, longitude] pairs".to_string(),
                        ))
                    }
                }
            }
            Ok(ParseValue::Polygon(out))
        }
        "Relation" => Ok(ParseValue::Relation {
            class_name: require_str(&map, "className", "Relation")?.to_string(),
        }),
        other => {
            if top_level {
                // Matches `validateObject`. The message shape is upstream's.
                Err(ParseError::new(
                    ErrorCode::IncorrectType,
                    format!("invalid type: {other}"),
                ))
            } else {
                // Nested: kept verbatim, because upstream does not recurse.
                plain_object(map)
            }
        }
    }
}

fn plain_object(map: serde_json::Map<String, Json>) -> Result<ParseValue, ParseError> {
    let mut out = ParseMap::with_capacity(map.len());
    for (k, v) in map {
        out.insert(k, classify_nested(v)?);
    }
    Ok(ParseValue::Object(out))
}

fn require_str<'a>(
    map: &'a serde_json::Map<String, Json>,
    key: &str,
    tag: &str,
) -> Result<&'a str, ParseError> {
    match map.get(key) {
        Some(Json::String(s)) => Ok(s),
        _ => Err(ParseError::incorrect_type(format!(
            "{tag} requires a string {key}"
        ))),
    }
}

fn require_f64(
    map: &serde_json::Map<String, Json>,
    key: &str,
    tag: &str,
) -> Result<f64, ParseError> {
    match map.get(key).and_then(|v| v.as_f64()) {
        Some(n) => Ok(n),
        None => Err(ParseError::incorrect_type(format!(
            "{tag} requires a numeric {key}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::deep_strict_eq;

    fn j(s: &str) -> Json {
        serde_json::from_str(s).expect("test literal must be valid JSON")
    }

    /// The property that matters most: anything we can emit, we can read back to the same value.
    fn round_trips(src: &str) {
        let v = classify(j(src)).expect("classify failed");
        let encoded = v.to_json();
        assert_eq!(encoded, src, "encoding changed the bytes");
        let again = classify(j(&encoded)).expect("re-classify failed");
        assert!(deep_strict_eq(&v, &again), "value changed on round trip");
    }

    #[test]
    fn primitives_round_trip() {
        for s in [
            "null",
            "true",
            "false",
            "0",
            "100",
            "-1.5",
            "0.000001",
            "100000000000000000000",
            r#""hello""#,
            r#""with \"quotes\" and \n""#,
            "[]",
            "[1,2,3]",
            "{}",
        ] {
            round_trips(s);
        }
    }

    #[test]
    fn tagged_types_round_trip() {
        round_trips(r#"{"__type":"Date","iso":"2026-08-14T13:34:33.581Z"}"#);
        round_trips(r#"{"__type":"Pointer","className":"_User","objectId":"abc123"}"#);
        round_trips(r#"{"__type":"GeoPoint","latitude":40,"longitude":-75.5}"#);
        round_trips(r#"{"__type":"Bytes","base64":"aGVsbG8="}"#);
        round_trips(r#"{"__type":"File","name":"a.png","url":"http://x/a.png"}"#);
        round_trips(r#"{"__type":"File","name":"a.png"}"#);
        round_trips(r#"{"__type":"Polygon","coordinates":[[0,0],[1,0],[1,1],[0,0]]}"#);
        round_trips(r#"{"__type":"Relation","className":"Post"}"#);
    }

    #[test]
    fn bytes_decode_to_real_octets() {
        let v = classify(j(r#"{"__type":"Bytes","base64":"aGVsbG8="}"#)).unwrap();
        match v {
            ParseValue::Bytes(b) => assert_eq!(b, b"hello"),
            other => panic!("expected Bytes, got {other:?}"),
        }
    }

    #[test]
    fn object_key_order_survives_decoding() {
        let src = r#"{"zebra":1,"apple":2,"mango":3}"#;
        let v = classify(j(src)).unwrap();
        assert_eq!(v.to_json(), src, "key order must survive the decoder too");
    }

    /// UPSTREAM-QUIRK. Rejecting nested unknown types would be tidier and would refuse writes
    /// parse-server accepts.
    #[test]
    fn unknown_type_is_rejected_at_top_level_and_kept_when_nested() {
        let err = classify(j(r#"{"__type":"Wat","x":1}"#)).unwrap_err();
        assert_eq!(err.code, ErrorCode::IncorrectType);

        // Nested inside a plain object: preserved verbatim, no error.
        let nested = classify(j(r#"{"field":{"__type":"Wat","x":1}}"#)).unwrap();
        assert_eq!(nested.to_json(), r#"{"field":{"__type":"Wat","x":1}}"#);

        // Nested inside an array: same.
        let in_array = classify(j(r#"[{"__type":"Wat"}]"#)).unwrap();
        assert_eq!(in_array.to_json(), r#"[{"__type":"Wat"}]"#);
    }

    #[test]
    fn a_non_string_type_tag_is_just_an_object() {
        // Upstream compares __type against strings, so a numeric one is not a tagged value.
        let v = classify(j(r#"{"__type":7}"#)).unwrap();
        assert_eq!(v.to_json(), r#"{"__type":7}"#);
    }

    #[test]
    fn malformed_tagged_values_carry_the_right_code() {
        for (src, code) in [
            (
                r#"{"__type":"Pointer","className":"A"}"#,
                ErrorCode::IncorrectType,
            ),
            (
                r#"{"__type":"GeoPoint","latitude":"x","longitude":1}"#,
                ErrorCode::IncorrectType,
            ),
            (
                r#"{"__type":"Bytes","base64":"not base64!!"}"#,
                ErrorCode::IncorrectType,
            ),
            (
                r#"{"__type":"Polygon","coordinates":[[1]]}"#,
                ErrorCode::IncorrectType,
            ),
            (
                r#"{"__type":"Date","iso":"nonsense"}"#,
                ErrorCode::InvalidJson,
            ),
        ] {
            let e = classify(j(src)).unwrap_err();
            assert_eq!(e.code, code, "wrong code for {src}");
        }
    }

    #[test]
    fn null_is_a_value_not_an_absence() {
        // Whether a null clears or skips a field is a schema decision, not a decoder one.
        let v = classify(j(r#"{"a":null}"#)).unwrap();
        assert_eq!(v.to_json(), r#"{"a":null}"#);
    }

    #[test]
    fn deeply_nested_structures_survive() {
        let src = r#"{"a":[{"b":[{"__type":"Pointer","className":"C","objectId":"x"}]}]}"#;
        round_trips(src);
    }
}
