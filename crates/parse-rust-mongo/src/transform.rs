//! Parse JSON to BSON and back.
//!
//! Upstream: `src/Adapters/Storage/Mongo/MongoTransform.js`. It is full of load-bearing special
//! cases, and those special cases are the whole job: the naive transform is trivial and wrong.
//!
//! The pair implemented here mirrors `parseObjectToMongoObjectForCreate` and
//! `mongoObjectToParseObject`, which are the two functions upstream exports and therefore the
//! two this can be differentially tested against. See `tests/transform_differential.rs`.
//!
//! Scope is the 0.1.0 field set: String, Number, Boolean, Date, Array, Object, Pointer, ACL.

use bson::{Bson, Document};
use parse_rust_core::{ParseDate, ParseError, ParseMap, ParseValue};
use parse_rust_storage::ClassSchema;

/// Keys that are renamed rather than stored under their Parse name (`transformKey`,
/// `MongoTransform.js:7-30`). The list is closed: everything else keeps its name, except a
/// declared Pointer field, which takes a `_p_` prefix.
pub fn storage_key(schema: &ClassSchema, field: &str) -> String {
    match field {
        "objectId" => return "_id".into(),
        "createdAt" => return "_created_at".into(),
        "updatedAt" => return "_updated_at".into(),
        "sessionToken" => return "_session_token".into(),
        "lastUsed" => return "_last_used".into(),
        "timesUsed" => return "times_used".into(),
        _ => {}
    }
    if schema.is_pointer_field(field) {
        format!("_p_{field}")
    } else {
        field.to_string()
    }
}

/// Server-internal columns that are read back under their own names.
///
/// **Deliberately not upstream's shape.** `mongoObjectToParseObject` rehydrates
/// `_hashed_password` onto the object as `password` (`DatabaseController.js:265-267`), so the hash
/// travels under a user-facing name and one later step has to remove it again. Any path that
/// forgets that step leaks the hash, so parse-rust does not create the condition: the column keeps
/// its internal name all the way through.
/// Keeping the internal name means no code path can mistake the hash for a user-facing field, and
/// `parse_rust_rest::strip_internal_keys` removes every `_`-prefixed key from responses as the
/// unconditional backstop, which is what upstream's `filterSensitiveData` also does
/// (`DatabaseController.js:288-292`).
///
/// `_session_token` is absent because it is already renamed to `sessionToken` above, which is
/// upstream's behavior for that one column.
const INTERNAL_COLUMNS: [&str; 6] = [
    "_rperm",
    "_wperm",
    "_hashed_password",
    "_perishable_token",
    "_email_verify_token",
    "_failed_login_count",
];

/// The inverse of [`storage_key`].
fn untransform_key(field: &str) -> Option<String> {
    match field {
        "_id" => Some("objectId".into()),
        "_created_at" => Some("createdAt".into()),
        "_updated_at" => Some("updatedAt".into()),
        "_session_token" => Some("sessionToken".into()),
        "_last_used" => Some("lastUsed".into()),
        "times_used" => Some("timesUsed".into()),
        _ => {
            if let Some(stripped) = field.strip_prefix("_p_") {
                return Some(stripped.to_string());
            }
            if INTERNAL_COLUMNS.contains(&field) || field.starts_with("_auth_data_") {
                return Some(field.to_string());
            }
            None
        }
    }
}

/// Choose the BSON number type.
///
/// **This is the rule that silently corrupts data if it is wrong**, and it is why Gate B of the
/// data-fidelity gate exists. The rule, measured against a real parse-server: a value that
/// is integral and fits in `i32` is stored as `Int32`, everything else as `Double`. The Node
/// driver does the same thing, which is why a database written by parse-server contains a mix of
/// both for what the client thinks is one numeric field.
///
/// Note that this is unrelated to JSON number *formatting*, which is `parse-rust-core::js_number`.
/// Conflating the two is the mistake this project already made once.
fn to_bson_number(n: f64) -> Bson {
    if n.fract() == 0.0 && n >= i32::MIN as f64 && n <= i32::MAX as f64 {
        // `-0.0` is integral and in range. It stores as Int32 0, losing the sign, which is what
        // the Node driver does too.
        Bson::Int32(n as i32)
    } else {
        Bson::Double(n)
    }
}

/// Lower a value that sits **inside** an array or object.
///
/// UPSTREAM-QUIRK: `transformInteriorAtom` (`MongoTransform.js:566`) handles a strictly smaller
/// set than the top level. Only Pointer, Date and Bytes are recognised; a GeoPoint, Polygon or
/// File nested inside an array is stored raw, as the plain `__type` object it arrived as. That is
/// wire-visible on read-back, and it is reproduced deliberately.
///
/// A nested Pointer also keeps its full `{__type, className, objectId}` shape rather than
/// collapsing to `"Class$id"`, because the `_p_` collapse is a *key* transformation and interior
/// values have no key of their own.
fn interior_value_to_bson(value: &ParseValue) -> Result<Bson, ParseError> {
    Ok(match value {
        ParseValue::Date(d) => date_to_bson(d),
        ParseValue::Bytes(b) => Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: b.clone(),
        }),
        ParseValue::Pointer {
            class_name,
            object_id,
        } => {
            let mut d = Document::new();
            d.insert("__type", "Pointer");
            d.insert("className", class_name.clone());
            d.insert("objectId", object_id.clone());
            Bson::Document(d)
        }
        other => plain_value_to_bson(other)?,
    })
}

fn date_to_bson(d: &ParseDate) -> Bson {
    Bson::DateTime(bson::DateTime::from_millis(d.timestamp_millis()))
}

/// Everything that is not position-dependent.
fn plain_value_to_bson(value: &ParseValue) -> Result<Bson, ParseError> {
    Ok(match value {
        ParseValue::Null => Bson::Null,
        ParseValue::Bool(b) => Bson::Boolean(*b),
        ParseValue::Number(n) => to_bson_number(*n),
        ParseValue::String(s) => Bson::String(s.clone()),
        ParseValue::Array(items) => Bson::Array(
            items
                .iter()
                .map(interior_value_to_bson)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        ParseValue::Object(map) => {
            let mut d = Document::new();
            for (k, v) in map {
                d.insert(k.clone(), interior_value_to_bson(v)?);
            }
            Bson::Document(d)
        }
        ParseValue::Date(d) => date_to_bson(d),
        ParseValue::Bytes(b) => Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: b.clone(),
        }),
        ParseValue::GeoPoint {
            latitude,
            longitude,
        } => {
            // Storage is GeoJSON order, longitude first, the reverse of the wire form.
            Bson::Array(vec![Bson::Double(*longitude), Bson::Double(*latitude)])
        }
        ParseValue::Pointer { .. } => {
            return Err(ParseError::incorrect_type(
                "a top-level Pointer is lowered by key, not by value".to_string(),
            ))
        }
        ParseValue::Polygon(coords) => Bson::Document({
            let mut d = Document::new();
            d.insert("type", "Polygon");
            d.insert(
                "coordinates",
                Bson::Array(vec![Bson::Array(
                    coords
                        .iter()
                        // Stored longitude-first; `PolygonCoder.databaseToJSON` swaps on the way
                        // out (`MongoTransform.js:1362-1372`).
                        .map(|(lat, lng)| Bson::Array(vec![Bson::Double(*lng), Bson::Double(*lat)]))
                        .collect(),
                )]),
            );
            d
        }),
        ParseValue::File { name, .. } => Bson::String(name.clone()),
        ParseValue::Relation { .. } => {
            return Err(ParseError::incorrect_type(
                "Relation fields are not stored on the object".to_string(),
            ))
        }
    })
}

/// `parseObjectToMongoObjectForCreate`.
///
/// Two behaviors that are easy to miss and both wire-visible:
/// - **Relation values are skipped entirely** (`MongoTransform.js:468-470`). A Relation lives in
///   a join table, not on the object, so a `{__type:"Relation"}` value in a create body is
///   dropped rather than stored or rejected.
/// - **`ACL` becomes three columns**: `_rperm`, `_wperm`, and the legacy `_acl` mirror.
pub fn parse_object_to_mongo_create(
    schema: &ClassSchema,
    object: &ParseMap,
) -> Result<Document, ParseError> {
    let mut out = Document::new();

    for (key, value) in object {
        if matches!(value, ParseValue::Relation { .. }) {
            continue;
        }
        if key == "ACL" {
            return Err(ParseError::invalid_json(
                "ACL must be lowered through parse_acl_to_columns, not as a field".to_string(),
            ));
        }

        let mongo_key = storage_key(schema, key);

        // A declared Pointer field collapses to "<Class>$<id>" under its `_p_` key.
        if schema.is_pointer_field(key) {
            match value {
                ParseValue::Pointer {
                    class_name,
                    object_id,
                } => {
                    out.insert(mongo_key, Bson::String(format!("{class_name}${object_id}")));
                    continue;
                }
                ParseValue::Null => {
                    out.insert(mongo_key, Bson::Null);
                    continue;
                }
                _ => {
                    return Err(ParseError::incorrect_type(format!(
                        "schema mismatch for {}.{key}; expected Pointer but got a non-pointer",
                        schema.class_name
                    )))
                }
            }
        }

        out.insert(mongo_key, plain_value_to_bson(value)?);
    }

    Ok(out)
}

/// `mongoObjectToParseObject`.
///
/// UPSTREAM-QUIRK: an unrecognised `_`-prefixed key raises, and it raises a **bare JavaScript
/// string** rather than a `Parse.Error` (`MongoTransform.js:1236-1237`). On the aggregate path
/// that surfaces to the client as code 102 with an `undefined` message. Reproduced here as an
/// error, though parse-rust cannot reproduce the `undefined` message without inventing one.
pub fn mongo_object_to_parse(doc: &Document) -> Result<ParseMap, ParseError> {
    let mut out = ParseMap::new();

    for (key, value) in doc {
        // `_acl` is the legacy write-only mirror and is dropped on read, exactly as upstream does
        // (`MongoTransform.js:1155-1156`, a bare `break`).
        //
        // `_rperm` and `_wperm` are NOT dropped here. They are what `parse_rust_rest::acl::raise_acl`
        // rebuilds the `ACL` field from, and dropping them meant a stored ACL could never be
        // returned. The response boundary strips any that survive, so they cannot leak.
        if key == "_acl" {
            continue;
        }

        let parse_key = match untransform_key(key) {
            Some(k) => k,
            None if key.starts_with('_') && key != "__type" => {
                return Err(ParseError::invalid_query(format!(
                    "bad key in untransform: {key}"
                )))
            }
            None => key.clone(),
        };

        // A `_p_` field carries "<Class>$<id>".
        if let Some(stripped) = key.strip_prefix("_p_") {
            match value {
                Bson::String(s) => {
                    let (class_name, object_id) = s.split_once('$').ok_or_else(|| {
                        ParseError::incorrect_type(format!(
                            "pointer field {stripped} is malformed: {s}"
                        ))
                    })?;
                    out.insert(
                        stripped.to_string(),
                        ParseValue::Pointer {
                            class_name: class_name.to_string(),
                            object_id: object_id.to_string(),
                        },
                    );
                }
                Bson::Null => {
                    out.insert(stripped.to_string(), ParseValue::Null);
                }
                _ => {
                    return Err(ParseError::incorrect_type(format!(
                        "pointer field {stripped} is not a string"
                    )))
                }
            }
            continue;
        }

        out.insert(parse_key, bson_to_parse_value(value)?);
    }

    Ok(out)
}

/// Raise a stored value. Takes no schema: the stored form is self-describing, which is the
/// asymmetry with lowering, where the schema decides whether a field is a `_p_` pointer.
fn bson_to_parse_value(value: &Bson) -> Result<ParseValue, ParseError> {
    Ok(match value {
        Bson::Null => ParseValue::Null,
        Bson::Boolean(b) => ParseValue::Bool(*b),
        // Both integer widths raise to the single JavaScript number type. This is the direction
        // that is lossless; the lossy direction is `to_bson_number`.
        Bson::Int32(n) => ParseValue::Number(*n as f64),
        Bson::Int64(n) => ParseValue::Number(*n as f64),
        Bson::Double(n) => ParseValue::Number(*n),
        Bson::String(s) => ParseValue::String(s.clone()),
        Bson::DateTime(dt) => ParseValue::Date(ParseDate::parse_iso(
            &dt.try_to_rfc3339_string()
                .map_err(|e| ParseError::invalid_json(format!("undecodable stored date: {e}")))?,
        )?),
        Bson::Binary(b) => ParseValue::Bytes(b.bytes.clone()),
        Bson::Array(items) => ParseValue::Array(
            items
                .iter()
                .map(bson_to_parse_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Bson::Document(d) => {
            let mut map = ParseMap::new();
            for (k, v) in d {
                map.insert(k.clone(), bson_to_parse_value(v)?);
            }
            ParseValue::Object(map)
        }
        other => {
            return Err(ParseError::incorrect_type(format!(
                "unsupported BSON type in stored document: {other:?}"
            )))
        }
    })
}

/// Lower a value for use in a query filter on `field`.
///
/// Differs from the create path in one way that matters: a declared Pointer field stores
/// `"Class$id"`, so a query for a pointer has to compare against that string rather than against
/// the `__type` envelope. Getting this wrong makes every pointer query silently return nothing.
pub fn value_to_bson_for_query(
    schema: &ClassSchema,
    field: &str,
    value: &ParseValue,
) -> Result<Bson, ParseError> {
    if schema.is_pointer_field(field) {
        if let ParseValue::Pointer {
            class_name,
            object_id,
        } = value
        {
            return Ok(Bson::String(format!("{class_name}${object_id}")));
        }
    }
    plain_value_to_bson(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_storage::FieldType;

    fn post_schema() -> ClassSchema {
        ClassSchema::new("Post")
            .with_field("title", FieldType::String)
            .with_field("views", FieldType::Number)
            .with_field(
                "author",
                FieldType::Pointer {
                    target_class: "_User".into(),
                },
            )
    }

    fn map(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
        let mut m = ParseMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        m
    }

    #[test]
    fn renamed_keys_round_trip() {
        let s = post_schema();
        assert_eq!(storage_key(&s, "objectId"), "_id");
        assert_eq!(storage_key(&s, "createdAt"), "_created_at");
        assert_eq!(storage_key(&s, "updatedAt"), "_updated_at");
        assert_eq!(storage_key(&s, "title"), "title");
        assert_eq!(storage_key(&s, "author"), "_p_author");

        assert_eq!(untransform_key("_id").as_deref(), Some("objectId"));
        assert_eq!(untransform_key("_created_at").as_deref(), Some("createdAt"));
        assert_eq!(untransform_key("_p_author").as_deref(), Some("author"));
        assert_eq!(untransform_key("title"), None);
    }

    /// The rule Gate B exists to prove.
    #[test]
    fn integral_numbers_in_i32_range_store_as_int32() {
        assert_eq!(to_bson_number(0.0), Bson::Int32(0));
        assert_eq!(to_bson_number(42.0), Bson::Int32(42));
        assert_eq!(to_bson_number(-42.0), Bson::Int32(-42));
        assert_eq!(to_bson_number(i32::MAX as f64), Bson::Int32(i32::MAX));
        assert_eq!(to_bson_number(i32::MIN as f64), Bson::Int32(i32::MIN));
    }

    #[test]
    fn everything_else_stores_as_double() {
        assert_eq!(to_bson_number(1.5), Bson::Double(1.5));
        // Just past the i32 range, still integral.
        assert_eq!(
            to_bson_number(i32::MAX as f64 + 1.0),
            Bson::Double(i32::MAX as f64 + 1.0)
        );
        assert_eq!(to_bson_number(1e20), Bson::Double(1e20));
    }

    #[test]
    fn a_pointer_field_collapses_to_class_dollar_id() {
        let doc = parse_object_to_mongo_create(
            &post_schema(),
            &map(vec![(
                "author",
                ParseValue::Pointer {
                    class_name: "_User".into(),
                    object_id: "abc123".into(),
                },
            )]),
        )
        .expect("transform");
        assert_eq!(doc.get_str("_p_author").expect("_p_author"), "_User$abc123");
        assert!(
            !doc.contains_key("author"),
            "must not also store the raw key"
        );
    }

    /// UPSTREAM-QUIRK. A nested pointer keeps its full shape, because the collapse is a key
    /// transformation and an interior value has no key.
    #[test]
    fn a_nested_pointer_keeps_its_type_envelope() {
        let doc = parse_object_to_mongo_create(
            &post_schema(),
            &map(vec![(
                "tags",
                ParseValue::Array(vec![ParseValue::Pointer {
                    class_name: "Tag".into(),
                    object_id: "t1".into(),
                }]),
            )]),
        )
        .expect("transform");
        let arr = doc.get_array("tags").expect("tags");
        let nested = arr[0].as_document().expect("document");
        assert_eq!(nested.get_str("__type").expect("__type"), "Pointer");
        assert_eq!(nested.get_str("className").expect("className"), "Tag");
    }

    #[test]
    fn relation_values_are_dropped_not_stored() {
        let doc = parse_object_to_mongo_create(
            &post_schema(),
            &map(vec![
                ("title", ParseValue::String("x".into())),
                (
                    "comments",
                    ParseValue::Relation {
                        class_name: "Comment".into(),
                    },
                ),
            ]),
        )
        .expect("transform");
        assert!(doc.contains_key("title"));
        assert!(
            !doc.contains_key("comments"),
            "a Relation lives in a join table, not on the object"
        );
    }

    #[test]
    fn read_back_restores_keys_and_pointers() {
        let mut doc = Document::new();
        doc.insert("_id", "objid1");
        doc.insert("title", "hello");
        doc.insert("views", Bson::Int32(7));
        doc.insert("_p_author", "_User$abc123");
        doc.insert(
            "_created_at",
            Bson::DateTime(bson::DateTime::from_millis(1_700_000_000_000)),
        );

        let parsed = mongo_object_to_parse(&doc).expect("untransform");
        assert!(matches!(parsed.get("objectId"), Some(ParseValue::String(s)) if s == "objid1"));
        assert!(matches!(parsed.get("views"), Some(ParseValue::Number(n)) if *n == 7.0));
        assert!(matches!(
            parsed.get("author"),
            Some(ParseValue::Pointer { class_name, object_id })
                if class_name == "_User" && object_id == "abc123"
        ));
        assert!(matches!(parsed.get("createdAt"), Some(ParseValue::Date(_))));
    }

    /// Regression: these used to be dropped here, which meant `raise_acl` never saw them and a
    /// stored ACL could never be returned to a client.
    #[test]
    fn permission_columns_survive_for_the_acl_rebuild() {
        let mut doc = Document::new();
        doc.insert("title", "x");
        doc.insert("_rperm", Bson::Array(vec![Bson::String("*".into())]));
        doc.insert("_wperm", Bson::Array(vec![]));
        doc.insert("_acl", Document::new());

        let parsed = mongo_object_to_parse(&doc).expect("untransform");
        assert!(parsed.get("_rperm").is_some(), "raise_acl needs this");
        assert!(parsed.get("_wperm").is_some(), "raise_acl needs this");
        assert!(
            parsed.get("_acl").is_none(),
            "the legacy mirror is write-only and is dropped on read"
        );
    }

    #[test]
    fn internal_columns_survive_under_their_own_names() {
        // Login needs to read the hash. It must NOT come back as `password`, which is the name
        // upstream raises it under and the one a response filter then has to strip again.
        let mut doc = Document::new();
        doc.insert("_hashed_password", "$2b$10$abc");
        doc.insert("_session_token", "r:tok");
        let parsed = mongo_object_to_parse(&doc).expect("untransform");
        assert!(parsed.get("_hashed_password").is_some());
        assert!(
            parsed.get("password").is_none(),
            "the hash must never be raised under a user-facing name"
        );
        // This one IS renamed, matching upstream.
        assert!(parsed.get("sessionToken").is_some());
    }

    #[test]
    fn an_unknown_underscore_key_is_refused_rather_than_passed_through() {
        let mut doc = Document::new();
        doc.insert("_mystery", "x"); // not in INTERNAL_COLUMNS
        let err = mongo_object_to_parse(&doc).unwrap_err();
        assert!(err.message.contains("bad key in untransform"));
    }

    #[test]
    fn int64_and_int32_both_raise_to_one_number_type() {
        let mut doc = Document::new();
        doc.insert("a", Bson::Int32(1));
        doc.insert("b", Bson::Int64(2));
        doc.insert("c", Bson::Double(3.5));
        let parsed = mongo_object_to_parse(&doc).expect("untransform");
        for (k, expected) in [("a", 1.0), ("b", 2.0), ("c", 3.5)] {
            assert!(matches!(parsed.get(k), Some(ParseValue::Number(n)) if *n == expected));
        }
    }
}
