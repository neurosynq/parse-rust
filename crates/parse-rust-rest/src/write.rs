//! The write body: decoding it, and lowering it onto the two write paths.
//!
//! This is the 0.1.0 gap. `Op` was decoded correctly and the write path never called the decoder,
//! so `{"__op":"Increment","amount":1}` was stored as a literal object with an `__op` key. The
//! body is a map of [`parse_rust_core::FieldWrite`] end to end for that reason: a field is either
//! a value or an operation, and "the write path forgot about operations" becomes a missing match
//! arm rather than silence.
//!
//! The two paths are genuinely different and upstream treats them so. A create flattens each
//! operation to the value it would produce against an absent field
//! (`flattenUpdateOperatorsForCreate`, `DatabaseController.js:323-365`); an update lowers each to
//! a storage operation.

use indexmap::IndexMap;
use parse_rust_core::op::OpPath;
use parse_rust_core::{
    classify_field, ErrorCode, FieldWrite, Op, ParseError, ParseMap, ParseValue,
};
use parse_rust_storage::{Update, UpdateValue};
use serde_json::Value as Json;

/// A decoded write body: ordered, because upstream field order is wire-visible.
pub type WriteBody = IndexMap<String, FieldWrite>;

/// Decode a JSON request body into fields and operations.
///
/// `path` decides one wire-visible error message: a non-numeric `Increment.amount` reports
/// `objects to add must be an array` on create, a copy-paste bug at
/// `DatabaseController.js:326-330`, and `incrementing must provide a number` on update.
pub fn decode_write_body(value: &Json, path: OpPath) -> Result<WriteBody, ParseError> {
    let Json::Object(map) = value else {
        return Err(ParseError::invalid_json("body must be an object"));
    };
    reject_invalid_files(value)?;
    let mut out = WriteBody::new();
    for (key, value) in map {
        out.insert(key.clone(), classify_field(value.clone(), path)?);
    }
    Ok(out)
}

/// `resolveFileUrls`'s validation (`RestWrite.js:240-249`, from 9.10.3): any object at any depth,
/// operation payloads included, whose `__type` is `File` must carry a non-empty string `name`, or
/// the write is refused with 111 `This is not a valid File`.
///
/// It walks the raw JSON rather than the classified body because classification stops at the
/// top level: a nested file was stored as it arrived, including one with no name at all, which
/// upstream answered with a crash before GHSA-gpr6-gr9g-pfw6 and refuses since. A `File` is not
/// descended into, as upstream's `collect` returns on one.
fn reject_invalid_files(value: &Json) -> Result<(), ParseError> {
    match value {
        Json::Object(map) => {
            if map.get("__type").and_then(Json::as_str) == Some("File") {
                return match map.get("name") {
                    Some(Json::String(name)) if !name.is_empty() => Ok(()),
                    _ => Err(ParseError::incorrect_type(
                        "This is not a valid File".to_string(),
                    )),
                };
            }
            map.values().try_for_each(reject_invalid_files)
        }
        Json::Array(items) => items.iter().try_for_each(reject_invalid_files),
        _ => Ok(()),
    }
}

/// The body as plain values, for the checks that run against the raw REST body.
///
/// `validateRequiredColumns` tests `object[column].__op == 'Delete'` on an undecoded body
/// (`SchemaController.js:1340-1342`), so a `Delete` has to be visible as its envelope rather than
/// as a decoded operation. Every other operation is represented by its `__op` name alone, which
/// is enough for a truthiness test and carries nothing that could be mistaken for a value.
pub fn as_plain_body(body: &WriteBody) -> ParseMap {
    let mut out = ParseMap::new();
    for (key, write) in body {
        let value = match write {
            FieldWrite::Value(v) => v.clone(),
            FieldWrite::Op(op) => {
                let mut envelope = ParseMap::new();
                envelope.insert(
                    "__op".to_string(),
                    ParseValue::String(op.name().to_string()),
                );
                ParseValue::Object(envelope)
            }
        };
        out.insert(key.clone(), value);
    }
    out
}

/// Flatten a write body onto the create path.
///
/// Two results are counter-intuitive and both are upstream's: `Remove` yields an **empty array**
/// rather than removing anything, and `Delete` removes the key entirely.
pub fn flatten_for_create(body: &WriteBody) -> Result<ParseMap, ParseError> {
    let mut out = ParseMap::new();
    for (key, write) in body {
        match write {
            FieldWrite::Value(value) => {
                out.insert(key.clone(), value.clone());
            }
            FieldWrite::Op(op) => {
                if let Some(value) = op.flatten_for_create()? {
                    out.insert(key.clone(), value);
                }
            }
        }
    }
    Ok(out)
}

/// Lower a write body onto the update path.
///
/// Every non-operation field is a `Set`. Relation operations must already have been stripped by
/// [`crate::relations::collect_relation_updates`]; one reaching here is refused rather than
/// written into a column that does not exist.
pub fn lower_update(body: &WriteBody) -> Result<Update, ParseError> {
    let mut out = Update::new();
    for (key, write) in body {
        let value = match write {
            FieldWrite::Value(value) => UpdateValue::Set(value.clone()),
            FieldWrite::Op(op) => match op {
                Op::Increment(amount) => UpdateValue::Increment(*amount),
                Op::SetOnInsert(value) => UpdateValue::SetOnInsert(value.clone()),
                Op::Add(objects) => UpdateValue::Add(objects.clone()),
                Op::AddUnique(objects) => UpdateValue::AddUnique(objects.clone()),
                Op::Remove(objects) => UpdateValue::Remove(objects.clone()),
                Op::Delete => UpdateValue::Unset,
                Op::AddRelation(_) | Op::RemoveRelation(_) | Op::Batch(_) => {
                    return Err(ParseError::new(
                        ErrorCode::CommandUnavailable,
                        format!("The {} operator is not supported yet.", op.name()),
                    ))
                }
            },
        };
        out.insert(key.clone(), value);
    }
    Ok(out)
}

/// `allowCustomObjectId`, on the create path only (`RestWrite.js:50-65`).
///
/// **This runs on the client's body, before any server-generated identity is folded in.** Signup
/// pre-generates an objectId so it can build the user's private ACL, so checking after that point
/// would refuse every signup. That is why this is a separate function called by each create route
/// rather than a guard inside the write pipeline.
///
/// At the default of `false`, `objectId` and `id` are both refused with `INVALID_KEY_NAME`. `id`
/// is there because the JavaScript SDK uses it internally and a body carrying one is a sign the
/// caller serialized a `Parse.Object` rather than its attributes.
///
/// At `true`, the only check is that a present `objectId` is not falsy, which upstream reports as
/// `MISSING_OBJECT_ID`. Note the asymmetry: `hasOwnProperty` decides whether to check and JS
/// truthiness decides the outcome, so `{"objectId": ""}` is an error while an absent key is fine.
pub fn enforce_object_id_policy(
    body: &WriteBody,
    allow_custom_object_id: bool,
) -> Result<(), ParseError> {
    let present = |key: &str| match body.get(key) {
        Some(FieldWrite::Value(value)) => Some(value),
        // An op in either of these positions is not a string objectId under any setting, and
        // upstream's truthiness test on the raw `{"__op":...}` object says truthy.
        Some(FieldWrite::Op(_)) => Some(&ParseValue::Bool(true)),
        None => None,
    };

    if allow_custom_object_id {
        if let Some(value) = present("objectId") {
            if !parse_rust_core::is_js_truthy(value) {
                return Err(ParseError::new(
                    ErrorCode::MissingObjectId,
                    "objectId must not be empty, null or undefined",
                ));
            }
        }
        return Ok(());
    }

    for key in ["objectId", "id"] {
        if present(key).is_some_and(parse_rust_core::is_js_truthy) {
            return Err(ParseError::new(
                ErrorCode::InvalidKeyName,
                format!("{key} is an invalid field name."),
            ));
        }
    }
    Ok(())
}

/// The keys whose post-write value the response echoes back.
///
/// Exactly the five operations in `_sanitizeDatabaseResult`'s allow-list
/// (`DatabaseController.js:2141-2169`): `Add`, `AddUnique`, `Remove`, `Increment` and
/// `SetOnInsert`. Nothing else, so a plain set and a `Delete` both produce `{updatedAt}` and
/// nothing more.
pub fn echoed_keys(body: &WriteBody) -> Vec<String> {
    body.iter()
        .filter_map(|(key, write)| match write {
            FieldWrite::Op(op) if op.echoes_result() => Some(key.clone()),
            _ => None,
        })
        .collect()
}

/// Build the response body for a write, from the keys the request asked to echo and the row the
/// adapter returned.
pub fn echo_response(body: &WriteBody, row: Option<&ParseMap>) -> ParseMap {
    let mut out = ParseMap::new();
    let Some(row) = row else { return out };
    for key in echoed_keys(body) {
        if let Some(value) = row.get(&key) {
            out.insert(key, value.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {

    /// `resolveFileUrls` rejects a nameless `File` at any depth, an operation's payload included,
    /// and leaves a well-formed nested one alone. Each case measured against 9.10.3.
    #[test]
    fn an_invalid_file_is_refused_at_any_depth() {
        for json in [
            r#"{"f":{"__type":"File","name":""}}"#,
            r#"{"f":{"__type":"File"}}"#,
            r#"{"o":{"a":{"__type":"File","name":5}}}"#,
            r#"{"o":[{"__type":"File","name":""}]}"#,
            r#"{"arr":{"__op":"Add","objects":[{"__type":"File"}]}}"#,
        ] {
            let e = decode_write_body(&serde_json::from_str(json).expect("json"), OpPath::Create)
                .expect_err(json);
            assert_eq!(e.code, ErrorCode::IncorrectType, "{json}");
            assert_eq!(e.message, "This is not a valid File", "{json}");
        }
        let ok = r#"{"o":{"a":{"__type":"File","name":"x.txt","url":"http://h/x.txt"}}}"#;
        decode_write_body(&serde_json::from_str(ok).expect("json"), OpPath::Create).expect(ok);
    }
    use super::*;

    fn body(json: &str, path: OpPath) -> WriteBody {
        decode_write_body(&serde_json::from_str(json).expect("test literal"), path).expect("decode")
    }

    #[test]
    fn an_op_is_decoded_rather_than_stored_as_an_object() {
        let b = body(
            r#"{"views":{"__op":"Increment","amount":2}}"#,
            OpPath::Update,
        );
        assert!(matches!(b.get("views"), Some(FieldWrite::Op(Op::Increment(a))) if *a == 2.0));
        let update = lower_update(&b).expect("lower");
        assert!(matches!(update.get("views"), Some(UpdateValue::Increment(a)) if *a == 2.0));
    }

    #[test]
    fn create_flattens_every_op_the_way_upstream_does() {
        let b = body(
            r#"{
                "views":{"__op":"Increment","amount":3},
                "tags":{"__op":"Add","objects":["a"]},
                "unique":{"__op":"AddUnique","objects":["b"]},
                "gone":{"__op":"Remove","objects":["c"]},
                "dropped":{"__op":"Delete"},
                "plain":"x"
            }"#,
            OpPath::Create,
        );
        let row = flatten_for_create(&b).expect("flatten");
        assert!(matches!(row.get("views"), Some(ParseValue::Number(n)) if *n == 3.0));
        assert!(matches!(row.get("tags"), Some(ParseValue::Array(a)) if a.len() == 1));
        assert!(matches!(row.get("unique"), Some(ParseValue::Array(a)) if a.len() == 1));
        assert!(
            matches!(row.get("gone"), Some(ParseValue::Array(a)) if a.is_empty()),
            "Remove yields an empty array rather than removing anything"
        );
        assert!(row.get("dropped").is_none());
        assert!(row.get("plain").is_some());
    }

    #[test]
    fn only_the_five_result_bearing_ops_echo_back() {
        let b = body(
            r#"{
                "views":{"__op":"Increment","amount":1},
                "tags":{"__op":"Add","objects":["a"]},
                "unique":{"__op":"AddUnique","objects":["b"]},
                "gone":{"__op":"Remove","objects":["c"]},
                "dropped":{"__op":"Delete"},
                "plain":"x"
            }"#,
            OpPath::Update,
        );
        assert_eq!(echoed_keys(&b), vec!["views", "tags", "unique", "gone"]);

        let mut row = ParseMap::new();
        row.insert("views".into(), ParseValue::Number(4.0));
        row.insert("plain".into(), ParseValue::String("x".into()));
        let echoed = echo_response(&b, Some(&row));
        assert!(matches!(echoed.get("views"), Some(ParseValue::Number(n)) if *n == 4.0));
        assert!(
            echoed.get("plain").is_none(),
            "a plain set tells the client nothing it did not already know"
        );
    }

    #[test]
    fn the_increment_message_differs_by_path() {
        let bad = serde_json::from_str(r#"{"n":{"__op":"Increment","amount":"x"}}"#)
            .expect("test literal");
        assert_eq!(
            decode_write_body(&bad, OpPath::Create).unwrap_err().message,
            "objects to add must be an array"
        );
        assert_eq!(
            decode_write_body(&bad, OpPath::Update).unwrap_err().message,
            "incrementing must provide a number"
        );
    }

    #[test]
    fn a_relation_op_reaching_the_update_lowering_is_refused() {
        let b = body(
            r#"{"users":{"__op":"AddRelation","objects":[]}}"#,
            OpPath::Update,
        );
        let e = lower_update(&b).unwrap_err();
        assert_eq!(e.code, ErrorCode::CommandUnavailable);
    }

    #[test]
    fn a_delete_survives_as_its_envelope_in_the_plain_view() {
        let b = body(r#"{"ACL":{"__op":"Delete"},"n":1}"#, OpPath::Update);
        let plain = as_plain_body(&b);
        match plain.get("ACL") {
            Some(ParseValue::Object(map)) => {
                assert!(matches!(map.get("__op"), Some(ParseValue::String(s)) if s == "Delete"))
            }
            other => panic!("expected an op envelope, got {other:?}"),
        }
        assert!(matches!(plain.get("n"), Some(ParseValue::Number(_))));
    }

    #[test]
    fn the_default_refuses_a_client_supplied_object_id_and_id() {
        for key in ["objectId", "id"] {
            let b = body(
                &format!(r#"{{"{key}":"chosen","title":"a"}}"#),
                OpPath::Create,
            );
            let e = enforce_object_id_policy(&b, false).unwrap_err();
            assert_eq!(e.code, ErrorCode::InvalidKeyName);
            assert_eq!(e.message, format!("{key} is an invalid field name."));
        }
        // A body carrying neither is the ordinary case and passes.
        let plain = body(r#"{"title":"a"}"#, OpPath::Create);
        assert!(enforce_object_id_policy(&plain, false).is_ok());
    }

    /// JS truthiness, not `is_some`. Upstream tests `if (data.objectId)`, so an empty string is a
    /// body without one as far as this check is concerned.
    #[test]
    fn a_falsy_object_id_is_not_a_custom_one() {
        let b = body(r#"{"objectId":""}"#, OpPath::Create);
        assert!(enforce_object_id_policy(&b, false).is_ok());
    }

    /// With the option on, the check inverts: any objectId is allowed and only a falsy one is
    /// refused, under a different code.
    #[test]
    fn allowing_custom_ids_refuses_only_an_empty_one() {
        let chosen = body(r#"{"objectId":"chosen"}"#, OpPath::Create);
        assert!(enforce_object_id_policy(&chosen, true).is_ok());

        for literal in [r#"{"objectId":""}"#, r#"{"objectId":null}"#] {
            let b = body(literal, OpPath::Create);
            let e = enforce_object_id_policy(&b, true).unwrap_err();
            assert_eq!(e.code, ErrorCode::MissingObjectId);
            assert_eq!(e.message, "objectId must not be empty, null or undefined");
        }

        // An absent key is fine under either setting: `hasOwnProperty` gates the check.
        let absent = body(r#"{"title":"a"}"#, OpPath::Create);
        assert!(enforce_object_id_policy(&absent, true).is_ok());
    }
}
