//! Field operations: the `{"__op":...}` values a client sends instead of a literal.
//!
//! Upstream decodes these in `src/Controllers/DatabaseController.js` and
//! `src/Adapters/Storage/Mongo/MongoTransform.js`. They are wire-visible in both directions:
//! a client sends them on a write, and `Increment` is echoed back as its resulting number.
//!
//! Deliberately no `PartialEq`, for the same reason as `ParseValue`: an `Op` carries
//! `ParseValue`, so a derived comparison would inherit the float hazards.

use crate::error::ParseError;
use crate::value::ParseValue;
use serde_json::Value as Json;

/// A field operation.
///
/// Not `#[non_exhaustive]`, for the reason given on `ParseValue`: a new operation must break
/// every write path that applies one, rather than falling into a wildcard arm that silently
/// ignores it.
#[derive(Debug, Clone)]
pub enum Op {
    /// `{"__op":"Increment","amount":n}`. Negative amounts decrement; there is no separate op.
    Increment(f64),
    /// `{"__op":"Add","objects":[...]}`. Appends, duplicates allowed.
    Add(Vec<ParseValue>),
    /// `{"__op":"AddUnique","objects":[...]}`. Appends only values not already present.
    AddUnique(Vec<ParseValue>),
    /// `{"__op":"Remove","objects":[...]}`. Removes every occurrence.
    Remove(Vec<ParseValue>),
    /// `{"__op":"Delete"}`. Unsets the field.
    Delete,
    /// `{"__op":"AddRelation","objects":[pointers]}`
    AddRelation(Vec<ParseValue>),
    /// `{"__op":"RemoveRelation","objects":[pointers]}`
    RemoveRelation(Vec<ParseValue>),
    /// `{"__op":"Batch","ops":[...]}`. Upstream only ever produces a batch of relation ops, but
    /// the decoder does not enforce that, so neither does this.
    Batch(Vec<Op>),
}

impl Op {
    /// Decode an `{"__op":...}` object.
    ///
    /// Returns `Ok(None)` when the value is not an op at all, so a caller can try this before
    /// falling back to [`crate::decode::classify`] without treating "not an op" as an error.
    pub fn classify(value: &Json) -> Result<Option<Op>, ParseError> {
        let map = match value {
            Json::Object(m) => m,
            _ => return Ok(None),
        };
        let name = match map.get("__op") {
            Some(Json::String(s)) => s.as_str(),
            _ => return Ok(None),
        };

        let objects = |key: &str| -> Result<Vec<ParseValue>, ParseError> {
            match map.get(key) {
                Some(Json::Array(a)) => a
                    .iter()
                    .cloned()
                    .map(crate::decode::classify_nested)
                    .collect::<Result<Vec<_>, _>>(),
                // UPSTREAM-QUIRK: this message is emitted for a non-array `objects` on every op
                // that takes one, including the relation ops. `DatabaseController.js:329`.
                _ => Err(ParseError::invalid_json(
                    "objects to add must be an array".to_string(),
                )),
            }
        };

        let op = match name {
            "Increment" => {
                let amount = map.get("amount").and_then(|v| v.as_f64()).ok_or_else(|| {
                    // UPSTREAM-QUIRK: the message for a non-numeric amount differs by path.
                    // Create says "objects to add must be an array" (a copy-paste bug at
                    // `DatabaseController.js:329`); update says this. Recorded in
                    // reproduced deliberately. The pipeline picks the message; the decoder
                    // cannot know which path it is on, so it uses the update wording.
                    ParseError::invalid_json("incrementing must provide a number".to_string())
                })?;
                Op::Increment(amount)
            }
            "Add" => Op::Add(objects("objects")?),
            "AddUnique" => Op::AddUnique(objects("objects")?),
            "Remove" => Op::Remove(objects("objects")?),
            "AddRelation" => Op::AddRelation(objects("objects")?),
            "RemoveRelation" => Op::RemoveRelation(objects("objects")?),
            "Delete" => Op::Delete,
            "Batch" => {
                let ops = match map.get("ops") {
                    Some(Json::Array(a)) => a,
                    _ => {
                        return Err(ParseError::invalid_json(
                            "Batch requires an ops array".to_string(),
                        ))
                    }
                };
                let mut out = Vec::with_capacity(ops.len());
                for o in ops {
                    match Op::classify(o)? {
                        Some(inner) => out.push(inner),
                        None => {
                            return Err(ParseError::invalid_json(
                                "Batch ops must all be operations".to_string(),
                            ))
                        }
                    }
                }
                Op::Batch(out)
            }
            other => {
                return Err(ParseError::invalid_json(format!(
                    "Unknown operation: {other}"
                )))
            }
        };
        Ok(Some(op))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    fn j(s: &str) -> Json {
        serde_json::from_str(s).expect("test literal must be valid JSON")
    }

    #[test]
    fn decodes_every_op() {
        assert!(matches!(
            Op::classify(&j(r#"{"__op":"Increment","amount":3}"#)).unwrap(),
            Some(Op::Increment(a)) if a == 3.0
        ));
        // Decrement is Increment with a negative amount; there is no Decrement op.
        assert!(matches!(
            Op::classify(&j(r#"{"__op":"Increment","amount":-2}"#)).unwrap(),
            Some(Op::Increment(a)) if a == -2.0
        ));
        assert!(matches!(
            Op::classify(&j(r#"{"__op":"Delete"}"#)).unwrap(),
            Some(Op::Delete)
        ));
        assert!(matches!(
            Op::classify(&j(r#"{"__op":"Add","objects":[1,2]}"#)).unwrap(),
            Some(Op::Add(v)) if v.len() == 2
        ));
        assert!(matches!(
            Op::classify(&j(r#"{"__op":"AddUnique","objects":[]}"#)).unwrap(),
            Some(Op::AddUnique(v)) if v.is_empty()
        ));
        assert!(matches!(
            Op::classify(&j(r#"{"__op":"Remove","objects":[1]}"#)).unwrap(),
            Some(Op::Remove(_))
        ));
        assert!(matches!(
            Op::classify(&j(r#"{"__op":"AddRelation","objects":[]}"#)).unwrap(),
            Some(Op::AddRelation(_))
        ));
        assert!(matches!(
            Op::classify(&j(r#"{"__op":"RemoveRelation","objects":[]}"#)).unwrap(),
            Some(Op::RemoveRelation(_))
        ));
    }

    #[test]
    fn batch_nests() {
        let src = r#"{"__op":"Batch","ops":[
            {"__op":"AddRelation","objects":[]},
            {"__op":"RemoveRelation","objects":[]}
        ]}"#;
        match Op::classify(&j(src)).unwrap() {
            Some(Op::Batch(ops)) => assert_eq!(ops.len(), 2),
            other => panic!("expected Batch, got {other:?}"),
        }
    }

    #[test]
    fn non_ops_are_not_errors() {
        // The caller needs to distinguish "not an op" from "a broken op".
        assert!(Op::classify(&j("42")).unwrap().is_none());
        assert!(Op::classify(&j(r#""text""#)).unwrap().is_none());
        assert!(Op::classify(&j(r#"{"a":1}"#)).unwrap().is_none());
        // A non-string __op is not an op either.
        assert!(Op::classify(&j(r#"{"__op":7}"#)).unwrap().is_none());
    }

    #[test]
    fn malformed_ops_are_errors() {
        assert_eq!(
            Op::classify(&j(r#"{"__op":"Nope"}"#)).unwrap_err().code,
            ErrorCode::InvalidJson
        );
        assert_eq!(
            Op::classify(&j(r#"{"__op":"Add","objects":3}"#))
                .unwrap_err()
                .code,
            ErrorCode::InvalidJson
        );
        assert_eq!(
            Op::classify(&j(r#"{"__op":"Increment","amount":"x"}"#))
                .unwrap_err()
                .code,
            ErrorCode::InvalidJson
        );
        assert_eq!(
            Op::classify(&j(r#"{"__op":"Batch","ops":[{"a":1}]}"#))
                .unwrap_err()
                .code,
            ErrorCode::InvalidJson
        );
    }

    #[test]
    fn op_objects_may_contain_tagged_values() {
        let src = r#"{"__op":"AddRelation","objects":[
            {"__type":"Pointer","className":"Post","objectId":"abc"}
        ]}"#;
        match Op::classify(&j(src)).unwrap() {
            Some(Op::AddRelation(v)) => {
                assert!(matches!(v[0], ParseValue::Pointer { .. }))
            }
            other => panic!("expected AddRelation, got {other:?}"),
        }
    }
}
