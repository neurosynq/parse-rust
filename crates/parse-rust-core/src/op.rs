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
    /// `{"__op":"SetOnInsert","amount":v}`. Sets the field only if the write inserts a row.
    ///
    /// Note the key: `amount`, not `objects` and not `value`, and it carries an arbitrary value
    /// rather than a number despite the name (`MongoTransform.js:993-998`). There is no type
    /// check on it anywhere upstream, so there is none here.
    SetOnInsert(ParseValue),
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

/// Which write path an op is being decoded on.
///
/// This exists for exactly one reason: upstream produces a different error message for a
/// non-numeric `Increment.amount` depending on the path, and the message is wire-visible. Create
/// goes through `flattenUpdateOperatorsForCreate`, whose `Increment` arm carries a copy-pasted
/// `'objects to add must be an array'` (`DatabaseController.js:326-330`). Update goes through
/// `transformUpdateOperator`, which says `'incrementing must provide a number'`
/// (`MongoTransform.js:983-985`). A decoder that cannot tell the two apart has to pick one and be
/// wrong half the time, so it is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpPath {
    Create,
    Update,
}

/// One field of a write body: either a literal value or an operation.
///
/// Deliberately an enum rather than "a `ParseValue` that might happen to be an op object". 0.1.0
/// decoded ops correctly and then never called the decoder from the write path, so
/// `{"__op":"Increment","amount":1}` was stored as a literal object. A sum type at the field
/// boundary makes that omission a missing match arm rather than silence.
#[derive(Debug, Clone)]
pub enum FieldWrite {
    Value(ParseValue),
    Op(Op),
}

/// Decode one field of a write body.
///
/// Tries the op decoder first, because an op object is structurally an ordinary object and
/// [`crate::decode::classify`] would happily accept it as one.
pub fn classify_field(value: Json, path: OpPath) -> Result<FieldWrite, ParseError> {
    if let Some(op) = Op::classify_with(&value, path)? {
        return Ok(FieldWrite::Op(op));
    }
    crate::decode::classify(value).map(FieldWrite::Value)
}

impl Op {
    /// Decode an `{"__op":...}` object on the update path.
    ///
    /// Returns `Ok(None)` when the value is not an op at all, so a caller can try this before
    /// falling back to [`crate::decode::classify`] without treating "not an op" as an error.
    pub fn classify(value: &Json) -> Result<Option<Op>, ParseError> {
        Op::classify_with(value, OpPath::Update)
    }

    /// Decode an `{"__op":...}` object, with the path that decides one error message.
    pub fn classify_with(value: &Json, path: OpPath) -> Result<Option<Op>, ParseError> {
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
                    // Create says "objects to add must be an array", a copy-paste bug at
                    // `DatabaseController.js:326-330`; update says "incrementing must provide a
                    // number" (`MongoTransform.js:983-985`). Both are reproduced deliberately.
                    ParseError::invalid_json(
                        match path {
                            OpPath::Create => "objects to add must be an array",
                            OpPath::Update => "incrementing must provide a number",
                        }
                        .to_string(),
                    )
                })?;
                Op::Increment(amount)
            }
            // No validation, matching upstream: neither `flattenUpdateOperatorsForCreate`
            // (`DatabaseController.js:333-335`) nor `transformUpdateOperator`
            // (`MongoTransform.js:993-998`) inspects `amount`. An absent one lands as `null`,
            // which is what the Node driver serializes `undefined` to.
            "SetOnInsert" => Op::SetOnInsert(match map.get("amount") {
                Some(value) => crate::decode::classify(value.clone())?,
                None => ParseValue::Null,
            }),
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
                    match Op::classify_with(o, path)? {
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

    /// What this op collapses to on a create, per `flattenUpdateOperatorsForCreate`
    /// (`DatabaseController.js:323-365`).
    ///
    /// `Ok(None)` means the key is removed from the row entirely, which is what `Delete` does.
    /// Two results are counter-intuitive and both are upstream's: `Remove` yields an **empty
    /// array** rather than removing anything, and the relation ops are not handled here at all
    /// because `collectRelationUpdates` has already stripped them out.
    pub fn flatten_for_create(&self) -> Result<Option<ParseValue>, ParseError> {
        Ok(match self {
            Op::Increment(amount) => Some(ParseValue::Number(*amount)),
            Op::SetOnInsert(value) => Some(value.clone()),
            Op::Add(objects) | Op::AddUnique(objects) => Some(ParseValue::Array(objects.clone())),
            Op::Remove(_) => Some(ParseValue::Array(Vec::new())),
            Op::Delete => None,
            Op::AddRelation(_) | Op::RemoveRelation(_) | Op::Batch(_) => {
                return Err(ParseError::new(
                    crate::error::ErrorCode::CommandUnavailable,
                    format!("The {} operator is not supported yet.", self.name()),
                ))
            }
        })
    }

    /// The `__op` string, for the error messages that quote it back.
    pub fn name(&self) -> &'static str {
        match self {
            Op::Increment(_) => "Increment",
            Op::SetOnInsert(_) => "SetOnInsert",
            Op::Add(_) => "Add",
            Op::AddUnique(_) => "AddUnique",
            Op::Remove(_) => "Remove",
            Op::Delete => "Delete",
            Op::AddRelation(_) => "AddRelation",
            Op::RemoveRelation(_) => "RemoveRelation",
            Op::Batch(_) => "Batch",
        }
    }

    /// Does the update response echo this op's resulting value back to the client?
    ///
    /// Exactly the five ops in `_sanitizeDatabaseResult`'s allow-list
    /// (`DatabaseController.js:2152`). `Delete` is not one of them, which is why deleting a field
    /// produces `{updatedAt}` and nothing else.
    pub fn echoes_result(&self) -> bool {
        matches!(
            self,
            Op::Increment(_) | Op::SetOnInsert(_) | Op::Add(_) | Op::AddUnique(_) | Op::Remove(_)
        )
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

    /// `SetOnInsert` decodes, carries an arbitrary value under `amount`, and echoes its result.
    ///
    /// Decoding it is not the same as accepting it on a REST write: `infer_op_type` refuses it the
    /// way `getObjectType` does. The decoder exists because the op is real everywhere else
    /// upstream, and because `Unknown operation: SetOnInsert` was the wrong reason to refuse it.
    #[test]
    fn set_on_insert_decodes_with_an_arbitrary_amount() {
        match Op::classify(&j(r#"{"__op":"SetOnInsert","amount":"a string"}"#)).unwrap() {
            Some(Op::SetOnInsert(ParseValue::String(s))) => assert_eq!(s, "a string"),
            other => panic!("expected SetOnInsert, got {other:?}"),
        }
        // No `amount` at all. Upstream sets the field to `undefined`, which the driver stores as
        // null rather than as an error.
        assert!(matches!(
            Op::classify(&j(r#"{"__op":"SetOnInsert"}"#)).unwrap(),
            Some(Op::SetOnInsert(ParseValue::Null))
        ));
        assert!(Op::SetOnInsert(ParseValue::Null).echoes_result());
    }
}
