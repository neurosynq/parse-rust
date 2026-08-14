//! Parsing the `where` parameter into constraints.
//!
//! A `where` value is `{"field": <literal>}` for equality, or `{"field": {"$op": <value>}}` for
//! everything else. An operator document may carry several operators, which is how a range is
//! expressed.
//!
//! **Anything unsupported is an error.** Silently ignoring an operator returns more rows than the
//! caller asked for, which is an authorization failure rather than a missing feature, and it is
//! the failure mode this rule exists to prevent.

use parse_rust_core::{classify, ParseError};
use parse_rust_storage::{Comparison, Constraint};
use serde_json::Value as Json;

/// Parse a decoded `where` object into constraints.
pub fn parse_where(where_json: &Json) -> Result<Vec<Constraint>, ParseError> {
    let Json::Object(map) = where_json else {
        return Err(ParseError::invalid_query(
            "where must be an object".to_string(),
        ));
    };

    let mut out = Vec::new();
    for (field, value) in map {
        // A top-level `$` key is a query-level operator such as `$or`. Out of scope for 0.1.0,
        // and refused rather than treated as a field name, which would match nothing and look
        // like an empty result rather than an unsupported query.
        if field.starts_with('$') {
            return Err(ParseError::invalid_query(format!(
                "unsupported query operator: {field}"
            )));
        }

        match value {
            // An operator document, unless it is a tagged Parse value like a Pointer or Date.
            Json::Object(inner) if is_operator_document(inner) => {
                for (op, operand) in inner {
                    let operand = classify(operand.clone())?;
                    out.push(Constraint {
                        field: field.clone(),
                        comparison: Comparison::from_operator(op, operand)?,
                    });
                }
            }
            literal => out.push(Constraint {
                field: field.clone(),
                comparison: Comparison::Equal(classify(literal.clone())?),
            }),
        }
    }
    Ok(out)
}

/// Is this object a set of `$` operators rather than a literal value?
///
/// The distinction matters because `{"__type":"Pointer",...}` is a literal and
/// `{"$gt":3}` is not. Upstream decides the same way: it looks for `$`-prefixed keys.
fn is_operator_document(map: &serde_json::Map<String, Json>) -> bool {
    !map.is_empty() && map.keys().all(|k| k.starts_with('$'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_core::ParseValue;

    fn j(s: &str) -> Json {
        serde_json::from_str(s).expect("test literal")
    }

    #[test]
    fn a_bare_value_is_equality() {
        let c = parse_where(&j(r#"{"title":"hello"}"#)).expect("parse");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field, "title");
        assert!(matches!(
            &c[0].comparison,
            Comparison::Equal(ParseValue::String(s)) if s == "hello"
        ));
    }

    #[test]
    fn several_operators_on_one_field_become_several_constraints() {
        // The storage layer merges these into a range. Producing one constraint here and letting
        // the adapter merge keeps the "constraints never overwrite" property in one place.
        let c = parse_where(&j(r#"{"views":{"$gt":1,"$lt":9}}"#)).expect("parse");
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(|x| x.field == "views"));
    }

    #[test]
    fn a_tagged_value_is_a_literal_not_an_operator_document() {
        let c = parse_where(&j(
            r#"{"author":{"__type":"Pointer","className":"_User","objectId":"u1"}}"#,
        ))
        .expect("parse");
        assert_eq!(c.len(), 1);
        assert!(matches!(
            &c[0].comparison,
            Comparison::Equal(ParseValue::Pointer { object_id, .. }) if object_id == "u1"
        ));
    }

    #[test]
    fn an_unsupported_operator_is_refused() {
        let e = parse_where(&j(r#"{"title":{"$regex":"^a"}}"#)).unwrap_err();
        assert_eq!(e.code, parse_rust_core::ErrorCode::InvalidQuery);
        assert!(e.message.contains("$regex"));
    }

    /// `$or` at the top level must not be read as a field named `$or`, which would match nothing
    /// and look like a legitimate empty result.
    #[test]
    fn a_top_level_operator_is_refused_rather_than_treated_as_a_field() {
        let e = parse_where(&j(r#"{"$or":[{"a":1},{"a":2}]}"#)).unwrap_err();
        assert_eq!(e.code, parse_rust_core::ErrorCode::InvalidQuery);
        assert!(e.message.contains("$or"));
    }

    #[test]
    fn in_and_exists_parse() {
        let c =
            parse_where(&j(r#"{"tag":{"$in":["a","b"]},"x":{"$exists":true}}"#)).expect("parse");
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn an_empty_object_is_an_empty_query_not_an_operator_document() {
        assert!(parse_where(&j("{}")).expect("parse").is_empty());
        // A field set to an empty object is a literal empty object, not an operator document.
        let c = parse_where(&j(r#"{"meta":{}}"#)).expect("parse");
        assert!(matches!(
            &c[0].comparison,
            Comparison::Equal(ParseValue::Object(_))
        ));
    }

    #[test]
    fn where_must_be_an_object() {
        assert!(parse_where(&j("[]")).is_err());
        assert!(parse_where(&j("3")).is_err());
    }
}
