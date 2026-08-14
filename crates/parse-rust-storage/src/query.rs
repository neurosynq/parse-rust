//! The query AST adapters lower.
//!
//! Not a Mongo query document. A Mongo query document is already lowered, and handing one to the
//! Postgres adapter would mean writing a Mongo-query interpreter in SQL, which is roughly the
//! shape upstream ended up with.
//!
//! The constraint set is the 0.1.0 scope: equality, `$ne`, `$in`, `$nin`, `$exists` and the four
//! range operators, plus `limit`, `skip`, `order`, `count` and `keys`. **Anything outside it
//! is an error, never silently ignored**, because a dropped constraint broadens the result set,
//! which is an authorization failure rather than a missing feature. That rule is enforced at
//! parse time by [`Comparison::from_operator`] returning an error for an unknown operator, so
//! there is no code path where an unrecognised constraint reaches an adapter.

use parse_rust_core::{ParseError, ParseValue};

/// How one field is compared to one value.
#[derive(Debug, Clone)]
pub enum Comparison {
    /// Bare equality: `{"field": value}`.
    Equal(ParseValue),
    NotEqual(ParseValue),
    GreaterThan(ParseValue),
    GreaterThanOrEqual(ParseValue),
    LessThan(ParseValue),
    LessThanOrEqual(ParseValue),
    In(Vec<ParseValue>),
    NotIn(Vec<ParseValue>),
    Exists(bool),
}

impl Comparison {
    /// Map a Parse `$` operator onto a comparison.
    ///
    /// Returns `INVALID_QUERY` for anything unsupported. That is the whole point: the alternative,
    /// ignoring it, returns more rows than the caller asked for.
    pub fn from_operator(op: &str, value: ParseValue) -> Result<Self, ParseError> {
        Ok(match op {
            "$ne" => Comparison::NotEqual(value),
            "$gt" => Comparison::GreaterThan(value),
            "$gte" => Comparison::GreaterThanOrEqual(value),
            "$lt" => Comparison::LessThan(value),
            "$lte" => Comparison::LessThanOrEqual(value),
            "$in" | "$nin" => {
                let items = match value {
                    ParseValue::Array(items) => items,
                    _ => {
                        return Err(ParseError::invalid_query(format!(
                            "bad {op} value: expected an array"
                        )))
                    }
                };
                if op == "$in" {
                    Comparison::In(items)
                } else {
                    Comparison::NotIn(items)
                }
            }
            "$exists" => match value {
                ParseValue::Bool(b) => Comparison::Exists(b),
                _ => {
                    return Err(ParseError::invalid_query(
                        "bad $exists value: expected a boolean".to_string(),
                    ))
                }
            },
            other => {
                return Err(ParseError::invalid_query(format!(
                    "unsupported query operator: {other}"
                )))
            }
        })
    }
}

/// One field, one comparison.
#[derive(Debug, Clone)]
pub struct Constraint {
    pub field: String,
    pub comparison: Comparison,
}

impl Constraint {
    pub fn equal(field: impl Into<String>, value: ParseValue) -> Self {
        Self {
            field: field.into(),
            comparison: Comparison::Equal(value),
        }
    }
}

/// Sort direction for one key. Parse spells descending with a leading `-`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

/// Parse's default page size when a query does not ask for one.
///
/// **Not unlimited.** An omitted `limit` used to produce an unbounded Mongo query, which is both
/// the wrong answer and a denial-of-service surface: one request could ask for every row in a
/// collection.
pub const DEFAULT_LIMIT: u32 = 100;

/// Everything about a read that is not a constraint.
#[derive(Debug, Clone)]
pub struct QueryOptions {
    pub limit: Option<u32>,
    pub skip: Option<u32>,
    pub order: Vec<(String, SortDirection)>,
    /// Projection. `None` means every field; `Some` is the explicit list.
    ///
    /// Upstream converts `excludeKeys` into `keys` before it reaches storage, so an adapter only
    /// ever sees the positive form.
    pub keys: Option<Vec<String>>,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            limit: Some(DEFAULT_LIMIT),
            skip: None,
            order: Vec::new(),
            keys: None,
        }
    }
}

impl QueryOptions {
    /// Parse Parse's `order` parameter: comma-separated keys, `-` prefix for descending.
    pub fn parse_order(order: &str) -> Vec<(String, SortDirection)> {
        order
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|k| match k.strip_prefix('-') {
                Some(rest) => (rest.to_string(), SortDirection::Descending),
                None => (k.to_string(), SortDirection::Ascending),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_operators_map() {
        for op in ["$ne", "$gt", "$gte", "$lt", "$lte"] {
            assert!(
                Comparison::from_operator(op, ParseValue::Number(1.0)).is_ok(),
                "{op}"
            );
        }
        assert!(Comparison::from_operator("$in", ParseValue::Array(vec![])).is_ok());
        assert!(Comparison::from_operator("$nin", ParseValue::Array(vec![])).is_ok());
        assert!(Comparison::from_operator("$exists", ParseValue::Bool(true)).is_ok());
    }

    /// The rule that keeps a dropped constraint from broadening a result set.
    #[test]
    fn an_unsupported_operator_is_an_error_not_a_no_op() {
        for op in [
            "$regex",
            "$select",
            "$inQuery",
            "$all",
            "$nearSphere",
            "$text",
        ] {
            let e = Comparison::from_operator(op, ParseValue::Null).unwrap_err();
            assert_eq!(e.code, parse_rust_core::ErrorCode::InvalidQuery, "{op}");
            assert!(e.message.contains(op), "the message must name the operator");
        }
    }

    #[test]
    fn in_requires_an_array_and_exists_requires_a_boolean() {
        assert!(Comparison::from_operator("$in", ParseValue::Number(1.0)).is_err());
        assert!(Comparison::from_operator("$exists", ParseValue::Number(1.0)).is_err());
    }

    #[test]
    fn the_default_limit_is_a_hundred_not_unlimited() {
        assert_eq!(QueryOptions::default().limit, Some(DEFAULT_LIMIT));
        assert_eq!(DEFAULT_LIMIT, 100);
    }

    #[test]
    fn order_parsing_handles_the_minus_prefix() {
        assert_eq!(
            QueryOptions::parse_order("name,-createdAt, score"),
            vec![
                ("name".to_string(), SortDirection::Ascending),
                ("createdAt".to_string(), SortDirection::Descending),
                ("score".to_string(), SortDirection::Ascending),
            ]
        );
        assert!(QueryOptions::parse_order("").is_empty());
    }
}
