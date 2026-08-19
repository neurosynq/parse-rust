//! Query parameters, from wherever they arrived.
//!
//! `ClassesRouter` merges `req.body` with the decoded query string before reading either
//! (`ClassesRouter.js:23`, `:49`), so a `where` sent in a POST body reaches the same code as one
//! sent in the URL. A `/batch` sub-request has no URL to carry them at all, so its parameters are
//! its body. One type for both, built at each entry point, so the readers below cannot know or
//! care which happened.
//!
//! Values are held as strings, which is the query-string form. A caller that starts from JSON
//! re-encodes objects and arrays as JSON text, which is what a real query string carries.

use std::collections::HashMap;

use parse_rust_core::ParseError;
use parse_rust_rest::{parse_include, parse_where, FindOptions, ParsedWhere};
use parse_rust_storage::{QueryOptions, DEFAULT_LIMIT};
use serde_json::Value as Json;

/// Parameters for one request.
#[derive(Debug, Clone, Default)]
pub struct Params(HashMap<String, String>);

/// `allowConstraints` (`ClassesRouter.js:177-194`). Anything else is `INVALID_QUERY`.
const FIND_KEYS: [&str; 16] = [
    "skip",
    "limit",
    "order",
    "count",
    "keys",
    "excludeKeys",
    "include",
    "includeAll",
    "redirectClassNameForKey",
    "where",
    "readPreference",
    "includeReadPreference",
    "subqueryReadPreference",
    "hint",
    "explain",
    "comment",
];

/// `ALLOWED_GET_QUERY_KEYS` (`ClassesRouter.js:8-15`).
const GET_KEYS: [&str; 6] = [
    "keys",
    "include",
    "excludeKeys",
    "readPreference",
    "includeReadPreference",
    "subqueryReadPreference",
];

/// Parameters upstream accepts and this server does not implement.
///
/// Refused rather than ignored, on the rule that an unsupported query constraint is an error.
/// Each one changes what comes back, so accepting it silently would answer a different question
/// than the client asked. `readPreference` and its two siblings are deliberately absent from this
/// list: they select a replica and do not change the result.
const UNIMPLEMENTED_KEYS: [&str; 5] = [
    "includeAll",
    "redirectClassNameForKey",
    "hint",
    "explain",
    "comment",
];

impl Params {
    pub fn from_map(map: HashMap<String, String>) -> Self {
        Self(map)
    }

    /// Build from a JSON object, which is how a `/batch` sub-request carries its parameters.
    ///
    /// Non-string values are re-encoded as JSON text, matching the query-string form. This is the
    /// inverse of upstream's `JSONFromQuery` (`ClassesRouter.js:142-152`), which parses each query
    /// value as JSON and falls back to the raw string.
    pub fn from_json(value: Option<&Json>) -> Self {
        let mut map = HashMap::new();
        if let Some(Json::Object(object)) = value {
            for (key, value) in object {
                let text = match value {
                    Json::String(s) => s.clone(),
                    other => other.to_string(),
                };
                map.insert(key.clone(), text);
            }
        }
        Self(map)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// `optionsFromBody`'s key check (`ClassesRouter.js:196-200`).
    pub fn reject_unknown_find_keys(&self) -> Result<(), ParseError> {
        for key in self.0.keys() {
            if !FIND_KEYS.contains(&key.as_str()) {
                return Err(ParseError::invalid_query(format!(
                    "Invalid parameter for query: {key}"
                )));
            }
        }
        self.reject_unimplemented()
    }

    /// `handleGet`'s key check (`ClassesRouter.js:52-56`). Note the message says nothing about
    /// which key, which is upstream's.
    pub fn reject_unknown_get_keys(&self) -> Result<(), ParseError> {
        for key in self.0.keys() {
            if !GET_KEYS.contains(&key.as_str()) {
                return Err(ParseError::invalid_query("Improper encode of parameter"));
            }
        }
        self.reject_unimplemented()
    }

    fn reject_unimplemented(&self) -> Result<(), ParseError> {
        for key in UNIMPLEMENTED_KEYS {
            if self.0.contains_key(key) {
                return Err(ParseError::new(
                    parse_rust_core::ErrorCode::CommandUnavailable,
                    format!("The {key} query parameter is not supported yet."),
                ));
            }
        }
        Ok(())
    }

    /// The `where` document, decoded.
    ///
    /// `decodeWhere` (`ClassesRouter.js:165-174`) reports `where parameter is not valid JSON` for
    /// a string that does not parse, and that is the message a client sees.
    pub fn parse_where(&self) -> Result<ParsedWhere, ParseError> {
        let Some(raw) = self.get("where") else {
            return Ok(ParsedWhere::default());
        };
        let value: Json = serde_json::from_str(raw)
            .map_err(|_| ParseError::invalid_json("where parameter is not valid JSON"))?;
        parse_where(&value)
    }

    pub fn wants_count(&self) -> bool {
        // `if (body.count)` is a truthiness test, so `count=0` and `count=false` are both off.
        !matches!(
            self.get("count"),
            None | Some("0") | Some("false") | Some("")
        )
    }

    /// Everything a find carries besides the constraints.
    pub fn find_options(&self) -> Result<FindOptions, ParseError> {
        Ok(FindOptions {
            // An absent or unparsable `limit` falls back to Parse's default of 100 rather than to
            // "no limit". `limit=0` is a legitimate request for zero rows, usually paired with
            // `count=1`, and must not be read as unlimited either.
            limit: Some(
                self.get("limit")
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(DEFAULT_LIMIT),
            ),
            skip: self.get("skip").and_then(|v| v.parse().ok()),
            order: self
                .get("order")
                .map(QueryOptions::parse_order)
                .unwrap_or_default(),
            keys: self.csv("keys"),
            exclude_keys: self.csv("excludeKeys"),
            include: match self.get("include") {
                Some(raw) => parse_include(raw)?,
                None => Vec::new(),
            },
        })
    }

    /// The subset of the above a `get` may carry.
    pub fn get_options(&self) -> Result<FindOptions, ParseError> {
        Ok(FindOptions {
            limit: Some(1),
            skip: None,
            order: Vec::new(),
            keys: self.csv("keys"),
            exclude_keys: self.csv("excludeKeys"),
            include: match self.get("include") {
                Some(raw) => parse_include(raw)?,
                None => Vec::new(),
            },
        })
    }

    fn csv(&self, key: &str) -> Option<Vec<String>> {
        self.get(key).map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> Params {
        Params::from_map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        )
    }

    #[test]
    fn an_unknown_find_parameter_is_named_in_the_error() {
        let e = params(&[("nonsense", "1")])
            .reject_unknown_find_keys()
            .unwrap_err();
        assert_eq!(e.code, parse_rust_core::ErrorCode::InvalidQuery);
        assert_eq!(e.message, "Invalid parameter for query: nonsense");
    }

    #[test]
    fn an_unknown_get_parameter_is_not_named() {
        // Upstream's message carries no key. Two similar checks, two different strings.
        let e = params(&[("limit", "1")])
            .reject_unknown_get_keys()
            .unwrap_err();
        assert_eq!(e.message, "Improper encode of parameter");
    }

    /// An accepted-but-unimplemented parameter is an error, not a silently different answer.
    #[test]
    fn unimplemented_parameters_are_refused_rather_than_ignored() {
        for key in UNIMPLEMENTED_KEYS {
            let e = params(&[(key, "1")])
                .reject_unknown_find_keys()
                .unwrap_err();
            assert_eq!(
                e.code,
                parse_rust_core::ErrorCode::CommandUnavailable,
                "{key}"
            );
        }
        // A read preference only picks a replica, so it is accepted and ignored.
        assert!(params(&[("readPreference", "SECONDARY")])
            .reject_unknown_find_keys()
            .is_ok());
    }

    #[test]
    fn a_batch_sub_request_carries_its_parameters_as_json() {
        let body: Json = serde_json::from_str(r#"{"where":{"a":1},"limit":5}"#).expect("literal");
        let p = Params::from_json(Some(&body));
        assert_eq!(p.get("where"), Some(r#"{"a":1}"#));
        assert_eq!(p.get("limit"), Some("5"));
        assert_eq!(p.find_options().expect("options").limit, Some(5));
    }

    #[test]
    fn a_malformed_where_reports_upstreams_message() {
        let e = params(&[("where", "{oops")]).parse_where().unwrap_err();
        assert_eq!(e.code, parse_rust_core::ErrorCode::InvalidJson);
        assert_eq!(e.message, "where parameter is not valid JSON");
    }

    #[test]
    fn count_is_a_truthiness_test() {
        assert!(params(&[("count", "1")]).wants_count());
        assert!(params(&[("count", "true")]).wants_count());
        assert!(!params(&[("count", "0")]).wants_count());
        assert!(!params(&[]).wants_count());
    }

    #[test]
    fn limit_falls_back_to_the_parse_default_and_zero_is_honoured() {
        assert_eq!(params(&[]).find_options().expect("o").limit, Some(100));
        assert_eq!(
            params(&[("limit", "0")]).find_options().expect("o").limit,
            Some(0)
        );
    }
}
