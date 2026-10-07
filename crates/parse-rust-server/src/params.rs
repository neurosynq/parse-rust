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
use parse_rust_storage::{ExplainVerbosity, Hint, QueryOptions};
use serde_json::Value as Json;

/// Parameters for one request.
#[derive(Debug, Clone, Default)]
pub struct Params(HashMap<String, String>);

/// `allowConstraints` (`ClassesRouter.js:161-178`). Anything else is `INVALID_QUERY`.
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
const UNIMPLEMENTED_KEYS: [&str; 2] = ["includeAll", "redirectClassNameForKey"];

/// The server's row-count settings, which `optionsFromBody` reads from the config.
#[derive(Debug, Clone, Copy)]
pub struct LimitPolicy {
    /// `defaultLimit`, default 100 (`Options/Definitions.js:185-190`).
    pub default_limit: u32,
    /// `maxLimit`, default none (`Options/Definitions.js:413-417`).
    pub max_limit: Option<u32>,
}

impl Default for LimitPolicy {
    fn default() -> Self {
        Self {
            default_limit: parse_rust_storage::DEFAULT_LIMIT,
            max_limit: None,
        }
    }
}

impl Params {
    pub fn from_map(map: HashMap<String, String>) -> Self {
        Self(map)
    }

    /// Build from a JSON object, which is how a `/batch` sub-request carries its parameters.
    ///
    /// Non-string values are re-encoded as JSON text, matching the query-string form. This is the
    /// inverse of upstream's `JSONFromQuery` (`ClassesRouter.js:148-158`), which parses each query
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

    /// `optionsFromBody`'s key check (`ClassesRouter.js:180-184`).
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

    /// `handleGet`'s key check (`ClassesRouter.js:58-62`). Note the message says nothing about
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
    /// `handleFind` (`ClassesRouter.js:32-37`) reports `where parameter is not valid JSON` for a
    /// string that does not parse, and that is the message a client sees.
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
        self.js_value("count").is_some_and(|v| js_truthy(&v))
    }

    /// A parameter as `JSONFromQuery` leaves it: parsed as JSON when it parses, the raw string
    /// otherwise (`ClassesRouter.js:148-158`). Every option below is read from this, because
    /// upstream's tests are JavaScript truthiness and `Number()` over exactly this value.
    fn js_value(&self, key: &str) -> Option<Json> {
        let raw = self.get(key)?;
        Some(serde_json::from_str(raw).unwrap_or_else(|_| Json::String(raw.to_string())))
    }

    /// Whether the request asks for an explain at all: `if (body.explain)`.
    pub fn js_explain_requested(&self) -> bool {
        self.js_value("explain").is_some_and(|v| js_truthy(&v))
    }

    /// `explain`, if the request asks for one, as upstream's adapter validates it: `true`, or one
    /// of the driver's four verbosity names (`MongoStorageAdapter.js:143-158`). Anything else that
    /// is truthy is 102 `Invalid value for explain`, including `1` and `"true"`.
    pub fn explain(&self) -> Result<Option<ExplainVerbosity>, ParseError> {
        let Some(value) = self.js_value("explain").filter(js_truthy) else {
            return Ok(None);
        };
        let verbosity = match &value {
            Json::Bool(true) => ExplainVerbosity::AllPlansExecution,
            Json::String(s) => match s.as_str() {
                "queryPlanner" => ExplainVerbosity::QueryPlanner,
                "queryPlannerExtended" => ExplainVerbosity::QueryPlannerExtended,
                "executionStats" => ExplainVerbosity::ExecutionStats,
                "allPlansExecution" => ExplainVerbosity::AllPlansExecution,
                _ => return Err(ParseError::invalid_query("Invalid value for explain")),
            },
            _ => return Err(ParseError::invalid_query("Invalid value for explain")),
        };
        Ok(Some(verbosity))
    }

    /// `limit`, as `optionsFromBody` and the driver between them resolve it.
    ///
    /// `if (body.limit || body.limit === 0) Number(body.limit) else defaultLimit`
    /// (`ClassesRouter.js:189-193`), then the `maxLimit` cap. Then the driver: exactly zero is no
    /// rows, short-circuited before the database (`RestQuery.js:864`); a value that truncates to
    /// zero, or is not finite, is no limit at all; a negative one is a single batch of its
    /// magnitude.
    ///
    /// `maxLimit` caps the resolved row count. An absent `limit` gets `defaultLimit` uncapped, as
    /// upstream's does, because the cap is on the option.
    fn resolve_limit(&self, policy: &LimitPolicy) -> Option<u32> {
        let requested = self
            .js_value("limit")
            .filter(|v| js_truthy(v) || is_js_zero(v));
        let Some(value) = requested else {
            return Some(policy.default_limit);
        };
        let n = js_number(&value);
        let resolved = if n == 0.0 {
            Some(0)
        } else if !n.is_finite() || n.trunc() == 0.0 {
            None
        } else {
            Some(n.trunc().abs().min(f64::from(u32::MAX)) as u32)
        };
        match policy.max_limit {
            Some(max) if resolved.is_none_or(|r| r > max) => Some(max),
            _ => resolved,
        }
    }

    /// `skip`: `if (body.skip) Number(body.skip)`, truncated by the driver. `NaN` and anything
    /// truncating to zero skip nothing. A negative value is kept, because it is the database that
    /// refuses it upstream, after planning, and the pipeline reproduces that position.
    fn resolve_skip(&self) -> Option<i64> {
        let value = self.js_value("skip").filter(js_truthy)?;
        let n = js_number(&value);
        if !n.is_finite() {
            return None;
        }
        let t = n.trunc();
        (t != 0.0).then(|| t.clamp(i64::MIN as f64, i64::MAX as f64) as i64)
    }

    /// `hint` when it is truthy and a string or an object (`ClassesRouter.js:221-223`). An array
    /// is an object to that test; it is held by index and the database rejects it.
    fn resolve_hint(&self) -> Option<Hint> {
        match self.js_value("hint").filter(js_truthy)? {
            Json::String(name) => Some(Hint::Name(name)),
            Json::Object(map) => Some(Hint::Keys(
                map.into_iter().map(|(k, v)| (k, plain_value(v))).collect(),
            )),
            Json::Array(items) => Some(Hint::Keys(
                items
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| (i.to_string(), plain_value(v)))
                    .collect(),
            )),
            _ => None,
        }
    }

    /// `comment` when it is a non-empty string (`ClassesRouter.js:227-229`). Anything else is
    /// dropped silently, which is upstream's.
    fn resolve_comment(&self) -> Option<String> {
        match self.js_value("comment")? {
            Json::String(s) if !s.is_empty() => Some(s),
            _ => None,
        }
    }

    /// Everything a find carries besides the constraints.
    pub fn find_options(&self, policy: &LimitPolicy) -> Result<FindOptions, ParseError> {
        Ok(FindOptions {
            limit: self.resolve_limit(policy),
            skip: self.resolve_skip(),
            hint: self.resolve_hint(),
            comment: self.resolve_comment(),
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
            hint: None,
            comment: None,
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

/// JavaScript truthiness of a JSON value.
fn js_truthy(value: &Json) -> bool {
    match value {
        Json::Null => false,
        Json::Bool(b) => *b,
        Json::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Json::String(s) => !s.is_empty(),
        Json::Array(_) | Json::Object(_) => true,
    }
}

/// `value === 0`, which `-0` also satisfies.
fn is_js_zero(value: &Json) -> bool {
    matches!(value, Json::Number(n) if n.as_f64() == Some(0.0))
}

/// JavaScript's `Number(value)`.
fn js_number(value: &Json) -> f64 {
    match value {
        Json::Null => 0.0,
        Json::Bool(b) => f64::from(u8::from(*b)),
        Json::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Json::String(s) => string_to_number(s),
        // `Number([3])` is `Number("3")`: an array converts through its `join(",")`, which
        // stringifies nested arrays the same way, so `[[3]]` is `"3"` too.
        Json::Array(_) => string_to_number(&js_join_element(value)),
        Json::Object(_) => f64::NAN,
    }
}

/// `ToString` of a value as `Array.prototype.join` sees an element: `null` is empty, an array is
/// its own `join(",")`, an object is `[object Object]`, a number is ECMAScript's formatting.
fn js_join_element(value: &Json) -> String {
    match value {
        Json::Null => String::new(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => {
            parse_rust_core::js_number::to_ecma_string(n.as_f64().unwrap_or(f64::NAN))
        }
        Json::String(s) => s.clone(),
        Json::Array(items) => items
            .iter()
            .map(js_join_element)
            .collect::<Vec<_>>()
            .join(","),
        Json::Object(_) => "[object Object]".to_string(),
    }
}

/// ECMAScript `StringToNumber`: surrounding whitespace ignored, empty is zero, `Infinity` and the
/// `0x`, `0o` and `0b` prefixes recognised, anything else that is not a decimal literal `NaN`.
fn string_to_number(s: &str) -> f64 {
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

/// A hint key pattern's value, kept as the client sent it.
fn plain_value(value: Json) -> parse_rust_core::ParseValue {
    use parse_rust_core::ParseValue;
    match value {
        Json::Number(n) => ParseValue::Number(n.as_f64().unwrap_or(f64::NAN)),
        Json::String(s) => ParseValue::String(s),
        Json::Bool(b) => ParseValue::Bool(b),
        _ => ParseValue::Null,
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
        assert_eq!(
            p.find_options(&LimitPolicy::default())
                .expect("options")
                .limit,
            Some(5)
        );
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
        assert_eq!(
            params(&[])
                .find_options(&LimitPolicy::default())
                .expect("o")
                .limit,
            Some(100)
        );
        assert_eq!(
            params(&[("limit", "0")])
                .find_options(&LimitPolicy::default())
                .expect("o")
                .limit,
            Some(0)
        );
    }

    /// Each value measured against the 9.10.3 pin over 150 rows. `None` is no limit.
    #[test]
    fn limit_follows_javascript_number_and_the_drivers_truncation() {
        let limit = |raw: &str| {
            params(&[("limit", raw)])
                .find_options(&LimitPolicy::default())
                .expect("options")
                .limit
        };
        for (raw, rows) in [
            ("-1", Some(1)),
            ("-3", Some(3)),
            ("1.5", Some(1)),
            ("99.9", Some(99)),
            ("\"2\"", Some(2)),
            ("[3]", Some(3)),
            ("[]", Some(0)),
            ("-0", Some(0)),
            ("true", Some(1)),
            ("0x10", Some(16)),
            ("\" 0x10 \"", Some(16)),
            ("abc", None),
            ("{}", None),
            ("[1,2]", None),
            ("Infinity", None),
            ("-Infinity", None),
            ("0.5", None),
            ("-0.5", None),
            ("", Some(100)),
            ("null", Some(100)),
            ("false", Some(100)),
            ("\"\"", Some(100)),
        ] {
            assert_eq!(limit(raw), rows, "limit={raw}");
        }
    }

    #[test]
    fn max_limit_caps_the_resolved_row_count_and_not_the_default() {
        let policy = LimitPolicy {
            default_limit: 100,
            max_limit: Some(3),
        };
        let limit = |raw: Option<&str>| {
            let pairs: Vec<(&str, &str)> = raw.map(|r| vec![("limit", r)]).unwrap_or_default();
            params(&pairs).find_options(&policy).expect("options").limit
        };
        assert_eq!(limit(Some("10")), Some(3));
        assert_eq!(limit(Some("2")), Some(2));
        assert_eq!(limit(Some("0")), Some(0));
        assert_eq!(limit(None), Some(100), "the default is not the option");
    }

    #[test]
    fn nested_arrays_and_signed_prefixes_coerce_as_javascript_does() {
        let n = |raw: &str| js_number(&serde_json::from_str(raw).expect("json"));
        assert_eq!(n("[[3]]"), 3.0);
        assert_eq!(n("[[[2]]]"), 2.0);
        assert!(n("[[1,2]]").is_nan(), "\"1,2\" is not a number");
        assert_eq!(n("[null]"), 0.0);
        assert!(n("[{}]").is_nan());
        assert!(string_to_number("0x+10").is_nan());
        assert!(string_to_number("0x").is_nan());
        assert_eq!(string_to_number("0x10"), 16.0);
    }

    #[test]
    fn skip_truncates_and_keeps_its_sign_for_the_database_to_refuse() {
        let skip = |raw: &str| {
            params(&[("skip", raw)])
                .find_options(&LimitPolicy::default())
                .expect("options")
                .skip
        };
        assert_eq!(skip("2"), Some(2));
        assert_eq!(skip("1.5"), Some(1));
        assert_eq!(skip("-1"), Some(-1));
        assert_eq!(skip("-0.5"), None);
        assert_eq!(skip("abc"), None);
        assert_eq!(skip("0"), None);
    }

    #[test]
    fn explain_accepts_true_and_the_four_verbosities_only() {
        let explain = |raw: &str| params(&[("explain", raw)]).explain();
        assert_eq!(
            explain("true").expect("true"),
            Some(ExplainVerbosity::AllPlansExecution)
        );
        assert_eq!(
            explain("queryPlanner").expect("name"),
            Some(ExplainVerbosity::QueryPlanner)
        );
        assert_eq!(explain("false").expect("falsy"), None);
        for bad in ["1", "\"true\"", "bogus", "{}"] {
            let e = explain(bad).expect_err(bad);
            assert_eq!(e.message, "Invalid value for explain", "{bad}");
        }
    }
}
