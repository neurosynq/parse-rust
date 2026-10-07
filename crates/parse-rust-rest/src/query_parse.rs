//! Parsing the `where` parameter.
//!
//! A `where` value is `{"field": <literal>}` for equality, or `{"field": {"$op": <value>}}` for
//! everything else. An operator document may carry several operators, which is how a range is
//! expressed. `$or`, `$and`, `$nor` and `$relatedTo` are query-level keys rather than field names.
//!
//! **Anything unsupported is an error.** Silently ignoring an operator returns more rows than the
//! caller asked for, which is an authorization failure rather than a missing feature, and it is
//! the failure mode this rule exists to prevent. The vocabulary grew at 0.2.0; the rule did not
//! relax.
//!
//! The output is a [`ParsedWhere`] rather than a `Query`, because two constructs cannot be
//! lowered without reading the database: `$relatedTo` and a constraint on a `Relation`-typed
//! field are both join-table reads. They stay as nodes here and are resolved by
//! [`crate::relations`] once a schema and a caller are known.

use std::collections::HashSet;

use parse_rust_core::{classify, ErrorCode, ParseError, ParseValue};
use parse_rust_storage::{Comparison, Constraint};
use serde_json::Value as Json;

/// A parsed `where` document: a conjunction of clauses.
#[derive(Debug, Clone, Default)]
pub struct ParsedWhere {
    pub clauses: Vec<ParsedClause>,
}

/// One element of a parsed `where`.
#[derive(Debug, Clone)]
pub enum ParsedClause {
    Field(Constraint),
    /// `{"$relatedTo": {"object": <pointer>, "key": <field>}}`. Resolved against the join table
    /// of the **owning** class, and only after the caller has been authorized to read the owning
    /// object.
    RelatedTo {
        class_name: String,
        object_id: String,
        key: String,
    },
    Or(Vec<ParsedWhere>),
    And(Vec<ParsedWhere>),
    Nor(Vec<ParsedWhere>),
}

impl ParsedWhere {
    pub fn is_empty(&self) -> bool {
        self.clauses.is_empty()
    }

    /// Every field key named anywhere in the tree, including inside logical clauses.
    ///
    /// Used by `denyProtectedFields`, which recurses into `$or`/`$and`/`$nor`
    /// (`RestQuery.js:956-967`).
    pub fn field_keys(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.collect_field_keys(&mut out);
        out
    }

    fn collect_field_keys(&self, out: &mut Vec<String>) {
        for clause in &self.clauses {
            match clause {
                ParsedClause::Field(c) => out.push(c.field.clone()),
                ParsedClause::RelatedTo { .. } => {}
                ParsedClause::Or(branches)
                | ParsedClause::And(branches)
                | ParsedClause::Nor(branches) => {
                    for branch in branches {
                        branch.collect_field_keys(out);
                    }
                }
            }
        }
    }

    /// The objectId this query is pinned to, if it is pinned by a top-level equality.
    ///
    /// Upstream reads `query.objectId` directly (`DatabaseController.js:1839`), which is a string
    /// only for the shorthand equality form. Deliberately does not look inside a logical clause:
    /// inside an `$or` no such pinning exists.
    pub fn pinned_object_id(&self) -> Option<&str> {
        self.clauses.iter().find_map(|c| match c {
            ParsedClause::Field(Constraint {
                field,
                comparison: Comparison::Equal(ParseValue::String(id)),
            }) if field == "objectId" => Some(id.as_str()),
            _ => None,
        })
    }

    pub fn push(&mut self, clause: ParsedClause) {
        self.clauses.push(clause);
    }
}

/// Parse a decoded `where` object.
pub fn parse_where(where_json: &Json) -> Result<ParsedWhere, ParseError> {
    parse_where_at(where_json, true)
}

/// `top_level` carries whether `replaceEquality` applies, which is not a detail worth hiding.
///
/// Upstream runs that rewrite as the last stage of `buildRestWhere`, over the keys of `restWhere`
/// itself (`RestQuery.js:852-858`). A branch inside `$or` is reached through an array, and
/// `replaceEqualityConstraint` iterates an array's indices, which are never `$`-prefixed, so it
/// finds no operator keys and returns the array untouched. The objects inside are therefore never
/// visited. Recursing with this flag unset is what reproduces that: the same mixed constraint
/// means one thing at the top level and another inside `$or`.
fn parse_where_at(where_json: &Json, top_level: bool) -> Result<ParsedWhere, ParseError> {
    let Json::Object(map) = where_json else {
        return Err(ParseError::invalid_query(
            "where must be an object".to_string(),
        ));
    };

    let mut out = ParsedWhere::default();
    for (field, value) in map {
        // `validateQuery` refuses a query on `ACL` outright (`DatabaseController.js:130-132`).
        // The ACL is stored as `_rperm`/`_wperm` and there is no column to match, so accepting
        // this would match nothing and look like a legitimate empty result.
        if field == "ACL" {
            return Err(ParseError::invalid_query(
                "Cannot query on ACL.".to_string(),
            ));
        }

        if let Some(clause) = parse_query_level_key(field, value)? {
            out.push(clause);
            continue;
        }

        match value {
            // An operator document, unless it is a tagged Parse value like a Pointer or Date.
            Json::Object(inner) if is_operator_document(inner) => {
                for constraint in parse_operators(field, inner)? {
                    out.push(ParsedClause::Field(constraint));
                }
            }
            // Mixed: some `$` keys and some ordinary ones. Upstream's `replaceEquality` folds the
            // ordinary keys into a single `$eq` whose value is an object of just those keys, and
            // leaves the operators alone (`RestQuery.js:828-849`).
            //
            // Treating the whole object as a literal instead is the reading that looks obvious and
            // it is wrong in the direction that matters: `{"foo": 1, "$gt": 0}` would ask for a
            // column exactly equal to that two-key object, which matches nothing, so the query
            // returns an empty result rather than an error and nothing says a constraint was
            // dropped.
            Json::Object(inner) if top_level && is_mixed_document(inner) => {
                let mut rewritten = serde_json::Map::new();
                let mut equal_to = serde_json::Map::new();
                for (key, v) in inner {
                    if key.starts_with('$') {
                        rewritten.insert(key.clone(), v.clone());
                    } else {
                        equal_to.insert(key.clone(), v.clone());
                    }
                }
                rewritten.insert("$eq".to_string(), Json::Object(equal_to));
                for constraint in parse_operators(field, &rewritten)? {
                    out.push(ParsedClause::Field(constraint));
                }
            }
            // Shorthand equality. Kept **raw**, like every other operand: see the note in
            // `parse_operators`.
            literal => out.push(ParsedClause::Field(Constraint {
                field: field.clone(),
                comparison: Comparison::Equal(parse_rust_core::classify_raw(literal.clone())?),
            })),
        }
    }
    Ok(out)
}

/// `$or`, `$and`, `$nor` and `$relatedTo` at the top level of a where document.
///
/// Returns `Ok(None)` when the key is not one of the four, so it is read as a field name. **An
/// unknown `$`-prefixed key is not accepted by that**: it reaches [`validate_query_keys`] as a
/// field, fails its pattern and is refused there with upstream's 105 `Invalid key name: $foo`.
/// Refusing it here instead answered with a different code and message, and too early: before
/// the `_Session` refusal, the explain gate and the CLP, all of which run first upstream
/// (`DatabaseController.js:161-188` is `validateQuery`, reached from `find` after the gate).
fn parse_query_level_key(field: &str, value: &Json) -> Result<Option<ParsedClause>, ParseError> {
    if !field.starts_with('$') {
        return Ok(None);
    }
    let clause = match field {
        "$or" | "$and" | "$nor" => {
            let branches = match value {
                Json::Array(items) => items
                    .iter()
                    .map(|item| parse_where_at(item, false))
                    .collect::<Result<Vec<_>, _>>()?,
                // Upstream's messages, `Bad $or format - use an array value.` and the `$nor`
                // variant naming a minimum of one element (`DatabaseController.js:134-159`).
                _ => {
                    return Err(ParseError::invalid_query(if field == "$nor" {
                        "Bad $nor format - use an array of at least 1 value.".to_string()
                    } else {
                        format!("Bad {field} format - use an array value.")
                    }))
                }
            };
            if field == "$nor" && branches.is_empty() {
                return Err(ParseError::invalid_query(
                    "Bad $nor format - use an array of at least 1 value.".to_string(),
                ));
            }
            match field {
                "$or" => ParsedClause::Or(branches),
                "$and" => ParsedClause::And(branches),
                _ => ParsedClause::Nor(branches),
            }
        }
        "$relatedTo" => parse_related_to(value)?,
        _ => return Ok(None),
    };
    Ok(Some(clause))
}

fn parse_related_to(value: &Json) -> Result<ParsedClause, ParseError> {
    let bad = || ParseError::invalid_query("improper usage of $relatedTo".to_string());
    let Json::Object(map) = value else {
        return Err(bad());
    };
    let key = match map.get("key") {
        Some(Json::String(k)) => k.clone(),
        _ => return Err(bad()),
    };
    let object = map.get("object").ok_or_else(bad)?;
    match classify(object.clone())? {
        ParseValue::Pointer {
            class_name,
            object_id,
        } => Ok(ParsedClause::RelatedTo {
            class_name,
            object_id,
            key,
        }),
        _ => Err(bad()),
    }
}

/// Turn one operator document into constraints.
///
/// `$regex` and `$options` are two keys producing one comparison, which is why this is not a
/// straight map over the entries. Upstream keeps them separate all the way down and relies on
/// reverse-alphabetical key iteration so `$regex` is handled before `$options`
/// (`MongoTransform.js:670-675`); folding them here removes the ordering dependency.
fn parse_operators(
    field: &str,
    inner: &serde_json::Map<String, Json>,
) -> Result<Vec<Constraint>, ParseError> {
    let mut out = Vec::new();

    let regex = inner.get("$regex");
    let options = inner.get("$options");
    if regex.is_none() && options.is_some() {
        // A lone `$options` is meaningless. Accepting it would drop the caller's intent
        // silently.
        return Err(ParseError::invalid_query(
            "$options is only valid with $regex".to_string(),
        ));
    }
    if let Some(regex) = regex {
        let Json::String(pattern) = regex else {
            return Err(ParseError::invalid_query(
                "$regex value must be a string".to_string(),
            ));
        };
        let options = match options {
            None => None,
            Some(Json::String(o)) => {
                if !o.chars().all(|c| matches!(c, 'i' | 'm' | 'x' | 's' | 'u')) || o.is_empty() {
                    return Err(ParseError::invalid_query(format!(
                        "Bad $options value for query: {o}"
                    )));
                }
                Some(o.clone())
            }
            Some(_) => {
                return Err(ParseError::invalid_query(
                    "$options value must be a string".to_string(),
                ))
            }
        };
        out.push(Constraint {
            field: field.to_string(),
            comparison: Comparison::Regex {
                pattern: pattern.clone(),
                options,
            },
        });
    }

    // The geo operators travel together, raw, in arrival order; see `Comparison::Geo`.
    let geo: Vec<(String, ParseValue)> = inner
        .iter()
        .filter(|(op, _)| parse_rust_storage::GEO_OPERATORS.contains(&op.as_str()))
        .map(|(op, operand)| Ok((op.clone(), parse_rust_core::classify_raw(operand.clone())?)))
        .collect::<Result<_, ParseError>>()?;
    if !geo.is_empty() {
        out.push(Constraint {
            field: field.to_string(),
            comparison: Comparison::Geo(geo),
        });
    }

    for (op, operand) in inner {
        if op == "$regex"
            || op == "$options"
            || parse_rust_storage::GEO_OPERATORS.contains(&op.as_str())
        {
            continue;
        }
        // **A query operand is compared, not stored, so it keeps what the client sent, and the
        // parser does not interpret a single `__type` envelope.**
        //
        // Two separate reasons, and the second is the one that decides where the work happens.
        //
        // Decoding an operand all the way down drops an unknown key inside a nested envelope, so
        // the operand compares equal to a row upstream would not return: upstream reconstructs a
        // recognized atom and leaves a plain object alone, and the nested case is the plain-object
        // one.
        //
        // Recognizing only the top would fix that, and it still cannot be done here, because
        // **which envelopes count is a property of the field** (`MongoTransform.js:655-662`) and
        // this function has no schema. A constraint operand on an `Array` field takes the interior
        // list of three tags; the same operand on a `GeoPoint` field takes the top-level list of
        // all of them. Choosing either one here is wrong for the other, in opposite directions.
        // So the operand stays raw and `parse-rust-mongo` recognizes it against the field, which is
        // where upstream decides too.
        let operand = parse_rust_core::classify_raw(operand.clone())?;
        let comparison = if op == "$text" {
            Comparison::Text(operand)
        } else {
            Comparison::from_operator(op, operand)?
        };
        out.push(Constraint {
            field: field.to_string(),
            comparison,
        });
    }
    Ok(out)
}

/// Is this object a set of `$` operators rather than a literal value?
///
/// The distinction matters because `{"__type":"Pointer",...}` is a literal and `{"$gt":3}` is
/// not. Upstream decides the same way: it looks for `$`-prefixed keys.
fn is_operator_document(map: &serde_json::Map<String, Json>) -> bool {
    !map.is_empty() && map.keys().all(|k| k.starts_with('$'))
}

/// Both kinds of key present, which is what `replaceEquality` acts on.
///
/// Neither `{"$gt": 0}` nor `{"__type": "Pointer", ...}` qualifies: the rewrite needs one of each,
/// which is exactly upstream's `hasDirectConstraint && hasOperatorConstraint`.
fn is_mixed_document(map: &serde_json::Map<String, Json>) -> bool {
    map.keys().any(|k| k.starts_with('$')) && map.keys().any(|k| !k.starts_with('$'))
}

/// Internal columns a **client** may name in a query (`clientRead`,
/// `DatabaseController.js:31-44`).
///
/// Only these two, and they are readable because a query on `_rperm` is how a client asks "which
/// rows can I see". Everything else internal is refused, and the refusal is load bearing: without
/// it a client can name `_hashed_password` in a `$regex` and recover a bcrypt hash one character
/// at a time.
pub const CLIENT_QUERYABLE_INTERNAL_FIELDS: [&str; 2] = ["_rperm", "_wperm"];

/// Internal columns the **master key** may additionally name (`masterRead`).
///
/// Note what is absent from both lists: `_hashed_password` is `masterRead: false`, so not even
/// master may query it.
pub const MASTER_QUERYABLE_INTERNAL_FIELDS: [&str; 10] = [
    "_email_verify_token",
    "_perishable_token",
    "_perishable_token_expires_at",
    "_email_verify_token_expires_at",
    "_failed_login_count",
    "_account_lockout_expires_at",
    "_password_changed_at",
    "_password_history",
    "_tombstone",
    "_session_token",
];

/// The key-name half of `validateQuery` (`DatabaseController.js:161-188`).
///
/// A key must match `^[a-zA-Z][a-zA-Z0-9_\.]*$` or be one of the internal columns the caller's
/// authority may name. `$relatedTo` is deliberately not in either list, and does not need to be:
/// upstream deletes it from the query before this runs (`DatabaseController.js:1209`), and here it
/// has already been resolved into an `objectId` constraint by the time the check happens.
pub fn validate_query_keys(where_: &ParsedWhere, is_master: bool) -> Result<(), ParseError> {
    for key in where_.field_keys() {
        if matches_query_key_regex(&key)
            || CLIENT_QUERYABLE_INTERNAL_FIELDS.contains(&key.as_str())
            || (is_master && MASTER_QUERYABLE_INTERNAL_FIELDS.contains(&key.as_str()))
        {
            continue;
        }
        return Err(ParseError::invalid_key_name(format!(
            "Invalid key name: {key}"
        )));
    }
    Ok(())
}

/// `^[a-zA-Z][a-zA-Z0-9_\.]*$`.
fn matches_query_key_regex(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// The deepest pointer chain an `include` may name. See [`parse_include`].
pub const MAX_INCLUDE_DEPTH: usize = 20;

/// The most distinct include paths one request may produce, counting expanded prefixes.
/// See [`parse_include`].
pub const MAX_INCLUDE_PATHS: usize = 500;

/// Parse the `include` parameter into paths, every prefix materialized and sorted by depth.
///
/// `a.b.c` yields `a`, `a.b`, `a.b.c`, sorted so a parent resolves before its child
/// (`RestQuery.js:241-257`).
///
/// **`include=*` is out of scope for 0.2.0 and is an explicit error**, not a silently
/// unexpanded response. `includeAll` requires walking every Pointer and Array field of every
/// result class, and returning bare pointers where a client asked for objects is the kind of
/// difference an SDK turns into a null dereference rather than an error.
///
/// **The two limits are a deliberate difference from upstream's defaults, not from upstream.**
/// The pin has `requestComplexity.includeDepth` and `requestComplexity.includeCount`
/// (`Options/Definitions.js:757-768`), and **both default to `-1`, meaning unbounded**, with master
/// and maintenance exempt. So upstream ships the unbounded configuration, which is the denial of
/// service described below; these limits are fixed and always on instead. Tier 2 under the security
/// carve-out, recorded with its blast radius.
///
/// Expanding every prefix means an `include` of *n* components produces *n* paths whose combined
/// component count is n(n+1)/2, and every one of those paths becomes at least one further query in
/// `expand_includes`. That is why the parameter is bounded before it is expanded rather than after,
/// and why the dedupe borrows from the original string: both keep the work linear in the length of
/// the input.
///
/// The values are not upstream's, which has no non-negative default to copy. They are set where a
/// real `include` stops and a hostile one begins: a pointer chain deeper than [`MAX_INCLUDE_DEPTH`] is already
/// beyond anything an SDK generates, and [`MAX_INCLUDE_PATHS`] distinct paths is more than a wide
/// class has fields. A client over either limit is refused by name rather than truncated, because
/// silently dropping an include returns bare pointers where objects were asked for.
pub fn parse_include(include: &str) -> Result<Vec<Vec<String>>, ParseError> {
    let mut paths: Vec<Vec<String>> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for raw in include.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if raw == "*" {
            return Err(ParseError::new(
                ErrorCode::CommandUnavailable,
                "include=* is not supported yet.",
            ));
        }
        let parts: Vec<&str> = raw.split('.').collect();
        if parts.len() > MAX_INCLUDE_DEPTH {
            return Err(ParseError::invalid_query(format!(
                "include path is too deep: at most {MAX_INCLUDE_DEPTH} components."
            )));
        }
        for depth in 1..=parts.len() {
            // Dedupe on a borrowed slice of the original string rather than on an owned
            // `Vec<String>`. The prefix `a.b` is already a substring of `a.b.c`, so its end offset
            // is the start of the next separator and no allocation is needed to recognise it.
            let end = parts[..depth].iter().map(|p| p.len()).sum::<usize>() + depth - 1;
            if !seen.insert(&raw[..end]) {
                continue;
            }
            if paths.len() == MAX_INCLUDE_PATHS {
                return Err(ParseError::invalid_query(format!(
                    "too many include paths: at most {MAX_INCLUDE_PATHS}."
                )));
            }
            paths.push(parts[..depth].iter().map(|s| s.to_string()).collect());
        }
    }
    // Stable, so paths of one depth keep the order the client asked for them in.
    paths.sort_by_key(Vec::len);
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(s: &str) -> Json {
        serde_json::from_str(s).expect("test literal")
    }

    fn fields(w: &ParsedWhere) -> Vec<&Constraint> {
        w.clauses
            .iter()
            .filter_map(|c| match c {
                ParsedClause::Field(f) => Some(f),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_bare_value_is_equality() {
        let w = parse_where(&j(r#"{"title":"hello"}"#)).expect("parse");
        let c = fields(&w);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field, "title");
        assert!(matches!(
            &c[0].comparison,
            Comparison::Equal(ParseValue::String(s)) if s == "hello"
        ));
    }

    #[test]
    fn several_operators_on_one_field_become_several_constraints() {
        let w = parse_where(&j(r#"{"views":{"$gt":1,"$lt":9}}"#)).expect("parse");
        assert_eq!(fields(&w).len(), 2);
        assert!(fields(&w).iter().all(|x| x.field == "views"));
    }

    /// A tagged value is a literal rather than an operator document, and it reaches the backend
    /// **undecoded**.
    ///
    /// Both halves are the assertion. The parser must not read `__type` as a constraint, and it
    /// must not read it as an envelope either: which envelopes count depends on the field's type,
    /// which this layer does not know. Recognition belongs to the backend and is asserted there
    /// (`parse-rust-mongo`'s `the_atom_list_is_chosen_by_the_field_not_by_the_parser`).
    #[test]
    fn a_tagged_value_is_a_literal_and_reaches_the_backend_undecoded() {
        let w = parse_where(&j(
            r#"{"author":{"__type":"Pointer","className":"_User","objectId":"u1","extra":7}}"#,
        ))
        .expect("parse");
        let Comparison::Equal(ParseValue::Object(map)) = &fields(&w)[0].comparison else {
            panic!("expected a raw object operand, got {:?}", fields(&w)[0]);
        };
        // Every key the client sent, including the one no envelope declares. Decoding here would
        // drop `extra`, and for a field type that takes the interior transform upstream compares
        // it.
        assert_eq!(map.len(), 4, "{map:?}");
        assert!(matches!(map.get("objectId"), Some(ParseValue::String(s)) if s == "u1"));
        assert!(matches!(map.get("extra"), Some(ParseValue::Number(n)) if *n == 7.0));
    }

    /// The rule that stops a dropped constraint from broadening a result set. The list shrank at
    /// 0.2.0; what must not change is that the remainder error and that the message names the
    /// operator.
    #[test]
    fn an_unsupported_operator_is_refused() {
        for op in [
            "$inQuery",
            "$notInQuery",
            "$select",
            "$dontSelect",
            "$containedBy",
        ] {
            let src = format!(r#"{{"title":{{"{op}":1}}}}"#);
            let e = parse_where(&j(&src)).unwrap_err();
            assert_eq!(e.code, ErrorCode::InvalidQuery, "{op}");
            assert!(e.message.contains(op), "{op}: {}", e.message);
        }
    }

    #[test]
    fn logical_operators_parse_recursively() {
        let w = parse_where(&j(
            r#"{"$or":[{"a":1},{"$and":[{"b":2},{"c":3}]}],"$nor":[{"d":4}]}"#,
        ))
        .expect("parse");
        assert_eq!(w.clauses.len(), 2);
        match &w.clauses[0] {
            ParsedClause::Or(branches) => {
                assert_eq!(branches.len(), 2);
                assert!(matches!(branches[1].clauses[0], ParsedClause::And(_)));
            }
            other => panic!("expected Or, got {other:?}"),
        }
        assert!(matches!(w.clauses[1], ParsedClause::Nor(_)));
    }

    #[test]
    fn a_non_array_logical_operator_is_invalid() {
        for src in [r#"{"$or":{"a":1}}"#, r#"{"$and":3}"#, r#"{"$nor":[]}"#] {
            let e = parse_where(&j(src)).unwrap_err();
            assert_eq!(e.code, ErrorCode::InvalidQuery, "{src}");
        }
    }

    #[test]
    fn regex_folds_its_options_in() {
        let w = parse_where(&j(r#"{"title":{"$regex":"^a","$options":"im"}}"#)).expect("parse");
        let c = fields(&w);
        assert_eq!(c.len(), 1, "two keys make one comparison");
        assert!(matches!(
            &c[0].comparison,
            Comparison::Regex { pattern, options } if pattern == "^a" && options.as_deref() == Some("im")
        ));
    }

    #[test]
    fn regex_rejects_a_non_string_pattern_and_bad_options() {
        assert!(parse_where(&j(r#"{"title":{"$regex":3}}"#)).is_err());
        let e = parse_where(&j(r#"{"title":{"$regex":"a","$options":"z"}}"#)).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidQuery);
        assert!(e.message.contains("Bad $options value for query: z"));
        assert!(parse_where(&j(r#"{"title":{"$options":"i"}}"#)).is_err());
    }

    #[test]
    fn all_parses() {
        let w = parse_where(&j(r#"{"tags":{"$all":["a","b"]}}"#)).expect("parse");
        assert!(matches!(&fields(&w)[0].comparison, Comparison::All(v) if v.len() == 2));
    }

    #[test]
    fn related_to_parses_into_its_own_clause() {
        let w = parse_where(&j(
            r#"{"$relatedTo":{"object":{"__type":"Pointer","className":"_Role","objectId":"r1"},"key":"users"}}"#,
        ))
        .expect("parse");
        match &w.clauses[0] {
            ParsedClause::RelatedTo {
                class_name,
                object_id,
                key,
            } => {
                assert_eq!(class_name, "_Role");
                assert_eq!(object_id, "r1");
                assert_eq!(key, "users");
            }
            other => panic!("expected RelatedTo, got {other:?}"),
        }
        assert!(parse_where(&j(r#"{"$relatedTo":{"key":"users"}}"#)).is_err());
        assert!(parse_where(&j(r#"{"$relatedTo":{"object":3,"key":"u"}}"#)).is_err());
    }

    #[test]
    fn querying_on_acl_is_refused() {
        let e = parse_where(&j(r#"{"ACL":{"*":{"read":true}}}"#)).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidQuery);
        assert_eq!(e.message, "Cannot query on ACL.");
    }

    #[test]
    fn in_and_exists_parse() {
        let w =
            parse_where(&j(r#"{"tag":{"$in":["a","b"]},"x":{"$exists":true}}"#)).expect("parse");
        assert_eq!(fields(&w).len(), 2);
    }

    #[test]
    fn an_empty_object_is_an_empty_query_not_an_operator_document() {
        assert!(parse_where(&j("{}")).expect("parse").is_empty());
        let w = parse_where(&j(r#"{"meta":{}}"#)).expect("parse");
        assert!(matches!(
            &fields(&w)[0].comparison,
            Comparison::Equal(ParseValue::Object(_))
        ));
    }

    #[test]
    fn where_must_be_an_object() {
        assert!(parse_where(&j("[]")).is_err());
        assert!(parse_where(&j("3")).is_err());
    }

    #[test]
    fn an_unknown_top_level_operator_is_an_invalid_key_at_validation() {
        let w = parse_where(&j(r#"{"$foo":[]}"#)).expect("parsed as a field");
        let e = validate_query_keys(&w, true).expect_err("refused at validation");
        assert_eq!(e.code, parse_rust_core::ErrorCode::InvalidKeyName);
        assert_eq!(e.message, "Invalid key name: $foo");
    }

    #[test]
    fn field_keys_reach_into_logical_clauses() {
        let w = parse_where(&j(r#"{"a":1,"$or":[{"b":2},{"$and":[{"c":3}]}]}"#)).expect("parse");
        let mut keys = w.field_keys();
        keys.sort();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn pinned_object_id_only_reads_a_top_level_equality() {
        let w = parse_where(&j(r#"{"objectId":"abc"}"#)).expect("parse");
        assert_eq!(w.pinned_object_id(), Some("abc"));
        let w = parse_where(&j(r#"{"$or":[{"objectId":"abc"}]}"#)).expect("parse");
        assert_eq!(w.pinned_object_id(), None);
    }

    #[test]
    fn include_paths_materialize_prefixes_and_sort_by_depth() {
        assert_eq!(
            parse_include("a.b.c,d").expect("parse"),
            vec![
                vec!["a".to_string()],
                vec!["d".to_string()],
                vec!["a".to_string(), "b".to_string()],
                vec!["a".to_string(), "b".to_string(), "c".to_string()],
            ]
        );
        assert!(parse_include("").expect("parse").is_empty());
    }

    /// The bound holds, and holds cheaply.
    ///
    /// Two assertions in one: an over-limit input is *refused* rather than truncated, and it is
    /// refused **before** expansion. The second is what the running time proves: this test finishes
    /// in the time a short string takes, which it could not if a 24,000-component path were
    /// expanded first.
    #[test]
    fn a_hostile_include_is_refused_rather_than_expanded() {
        let deep = vec!["a"; MAX_INCLUDE_DEPTH + 1].join(".");
        let err = parse_include(&deep).expect_err("over the depth limit");
        assert_eq!(err.code, ErrorCode::InvalidQuery);

        // What the measured 2.7 GB allocation came from: thousands of components in one path.
        let huge = vec!["a"; 24_000].join(".");
        assert_eq!(
            parse_include(&huge).expect_err("over the depth limit").code,
            ErrorCode::InvalidQuery
        );

        // Many shallow paths hit the path cap instead of the depth cap.
        let wide = (0..MAX_INCLUDE_PATHS + 1)
            .map(|i| format!("f{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_include(&wide).expect_err("over the path limit").code,
            ErrorCode::InvalidQuery
        );

        // The control: something a real client sends is still accepted, so the limits refuse
        // hostile input rather than ordinary input.
        assert_eq!(
            parse_include("author.company.owner").expect("parse").len(),
            3
        );
        let at_depth = vec!["a"; MAX_INCLUDE_DEPTH].join(".");
        assert_eq!(
            parse_include(&at_depth)
                .expect("exactly at the limit")
                .len(),
            MAX_INCLUDE_DEPTH
        );
    }

    #[test]
    fn a_client_cannot_name_an_internal_column_in_a_query() {
        // The one that matters: a `$regex` on the password hash would recover it a character at a
        // time.
        let w = parse_where(&j(r#"{"_hashed_password":{"$regex":"^a"}}"#)).expect("parse");
        for is_master in [false, true] {
            let e = validate_query_keys(&w, is_master).unwrap_err();
            assert_eq!(e.code, ErrorCode::InvalidKeyName);
            assert_eq!(e.message, "Invalid key name: _hashed_password");
        }

        // `_rperm` is queryable by anyone, which is how a client asks what it can see.
        let w = parse_where(&j(r#"{"_rperm":"u1"}"#)).expect("parse");
        assert!(validate_query_keys(&w, false).is_ok());

        // A session token is master-only.
        let w = parse_where(&j(r#"{"_session_token":"r:t"}"#)).expect("parse");
        assert!(validate_query_keys(&w, false).is_err());
        assert!(validate_query_keys(&w, true).is_ok());

        // Nested inside a logical clause, where it would otherwise slip past.
        let w = parse_where(&j(r#"{"$or":[{"_session_token":"r:t"}]}"#)).expect("parse");
        assert!(validate_query_keys(&w, false).is_err());
    }

    #[test]
    fn ordinary_and_dotted_field_names_pass() {
        for src in [r#"{"title":"x"}"#, r#"{"meta.a_b":1}"#] {
            let w = parse_where(&j(src)).expect("parse");
            assert!(validate_query_keys(&w, false).is_ok(), "{src}");
        }
        // A leading digit is not a legal field name.
        let w = parse_where(&j(r#"{"1bad":1}"#)).expect("parse");
        assert!(validate_query_keys(&w, false).is_err());
    }

    #[test]
    fn include_all_is_an_explicit_error() {
        let e = parse_include("*").unwrap_err();
        assert_eq!(e.code, ErrorCode::CommandUnavailable);
        assert!(e.message.contains("include=*"));
    }
}

#[cfg(test)]
mod mixed_constraint_tests {
    use super::*;

    fn parse(json: &str) -> Result<ParsedWhere, ParseError> {
        parse_where(&serde_json::from_str(json).expect("test literal"))
    }

    /// `replaceEquality`: the ordinary keys become one `$eq` object, the operators survive.
    #[test]
    fn a_mixed_constraint_becomes_an_eq_plus_the_operators() {
        let parsed = parse(r#"{"meta": {"foo": 1, "$gt": 0}}"#).expect("parses");
        let mut equals = 0;
        let mut greater = 0;
        for clause in &parsed.clauses {
            let ParsedClause::Field(c) = clause else {
                panic!("expected field clauses")
            };
            assert_eq!(c.field, "meta");
            match &c.comparison {
                // The `$eq` value is an object of just the non-operator keys, not the whole
                // submitted document.
                Comparison::EqualOperator(ParseValue::Object(map)) => {
                    assert_eq!(map.len(), 1, "only the direct keys: {map:?}");
                    assert!(map.contains_key("foo"));
                    equals += 1;
                }
                Comparison::GreaterThan(_) => greater += 1,
                other => panic!("unexpected comparison: {other:?}"),
            }
        }
        assert_eq!((equals, greater), (1, 1));
    }

    /// The whole point: the constraint must not collapse into equality against the submitted
    /// object, which is what matches nothing while returning 200.
    #[test]
    fn a_mixed_constraint_is_not_one_literal_equality() {
        let parsed = parse(r#"{"meta": {"foo": 1, "$gt": 0}}"#).expect("parses");
        assert_eq!(
            parsed.clauses.len(),
            2,
            "one clause means it was read as a literal"
        );
    }

    /// All-operator and all-literal documents are untouched by the rewrite.
    #[test]
    fn unmixed_documents_are_unchanged() {
        let ops = parse(r#"{"n": {"$gt": 0, "$lt": 9}}"#).expect("parses");
        assert_eq!(ops.clauses.len(), 2);

        // A tagged Parse value has no `$` key, so it stays a single literal equality.
        let literal = parse(r#"{"p": {"__type": "Pointer", "className": "C", "objectId": "x"}}"#)
            .expect("parses");
        assert_eq!(literal.clauses.len(), 1);
    }

    /// Upstream applies the rewrite to the keys of `restWhere` itself. A branch of `$or` is
    /// reached through an array, whose indices are never `$`-prefixed, so
    /// `replaceEqualityConstraint` finds no operator key and returns it untouched. The same
    /// constraint therefore means different things at the two depths, and reproducing that is the
    /// whole reason the recursion carries a flag.
    #[test]
    fn the_rewrite_does_not_reach_inside_or() {
        let parsed = parse(r#"{"$or": [{"meta": {"foo": 1, "$gt": 0}}]}"#).expect("parses");
        let [ParsedClause::Or(branches)] = parsed.clauses.as_slice() else {
            panic!("expected one $or clause")
        };
        assert_eq!(branches.len(), 1);
        assert_eq!(
            branches[0].clauses.len(),
            1,
            "inside $or the mixed document stays one literal equality"
        );
    }

    /// An explicit `$eq` from a client, which upstream accepts and parse-rust used to refuse.
    #[test]
    fn an_explicit_eq_operator_is_accepted() {
        let parsed = parse(r#"{"n": {"$eq": 5}}"#).expect("parses");
        assert_eq!(parsed.clauses.len(), 1);
        let ParsedClause::Field(c) = &parsed.clauses[0] else {
            panic!("expected a field clause")
        };
        assert!(matches!(c.comparison, Comparison::EqualOperator(_)));
    }
}
