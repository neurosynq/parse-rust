//! The query AST adapters lower, and the update AST they apply.
//!
//! Not a Mongo query document. A Mongo query document is already lowered, and handing one to the
//! Postgres adapter would mean writing a Mongo-query interpreter in SQL, which is roughly the
//! shape upstream ended up with.
//!
//! **Anything outside the supported vocabulary is an error, never silently ignored**, because a
//! dropped constraint broadens the result set, which is an authorization failure rather than a
//! missing feature. That rule is enforced at parse time by [`Comparison::from_operator`] returning
//! an error for an unknown operator, so there is no code path where an unrecognised constraint
//! reaches an adapter.
//!
//! 0.2.0 turned the flat constraint list into a tree. That was not a generalization for its own
//! sake: pointer permissions compose **disjunctively** across fields
//! (`DatabaseController.js:1816`), so a class permitting `{find: {pointerFields: ['owner',
//! 'editor']}}` cannot be expressed without `$or`. A flat list would have forced either a wrong
//! conjunction, which under-returns, or no constraint at all, which is the breach.

use indexmap::IndexMap;

use parse_rust_core::{ParseError, ParseValue};

/// How one field is compared to one value.
#[derive(Debug, Clone)]
pub enum Comparison {
    /// Bare equality: `{"field": value}`. Lowers to the value itself, with no operator wrapper.
    Equal(ParseValue),
    /// Explicit `$eq`: `{"field": {"$eq": value}}`.
    ///
    /// **Deliberately not the same variant as [`Comparison::Equal`], because the two do not lower
    /// the same way.** Bare equality puts the value directly under the field, so it cannot share
    /// the field with another operator: `{"n": 5}` and `{"n": {"$gt": 1}}` are two whole documents
    /// for one key and merging them means one overwrites the other. `$eq` is an operator like any
    /// other and composes, which is the entire reason upstream's `replaceEquality` rewrites a
    /// mixed constraint into this form rather than leaving it bare (`RestQuery.js:828-849`).
    ///
    /// Folding the two together compiles, passes a round-trip test, and silently undoes that
    /// rewrite one layer below where it was applied.
    ///
    /// It also must not pin an objectId. `ParsedWhere::pinned_object_id` reads the shorthand form
    /// only, matching upstream's direct `query.objectId` read (`DatabaseController.js:1839`), and
    /// a separate variant is what keeps `{"objectId": {"$eq": "x"}}` out of that path.
    EqualOperator(ParseValue),
    NotEqual(ParseValue),
    GreaterThan(ParseValue),
    GreaterThanOrEqual(ParseValue),
    LessThan(ParseValue),
    LessThanOrEqual(ParseValue),
    In(Vec<ParseValue>),
    NotIn(Vec<ParseValue>),
    Exists(bool),
    /// `$all`: the array field contains every listed value.
    All(Vec<ParseValue>),
    /// `$regex`, with `$options` folded in.
    ///
    /// The two arrive as separate keys and upstream keeps them separate all the way down, relying
    /// on reverse-alphabetical key iteration so that `$regex` is handled before `$options`
    /// (`MongoTransform.js:670-675`). Folding them into one variant here removes the ordering
    /// dependency without changing what reaches the backend, because a lone `$options` is
    /// meaningless and a lone `$regex` gets `None`.
    Regex {
        pattern: String,
        options: Option<String>,
    },
    /// Every geo operator one field's constraint document carries, as `(key, operand)` pairs in
    /// the order they arrived, operands raw.
    ///
    /// **One variant for all of them, because upstream lowers them as one loop**
    /// (`MongoTransform.js:670-675`, `:812-955`): the keys are visited in reverse alphabetical
    /// order so `$nearSphere` precedes `$maxDistance`, a count rewrites `$nearSphere` into
    /// `$geoWithin` using its sibling's raw `$maxDistance`, and three spellings of a distance all
    /// write the same output key with the last one visited winning. Splitting them into separate
    /// comparisons would scatter that ordering across a merge that knows nothing about it.
    Geo(Vec<(String, ParseValue)>),
    /// `$text`, the operand raw: `{"$search": {"$term": .., "$language": .., ..}}`. Lowered to the
    /// top level of the filter, where Mongo requires it, rather than under the field
    /// (`MongoTransform.js:332-334`); the field still decides which text index is built.
    Text(ParseValue),
}

/// The constraint keys that belong to [`Comparison::Geo`].
pub const GEO_OPERATORS: [&str; 8] = [
    "$nearSphere",
    "$maxDistance",
    "$maxDistanceInRadians",
    "$maxDistanceInMiles",
    "$maxDistanceInKilometers",
    "$within",
    "$geoWithin",
    "$geoIntersects",
];

impl Comparison {
    /// Map a Parse `$` operator onto a comparison.
    ///
    /// Returns `INVALID_QUERY` for anything unsupported. That is the whole point: the alternative,
    /// ignoring it, returns more rows than the caller asked for.
    ///
    /// `$regex` and `$options` are not handled here, because they are two keys producing one
    /// comparison. The caller assembles them; see `parse_operators` in `parse-rust-rest`.
    pub fn from_operator(op: &str, value: ParseValue) -> Result<Self, ParseError> {
        Ok(match op {
            // Upstream accepts an explicit `$eq` alongside the bare-value form
            // (`MongoTransform.js:684-696`), and `replaceEquality` synthesizes one, so this arm is
            // reachable both from a client that wrote `{"$eq": v}` and from a mixed constraint
            // that was rewritten into one. Either way it stays an operator all the way down.
            "$eq" => Comparison::EqualOperator(value),
            "$ne" => Comparison::NotEqual(value),
            "$gt" => Comparison::GreaterThan(value),
            "$gte" => Comparison::GreaterThanOrEqual(value),
            "$lt" => Comparison::LessThan(value),
            "$lte" => Comparison::LessThanOrEqual(value),
            "$in" | "$nin" | "$all" => {
                let items = match value {
                    ParseValue::Array(items) => items,
                    _ => {
                        return Err(ParseError::invalid_query(format!(
                            "bad {op} value: expected an array"
                        )))
                    }
                };
                match op {
                    "$in" => Comparison::In(items),
                    "$nin" => Comparison::NotIn(items),
                    _ => Comparison::All(items),
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

    pub fn one_of(field: impl Into<String>, values: Vec<ParseValue>) -> Self {
        Self {
            field: field.into(),
            comparison: Comparison::In(values),
        }
    }
}

/// One element of a query. Elements of a [`Query`] are conjoined.
#[derive(Debug, Clone)]
pub enum Clause {
    Field(Constraint),
    /// At least one sub-query matches.
    Or(Vec<Query>),
    /// Every sub-query matches. Distinct from putting the clauses side by side, because a nested
    /// `$and` can carry two constraints on the same field without them merging.
    And(Vec<Query>),
    /// No sub-query matches.
    Nor(Vec<Query>),
}

/// A conjunction of clauses. An empty query matches everything.
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub clauses: Vec<Clause>,
}

impl Query {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.clauses.is_empty()
    }

    pub fn push(&mut self, clause: Clause) {
        self.clauses.push(clause);
    }

    pub fn push_constraint(&mut self, constraint: Constraint) {
        self.clauses.push(Clause::Field(constraint));
    }

    /// Conjoin another query into this one.
    ///
    /// Splicing the other query's clauses in rather than nesting an `And` keeps the common case
    /// flat, which matters because the compiled Mongo document is snapshot-compared. Nesting
    /// would be equally correct and would change every fixture.
    ///
    /// **Only safe when the two queries cannot name the same field.** Two constraints on one
    /// field spliced side by side either merge, which silently drops one, or collide and fail;
    /// [`Query::conjoin`] is the one to reach for when a server-imposed predicate meets a
    /// client-supplied one.
    pub fn extend(&mut self, other: Query) {
        self.clauses.extend(other.clauses);
    }

    /// Conjoin another query into this one **without letting either predicate be lost**.
    ///
    /// A field the receiver already constrains at top level is nested under `And` instead of
    /// spliced in beside the existing constraint. Upstream does the same thing and for the same
    /// reason: `addPointerPermissions` tests `hasOwnProperty(query, key)` and falls back to
    /// `reduceAndOperation({$and: [queryClause, query]})` when it holds
    /// (`DatabaseController.js:1808-1812`).
    ///
    /// Splicing instead is not a cosmetic difference. A client that queries `owner` explicitly on
    /// a class whose `find` CLP names `owner` as a pointer field produces two equalities on one
    /// field, which `merge_constraint` reports as `INVALID_QUERY` rather than answering the query.
    ///
    /// Top level only, matching `hasOwnProperty`: a field named inside an `$or` is a different
    /// key as far as the compiled document is concerned and cannot collide.
    pub fn conjoin(&mut self, other: Query) {
        let mut nested = Vec::new();
        for clause in other.clauses {
            match &clause {
                Clause::Field(constraint) if self.constrains_field(&constraint.field) => {
                    nested.push(Query {
                        clauses: vec![clause],
                    });
                }
                _ => self.clauses.push(clause),
            }
        }
        if !nested.is_empty() {
            self.clauses.push(Clause::And(nested));
        }
    }

    /// Does a top-level clause constrain this field?
    pub fn constrains_field(&self, field: &str) -> bool {
        self.top_level_constraints().any(|c| c.field == field)
    }

    /// A disjunction of alternatives, simplified the way `reduceOrOperation` does
    /// (`DatabaseController.js:1658-1725`): an `$or` with a single element collapses into that
    /// element rather than staying wrapped.
    pub fn any_of(alternatives: Vec<Query>) -> Query {
        let mut alternatives: Vec<Query> =
            alternatives.into_iter().filter(|q| !q.is_empty()).collect();
        match alternatives.len() {
            0 => Query::new(),
            1 => alternatives.remove(0),
            _ => {
                let mut q = Query::new();
                q.push(Clause::Or(alternatives));
                q
            }
        }
    }

    pub fn from_constraints(constraints: Vec<Constraint>) -> Query {
        Query {
            clauses: constraints.into_iter().map(Clause::Field).collect(),
        }
    }

    /// Every top-level field constraint, ignoring nested logical clauses.
    ///
    /// Used by the pieces that need to know whether a query is pinned to one objectId. It is
    /// deliberately not a general "find the constraint on field X", because inside an `$or` no
    /// such thing exists.
    pub fn top_level_constraints(&self) -> impl Iterator<Item = &Constraint> {
        self.clauses.iter().filter_map(|c| match c {
            Clause::Field(f) => Some(f),
            _ => None,
        })
    }
}

impl From<Vec<Constraint>> for Query {
    fn from(constraints: Vec<Constraint>) -> Self {
        Query::from_constraints(constraints)
    }
}

/// What one field of an update does.
///
/// 0.1.0 modelled an update as a row of literal values, which is why `{"__op":"Increment"}`
/// round-tripped into storage as an object with an `__op` key. Modelling the op set explicitly
/// makes "the adapter forgot to handle Increment" a missing match arm.
#[derive(Debug, Clone)]
pub enum UpdateValue {
    /// `$setOnInsert`: set the field only if this operation inserts the row
    /// (`MongoTransform.js:993-998`).
    ///
    /// Carried because upstream carries it, not because a REST write can produce one:
    /// `getObjectType` has no arm for `SetOnInsert` and throws before the write path is reached
    /// (`SchemaController.js:1652-1653`). See `infer_op_type`.
    SetOnInsert(ParseValue),
    /// Replace the field.
    Set(ParseValue),
    /// `$inc`.
    Increment(f64),
    /// `$push` with `$each`. Duplicates allowed.
    Add(Vec<ParseValue>),
    /// `$addToSet` with `$each`.
    AddUnique(Vec<ParseValue>),
    /// `$pullAll`. Note the shape difference from `Add`: no `$each` wrapper
    /// (`MongoTransform.js:1024-1029`).
    Remove(Vec<ParseValue>),
    /// `$unset`.
    Unset,
}

impl UpdateValue {
    /// Does applying this need the post-image read back?
    ///
    /// Only ops do. A `Set` tells the client nothing it did not already know, which is why
    /// `_sanitizeDatabaseResult` returns only op keys (`DatabaseController.js:2141-2169`).
    pub fn echoes_result(&self) -> bool {
        !matches!(self, UpdateValue::Set(_) | UpdateValue::Unset)
    }
}

/// An update: ordered, because the compiled document is snapshot-compared.
pub type Update = IndexMap<String, UpdateValue>;

/// Sort direction for one key. Parse spells descending with a leading `-`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
    /// A full-text search's relevance, from `$score` or `-$score`, on the key `score`. Upstream
    /// maps both spellings to `{score: {$meta: 'textScore'}}` (`RestQuery.js:221-232`), so the
    /// sign is dropped and the order is the database's: most relevant first.
    TextScore,
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
    /// Signed, because a negative skip is the database's refusal, not the parser's. An adapter
    /// refuses it where the database would: after the query is built, so the query's own errors
    /// come first, as upstream's synchronous `transformWhere` makes them.
    pub skip: Option<i64>,
    pub order: Vec<(String, SortDirection)>,
    /// Projection. `None` means every field; `Some` is the explicit list.
    ///
    /// Upstream converts `excludeKeys` into `keys` before it reaches storage, so an adapter only
    /// ever sees the positive form.
    pub keys: Option<Vec<String>>,
    /// Compare strings under upstream's case-insensitive collation rather than byte for byte.
    ///
    /// `{caseInsensitive: true}` (`MongoStorageAdapter.js:723`, `:801-803`), which resolves to
    /// `{locale: "en_US", strength: 2}`. Used by the `_User` username and email uniqueness checks
    /// and by nothing else, because it is the only place upstream asks for it.
    ///
    /// **A case-folding regex is not a substitute and the difference is not academic.** Strength 2
    /// normalizes as well as folding case, so a precomposed `Café` and a decomposed `Café` are one
    /// key to the collation and two distinct byte strings to any regex, which means a regex admits
    /// identities upstream treats as duplicates. It does not fold diacritics: `Café` and `Cafe`
    /// remain different identities under it.
    pub case_insensitive: bool,
    /// `hint`, handed to the driver untouched (`MongoStorageAdapter.js:767`). An index that does
    /// not exist is the driver's error, not a validation here.
    pub hint: Option<Hint>,
    /// `comment`, attached to the operation for the database's profiler and logs.
    pub comment: Option<String>,
}

/// The options a count carries, which are the two upstream hands to `countDocuments`
/// (`MongoStorageAdapter.js:888-910`, `MongoCollection.js:179-198`). A count has no sort, skip,
/// limit or projection of its own.
#[derive(Debug, Clone, Default)]
pub struct CountOptions {
    pub hint: Option<Hint>,
    pub comment: Option<String>,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            limit: Some(DEFAULT_LIMIT),
            skip: None,
            order: Vec::new(),
            keys: None,
            case_insensitive: false,
            hint: None,
            comment: None,
        }
    }
}

/// An index hint: a name, or a key pattern.
///
/// Upstream accepts a string or any object (`ClassesRouter.js:221-223`) and passes it on, so the
/// key pattern is kept as the client sent it, field names included. It is not translated to
/// storage names, because upstream does not translate it either.
#[derive(Debug, Clone)]
pub enum Hint {
    Name(String),
    Keys(parse_rust_core::ParseMap),
}

/// The verbosity of an `explain`. `explain=true` is [`ExplainVerbosity::AllPlansExecution`], which
/// is what the Node driver sends for a boolean (`MongoCollection.js:176`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplainVerbosity {
    QueryPlanner,
    QueryPlannerExtended,
    ExecutionStats,
    AllPlansExecution,
}

impl ExplainVerbosity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QueryPlanner => "queryPlanner",
            Self::QueryPlannerExtended => "queryPlannerExtended",
            Self::ExecutionStats => "executionStats",
            Self::AllPlansExecution => "allPlansExecution",
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
            .map(|k| match k {
                "$score" | "-$score" => ("score".to_string(), SortDirection::TextScore),
                _ => match k.strip_prefix('-') {
                    Some(rest) => (rest.to_string(), SortDirection::Descending),
                    None => (k.to_string(), SortDirection::Ascending),
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_in_either_sign_is_relevance_on_score() {
        assert_eq!(
            QueryOptions::parse_order("-$score,name, $score"),
            vec![
                ("score".to_string(), SortDirection::TextScore),
                ("name".to_string(), SortDirection::Ascending),
                ("score".to_string(), SortDirection::TextScore),
            ]
        );
    }

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
        assert!(Comparison::from_operator("$all", ParseValue::Array(vec![])).is_ok());
        assert!(Comparison::from_operator("$exists", ParseValue::Bool(true)).is_ok());
    }

    /// The rule that keeps a dropped constraint from broadening a result set. The list shrank at
    /// 0.2.0 because some of these landed; what must not change is that the remainder error.
    #[test]
    fn an_unsupported_operator_is_an_error_not_a_no_op() {
        for op in [
            "$select",
            "$dontSelect",
            "$inQuery",
            "$notInQuery",
            "$nearSphere",
            "$text",
            "$containedBy",
            "$geoWithin",
        ] {
            let e = Comparison::from_operator(op, ParseValue::Null).unwrap_err();
            assert_eq!(e.code, parse_rust_core::ErrorCode::InvalidQuery, "{op}");
            assert!(e.message.contains(op), "the message must name the operator");
        }
    }

    #[test]
    fn in_requires_an_array_and_exists_requires_a_boolean() {
        assert!(Comparison::from_operator("$in", ParseValue::Number(1.0)).is_err());
        assert!(Comparison::from_operator("$all", ParseValue::Number(1.0)).is_err());
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

    /// `reduceOrOperation` collapses a single-element disjunction. Reproduced so that a class with
    /// exactly one pointer field compiles to the same document upstream produces.
    #[test]
    fn a_single_alternative_disjunction_collapses() {
        let one = Query::from_constraints(vec![Constraint::equal(
            "owner",
            ParseValue::String("u1".into()),
        )]);
        let q = Query::any_of(vec![one]);
        assert_eq!(q.clauses.len(), 1);
        assert!(matches!(q.clauses[0], Clause::Field(_)));

        let two = Query::any_of(vec![
            Query::from_constraints(vec![Constraint::equal("a", ParseValue::Null)]),
            Query::from_constraints(vec![Constraint::equal("b", ParseValue::Null)]),
        ]);
        assert!(matches!(two.clauses.as_slice(), [Clause::Or(alts)] if alts.len() == 2));
    }

    #[test]
    fn an_empty_alternative_is_dropped_and_an_empty_disjunction_is_unconstrained() {
        assert!(Query::any_of(vec![]).is_empty());
        assert!(Query::any_of(vec![Query::new(), Query::new()]).is_empty());
    }

    #[test]
    fn conjoin_nests_a_colliding_field_and_splices_everything_else() {
        let mut client = Query::from_constraints(vec![Constraint::equal(
            "owner",
            ParseValue::String("u1".into()),
        )]);
        client.conjoin(Query::from_constraints(vec![
            Constraint::equal("owner", ParseValue::String("u1".into())),
            Constraint::equal("state", ParseValue::String("open".into())),
        ]));

        // The client's `owner` survives untouched, `state` is spliced in flat, and the second
        // `owner` is nested where it cannot merge with or displace the first.
        assert!(matches!(
            client.clauses.as_slice(),
            [Clause::Field(a), Clause::Field(b), Clause::And(nested)]
                if a.field == "owner" && b.field == "state" && nested.len() == 1
        ));
    }

    #[test]
    fn conjoin_stays_flat_when_no_field_collides() {
        let mut q = Query::from_constraints(vec![Constraint::equal(
            "title",
            ParseValue::String("a".into()),
        )]);
        q.conjoin(Query::from_constraints(vec![Constraint::equal(
            "owner",
            ParseValue::String("u1".into()),
        )]));
        assert!(matches!(
            q.clauses.as_slice(),
            [Clause::Field(_), Clause::Field(_)]
        ));
    }

    #[test]
    fn conjoin_only_looks_at_top_level_fields() {
        // `owner` named inside an `$or` is a different key in the compiled document, so it cannot
        // collide and must not force the nesting. `hasOwnProperty` upstream behaves the same way.
        let mut q = Query::new();
        q.push(Clause::Or(vec![Query::from_constraints(vec![
            Constraint::equal("owner", ParseValue::String("u2".into())),
        ])]));
        q.conjoin(Query::from_constraints(vec![Constraint::equal(
            "owner",
            ParseValue::String("u1".into()),
        )]));
        assert!(matches!(
            q.clauses.as_slice(),
            [Clause::Or(_), Clause::Field(_)]
        ));
    }

    #[test]
    fn only_ops_echo_their_result_back() {
        assert!(!UpdateValue::Set(ParseValue::Null).echoes_result());
        assert!(!UpdateValue::Unset.echoes_result());
        assert!(UpdateValue::Increment(1.0).echoes_result());
        assert!(UpdateValue::Add(vec![]).echoes_result());
        assert!(UpdateValue::AddUnique(vec![]).echoes_result());
        assert!(UpdateValue::Remove(vec![]).echoes_result());
    }
}
