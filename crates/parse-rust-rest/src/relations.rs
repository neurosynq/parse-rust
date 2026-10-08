//! Relations: the join tables, and the query constructs that read them.
//!
//! **A `Relation` field has no column.** It is skipped on write, stored as `relation<Target>` in
//! `_SCHEMA`, and synthesized from the schema on read. Membership lives in
//! `_Join:<key>:<className>` as documents of exactly `{relatedId, owningId}`
//! (`DatabaseController.js:319-321`, `:418-420`, `:794-830`), and **those collections have no
//! `_SCHEMA` row at all**. `parse_rust_storage::join_schema` builds the shape in memory for that
//! reason: writing a schema row for a join table would add a class every parse-server node
//! reading the same database would then see.
//!
//! **The writes here are not atomic with the parent write.** The row write, the join upsert and
//! the schema reservation are three operations, and without transactions any of them can fail
//! independently, leaving a membership recorded against a row that was never written or a row
//! written without its membership. Upstream has the same exposure on a non-replica-set
//! deployment. It is stated here rather than left to be discovered.

use parse_rust_core::{js_number, ErrorCode, ErrorDetail, ParseError, ParseMap, ParseValue};
use parse_rust_storage::{
    join_schema, Clause, Comparison, Constraint, Query, QueryOptions, StorageAdapter,
};

/// One pending membership change, stripped out of a write body.
#[derive(Debug, Clone)]
pub struct RelationUpdate {
    pub key: String,
    pub kind: RelationOpKind,
    /// The objectIds of the related objects, in the order the client sent them.
    pub related_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationOpKind {
    Add,
    Remove,
}

/// What a `$relatedTo` resolved to.
///
/// Not `Vec<String>` with an empty vector standing in for "denied", because the two have to be
/// distinguishable at the call site even though they narrow the query identically. A caller who
/// cannot read the owning object gets an empty `objectId $in` rather than an error
/// (`DatabaseController.js:1210-1214`), so the relation cannot be used as a membership oracle.
#[derive(Debug, Clone)]
pub enum RelatedToOutcome {
    Ids(Vec<String>),
    DeniedYieldEmpty,
}

impl RelatedToOutcome {
    pub fn ids(&self) -> &[String] {
        match self {
            RelatedToOutcome::Ids(ids) => ids,
            RelatedToOutcome::DeniedYieldEmpty => &[],
        }
    }
}

/// The find options a join-table read uses.
///
/// **Not `QueryOptions::default()`**, whose limit is 100. A role with more than a hundred members
/// would silently lose the rest, and the loss would look like a permission problem. Upstream
/// passes an empty options object, meaning unbounded (`DatabaseController.js:1031`).
fn join_query_options(keys: &[&str]) -> QueryOptions {
    QueryOptions {
        limit: None,
        skip: None,
        order: Vec::new(),
        keys: Some(keys.iter().map(|k| k.to_string()).collect()),
        case_insensitive: false,
        ..QueryOptions::default()
    }
}

/// Strip `AddRelation` and `RemoveRelation` out of a write body, including inside a `Batch`.
///
/// `collectRelationUpdates` (`DatabaseController.js:733-766`). Note that a `Batch` containing a
/// relation op removes the **whole key** from the write, so a batch mixing a relation op with
/// anything else loses the rest. That is upstream's `deleteMe.push(key)` and it is reproduced.
pub fn collect_relation_updates(body: &mut crate::WriteBody) -> Vec<RelationUpdate> {
    use parse_rust_core::{FieldWrite, Op};

    fn walk(key: &str, op: &Op, out: &mut Vec<RelationUpdate>) -> bool {
        match op {
            Op::AddRelation(objects) => {
                out.push(RelationUpdate {
                    key: key.to_string(),
                    kind: RelationOpKind::Add,
                    related_ids: related_object_ids(objects),
                });
                true
            }
            Op::RemoveRelation(objects) => {
                out.push(RelationUpdate {
                    key: key.to_string(),
                    kind: RelationOpKind::Remove,
                    related_ids: related_object_ids(objects),
                });
                true
            }
            Op::Batch(ops) => {
                let mut any = false;
                for inner in ops {
                    any |= walk(key, inner, out);
                }
                any
            }
            _ => false,
        }
    }

    let mut updates = Vec::new();
    let mut remove: Vec<String> = Vec::new();
    for (key, write) in body.iter() {
        if let FieldWrite::Op(op) = write {
            if walk(key, op, &mut updates) {
                remove.push(key.clone());
            }
        }
    }
    for key in remove {
        body.shift_remove(&key);
    }
    updates
}

/// The objectIds inside a relation op's `objects` array.
///
/// Upstream reads `object.objectId` without checking `__type`, so a bare `{objectId: "x"}` works
/// the same as a Pointer. An element with no objectId is skipped rather than written as a join
/// document with a null `relatedId`, which is what upstream's `undefined` would store.
fn related_object_ids(objects: &[ParseValue]) -> Vec<String> {
    objects
        .iter()
        .filter_map(|v| match v {
            ParseValue::Pointer { object_id, .. } => Some(object_id.clone()),
            ParseValue::Object(map) => match map.get("objectId") {
                Some(ParseValue::String(id)) => Some(id.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Apply membership changes, after the row write has succeeded.
///
/// `handleRelationUpdates` (`DatabaseController.js:770-831`). An add is an upsert, so adding a
/// user to a role twice is one membership. A remove that matches nothing is not an error:
/// upstream swallows `OBJECT_NOT_FOUND` (`:823-829`).
pub async fn apply_relation_updates<S: StorageAdapter>(
    storage: &S,
    class_name: &str,
    object_id: &str,
    updates: &[RelationUpdate],
) -> Result<(), ParseError> {
    for update in updates {
        let schema = join_schema(class_name, &update.key);
        for related_id in &update.related_ids {
            let mut doc = ParseMap::new();
            doc.insert(
                "relatedId".to_string(),
                ParseValue::String(related_id.clone()),
            );
            doc.insert(
                "owningId".to_string(),
                ParseValue::String(object_id.to_string()),
            );
            let query = Query::from_constraints(vec![
                Constraint::equal("relatedId", ParseValue::String(related_id.clone())),
                Constraint::equal("owningId", ParseValue::String(object_id.to_string())),
            ]);
            match update.kind {
                RelationOpKind::Add => storage.upsert_one(&schema, &query, &doc).await?,
                RelationOpKind::Remove => match storage.delete(&schema, &query).await {
                    Ok(_) => {}
                    Err(e) if e.code == ErrorCode::ObjectNotFound => {}
                    Err(e) => return Err(e),
                },
            }
        }
    }
    Ok(())
}

/// The related objectIds of one owning object. `relatedIds` (`DatabaseController.js:1016-1033`).
pub async fn related_ids<S: StorageAdapter>(
    storage: &S,
    owning_class: &str,
    key: &str,
    owning_id: &str,
) -> Result<Vec<String>, ParseError> {
    let schema = join_schema(owning_class, key);
    let query = Query::from_constraints(vec![Constraint::equal(
        "owningId",
        ParseValue::String(owning_id.to_string()),
    )]);
    let rows = storage
        .find(&schema, &query, &join_query_options(&["relatedId"]))
        .await?;
    Ok(string_column(rows, "relatedId"))
}

/// The owning objectIds that relate to any of these ids. `owningIds`
/// (`DatabaseController.js:1037-1046`).
pub async fn owning_ids<S: StorageAdapter>(
    storage: &S,
    owning_class: &str,
    key: &str,
    related_ids: &[String],
) -> Result<Vec<String>, ParseError> {
    let schema = join_schema(owning_class, key);
    let query = Query::from_constraints(vec![Constraint::one_of(
        "relatedId",
        related_ids
            .iter()
            .map(|id| ParseValue::String(id.clone()))
            .collect(),
    )]);
    let rows = storage
        .find(&schema, &query, &join_query_options(&["owningId"]))
        .await?;
    Ok(string_column(rows, "owningId"))
}

fn string_column(rows: Vec<ParseMap>, key: &str) -> Vec<String> {
    rows.into_iter()
        .filter_map(|row| match row.get(key) {
            Some(ParseValue::String(s)) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

/// `authorizeRelatedToQuery` (`DatabaseController.js:1261-1309`), run **before** the join table
/// is read.
///
/// Two checks, and neither is redundant. The relation key must not be a protected field on the
/// *owning* class, because the downstream protected-field filter only ever applies to the class
/// being queried. And the caller must be able to read the owning object, because none of the
/// owning class's CLP or ACL is otherwise consulted.
///
/// `can_read_owning` performs the second check as a full read with the caller's own auth. It is a
/// parameter rather than a call into the pipeline so that the recursion stays at the one place
/// that owns it.
pub async fn authorize_related_to<F, Fut>(
    owning_class: &str,
    relation_key: &str,
    owning_protected_fields: &[String],
    detail: ErrorDetail,
    can_read_owning: F,
) -> Result<bool, ParseError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<bool, ParseError>>,
{
    let root = relation_key.split('.').next().unwrap_or(relation_key);
    if owning_protected_fields
        .iter()
        .any(|f| f == relation_key || f == root)
    {
        // `createSanitizedError` (`DatabaseController.js:1280-1284`).
        return Err(ParseError::permission_denied(
            ErrorCode::OperationForbidden,
            format!("This user is not allowed to query {relation_key} on class {owning_class}"),
            detail,
        ));
    }
    can_read_owning().await
}

/// Which reverse-join read a constraint on a `Relation`-typed field asks for.
///
/// `reduceInRelation` (`DatabaseController.js:1051-1144`). Note the fourth case: **any other
/// constraint on a relation field yields no results at all**, because upstream falls into its
/// `else` branch with an empty related-id list. That is reproduced rather than turned into an
/// error, since it narrows rather than broadens and a client can already observe it.
#[derive(Debug, Clone)]
pub enum RelationConstraint {
    /// The owning objects related to any of these ids.
    OwnersOf(Vec<String>),
    /// The complement: `objectId $nin`.
    NotOwnersOf(Vec<String>),
}

/// The `objectId` of an operand, **with no tag check**.
///
/// **Upstream reads the key off the raw REST JSON and never runs an atom transform here**
/// (`DatabaseController.js:1093-1102`: `relatedIds = [query[key].objectId]`, and `r => r.objectId`
/// across `$in` and `$nin`). `reduceInRelation` runs on the REST query, before anything reaches the
/// Mongo lowering, so the value it sees is the object the client sent, and `r.objectId` asks
/// nothing about `__type`.
///
/// Both spellings are read because both occur. A parsed operand is a raw `Object`, since query
/// operands are no longer decoded before the schema is known; a constraint the CLP and ACL paths
/// build in Rust carries a real `Pointer`.
///
/// **`null` is refused rather than skipped.** It is the one operand upstream cannot read
/// `.objectId` from, because it is the one value JavaScript will not box, so it raises an uncaught
/// `TypeError` and the request 500s (`DatabaseController.js:1097-1105`; reported upstream as
/// parse-community/parse-server#10637). Every other unusable operand is harmless there: `7` and
/// `{"foo":1}` both yield `undefined`, which contributes no id.
///
/// Skipping it silently is the one answer that must not be given. A dropped element of a `$nin`
/// leaves an empty exclusion list, which excludes nobody, so `{"friends":{"$nin":[null]}}` returns
/// every otherwise-readable row where upstream returns none at all. Refusing narrows instead, and
/// says why.
fn object_id_of(value: &ParseValue) -> Result<Option<String>, ParseError> {
    match value {
        ParseValue::Null => Err(ParseError::invalid_json(
            "cannot use null in a constraint on a Relation field",
        )),
        ParseValue::Pointer { object_id, .. } => Ok(Some(object_id.clone())),
        // Note what is *not* checked: upstream does not require `className` to agree with the
        // relation's target, and does not reject a missing one. Adding either would narrow a query
        // it answers.
        ParseValue::Object(map) => Ok(match map.get("objectId") {
            Some(ParseValue::String(id)) => Some(id.clone()),
            _ => None,
        }),
        _ => Ok(None),
    }
}

/// Does this operand carry the `Pointer` tag?
///
/// **Only shorthand equality asks.** The gate is
/// `query[key].$in || query[key].$ne || query[key].$nin || query[key].__type == 'Pointer'`
/// (`DatabaseController.js:1085-1091`): the first three are satisfied by the *operator* being
/// present, and only the fourth, which is the no-operator case, inspects a tag.
fn is_tagged_pointer(value: &ParseValue) -> bool {
    match value {
        ParseValue::Pointer { .. } => true,
        ParseValue::Object(map) => {
            matches!(map.get("__type"), Some(ParseValue::String(t)) if t == "Pointer")
        }
        _ => false,
    }
}

/// Does this comparison satisfy upstream's gate?
///
/// ```text
/// query[key] && (query[key]['$in'] || query[key]['$ne'] || query[key]['$nin']
///                || query[key].__type == 'Pointer')
/// ```
///
/// (`DatabaseController.js:1085-1091`.) **Every term is a truthiness test**, and the third one has
/// teeth because `$ne`'s operand is arbitrary: `$ne: null`, `$ne: false`, `$ne: 0` and `$ne: ""`
/// are all falsy, so the gate fails and the whole constraint resolves to no owners. Treating `$ne`
/// as satisfied merely by being present made those four return **every** owner, where upstream
/// returns none. Measured against a running server at the pin.
///
/// `$in` and `$nin` always satisfy it, because the parser guarantees an array and every array is
/// truthy in JavaScript, the empty one included.
fn satisfies_gate(comparison: &Comparison) -> bool {
    match comparison {
        Comparison::Equal(v) => is_tagged_pointer(v),
        Comparison::In(_) | Comparison::NotIn(_) => true,
        Comparison::NotEqual(v) => js_number::is_truthy(v),
        _ => false,
    }
}

/// Read **every constraint on one `Relation`-typed field**, as one group.
///
/// **The group is the unit, not the comparison, and that is what makes the gate expressible.**
/// Upstream tests `query[key]`, the entire operator document, and then iterates its keys
/// (`DatabaseController.js:1085-1113`). So `{"$ne": false, "$in": [<pointer>]}` passes on the `$in`
/// and still processes the `$ne`, which contributes nothing because its operand names no id.
/// Evaluating the gate one comparison at a time cannot express that: it either drops the `$in`
/// along with the `$ne` or keeps the `$ne` along with the `$in`, and the second is what returned
/// every owner for a falsy `$ne` alone.
///
/// Returns one entry per operator upstream would build a query for, which is why it is a `Vec`:
/// `{"$in": [a], "$nin": [b]}` is an inclusion *and* an exclusion, applied independently.
///
/// **The tag requirement belongs to shorthand equality alone.** Requiring it everywhere silently
/// drops the ids out of a `$nin`, and an empty exclusion list excludes nobody, so the query returns
/// the owners it was told to remove.
///
/// ACL and CLP still apply to whatever this produces, so getting it wrong widens a result set
/// rather than bypassing authorization. Widening is still wrong.
pub fn relation_constraints_for(
    comparisons: &[Comparison],
) -> Result<Vec<RelationConstraint>, ParseError> {
    fn ids(values: &[ParseValue]) -> Result<Vec<String>, ParseError> {
        let mut out = Vec::new();
        for value in values {
            if let Some(id) = object_id_of(value)? {
                out.push(id);
            }
        }
        Ok(out)
    }
    // The gate fails: `queries = [{isNegation: false, relatedIds: []}]`, which resolves to no
    // owners and therefore to an empty result. Nothing is extracted, so nothing is refused: a bare
    // `{"$ne": null}` is an empty result upstream and here, not an error.
    if !comparisons.iter().any(satisfies_gate) {
        return Ok(vec![RelationConstraint::OwnersOf(Vec::new())]);
    }
    let mut out = Vec::new();
    for comparison in comparisons {
        out.push(match comparison {
            // The gate's fourth term, and the only one that reads a tag.
            Comparison::Equal(v) if is_tagged_pointer(v) => {
                RelationConstraint::OwnersOf(object_id_of(v)?.into_iter().collect())
            }
            Comparison::In(values) => RelationConstraint::OwnersOf(ids(values)?),
            // An empty list is upstream's answer too, and it is the right one: `$nin` against no
            // ids excludes nothing. It arises from `relatedIds` holding only `undefined`, which
            // `owningIds` resolves to no owners.
            Comparison::NotIn(values) => RelationConstraint::NotOwnersOf(ids(values)?),
            // A falsy `$ne` that rode in on a sibling's gate names no id, so it excludes nothing.
            // A **null** one is refused, because that is where upstream throws.
            Comparison::NotEqual(v) => {
                RelationConstraint::NotOwnersOf(object_id_of(v)?.into_iter().collect())
            }
            // Upstream's `else { return; }`: a key it does not handle yields `undefined`, and
            // `if (!q) return` drops it before any query runs. `$eq` lands here, having no case of
            // its own, and so does every operator that is not one of the four.
            _ => continue,
        });
    }
    Ok(out)
}

/// Intersect an `objectId $in` into a query. `addInObjectIdsIds`
/// (`DatabaseController.js:1311-1346`).
///
/// The intersection is the point. Two separate `objectId` constraints cannot be conjoined by the
/// Mongo lowering (a second `$in` would overwrite the first, and an `$eq` beside an `$in` is a
/// conflict), so the existing constraints are collected and folded in here instead.
pub fn add_in_object_ids(query: &mut Query, ids: &[String]) {
    let mut sets: Vec<Vec<String>> = Vec::new();
    query.clauses.retain(|clause| match clause {
        Clause::Field(Constraint { field, comparison }) if field == "objectId" => {
            match comparison {
                Comparison::Equal(ParseValue::String(id)) => {
                    sets.push(vec![id.clone()]);
                    false
                }
                Comparison::In(values) => {
                    sets.push(
                        values
                            .iter()
                            .filter_map(|v| match v {
                                ParseValue::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .collect(),
                    );
                    false
                }
                _ => true,
            }
        }
        _ => true,
    });
    sets.push(ids.to_vec());

    let mut intersection: Vec<String> = Vec::new();
    if let Some((first, rest)) = sets.split_first() {
        for id in first {
            if !intersection.contains(id) && rest.iter().all(|set| set.contains(id)) {
                intersection.push(id.clone());
            }
        }
    }
    query.push_constraint(Constraint::one_of(
        "objectId",
        intersection.into_iter().map(ParseValue::String).collect(),
    ));
}

/// Union an `objectId $nin` into a query. `addNotInObjectIdsIds`
/// (`DatabaseController.js:1348-1373`).
pub fn add_not_in_object_ids(query: &mut Query, ids: &[String]) {
    let mut union: Vec<String> = Vec::new();
    query.clauses.retain(|clause| match clause {
        Clause::Field(Constraint {
            field,
            comparison: Comparison::NotIn(values),
        }) if field == "objectId" => {
            for v in values {
                if let ParseValue::String(s) = v {
                    if !union.contains(s) {
                        union.push(s.clone());
                    }
                }
            }
            false
        }
        _ => true,
    });
    for id in ids {
        if !union.contains(id) {
            union.push(id.clone());
        }
    }
    query.push_constraint(Constraint {
        field: "objectId".to_string(),
        comparison: Comparison::NotIn(union.into_iter().map(ParseValue::String).collect()),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_core::{op::OpPath, FieldWrite};

    fn body(json: &str) -> crate::WriteBody {
        crate::decode_write_body(
            &serde_json::from_str(json).expect("test literal"),
            OpPath::Update,
        )
        .expect("decode")
    }

    #[test]
    fn relation_ops_are_stripped_out_of_the_write() {
        let mut b = body(
            r#"{
                "name":"admins",
                "users":{"__op":"AddRelation","objects":[
                    {"__type":"Pointer","className":"_User","objectId":"u1"},
                    {"__type":"Pointer","className":"_User","objectId":"u2"}
                ]}
            }"#,
        );
        let ops = collect_relation_updates(&mut b);
        assert!(b.contains_key("name"));
        assert!(
            !b.contains_key("users"),
            "a Relation field has no column, so it must not reach the row write"
        );
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].kind, RelationOpKind::Add);
        assert_eq!(ops[0].related_ids, vec!["u1", "u2"]);
    }

    #[test]
    fn a_batch_of_relation_ops_is_stripped_whole() {
        let mut b = body(
            r#"{"users":{"__op":"Batch","ops":[
                {"__op":"AddRelation","objects":[{"__type":"Pointer","className":"_User","objectId":"u1"}]},
                {"__op":"RemoveRelation","objects":[{"__type":"Pointer","className":"_User","objectId":"u2"}]}
            ]}}"#,
        );
        let ops = collect_relation_updates(&mut b);
        assert!(b.is_empty());
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].kind, RelationOpKind::Add);
        assert_eq!(ops[1].kind, RelationOpKind::Remove);
    }

    #[test]
    fn a_non_relation_op_is_left_alone() {
        let mut b = body(r#"{"views":{"__op":"Increment","amount":1}}"#);
        assert!(collect_relation_updates(&mut b).is_empty());
        assert!(matches!(b.get("views"), Some(FieldWrite::Op(_))));
    }

    /// **Both spellings of a pointer operand, and the gate the group has to satisfy.**
    ///
    /// A parsed constraint carries the raw object: query operands are no longer decoded before the
    /// schema is known, since which envelopes count depends on the field. A constraint the ACL and
    /// CLP paths build in Rust carries a real `Pointer`.
    #[test]
    fn relation_field_constraints_map_to_the_reverse_join() {
        let decoded = ParseValue::Pointer {
            class_name: "_User".into(),
            object_id: "u1".into(),
        };
        let mut raw = ParseMap::new();
        raw.insert("__type".into(), ParseValue::String("Pointer".into()));
        raw.insert("className".into(), ParseValue::String("_User".into()));
        raw.insert("objectId".into(), ParseValue::String("u1".into()));
        // An extra key an envelope does not declare, which the raw form keeps and which must not
        // stop the objectId being read: upstream reads the key off the object and checks nothing
        // else.
        raw.insert("extra".into(), ParseValue::Number(7.0));
        let raw = ParseValue::Object(raw);

        let one = |c: Comparison| {
            let out = relation_constraints_for(&[c]).expect("accepted");
            assert_eq!(out.len(), 1, "{out:?}");
            out.into_iter().next().unwrap()
        };

        for pointer in [decoded, raw] {
            assert!(matches!(
                one(Comparison::Equal(pointer.clone())),
                RelationConstraint::OwnersOf(ids) if ids == ["u1"]
            ));
            assert!(matches!(
                one(Comparison::In(vec![pointer.clone()])),
                RelationConstraint::OwnersOf(ids) if ids == ["u1"]
            ));
            assert!(matches!(
                one(Comparison::NotIn(vec![pointer.clone()])),
                RelationConstraint::NotOwnersOf(ids) if ids == ["u1"]
            ));
            assert!(matches!(
                one(Comparison::NotEqual(pointer)),
                RelationConstraint::NotOwnersOf(ids) if ids == ["u1"]
            ));
        }

        // Anything else fails upstream's gate and yields no owners, which is an empty result
        // rather than an unconstrained one.
        assert!(matches!(
            one(Comparison::Exists(true)),
            RelationConstraint::OwnersOf(ids) if ids.is_empty()
        ));
        // Shorthand equality is the one form that needs the tag, because it is the one term of
        // upstream's gate that inspects a value rather than a key.
        let untagged = {
            let mut m = ParseMap::new();
            m.insert("objectId".into(), ParseValue::String("u1".into()));
            ParseValue::Object(m)
        };
        assert!(matches!(
            one(Comparison::Equal(untagged.clone())),
            RelationConstraint::OwnersOf(ids) if ids.is_empty()
        ));

        // **And the three operator forms must not need it.** An operator satisfies the gate by
        // being present, so the id is read whatever the operand is tagged. Requiring the tag here
        // dropped it, and an empty `$nin` excludes nobody: the query then returns the very owners
        // it was told to remove.
        assert!(matches!(
            one(Comparison::NotIn(vec![untagged.clone()])),
            RelationConstraint::NotOwnersOf(ids) if ids == ["u1"]
        ));
        assert!(matches!(
            one(Comparison::In(vec![untagged.clone()])),
            RelationConstraint::OwnersOf(ids) if ids == ["u1"]
        ));
        assert!(matches!(
            one(Comparison::NotEqual(untagged)),
            RelationConstraint::NotOwnersOf(ids) if ids == ["u1"]
        ));
    }

    /// **A falsy `$ne` fails the gate, and failing the gate means no owners rather than no
    /// exclusion.**
    ///
    /// Measured against a running server at the pin: `$ne` with `null`, `false`, `0` or `""`
    /// returns nothing at all. Producing `NotOwnersOf([])` for them instead excludes nobody, so
    /// every owner comes back. ACL and CLP still apply on top, so this widens a result set rather
    /// than bypassing authorization, and widening is still the wrong direction.
    #[test]
    fn a_falsy_ne_fails_the_gate_and_returns_no_owners() {
        for falsy in [
            ParseValue::Null,
            ParseValue::Bool(false),
            ParseValue::Number(0.0),
            ParseValue::String(String::new()),
        ] {
            let out =
                relation_constraints_for(&[Comparison::NotEqual(falsy.clone())]).expect("accepted");
            assert!(
                matches!(out.as_slice(), [RelationConstraint::OwnersOf(ids)] if ids.is_empty()),
                "{falsy:?} must fail the gate, got {out:?}"
            );
        }
        // A truthy non-object operand passes the gate and names no id, so it excludes nothing.
        // That is upstream's `undefined` reaching `owningIds`, and it returns every owner.
        let out = relation_constraints_for(&[Comparison::NotEqual(ParseValue::Number(7.0))])
            .expect("accepted");
        assert!(
            matches!(out.as_slice(), [RelationConstraint::NotOwnersOf(ids)] if ids.is_empty()),
            "{out:?}"
        );
    }

    /// **A `null` operand is refused rather than skipped.**
    ///
    /// It is the one value upstream cannot read `.objectId` from, so it raises an uncaught
    /// `TypeError` and the request 500s. Skipping it is the one answer that must not be given:
    /// a dropped element of a `$nin` leaves an empty exclusion list, which excludes nobody, so the
    /// query returns every otherwise-readable row where upstream returns none.
    #[test]
    fn a_null_operand_is_refused_rather_than_erased() {
        for comparison in [
            Comparison::In(vec![ParseValue::Null]),
            Comparison::NotIn(vec![ParseValue::Null]),
            Comparison::In(vec![
                ParseValue::Pointer {
                    class_name: "_User".into(),
                    object_id: "u1".into(),
                },
                ParseValue::Null,
            ]),
        ] {
            let err = relation_constraints_for(std::slice::from_ref(&comparison))
                .expect_err("a null operand is refused");
            assert_eq!(
                err.message, "cannot use null in a constraint on a Relation field",
                "{comparison:?}"
            );
        }

        // A `$ne: null` riding in on a truthy sibling is extracted, so it is refused too. This is
        // the case that 500s upstream.
        let err = relation_constraints_for(&[
            Comparison::NotEqual(ParseValue::Null),
            Comparison::In(Vec::new()),
        ])
        .expect_err("refused");
        assert_eq!(
            err.message,
            "cannot use null in a constraint on a Relation field"
        );

        // **A bare `{"$ne": null}` is not refused**, because it fails the gate and nothing is ever
        // extracted. Upstream answers it with an empty result rather than an error, and so does
        // this.
        let out = relation_constraints_for(&[Comparison::NotEqual(ParseValue::Null)])
            .expect("the gate fails before anything is read");
        assert!(
            matches!(out.as_slice(), [RelationConstraint::OwnersOf(ids)] if ids.is_empty()),
            "{out:?}"
        );

        // A non-null operand that names no id is still harmless, which is what makes the refusal
        // specific to `null` rather than to "not a pointer".
        let out = relation_constraints_for(&[Comparison::In(vec![ParseValue::Number(7.0)])])
            .expect("accepted");
        assert!(
            matches!(out.as_slice(), [RelationConstraint::OwnersOf(ids)] if ids.is_empty()),
            "{out:?}"
        );
    }

    /// **The gate is evaluated over the whole operator document, which is why the group is the
    /// unit.**
    ///
    /// `{"$ne": false, "$in": [<pointer>]}` passes on the `$in` and still processes the `$ne`.
    /// Deciding per comparison cannot express that: it either drops the `$in` with the `$ne`, or
    /// keeps the `$ne` with the `$in` and so widens the falsy case above.
    #[test]
    fn a_truthy_sibling_carries_a_falsy_ne_through_the_gate() {
        let pointer = ParseValue::Pointer {
            class_name: "_User".into(),
            object_id: "u1".into(),
        };
        let out = relation_constraints_for(&[
            Comparison::NotEqual(ParseValue::Bool(false)),
            Comparison::In(vec![pointer]),
        ])
        .expect("accepted");
        // Two reads, in the order the operators were given: the `$ne` excludes nothing because it
        // names no id, and the `$in` includes u1's owners.
        assert!(
            matches!(
                out.as_slice(),
                [RelationConstraint::NotOwnersOf(none), RelationConstraint::OwnersOf(one)]
                    if none.is_empty() && one.as_slice() == ["u1"]
            ),
            "{out:?}"
        );
    }
    #[test]
    fn object_id_constraints_intersect_rather_than_stack() {
        let mut q = Query::from_constraints(vec![Constraint::equal(
            "objectId",
            ParseValue::String("a".into()),
        )]);
        add_in_object_ids(&mut q, &["a".to_string(), "b".to_string()]);
        assert_eq!(q.clauses.len(), 1, "the original constraint is folded in");
        match &q.clauses[0] {
            Clause::Field(Constraint {
                comparison: Comparison::In(values),
                ..
            }) => assert_eq!(values.len(), 1),
            other => panic!("expected an In, got {other:?}"),
        }
    }

    #[test]
    fn a_denied_related_to_intersects_to_nothing() {
        let mut q = Query::new();
        add_in_object_ids(&mut q, &[]);
        match &q.clauses[0] {
            Clause::Field(Constraint {
                comparison: Comparison::In(values),
                ..
            }) => assert!(values.is_empty()),
            other => panic!("expected an empty In, got {other:?}"),
        }
    }

    #[test]
    fn not_in_object_ids_unions() {
        let mut q = Query::from_constraints(vec![Constraint {
            field: "objectId".into(),
            comparison: Comparison::NotIn(vec![ParseValue::String("a".into())]),
        }]);
        add_not_in_object_ids(&mut q, &["b".to_string(), "a".to_string()]);
        assert_eq!(q.clauses.len(), 1);
        match &q.clauses[0] {
            Clause::Field(Constraint {
                comparison: Comparison::NotIn(values),
                ..
            }) => assert_eq!(values.len(), 2),
            other => panic!("expected a NotIn, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_protected_key_check_precedes_the_read() {
        let e = authorize_related_to(
            "_Role",
            "users",
            &["users".to_string()],
            ErrorDetail::Disclosed,
            || async { panic!("the owning object must not be read once the key is refused") },
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);
        assert_eq!(
            e.message,
            "This user is not allowed to query users on class _Role"
        );

        // The default regime says only that it was refused, and still does not read the owner.
        let withheld = authorize_related_to(
            "_Role",
            "users",
            &["users".to_string()],
            ErrorDetail::Withheld,
            || async { panic!("the owning object must not be read once the key is refused") },
        )
        .await
        .unwrap_err();
        assert_eq!(withheld.code, ErrorCode::OperationForbidden);
        assert_eq!(withheld.message, "Permission denied");
    }
}
