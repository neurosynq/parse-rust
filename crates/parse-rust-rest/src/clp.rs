//! Class-level permission enforcement.
//!
//! **CLP evaluation is two stages, not one.** Stage one, [`validate_permission`], is a gate that
//! throws. Stage two, [`apply_pointer_permissions`], is a filter that narrows the query. Passing
//! the gate is not authorization to read anything: `{find: {requiresAuthentication: true,
//! pointerFields: ['owner']}}` passes the gate for any logged-in user and is still restricted to
//! that user's own rows by stage two. Conflating them, or treating stage two as optional extra
//! narrowing, is a data-exposure bug rather than a missing feature.
//!
//! Two more shapes here are load bearing:
//!
//! - **CLP is default-open.** An absent operation entry means unrestricted. That lives in
//!   `parse_rust_core::clp`, where `op()` returns `Option<&OpPerm>` and `OpPerm` has no `Default`.
//!   [`test_permissions`] is the only place that reads the rule, and both stages call it.
//! - **Deny-all cannot be spelled `None`.** [`PointerPermOutcome`] has three variants and is
//!   `#[must_use]`, because upstream signals deny-all by returning `undefined` from a function
//!   that otherwise returns a query (`DatabaseController.js:1770-1772`), and an `Option<Query>`
//!   reproduces that hazard exactly: `None` reads as "nothing to add".
//!
//! Every denial in this module is one of upstream's `createSanitizedError` call sites, so each
//! one goes through [`ParseError::permission_denied`] and the client sees `Permission denied` at
//! the default. The detailed strings are still exact, because they are what the wire carries when
//! `enableSanitizedErrorResponse` is off, and they are what the log carries either way.
//!
//! Master and maintenance never reach any of this. Every upstream call site is guarded by
//! `isMaster ? Promise.resolve() : ...` (`DatabaseController.js:575-578`, `:849-852`, `:935-938`,
//! `:1471-1474`), and here the guard is the caller matching on [`crate::AclScope::Unrestricted`].

use parse_rust_core::{
    ClassLevelPermissions, ErrorCode, ErrorDetail, OpEntity, Operation, ParseError, ParseMap,
    ParseValue, PfEntity, UserFieldsKey,
};
use parse_rust_storage::{ClassSchema, Comparison, Constraint, FieldType, Query, SortDirection};

use crate::acl::AclScope;
use crate::query_parse::ParsedWhere;

/// Which write a permission check belongs to.
///
/// Upstream's `runOptions.action` (`DatabaseController.js:994`), which exists only to answer one
/// question: may this write add a field through a pointer permission? Only an update may.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAction {
    Create,
    Update,
}

/// Options that change what a permission check decides, and what it says when it denies.
#[derive(Debug, Clone)]
pub struct PermissionOptions {
    /// `protectedFieldsOwnerExempt`. Upstream tests `!== false`, so an unset option is exempt and
    /// the default is `true` (`DatabaseController.js:1838`).
    pub protected_fields_owner_exempt: bool,
    /// `enableSanitizedErrorResponse`, carried here because every denial in this module is one of
    /// upstream's `createSanitizedError` call sites and needs it.
    pub error_detail: ErrorDetail,
    /// `allowClientClassCreation` (`Options/Definitions.js:67-72`).
    ///
    /// **The default is `false`, and that is the whole reason this option has to exist rather than
    /// be left for later.** An unimplemented option is silently the permissive value, and here the
    /// permissive value lets any caller holding only the app id and client key create classes. Each
    /// one gets a `_SCHEMA` row and a collection on a database parse-server nodes also read, and
    /// each has no CLP block, which is default-open. So the gap is not a missing feature, it is a
    /// security default flipped open.
    pub allow_client_class_creation: bool,
}

impl Default for PermissionOptions {
    fn default() -> Self {
        Self {
            protected_fields_owner_exempt: true,
            allow_client_class_creation: false,
            // Upstream's default is `enableSanitizedErrorResponse: true`, so the default here has
            // to be the withholding regime. `ErrorDetail` has no `Default` of its own precisely so
            // that this choice is written down at the one place a default is legitimate.
            error_detail: ErrorDetail::Withheld,
        }
    }
}

/// `testPermissions` (`SchemaController.js:1365-1382`).
///
/// **Default-open.** No CLP block, or no entry for this operation, means unrestricted. This is
/// the single most consequential CLP semantic: inverting it fails closed, which looks safe, and
/// locks every existing database out on upgrade.
pub fn test_permissions(
    clp: Option<&ClassLevelPermissions>,
    acl_group: &[String],
    operation: Operation,
) -> bool {
    let Some(clp) = clp else { return true };
    let Some(perm) = clp.op(operation) else {
        return true;
    };
    if perm.grants(&OpEntity::Public) {
        return true;
    }
    acl_group.iter().any(|a| perm.grants(&OpEntity::parse(a)))
}

/// Stage one: the gate. `validatePermission` (`SchemaController.js:1385-1459`).
///
/// Never called for master or maintenance.
///
/// Both denials are `createSanitizedError` call sites upstream (`SchemaController.js:1406`,
/// `:1412`, `:1430`, `:1454`), so `detail` decides whether the client is told which rule refused
/// it or only that something did.
pub fn validate_permission(
    clp: Option<&ClassLevelPermissions>,
    class_name: &str,
    acl_group: &[String],
    operation: Operation,
    action: Option<WriteAction>,
    detail: ErrorDetail,
) -> Result<(), ParseError> {
    // Step 1.
    if test_permissions(clp, acl_group, operation) {
        return Ok(());
    }

    // Step 2 (`SchemaController.js:1396-1398`) re-checks the no-CLP case and returns a bare
    // `true` rather than a promise. It is unreachable, because step 1 already covered both of
    // its conditions. Read and deliberately not ported; the two `else { return Ok(()) }` arms
    // below are the same unreachable case expressed as the resolve it would have produced.
    let Some(clp) = clp else { return Ok(()) };
    let Some(perm) = clp.op(operation) else {
        return Ok(());
    };

    // Step 3: requiresAuthentication. Note the code: 101, not 119. It is deliberate existence
    // hiding and it is wire contract.
    if perm.grants(&OpEntity::RequiresAuthentication) {
        let anonymous = acl_group.is_empty() || acl_group == ["*"];
        if anonymous {
            return Err(ParseError::permission_denied(
                ErrorCode::ObjectNotFound,
                "Permission denied, user needs to be authenticated.",
                detail,
            ));
        }
        // Resolves unconditionally, and precedes the pointer branches. A logged-in caller passes
        // the gate here and is still narrowed by stage two.
        return Ok(());
    }

    // Step 4: a write pointer-permission scheme can never authorize a create, because a create
    // has no existing object whose pointer field could name the caller.
    if operation.user_fields_key() == UserFieldsKey::Write && operation == Operation::Create {
        return Err(forbidden(class_name, operation, detail));
    }

    // Step 5: defer the class-wide arrays to stage two.
    if !clp.user_fields(operation).is_empty() {
        return Ok(());
    }

    // Step 6: defer per-operation pointerFields to stage two, except when adding a field on a
    // create. The condition is upstream's `operation !== 'addField' || action === 'update'`.
    if !perm.pointer_fields.is_empty()
        && (operation != Operation::AddField || action == Some(WriteAction::Update))
    {
        return Ok(());
    }

    // Step 7.
    Err(forbidden(class_name, operation, detail))
}

fn forbidden(class_name: &str, operation: Operation, detail: ErrorDetail) -> ParseError {
    ParseError::permission_denied(
        ErrorCode::OperationForbidden,
        format!(
            "Permission denied for action {} on class {class_name}.",
            operation.as_key()
        ),
        detail,
    )
}

/// Stage two's three outcomes. `#[must_use]`, and every caller matches all three.
///
/// See the module note for why this is not `Option<Query>`.
#[must_use]
#[derive(Debug)]
pub enum PointerPermOutcome {
    /// No pointer permission applies. The query stands as it was.
    Unconstrained,
    /// The query, narrowed.
    Constrained(Query),
    /// Upstream's `return undefined`. The caller must deny: an empty result for a `find` or a
    /// `count`, and `OBJECT_NOT_FOUND` for a `get`, an update or a delete.
    DenyAll,
}

/// Stage two: the query filter. `addPointerPermissions` (`DatabaseController.js:1731-1819`).
///
/// Never called for master or maintenance.
pub fn apply_pointer_permissions(
    schema: &ClassSchema,
    clp: Option<&ClassLevelPermissions>,
    operation: Operation,
    acl_group: &[String],
    query: &Query,
) -> Result<PointerPermOutcome, ParseError> {
    // 1. A class the caller can already reach through the base CLP is never pointer-restricted.
    //    Same predicate as the gate's step 1, deliberately re-evaluated through one function so
    //    the two stages cannot drift.
    if test_permissions(clp, acl_group, operation) {
        return Ok(PointerPermOutcome::Unconstrained);
    }
    let Some(clp) = clp else {
        return Ok(PointerPermOutcome::Unconstrained);
    };

    // 3. Per-operation pointerFields first, then the class-wide array, deduped in upstream's
    //    order, which is observable in the compiled `$or`.
    let fields = clp.applicable_pointer_fields(operation);
    // 4.
    if fields.is_empty() {
        return Ok(PointerPermOutcome::Unconstrained);
    }

    // 2. The caller's user ids: everything that is neither a role nor the public entity.
    let user_acl: Vec<&String> = acl_group
        .iter()
        .filter(|a| !a.starts_with("role:") && a.as_str() != "*")
        .collect();

    // 5. The deny-all signal. Fires for every anonymous caller, whose list is empty once `*` is
    //    filtered out.
    let [user_id] = user_acl.as_slice() else {
        return Ok(PointerPermOutcome::DenyAll);
    };

    let user_pointer = ParseValue::Pointer {
        class_name: "_User".to_string(),
        object_id: (*user_id).clone(),
    };

    // 6. One clause per field, keyed on the schema type rather than on the runtime value.
    let mut alternatives = Vec::with_capacity(fields.len());
    for field in &fields {
        let constraint = match schema.field(field) {
            Some(FieldType::Pointer { .. }) | Some(FieldType::Object) => {
                Constraint::equal(field.clone(), user_pointer.clone())
            }
            Some(FieldType::Array) => Constraint {
                field: field.clone(),
                comparison: Comparison::All(vec![user_pointer.clone()]),
            },
            // A CLP naming a field of any other type, or naming no field at all, is a
            // misconfiguration. Upstream throws a plain `Error` here
            // (`DatabaseController.js:1803-1805`), which is deliberate: failing open would hand
            // the whole class to the caller, which is the breach this branch exists to prevent.
            //
            // A plain `Error` and not a `Parse.Error`, so the class and field name reach the log
            // and never the client: `handleParseErrors` renders the fixed
            // `{"code":1,"message":"Internal server error."}` for anything that is not a
            // `Parse.Error` (`middlewares.js:636-644`). `ParseError::internal` is that shape.
            _ => {
                let class_name = &schema.class_name;
                return Err(ParseError::internal(format!(
                    "An unexpected condition occurred when resolving pointer permissions: \
                     {class_name} {field}"
                )));
            }
        };
        alternatives.push(Query::from_constraints(vec![constraint]));
    }

    // 7. Disjunctive across fields (`DatabaseController.js:1815`). `Query::any_of` reproduces
    //    `reduceOrOperation`'s single-element collapse.
    //
    //    Upstream copies the whole incoming query into each disjunct and ORs those; conjoining
    //    the bare disjunction of clauses onto the query is the same predicate, `q AND (c1 OR
    //    c2)`, without duplicating the client's constraints into every branch.
    //
    //    `conjoin` and not `extend`, because with a single permission field `any_of` collapses to
    //    a bare constraint on that field and the client may already be constraining it. Upstream
    //    guards the same case at `DatabaseController.js:1807-1811`.
    let mut out = query.clone();
    out.conjoin(Query::any_of(alternatives));
    Ok(PointerPermOutcome::Constrained(out))
}

/// `canAddField` (`DatabaseController.js:970-998`): does this write introduce a field the schema
/// does not have?
///
/// `class_exists` is upstream's `if (!classSchema) return`, so a write that creates the class
/// never runs the `addField` gate at all.
pub fn adds_field<'a>(
    schema: &ClassSchema,
    class_exists: bool,
    keys: impl IntoIterator<Item = &'a str>,
    is_delete: impl Fn(&str) -> bool,
) -> bool {
    if !class_exists {
        return false;
    }
    keys.into_iter().any(|key| {
        if is_delete(key) {
            return false;
        }
        // The root of a dotted key: `temperature.celsius` is not a new field if `temperature`
        // exists, which is why a nested write is exempt in practice.
        let root = key.split('.').next().unwrap_or(key);
        schema.field(root).is_none()
    })
}

/// The fields to strip from a result, plus the rules that can only be evaluated against a row.
///
/// Entirely request state. Nothing derived from a request is ever written back into the schema
/// snapshot, which is the deliberate divergence from upstream's `temporaryKeys`
/// (`DatabaseController.js:1907`): that writes into the CLP object held by the shared schema
/// controller, so two concurrent requests corrupt each other's key list in both directions.
#[derive(Debug, Clone, Default)]
pub struct ProtectedFieldPlan {
    /// Already intersected across every applicable entity.
    pub strip: Vec<String>,
    /// `userField:<name>` rules: the field to look at, and what it protects when the row's value
    /// points at the caller.
    pub user_field_rules: Vec<(String, Vec<String>)>,
}

impl ProtectedFieldPlan {
    pub fn is_empty(&self) -> bool {
        self.strip.is_empty() && self.user_field_rules.is_empty()
    }
}

/// `addProtectedFields` (`DatabaseController.js:1821-1925`).
///
/// `pinned_object_id` is the query's top-level `objectId` equality, if it has one. It exists only
/// for the `_User` owner exemption.
///
/// Returns `None` when nothing is protected, which is upstream's `null`.
pub fn plan_protected_fields(
    class_name: &str,
    clp: Option<&ClassLevelPermissions>,
    scope: &AclScope,
    pinned_object_id: Option<&str>,
    options: &PermissionOptions,
) -> Option<ProtectedFieldPlan> {
    // 1.
    let clp = clp?;
    if clp.protected_fields().is_empty() {
        return None;
    }

    // 2. The `_User` owner exemption. Note upstream's triple-equals against `false`: an unset
    //    option means exempt, so the default is exempt.
    let acl_group = scope.acl_group();
    if class_name == "_User"
        && options.protected_fields_owner_exempt
        && pinned_object_id.is_some_and(|id| acl_group.iter().any(|a| a == id))
    {
        return None;
    }

    // 3. One set per applicable entity.
    let authenticated = scope.user_id().is_some();
    let mut sets: Vec<&Vec<String>> = Vec::new();
    let mut user_field_rules = Vec::new();

    for (entity, fields) in clp.protected_fields() {
        match entity {
            // Deferred: whether it applies cannot be known until the row has been read.
            PfEntity::UserField(name) => user_field_rules.push((name.clone(), fields.clone())),
            PfEntity::Public => sets.push(fields),
            PfEntity::Authenticated if authenticated => sets.push(fields),
            PfEntity::Role(name) if authenticated && scope.has_role(name) => sets.push(fields),
            _ => {}
        }
    }
    // The caller's own objectId, if the block names it. Kept out of the loop above because
    // upstream adds it afterwards (`DatabaseController.js:1898-1903`), and the order of the sets
    // does not change an intersection.
    if let Some(user_id) = scope.user_id() {
        if let Some(fields) = clp
            .protected_fields()
            .get(&PfEntity::User(user_id.to_string()))
        {
            sets.push(fields);
        }
    }

    Some(ProtectedFieldPlan {
        strip: intersect_all(&sets),
        user_field_rules,
    })
}

/// 4. Intersect every collected set (`DatabaseController.js:1910-1922`).
///
/// **More applicable groups means fewer protected fields.** A union over-protects and shows up as
/// a failing test; a first-match-wins under-protects and shows up as nothing at all.
fn intersect_all(sets: &[&Vec<String>]) -> Vec<String> {
    let Some((first, rest)) = sets.split_first() else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for field in first.iter() {
        if out.contains(field) {
            continue;
        }
        if rest.iter().all(|set| set.contains(field)) {
            out.push(field.clone());
        }
    }
    out
}

/// `denyProtectedFields` (`RestQuery.js:928-984`).
///
/// A pre-flight denial, not a filter. Without it a client binary-searches a protected value
/// through equality constraints even though the field never appears in a response.
///
/// Both denials are `createSanitizedError` call sites (`RestQuery.js:949`, `:976`). Note what
/// that means at the default: the client learns it was refused, but not which field it named.
pub fn deny_protected_fields(
    plan: Option<&ProtectedFieldPlan>,
    class_name: &str,
    where_: &ParsedWhere,
    order: &[(String, SortDirection)],
    detail: ErrorDetail,
) -> Result<(), ParseError> {
    let Some(plan) = plan else { return Ok(()) };
    if plan.strip.is_empty() {
        return Ok(());
    }

    let denied = |key: &str| -> bool {
        // Checked both as the full key and as its dot-prefix root, so `{"obj.secret": v}` cannot
        // slip past a protection on `obj`.
        let root = key.split('.').next().unwrap_or(key);
        plan.strip.iter().any(|f| f == key || f == root)
    };

    for key in where_.field_keys() {
        if denied(&key) {
            return Err(ParseError::permission_denied(
                ErrorCode::OperationForbidden,
                format!("This user is not allowed to query {key} on class {class_name}"),
                detail,
            ));
        }
    }
    for (key, _) in order {
        if denied(key) {
            return Err(ParseError::permission_denied(
                ErrorCode::OperationForbidden,
                format!("This user is not allowed to sort by {key} on class {class_name}"),
                detail,
            ));
        }
    }
    Ok(())
}

/// `filterSensitiveData` (`DatabaseController.js:192-303`), applied to one row in upstream's
/// order.
///
/// `is_read` is upstream's `['get','find'].indexOf(operation) > -1`, which gates the `userField:`
/// evaluation only.
///
/// Two deliberate absences, both stated rather than left implicit:
///
/// - **The password hash is never rehydrated under a user-facing name.** Upstream reattaches it
///   as `password` here (`:266-271`) and strips it at a later stage. parse-rust keeps the hash
///   under its internal name end to end, so the underscore strip below removes it and there is
///   nothing for a later stage to undo. That is the point of the divergence: no response path
///   depends on remembering to remove it, so a new read path cannot acquire the obligation and
///   miss it.
/// - **The maintenance bypass (`:273-275`) is not reproduced.** It skips the underscore strip as
///   well as the protected-field strip, and `AclScope::Unrestricted` covers master and
///   maintenance together, so parse-rust always strips. Master already strips upstream, so this
///   only differs for a maintenance caller, and it differs in the direction of removing less
///   information from nobody.
pub fn filter_sensitive_data(
    row: &mut ParseMap,
    class_name: &str,
    scope: &AclScope,
    plan: Option<&ProtectedFieldPlan>,
    is_read: bool,
    options: &PermissionOptions,
) {
    let is_user_class = class_name == "_User";
    let acl_group = scope.acl_group();

    // 1. `userField:` matching, against the row rather than the request.
    let mut protected: Option<Vec<String>> = plan.map(|p| p.strip.clone());
    if is_read {
        if let Some(plan) = plan {
            let matched: Vec<&Vec<String>> = plan
                .user_field_rules
                .iter()
                .filter(|(field, _)| row_field_points_at(row.get(field), scope.user_id()))
                .map(|(_, fields)| fields)
                .collect();
            if !matched.is_empty() {
                // If a list already exists from the pre-query stage it joins the intersection
                // rather than being replaced (`DatabaseController.js:248-262`). Matching a
                // `userField:` rule can therefore only ever protect fewer fields.
                let mut sets = matched;
                if let Some(existing) = protected.as_ref() {
                    sets.push(existing);
                }
                protected = Some(intersect_all(&sets));
            }
        }
    }

    // 2. `_User` shaping. See the note above for what is deliberately not here.
    if is_user_class {
        row.shift_remove("sessionToken");
    }

    // 4. Strip the protected fields, unless the caller is the `_User` row's own user.
    let owner_exempt = options.protected_fields_owner_exempt
        && is_user_class
        && scope.user_id().is_some_and(
            |uid| matches!(row.get("objectId"), Some(ParseValue::String(id)) if id == uid),
        );
    if !owner_exempt {
        if let Some(fields) = protected {
            for field in fields {
                row.shift_remove(&field);
            }
        }
    }

    // 5. Every `_`-prefixed key, unconditionally.
    crate::guard::strip_internal_keys(row);

    // 6. `authData` survives for master and for the object's own user.
    if !is_user_class || scope.is_master() {
        return;
    }
    let own_row =
        matches!(row.get("objectId"), Some(ParseValue::String(id)) if acl_group.contains(id));
    if !own_row {
        row.shift_remove("authData");
    }
}

/// Does this row value point at the caller? A pointer, or an array containing one
/// (`DatabaseController.js:227-237`).
fn row_field_points_at(value: Option<&ParseValue>, user_id: Option<&str>) -> bool {
    let Some(user_id) = user_id else { return false };
    match value {
        Some(ParseValue::Pointer { object_id, .. }) => object_id == user_id,
        Some(ParseValue::Array(items)) => items
            .iter()
            .any(|v| matches!(v, ParseValue::Pointer { object_id, .. } if object_id == user_id)),
        // An `Object`-typed field holding a raw `{objectId: ...}` map, which is what upstream
        // reads: it inspects `.objectId` without checking `__type`.
        Some(ParseValue::Object(map)) => {
            matches!(map.get("objectId"), Some(ParseValue::String(id)) if id == user_id)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_core::ClassLevelPermissions;

    fn clp(json: &str) -> ClassLevelPermissions {
        let value = parse_rust_core::classify(
            serde_json::from_str(json).expect("test literal must be valid JSON"),
        )
        .expect("classify");
        match value {
            ParseValue::Object(m) => ClassLevelPermissions::from_map(m),
            _ => panic!("expected an object"),
        }
    }

    fn user_scope() -> AclScope {
        AclScope::user("u1", vec![]).expect("scope")
    }

    /// The default regime, `enableSanitizedErrorResponse: true`. Named rather than spelled at
    /// each call site so that a test asserting a detailed message cannot be reading this one.
    const WITHHELD: ErrorDetail = ErrorDetail::Withheld;
    /// `enableSanitizedErrorResponse: false`. The detailed strings are contract too: they are
    /// what the wire carries under this option and what the log carries under either.
    const DISCLOSED: ErrorDetail = ErrorDetail::Disclosed;

    #[test]
    fn no_clp_at_all_allows_every_operation() {
        for op in Operation::ALL {
            assert!(test_permissions(None, &["*".to_string()], op), "{op:?}");
            assert!(
                validate_permission(None, "Post", &["*".to_string()], op, None, DISCLOSED).is_ok()
            );
        }
    }

    /// The rule that locks every existing database out if it is inverted.
    #[test]
    fn an_absent_operation_entry_is_unrestricted() {
        let c = clp(r#"{"find":{}}"#);
        assert!(
            validate_permission(
                Some(&c),
                "Post",
                &["*".into()],
                Operation::Update,
                None,
                DISCLOSED
            )
            .is_ok(),
            "update has no entry, so it is unrestricted"
        );
        let e = validate_permission(
            Some(&c),
            "Post",
            &["*".into()],
            Operation::Find,
            None,
            DISCLOSED,
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);
        assert_eq!(
            e.message,
            "Permission denied for action find on class Post."
        );

        // The regime a stock deployment runs. The code is unchanged and only the message moves.
        let withheld = validate_permission(
            Some(&c),
            "Post",
            &["*".into()],
            Operation::Find,
            None,
            WITHHELD,
        )
        .unwrap_err();
        assert_eq!(withheld.code, ErrorCode::OperationForbidden);
        assert_eq!(withheld.message, "Permission denied");
    }

    #[test]
    fn a_granted_role_passes_the_gate() {
        let c = clp(r#"{"find":{"role:Admins":true}}"#);
        let member = AclScope::user("u1", vec!["Admins".into()]).expect("scope");
        assert!(validate_permission(
            Some(&c),
            "Post",
            &member.acl_group(),
            Operation::Find,
            None,
            WITHHELD
        )
        .is_ok());
        let outsider = AclScope::user("u2", vec!["Others".into()]).expect("scope");
        assert!(validate_permission(
            Some(&c),
            "Post",
            &outsider.acl_group(),
            Operation::Find,
            None,
            WITHHELD
        )
        .is_err());
    }

    /// The code is 101, not 119. Gate C asserts on it.
    #[test]
    fn requires_authentication_denies_anonymously_with_object_not_found() {
        let c = clp(r#"{"find":{"requiresAuthentication":true}}"#);
        let e = validate_permission(
            Some(&c),
            "Post",
            &AclScope::Anonymous.acl_group(),
            Operation::Find,
            None,
            DISCLOSED,
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::ObjectNotFound);
        assert_eq!(
            e.message,
            "Permission denied, user needs to be authenticated."
        );

        // At the default the caller is told nothing beyond the refusal, and the code still hides
        // the class's existence.
        let withheld = validate_permission(
            Some(&c),
            "Post",
            &AclScope::Anonymous.acl_group(),
            Operation::Find,
            None,
            WITHHELD,
        )
        .unwrap_err();
        assert_eq!(withheld.code, ErrorCode::ObjectNotFound);
        assert_eq!(withheld.message, "Permission denied");

        // An empty aclGroup denies too, which is the other half of upstream's test.
        assert_eq!(
            validate_permission(Some(&c), "Post", &[], Operation::Find, None, WITHHELD)
                .unwrap_err()
                .code,
            ErrorCode::ObjectNotFound
        );

        assert!(validate_permission(
            Some(&c),
            "Post",
            &user_scope().acl_group(),
            Operation::Find,
            None,
            WITHHELD
        )
        .is_ok());
    }

    /// Passing the gate is not authorization to read anything.
    #[test]
    fn requires_authentication_with_pointer_fields_still_narrows_in_stage_two() {
        let c = clp(r#"{"find":{"requiresAuthentication":true,"pointerFields":["owner"]}}"#);
        let scope = user_scope();
        assert!(validate_permission(
            Some(&c),
            "Post",
            &scope.acl_group(),
            Operation::Find,
            None,
            WITHHELD
        )
        .is_ok());

        let schema = ClassSchema::new("Post").with_field(
            "owner",
            FieldType::Pointer {
                target_class: "_User".into(),
            },
        );
        match apply_pointer_permissions(
            &schema,
            Some(&c),
            Operation::Find,
            &scope.acl_group(),
            &Query::new(),
        )
        .expect("no misconfiguration")
        {
            PointerPermOutcome::Constrained(q) => assert_eq!(q.clauses.len(), 1),
            other => panic!("expected Constrained, got {other:?}"),
        }
    }

    #[test]
    fn write_user_fields_lock_down_create_only() {
        let c = clp(r#"{"create":{},"update":{},"writeUserFields":["owner"]}"#);
        let scope = user_scope();
        let e = validate_permission(
            Some(&c),
            "Post",
            &scope.acl_group(),
            Operation::Create,
            Some(WriteAction::Create),
            DISCLOSED,
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);
        assert_eq!(
            e.message,
            "Permission denied for action create on class Post."
        );
        assert_eq!(
            validate_permission(
                Some(&c),
                "Post",
                &scope.acl_group(),
                Operation::Create,
                Some(WriteAction::Create),
                WITHHELD,
            )
            .unwrap_err()
            .message,
            "Permission denied"
        );
        assert!(validate_permission(
            Some(&c),
            "Post",
            &scope.acl_group(),
            Operation::Update,
            Some(WriteAction::Update),
            WITHHELD
        )
        .is_ok());
    }

    #[test]
    fn add_field_defers_only_on_update() {
        let c = clp(r#"{"addField":{"pointerFields":["owner"]}}"#);
        let scope = user_scope();
        assert!(validate_permission(
            Some(&c),
            "Post",
            &scope.acl_group(),
            Operation::AddField,
            Some(WriteAction::Update),
            WITHHELD
        )
        .is_ok());
        assert_eq!(
            validate_permission(
                Some(&c),
                "Post",
                &scope.acl_group(),
                Operation::AddField,
                Some(WriteAction::Create),
                WITHHELD
            )
            .unwrap_err()
            .code,
            ErrorCode::OperationForbidden
        );
    }

    #[test]
    fn a_public_class_is_never_pointer_restricted() {
        let c = clp(r#"{"find":{"*":true,"pointerFields":["owner"]}}"#);
        let schema = ClassSchema::new("Post");
        assert!(matches!(
            apply_pointer_permissions(
                &schema,
                Some(&c),
                Operation::Find,
                &AclScope::Anonymous.acl_group(),
                &Query::new()
            )
            .expect("ok"),
            PointerPermOutcome::Unconstrained
        ));
    }

    #[test]
    fn an_anonymous_caller_is_denied_all_by_a_pointer_permission() {
        let c = clp(r#"{"find":{"pointerFields":["owner"]}}"#);
        let schema = ClassSchema::new("Post").with_field(
            "owner",
            FieldType::Pointer {
                target_class: "_User".into(),
            },
        );
        assert!(matches!(
            apply_pointer_permissions(
                &schema,
                Some(&c),
                Operation::Find,
                &AclScope::Anonymous.acl_group(),
                &Query::new()
            )
            .expect("ok"),
            PointerPermOutcome::DenyAll
        ));
    }

    #[test]
    fn the_clause_shape_follows_the_schema_type() {
        let c = clp(r#"{"find":{"pointerFields":["owner","editors","meta"]}}"#);
        let schema = ClassSchema::new("Post")
            .with_field(
                "owner",
                FieldType::Pointer {
                    target_class: "_User".into(),
                },
            )
            .with_field("editors", FieldType::Array)
            .with_field("meta", FieldType::Object);
        let scope = user_scope();
        let q = match apply_pointer_permissions(
            &schema,
            Some(&c),
            Operation::Find,
            &scope.acl_group(),
            &Query::new(),
        )
        .expect("ok")
        {
            PointerPermOutcome::Constrained(q) => q,
            other => panic!("expected Constrained, got {other:?}"),
        };
        // Three fields compose disjunctively.
        match q.clauses.as_slice() {
            [parse_rust_storage::Clause::Or(alts)] => {
                assert_eq!(alts.len(), 3);
                assert!(matches!(
                    alts[1].clauses[0],
                    parse_rust_storage::Clause::Field(Constraint {
                        comparison: Comparison::All(_),
                        ..
                    })
                ));
            }
            other => panic!("expected a single Or clause, got {other:?}"),
        }
    }

    /// The owner asking for their own rows by name is the ordinary case, not an edge case, and
    /// splicing the permission constraint in beside the client's produced `INVALID_QUERY`.
    #[test]
    fn a_client_constraint_on_the_permission_field_survives_composition() {
        let c = clp(r#"{"find":{"pointerFields":["owner"]}}"#);
        let schema = ClassSchema::new("Post").with_field(
            "owner",
            FieldType::Pointer {
                target_class: "_User".into(),
            },
        );
        let scope = user_scope();
        let client = Query::from_constraints(vec![Constraint::equal(
            "owner",
            ParseValue::Pointer {
                class_name: "_User".into(),
                object_id: "u1".into(),
            },
        )]);
        let q = match apply_pointer_permissions(
            &schema,
            Some(&c),
            Operation::Find,
            &scope.acl_group(),
            &client,
        )
        .expect("ok")
        {
            PointerPermOutcome::Constrained(q) => q,
            other => panic!("expected Constrained, got {other:?}"),
        };
        // The client's constraint stays where it was and the permission's is nested, so neither
        // is dropped and the two never merge.
        assert!(matches!(
            q.clauses.as_slice(),
            [
                parse_rust_storage::Clause::Field(f),
                parse_rust_storage::Clause::And(nested)
            ] if f.field == "owner" && nested.len() == 1
        ));
    }

    /// Failing open here would hand the whole class to the caller.
    #[test]
    fn a_pointer_permission_on_an_unusable_field_type_is_a_500() {
        let c = clp(r#"{"find":{"pointerFields":["title"]}}"#);
        let schema = ClassSchema::new("Post").with_field("title", FieldType::String);
        let e = apply_pointer_permissions(
            &schema,
            Some(&c),
            Operation::Find,
            &user_scope().acl_group(),
            &Query::new(),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::InternalServerError);
        // The class and the field are in the message, and the message is log-only. Upstream
        // throws a plain `Error` here for exactly that reason.
        assert_eq!(e.origin, parse_rust_core::ErrorOrigin::Internal);
        assert!(e.message.contains("Post"));
        assert!(e.message.contains("title"));

        // A field the schema does not know about lands in the same arm.
        let c2 = clp(r#"{"find":{"pointerFields":["nope"]}}"#);
        assert_eq!(
            apply_pointer_permissions(
                &ClassSchema::new("Post"),
                Some(&c2),
                Operation::Find,
                &user_scope().acl_group(),
                &Query::new()
            )
            .unwrap_err()
            .code,
            ErrorCode::InternalServerError
        );
    }

    #[test]
    fn protected_fields_intersect_rather_than_union() {
        let c = clp(
            r#"{"protectedFields":{"*":["email","phone","ssn"],"authenticated":["email","phone"],"role:A":["email"]}}"#,
        );

        // Anonymous: only the public tier applies, so everything it names is protected.
        let anon = plan_protected_fields(
            "Post",
            Some(&c),
            &AclScope::Anonymous,
            None,
            &PermissionOptions::default(),
        )
        .expect("plan");
        assert_eq!(anon.strip, vec!["email", "phone", "ssn"]);

        // Authenticated: two tiers apply, and the intersection is smaller.
        let user = AclScope::user("u1", vec![]).expect("scope");
        let plan =
            plan_protected_fields("Post", Some(&c), &user, None, &PermissionOptions::default())
                .expect("plan");
        assert_eq!(plan.strip, vec!["email", "phone"]);

        // Three tiers apply, and it shrinks again. More groups means fewer protected fields.
        let admin = AclScope::user("u1", vec!["A".into()]).expect("scope");
        let plan = plan_protected_fields(
            "Post",
            Some(&c),
            &admin,
            None,
            &PermissionOptions::default(),
        )
        .expect("plan");
        assert_eq!(plan.strip, vec!["email"]);
    }

    /// The other direction: an entity that does not apply must not contribute, or the
    /// intersection silently unprotects everything.
    #[test]
    fn an_inapplicable_role_contributes_nothing() {
        let c = clp(r#"{"protectedFields":{"*":["email"],"role:A":["phone"]}}"#);
        let outsider = AclScope::user("u1", vec!["B".into()]).expect("scope");
        let plan = plan_protected_fields(
            "Post",
            Some(&c),
            &outsider,
            None,
            &PermissionOptions::default(),
        )
        .expect("plan");
        assert_eq!(
            plan.strip,
            vec!["email"],
            "a role the caller does not hold must not join the intersection"
        );
    }

    #[test]
    fn the_user_owner_exemption_defaults_to_exempt_and_honors_the_option() {
        let c = clp(r#"{"protectedFields":{"*":["email"]}}"#);
        let user = AclScope::user("u1", vec![]).expect("scope");
        assert!(
            plan_protected_fields(
                "_User",
                Some(&c),
                &user,
                Some("u1"),
                &PermissionOptions::default()
            )
            .is_none(),
            "an unset option means exempt"
        );
        let strict = PermissionOptions {
            protected_fields_owner_exempt: false,
            ..PermissionOptions::default()
        };
        assert!(plan_protected_fields("_User", Some(&c), &user, Some("u1"), &strict).is_some());
        // Another user's row is not exempt.
        assert!(plan_protected_fields(
            "_User",
            Some(&c),
            &user,
            Some("u2"),
            &PermissionOptions::default()
        )
        .is_some());
    }

    #[test]
    fn a_user_field_rule_matching_the_row_reduces_what_is_stripped() {
        let c = clp(r#"{"protectedFields":{"*":["email","phone"],"userField:owner":["phone"]}}"#);
        let user = AclScope::user("u1", vec![]).expect("scope");
        let plan =
            plan_protected_fields("Post", Some(&c), &user, None, &PermissionOptions::default())
                .expect("plan");
        assert_eq!(plan.strip, vec!["email", "phone"]);
        assert_eq!(plan.user_field_rules.len(), 1);

        let mut row = ParseMap::new();
        row.insert("objectId".into(), ParseValue::String("p1".into()));
        row.insert(
            "owner".into(),
            ParseValue::Pointer {
                class_name: "_User".into(),
                object_id: "u1".into(),
            },
        );
        row.insert("email".into(), ParseValue::String("a@b.c".into()));
        row.insert("phone".into(), ParseValue::String("555".into()));
        filter_sensitive_data(
            &mut row,
            "Post",
            &user,
            Some(&plan),
            true,
            &PermissionOptions::default(),
        );
        // The matched rule intersects the two lists down to {phone}, so the owner keeps `email`
        // and loses `phone`. Matching a `userField:` rule protects fewer fields, not more.
        assert!(row.get("email").is_some());
        assert!(row.get("phone").is_none());

        // A row owned by somebody else keeps the pre-query list, so both are stripped.
        let mut other = ParseMap::new();
        other.insert(
            "owner".into(),
            ParseValue::Pointer {
                class_name: "_User".into(),
                object_id: "u2".into(),
            },
        );
        other.insert("email".into(), ParseValue::String("a@b.c".into()));
        other.insert("phone".into(), ParseValue::String("555".into()));
        filter_sensitive_data(
            &mut other,
            "Post",
            &user,
            Some(&plan),
            true,
            &PermissionOptions::default(),
        );
        assert!(other.get("phone").is_none());
        assert!(
            other.get("email").is_none(),
            "no rule matched, so the pre-query list stands and both are stripped"
        );
    }

    /// The direction of a deliberate divergence, pinned so a later change cannot flip it.
    ///
    /// Upstream temporarily appends the `userField:` name to the projection and records it in
    /// `serverOnlyKeys` so the rule can still be evaluated when the client asked for `keys`
    /// (`DatabaseController.js:1859-1874`). parse-rust does not, for the reason stated on
    /// [`ProtectedFieldPlan`]: that mechanism writes into a memoized schema object upstream and
    /// nothing resets it.
    ///
    /// The consequence is that with `keys` the row carries no `owner` to inspect, the rule cannot
    /// match, and the **larger** pre-query strip list stands. That protects more, not less, and
    /// that is the whole point of this test: a client asking for fewer fields can never thereby
    /// see a field it could not see otherwise.
    #[test]
    fn a_user_field_rule_that_cannot_be_evaluated_protects_more_not_less() {
        let c = clp(r#"{"protectedFields":{"*":["email","phone"],"userField:owner":["phone"]}}"#);
        let user = AclScope::user("u1", vec![]).expect("scope");
        let plan =
            plan_protected_fields("Post", Some(&c), &user, None, &PermissionOptions::default())
                .expect("plan");

        // With `owner` projected away, exactly as a `keys=email,phone` request would leave it.
        let mut projected = ParseMap::new();
        projected.insert("email".into(), ParseValue::String("a@b.c".into()));
        projected.insert("phone".into(), ParseValue::String("555".into()));
        filter_sensitive_data(
            &mut projected,
            "Post",
            &user,
            Some(&plan),
            true,
            &PermissionOptions::default(),
        );
        assert!(
            projected.get("phone").is_none(),
            "the rule cannot match without `owner`, so `phone` stays protected"
        );
        assert!(
            projected.get("email").is_none(),
            "and so does `email`: the unreduced list is the one that applies"
        );

        // The same owner, same rule, with `owner` present, keeps `email`. Fewer requested fields
        // must never produce more visible ones, so this side has to be the permissive one.
        let mut full = ParseMap::new();
        full.insert(
            "owner".into(),
            ParseValue::Pointer {
                class_name: "_User".into(),
                object_id: "u1".into(),
            },
        );
        full.insert("email".into(), ParseValue::String("a@b.c".into()));
        full.insert("phone".into(), ParseValue::String("555".into()));
        filter_sensitive_data(
            &mut full,
            "Post",
            &user,
            Some(&plan),
            true,
            &PermissionOptions::default(),
        );
        assert!(full.get("email").is_some());
    }

    /// A role whose name is itself principal-shaped.
    ///
    /// `_Role.name` has no character-set validation upstream, so `role:Admin` is a legal role
    /// name and produces the principal `role:role:Admin`. The seam this pins is the one where a
    /// refactor "tidies up" the prefixing and silently unwraps one layer, at which point holding
    /// the role named `role:Admin` would grant everything ACL'd to `Admin`.
    #[test]
    fn a_principal_shaped_role_name_is_not_unwrapped() {
        let scope = AclScope::user("u1", vec!["role:Admin".to_string()]).expect("scope");
        let group = scope.acl_group();
        assert!(
            group.iter().any(|g| g == "role:role:Admin"),
            "the name is prefixed once, not collapsed: {group:?}"
        );
        assert!(
            !group.iter().any(|g| g == "role:Admin"),
            "holding a role named `role:Admin` must not grant `Admin`: {group:?}"
        );

        // And the CLP side agrees: the entry that grants this holder is the doubled one.
        let doubled = clp(r#"{"find":{"role:role:Admin":true}}"#);
        assert!(test_permissions(
            Some(&doubled),
            &group,
            parse_rust_core::Operation::Find
        ));
        let single = clp(r#"{"find":{"role:Admin":true}}"#);
        assert!(!test_permissions(
            Some(&single),
            &group,
            parse_rust_core::Operation::Find
        ));
    }

    #[test]
    fn auth_data_survives_only_for_master_and_the_row_owner() {
        let mut row = ParseMap::new();
        row.insert("objectId".into(), ParseValue::String("u1".into()));
        row.insert("authData".into(), ParseValue::Object(ParseMap::new()));
        let owner = AclScope::user("u1", vec![]).expect("scope");
        filter_sensitive_data(
            &mut row,
            "_User",
            &owner,
            None,
            true,
            &PermissionOptions::default(),
        );
        assert!(row.get("authData").is_some());

        let mut row = ParseMap::new();
        row.insert("objectId".into(), ParseValue::String("u1".into()));
        row.insert("authData".into(), ParseValue::Object(ParseMap::new()));
        let stranger = AclScope::user("u2", vec![]).expect("scope");
        filter_sensitive_data(
            &mut row,
            "_User",
            &stranger,
            None,
            true,
            &PermissionOptions::default(),
        );
        assert!(row.get("authData").is_none());
    }

    #[test]
    fn the_password_hash_never_reaches_a_response_under_any_name() {
        let mut row = ParseMap::new();
        row.insert("objectId".into(), ParseValue::String("u1".into()));
        row.insert("_hashed_password".into(), ParseValue::String("hash".into()));
        row.insert("sessionToken".into(), ParseValue::String("r:t".into()));
        filter_sensitive_data(
            &mut row,
            "_User",
            &AclScope::user("u1", vec![]).expect("scope"),
            None,
            true,
            &PermissionOptions::default(),
        );
        assert!(row.get("_hashed_password").is_none());
        assert!(
            row.get("password").is_none(),
            "the hash is never rehydrated under a user-facing name"
        );
        assert!(row.get("sessionToken").is_none());
    }

    #[test]
    fn adds_field_ignores_deletes_and_dotted_roots() {
        let schema = ClassSchema::new("Post").with_field("meta", FieldType::Object);
        assert!(!adds_field(&schema, true, ["meta.x"], |_| false));
        assert!(adds_field(&schema, true, ["fresh"], |_| false));
        assert!(!adds_field(&schema, true, ["fresh"], |k| k == "fresh"));
        assert!(
            !adds_field(&schema, false, ["fresh"], |_| false),
            "a write that creates the class never runs the addField gate"
        );
    }
}
