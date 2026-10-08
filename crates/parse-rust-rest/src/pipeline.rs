//! The read and write pipelines.
//!
//! Generic over [`StorageAdapter`] rather than taking a `dyn`, so the storage boundary costs
//! nothing at runtime and a future Postgres adapter drops in by type rather than by trait object.
//!
//! Every entry point takes a [`SchemaSnapshot`] and an [`AclScope`] and runs the stages in
//! upstream's order. The read order is `DatabaseController.js:1419-1599`:
//!
//! load the schema, once per request; resolve the class, a missing one behaving as empty;
//! validate the sort, dropping unknown keys; the CLP gate; `$relatedTo` with its authorization;
//! relation-field constraints; pointer permissions; protected fields; the deny check; the ACL
//! clause; query validation; dispatch; raise the ACL and filter sensitive data.
//!
//! Two orderings differ from a naive reading and both are upstream's. `denyProtectedFields` runs
//! in `RestQuery.execute` *before* the CLP gate (`RestQuery.js:284-288`), so a query naming a
//! protected field reports that rather than the CLP denial. And `canAddField` runs before the
//! per-operation gate on a write (`DatabaseController.js:527-537`), so an unauthorized field
//! addition is reported ahead of an unauthorized create.

use std::future::Future;
use std::pin::Pin;

use indexmap::IndexMap;
use parse_rust_core::{
    new_object_id, ErrorCode, FieldWrite, Op, Operation, ParseDate, ParseError, ParseMap,
    ParseValue,
};
use parse_rust_schema::{
    apply, default_schema, field_name_is_valid, infer::schema_mismatch, infer_op_type, infer_type,
    validate_required_columns, validate_write_fields,
};
use parse_rust_storage::{
    AddFieldOutcome, ClassSchema, Clause, Comparison, Constraint, FieldType, Query, QueryOptions,
    SortDirection, StorageAdapter, UpdateValue, DEFAULT_LIMIT,
};

use crate::acl::{default_acl_for_create, lower_acl, raise_acl, AclScope};
use crate::clp::{
    self, adds_field, apply_pointer_permissions, deny_protected_fields, filter_sensitive_data,
    plan_protected_fields, validate_permission, PermissionOptions, PointerPermOutcome,
    ProtectedFieldPlan, WriteAction,
};
use crate::include;
use crate::query_parse::{DeferredWhere, ParsedClause, ParsedWhere};
use crate::relations::{self, RelationConstraint};
use crate::snapshot::SchemaSnapshot;
use crate::write::{
    as_plain_body, echo_response, echoed_keys, flatten_for_create, lower_update, WriteBody,
};

/// A boxed future, used at the one place the read pipeline is genuinely recursive: `$relatedTo`
/// authorization reads the owning object through the same pipeline with the same caller.
type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Everything one request carries into every stage.
///
/// The snapshot is taken once and threaded down, so a batch cannot evaluate half its work under
/// one schema and half under another.
pub struct Ctx<'a, S: StorageAdapter> {
    pub storage: &'a S,
    pub snapshot: &'a SchemaSnapshot,
    pub scope: &'a AclScope,
    pub options: &'a PermissionOptions,
    /// Whether this request authenticated with the **maintenance** key rather than the master key.
    ///
    /// [`AclScope::Unrestricted`] covers both, because they apply the same ACL treatment: none. But
    /// they are not the same authority, and at least one decision reads them differently.
    /// `validateClientClassCreation` exempts master *and* maintenance on a write
    /// (`RestWrite.js:206-208`) and only master on a read (`RestQuery.js:486-489`), so the read path
    /// needs to tell them apart and the scope cannot.
    ///
    /// A separate flag rather than an `AclScope` variant, deliberately and narrowly: a variant
    /// would force a master-versus-maintenance judgment at all twenty-five `Unrestricted` sites,
    /// and only this one is known to differ. The general conflation is recorded in
    /// the deliberate differences in `CHANGELOG.md`; this closes the case that is known to be
    /// wrong rather than pretending to close the rest.
    pub is_maintenance: bool,
}

impl<'a, S: StorageAdapter> Ctx<'a, S> {
    pub fn new(
        storage: &'a S,
        snapshot: &'a SchemaSnapshot,
        scope: &'a AclScope,
        options: &'a PermissionOptions,
    ) -> Self {
        Self {
            is_maintenance: false,
            storage,
            snapshot,
            scope,
            options,
        }
    }

    /// Mark the request as maintenance-key authenticated.
    ///
    /// Defaults to false so the forty-odd `Ctx::new` call sites, nearly all of them tests, keep
    /// their signature: a test that does not care about the distinction cannot get it wrong.
    pub fn maintenance(mut self, yes: bool) -> Self {
        self.is_maintenance = yes;
        self
    }
}

/// Everything about a read that is not a constraint.
#[derive(Debug, Clone)]
pub struct FindOptions {
    pub limit: Option<u32>,
    /// Signed, because a negative skip is refused by the database rather than by the parser, and
    /// that position is what the client sees. See [`QueryOptions::skip`].
    pub skip: Option<i64>,
    pub order: Vec<(String, SortDirection)>,
    pub keys: Option<Vec<String>>,
    /// Subtracted from the projection before it reaches storage, so an adapter only ever sees the
    /// positive form.
    pub exclude_keys: Option<Vec<String>>,
    /// Include paths, every prefix materialized and sorted by depth. Build with
    /// [`crate::query_parse::parse_include`].
    pub include: Vec<Vec<String>>,
    pub hint: Option<parse_rust_storage::Hint>,
    pub comment: Option<String>,
}

impl Default for FindOptions {
    fn default() -> Self {
        Self {
            limit: Some(DEFAULT_LIMIT),
            skip: None,
            order: Vec::new(),
            keys: None,
            exclude_keys: None,
            include: Vec::new(),
            hint: None,
            comment: None,
        }
    }
}

/// What a create returns: `{objectId, createdAt}`, plus the post-write value of any operation the
/// request carried.
#[derive(Debug, Clone)]
pub struct CreateResponse {
    pub object_id: String,
    pub created_at: ParseDate,
    /// The results of `Add`, `AddUnique`, `Remove` and `Increment`, and any defaults applied.
    pub echoed: ParseMap,
}

/// What an update returns: `{updatedAt}`, plus the same operation echo.
#[derive(Debug, Clone)]
pub struct UpdateResponse {
    pub updated_at: ParseDate,
    pub echoed: ParseMap,
}

/// The error both "does not exist" and "you cannot see it" produce.
///
/// Upstream conflates them deliberately: distinguishing them would tell an unauthorized caller
/// that the object exists.
fn object_not_found() -> ParseError {
    ParseError::new(ErrorCode::ObjectNotFound, "Object not found.")
}

// ---------------------------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------------------------

/// Find objects, then expand any `include` paths.
pub async fn find<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    where_: ParsedWhere,
    options: FindOptions,
) -> Result<Vec<ParseMap>, ParseError> {
    if options.limit == Some(0) {
        zero_limit_checks(ctx, class_name, where_, &options)?;
        return Ok(Vec::new());
    }

    // `op` is derived, not passed: a query whose only constraint pins one objectId is a `get` for
    // CLP purposes (`DatabaseController.js:1413-1414`), so a class that grants `get` and denies
    // `find` still serves it.
    let op = derived_op(&where_);
    let mut results = find_core(
        ctx,
        class_name,
        where_,
        options.clone(),
        op,
        // The method is the route's, not the query's (`rest.js:136`). A pinned `where` narrows
        // what the CLP is asked about; it does not turn a `find` request into a `get` request.
        ReadMethod::Find,
    )
    .await?;
    expand_includes(ctx, &mut results, &options).await?;
    Ok(results)
}

/// What a `limit=0` find still checks before answering `[]`.
///
/// **`limit=0` asks the database nothing, and so asks no permission either**
/// (`RestQuery.js:864-867`): `runFind` answers an empty result before `DatabaseController.find`,
/// where the CLP gate lives. It is what `query.count()` sends, `limit=0&count=1`, so a class whose
/// CLP grants `count` and not `find` is countable. An explain takes the same branch, because the
/// explain is a find option that only `DatabaseController.find` reads, and the `include` pass that
/// fails on an explain document walks an empty list instead.
///
/// What runs before `runFind` still runs, in upstream's order: the constructor's class security
/// and `_Session` refusal (`RestQuery.js:54`, `:118-120`), the class-creation check in
/// `buildRestWhere`, and `denyProtectedFields` (`RestQuery.js:287`). Skipping them let
/// `GET /classes/_Session?limit=0` with no session answer 200 where upstream answers 209.
fn zero_limit_checks<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    where_: ParsedWhere,
    options: &FindOptions,
) -> Result<(), ParseError> {
    let master = ctx.scope.is_master();
    crate::class_security::enforce_class_security(
        class_name,
        master,
        ReadMethod::Find.as_str(),
        ctx.options.error_detail,
    )?;
    let mut where_ = where_;
    narrow_sessions(&mut where_, class_name, ctx.scope, ctx.options.error_detail)?;
    if !ctx.snapshot.contains(class_name) {
        validate_client_class_creation(ctx, class_name, false)?;
    }
    if !master {
        let protected = plan_protected_fields(
            class_name,
            ctx.snapshot.clp(class_name),
            ctx.scope,
            where_.pinned_object_id(),
            ctx.options,
        );
        deny_protected_fields(
            protected.as_ref(),
            class_name,
            &where_,
            &options.order,
            ctx.options.error_detail,
        )?;
        // `denyProtectedFields` runs before the `limit=0` answer, so this refusal does too.
        deny_malformed_logical(&where_)?;
    }
    Ok(())
}

/// Fetch one object by id.
pub async fn get<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    object_id: &str,
    options: FindOptions,
) -> Result<ParseMap, ParseError> {
    let options = FindOptions {
        limit: Some(1),
        ..options
    };
    let mut results = find_core(
        ctx,
        class_name,
        pinned_where(object_id),
        options.clone(),
        Operation::Get,
        ReadMethod::Get,
    )
    .await?;
    expand_includes(ctx, &mut results, &options).await?;
    results.into_iter().next().ok_or_else(object_not_found)
}

/// Count objects.
///
/// `order` is the find's. A count never sorts, but upstream's `runCount` sends the find's options
/// through `DatabaseController.find` again (`RestQuery.js:917-925`), which validates every sort
/// key, so `limit=0&count=1&order=$bad` is 105 there and must be here.
pub async fn count<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    where_: ParsedWhere,
    order: &[(String, SortDirection)],
    options: &parse_rust_storage::CountOptions,
) -> Result<u64, ParseError> {
    let schema = ctx.snapshot.get_or_default(class_name);
    // A count is served by the find route, so the class-security method is `find` (`rest.js:136`).
    let plan = plan_read(
        ctx,
        class_name,
        &schema,
        where_,
        order,
        Operation::Count,
        ReadMethod::Find,
    )
    .await?;
    let (query, protected) = match plan {
        // A count denied by a pointer permission is zero.
        //
        // UPSTREAM-QUIRK, deliberately not reproduced: upstream returns the literal `[]` from the
        // shared deny branch (`DatabaseController.js:1510-1516`) whatever the operation, so a
        // denied count answers `{"count": []}` on the wire. That is a type confusion rather than
        // a behavior a client can depend on, and reproducing it would mean giving this function a
        // return type that can hold an array.
        ReadPlan::Denied => return Ok(0),
        ReadPlan::Run {
            query, protected, ..
        } => (query, protected),
    };
    if !ctx.snapshot.contains(class_name) {
        return Ok(0);
    }
    deny_protected_index_fields(
        ctx,
        class_name,
        protected.as_ref(),
        &query,
        options.hint.as_ref(),
    )
    .await?;
    ctx.storage.count(&schema, &query, options).await
}

/// `RestQuery.Method` (`RestQuery.js:80-83`): which read this is, as opposed to what the CLP gate
/// is asked about.
///
/// **These are two different questions and upstream answers them from two different places.** The
/// method comes from the route (`rest.js:136` and `:150` name it literally) or, on the include
/// path, from how many ids were collected (`RestQuery.js:1250-1251`). The CLP operation is derived
/// from the query shape instead (`DatabaseController.js:1413-1414`), and the include path pins it
/// to `get` regardless of the method it just chose (`RestQuery.js:1259`).
///
/// Collapsing the two loses `enforceRoleSecurity`'s method-sensitive rules. `_Installation` is the
/// one that bites: clients may `get` an installation and may not `find` one, so deriving the
/// method from the query shape hands a client every installation row through either a pinned
/// `where` or a multi-object `include`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadMethod {
    Get,
    Find,
}

impl ReadMethod {
    fn as_str(self) -> &'static str {
        match self {
            ReadMethod::Get => "get",
            ReadMethod::Find => "find",
        }
    }
}

/// The `get`/`find` distinction upstream derives from the query shape.
fn derived_op(where_: &ParsedWhere) -> Operation {
    if where_.clauses.len() == 1 && where_.pinned_object_id().is_some() {
        Operation::Get
    } else {
        Operation::Find
    }
}

fn pinned_where(object_id: &str) -> ParsedWhere {
    let mut where_ = ParsedWhere::default();
    where_.push(ParsedClause::Field(Constraint::equal(
        "objectId",
        ParseValue::String(object_id.to_string()),
    )));
    where_
}

/// A read that survived the authorization stages, or one that did not.
enum ReadPlan {
    Run {
        query: Query,
        protected: Option<ProtectedFieldPlan>,
        order: Vec<(String, SortDirection)>,
    },
    /// Stage two said deny-all. The caller decides what that looks like on the wire.
    Denied,
}

/// The class sessions live in.
pub const SESSION_CLASS: &str = "_Session";
/// The class users live in.
pub const USER_CLASS: &str = "_User";

/// Narrow a `_Session` read to the caller's own sessions.
///
/// **Load-bearing, and it belongs here rather than in the router.** `_Session` rows carry no ACL,
/// so the `_rperm $in [null, ...]` clause matches every one of them and this is the only thing
/// standing between a client and every session token on the server.
///
/// Upstream narrows in the `_UnsafeRestQuery` constructor (`RestQuery.js:116-134`), not at a route
/// handler, and that placement is the substance rather than an accident of where the code sits.
/// The include path builds a real `RestQuery` (`RestQuery.js:1250-1258`), so an included
/// `_Session` read is narrowed too. parse-rust had this at the router until 0.2.0, and
/// `GET /classes/Leak?include=s` against a pointer to someone else's session returned that
/// session's token. Every future consumer of this pipeline (LiveQuery matching, `afterFind`,
/// aggregate) would have inherited the same gap.
///
/// Upstream wraps the client's whole where clause as `$and: [clientWhere, {user: <pointer>}]`
/// rather than appending a sibling key, so that a client `$or` cannot widen it. A [`ParsedWhere`]
/// is already a conjunction of clauses, so pushing one more conjunct is the same predicate.
fn narrow_sessions(
    where_: &mut ParsedWhere,
    class_name: &str,
    scope: &AclScope,
    detail: parse_rust_core::ErrorDetail,
) -> Result<(), ParseError> {
    if class_name != SESSION_CLASS || scope.is_master() {
        return Ok(());
    }
    let Some(user_id) = scope.user_id() else {
        // A caller with no user at all is refused outright rather than narrowed to nothing, which
        // is upstream's order (`RestQuery.js:118-120`).
        return Err(ParseError::permission_denied(
            ErrorCode::InvalidSessionToken,
            "Invalid session token",
            detail,
        ));
    };
    let mine = ParsedWhere {
        clauses: vec![ParsedClause::Field(Constraint::equal(
            "user",
            ParseValue::Pointer {
                class_name: USER_CLASS.to_string(),
                object_id: user_id.to_string(),
            },
        ))],
        deferred: None,
    };
    // `$and: [restWhere, {user}]` and not a pushed constraint (`RestQuery.js:121-131`). A client
    // is free to send its own `user` constraint, and two equalities on one field spliced side by
    // side collide in the transform rather than answering the query. The nesting is what lets the
    // server's predicate and the client's coexist.
    //
    // The one departure: an empty `restWhere` is dropped rather than nested as `{}`. Upstream
    // nests it, and `$and: [{}, ...]` is a valid but pointless branch.
    // A deferred failure stays at the top, where the read path looks for it.
    let deferred = where_.deferred.take();
    if where_.is_empty() {
        *where_ = mine;
    } else {
        let client = std::mem::take(where_);
        where_.push(ParsedClause::And(vec![client, mine]));
    }
    where_.deferred = deferred;
    Ok(())
}

/// `checkWhere`'s refusal of a `$or`, `$and` or `$nor` that is not an array, for a caller other
/// than master and maintenance, whether or not anything is protected (`RestQuery.js:956-963`).
fn deny_malformed_logical(where_: &ParsedWhere) -> Result<(), ParseError> {
    match &where_.deferred {
        // Upstream sanitizes this to `Permission denied`, which tells the client nothing about
        // its malformed query. The message says what is wrong instead.
        Some(DeferredWhere::MalformedLogical(message)) => {
            Err(ParseError::invalid_query(message.clone()))
        }
        _ => Ok(()),
    }
}

/// A field of an index that only the server reads: an `_`-prefixed column such as a token or the
/// password hash, or `authData`, which the adapter stores under `_auth_data_*`.
///
/// `_rperm` and `_wperm` are not among them: they are the ACL, which every row a caller can read
/// already shows it.
fn internal_index_field(fields: &[String]) -> Option<&str> {
    fields
        .iter()
        .find(|field| {
            (field.starts_with('_') && !matches!(field.as_str(), "_rperm" | "_wperm"))
                || field.as_str() == "authData"
        })
        .map(String::as_str)
}

/// [`deny_protected_fields`] for a field a read reaches through an index rather than by name.
///
/// Held to the same rule, with the same refusals. Only a caller with something protected pays for
/// listing the class's indexes. A deliberate difference: upstream accepts any `hint`.
async fn deny_protected_index_fields<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    protected: Option<&ProtectedFieldPlan>,
    query: &Query,
    hint: Option<&parse_rust_storage::Hint>,
) -> Result<(), ParseError> {
    // A hinted index is checked for every caller but master, because an internal column is
    // never readable by one. A text index is checked only when something is protected.
    let has_protected = protected.is_some_and(|p| !p.strip.is_empty());
    let text = has_protected && has_text_search(query);
    if ctx.scope.is_master() || (hint.is_none() && !text) {
        return Ok(());
    }
    let indexes = ctx.storage.index_fields(class_name).await?;
    let refuse = |verb: &str, field: &str| {
        ParseError::permission_denied(
            ErrorCode::OperationForbidden,
            format!("This user is not allowed to {verb} {field} on class {class_name}"),
            ctx.options.error_detail,
        )
    };
    if let Some(hint) = hint {
        // A hint naming no index is the database's refusal, which reveals nothing protected.
        let hinted = indexes.iter().find(|index| match hint {
            parse_rust_storage::Hint::Name(name) => index.name == *name,
            parse_rust_storage::Hint::Keys(keys) => {
                index.columns.len() == keys.len()
                    && index.columns.iter().zip(keys.keys()).all(|(c, k)| c == k)
            }
        });
        if let Some(field) = hinted.and_then(|index| {
            clp::protected_index_field(protected, &index.fields)
                .or_else(|| internal_index_field(&index.fields))
        }) {
            return Err(refuse("sort by", field));
        }
    }
    if text {
        for index in indexes.iter().filter(|index| index.text) {
            if let Some(field) = clp::protected_index_field(protected, &index.fields) {
                return Err(refuse("query", field));
            }
        }
    }
    Ok(())
}

/// Does the query carry a `$text` search anywhere?
fn has_text_search(query: &Query) -> bool {
    query.clauses.iter().any(|clause| match clause {
        Clause::Field(Constraint {
            comparison: Comparison::Text(_),
            ..
        }) => true,
        Clause::Field(_) => false,
        Clause::Or(subs) | Clause::And(subs) | Clause::Nor(subs) => {
            subs.iter().any(has_text_search)
        }
    })
}

/// Steps 2 through 11 of the read ordering.
fn plan_read<'a, S: StorageAdapter>(
    ctx: &'a Ctx<'a, S>,
    class_name: &'a str,
    schema: &'a ClassSchema,
    mut where_: ParsedWhere,
    order: &'a [(String, SortDirection)],
    op: Operation,
    method: ReadMethod,
) -> BoxFut<'a, Result<ReadPlan, ParseError>> {
    Box::pin(async move {
        refuse_unnamed_class(ctx, class_name, "find")?;
        let clp = ctx.snapshot.clp(class_name);
        let acl_group = ctx.scope.acl_group();
        let master = ctx.scope.is_master();

        // Before everything, matching upstream's constructor-time position. Both of these are
        // enforced here rather than at a route handler because upstream enforces them in the
        // `RestQuery` constructor (`RestQuery.js:54`, `:116-134`), which the include path and
        // `$relatedTo`'s authorization read both go through.
        crate::class_security::enforce_class_security(
            class_name,
            master,
            // The caller's `RestQuery.Method`, never the derived CLP operation. See [`ReadMethod`]
            // for why the two cannot be collapsed.
            method.as_str(),
            ctx.options.error_detail,
        )?;
        narrow_sessions(&mut where_, class_name, ctx.scope, ctx.options.error_detail)?;

        // **The read path runs the same option the write path does**, from `buildRestWhere`
        // (`RestQuery.js:485-500`), so before the protected-field, sort and CLP checks. Answering
        // an empty result instead tells a client that cannot create classes that the class simply
        // has no rows, which is a different statement from upstream's refusal and hides a
        // misconfigured client behind a plausible-looking 200.
        if !ctx.snapshot.contains(class_name) {
            validate_client_class_creation(ctx, class_name, false)?;
        }

        // 8 (computed early, because the denial below needs it). Master never reaches it.
        let protected = if master {
            None
        } else {
            plan_protected_fields(
                class_name,
                clp,
                ctx.scope,
                where_.pinned_object_id(),
                ctx.options,
            )
        };

        // `denyProtectedFields`, which runs before the gate and against the unfiltered sort.
        if !master {
            deny_protected_fields(
                protected.as_ref(),
                class_name,
                &where_,
                order,
                ctx.options.error_detail,
            )?;
            deny_malformed_logical(&where_)?;
        }
        // `find` reads `query.objectId` before it loads the schema, so a null `where` fails here,
        // for every caller.
        if matches!(where_.deferred, Some(DeferredWhere::Null)) {
            return Err(ParseError::internal("where is null".to_string()));
        }

        // 3. Sort validation. Unknown keys are dropped rather than refused, except `score`.
        let order = validate_sort(schema, class_name, order)?;

        // 4. The CLP gate.
        if !master {
            validate_permission(
                clp,
                class_name,
                &acl_group,
                op,
                None,
                ctx.options.error_detail,
            )?;
        }

        // 11. Query validation, computed over the client's keys before the resolution steps
        //     consume them and raised at upstream's position, after pointer permissions. Upstream
        //     runs it on a query that by then also carries the server's own `_rperm`/`_wperm` and
        //     has had `$relatedTo` deleted; both of those are keys it would allow anyway, so
        //     checking the client's keys is the same predicate over a smaller set. The position
        //     matters: a query a pointer permission denies outright answers empty, whatever keys
        //     it names (`DatabaseController.js:1510-1516` before `:1524`).
        let keys_checked = match where_.deferred.take() {
            // The conversion's own error, at the conversion's position, which follows the key-name
            // check. The clauses are only the failed `where`'s shape, kept for the checks above
            // and this one, so they go before anything resolves them.
            Some(DeferredWhere::Error(e)) => {
                let keys = crate::query_parse::validate_query_keys(&where_, master);
                where_.clauses.clear();
                keys.and(Err(e))
            }
            // Master skips `checkWhere`; the same malformed shape is refused here with the same
            // message, where upstream answers a 500 for `$or` and `$and`.
            Some(DeferredWhere::MalformedLogical(message)) => {
                where_.clauses.clear();
                Err(ParseError::invalid_query(message))
            }
            // `addReadACL` assigns onto it for anyone but master; master's query has no keys.
            Some(DeferredWhere::Scalar) if !master => {
                Err(ParseError::internal("where is not an object".to_string()))
            }
            _ => crate::query_parse::validate_query_keys(&where_, master),
        };

        // 5 and 6. `$relatedTo` and relation-field constraints, both join-table reads.
        let mut query = resolve_where(ctx, class_name, schema, where_).await?;

        // 7. Pointer permissions.
        if !master {
            match apply_pointer_permissions(schema, clp, op, &acl_group, &query)? {
                PointerPermOutcome::Unconstrained => {}
                PointerPermOutcome::Constrained(narrowed) => query = narrowed,
                // 9. The deny check.
                PointerPermOutcome::DenyAll => return Ok(ReadPlan::Denied),
            }
        }
        keys_checked?;

        // 10. The ACL clause.
        //
        // Upstream **overwrites** `_rperm`/`_wperm` at the query's top level rather than
        // conjoining (`DatabaseController.js:78-90`), relying on the invariant that this runs
        // last, after pointer rewriting, and on clients never being allowed to query those
        // columns. A clause list conjoins instead, which is equivalent here and does not depend
        // on the invariant holding.
        let constraint = match op {
            Operation::Update | Operation::Delete => ctx.scope.write_constraint(),
            _ => ctx.scope.read_constraint(),
        };
        if let Some(constraint) = constraint {
            query.push_constraint(constraint);
        }

        Ok(ReadPlan::Run {
            query,
            protected,
            order,
        })
    })
}

/// The read itself, without `include`.
///
/// Split from [`find`] because `include` runs one nested read per class per level and those must
/// not themselves expand includes.
fn find_core<'a, S: StorageAdapter>(
    ctx: &'a Ctx<'a, S>,
    class_name: &'a str,
    where_: ParsedWhere,
    options: FindOptions,
    op: Operation,
    method: ReadMethod,
) -> BoxFut<'a, Result<Vec<ParseMap>, ParseError>> {
    Box::pin(async move {
        let schema = ctx.snapshot.get_or_default(class_name);
        let plan = plan_read(ctx, class_name, &schema, where_, &options.order, op, method).await?;
        let (query, protected, order) = match plan {
            ReadPlan::Denied => {
                // 9. A denied `get` is `OBJECT_NOT_FOUND`; a denied `find` is empty.
                return if op == Operation::Get {
                    Err(object_not_found())
                } else {
                    Ok(Vec::new())
                };
            }
            ReadPlan::Run {
                query,
                protected,
                order,
            } => (query, protected, order),
        };
        deny_protected_index_fields(
            ctx,
            class_name,
            protected.as_ref(),
            &query,
            options.hint.as_ref(),
        )
        .await?;

        // **A class that does not exist is still read.** Upstream reads it under `{fields: {}}`
        // and asks the adapter anyway (`DatabaseController.js:1423-1433`, `:1561-1563`), so the
        // query is built and its errors raised: a malformed `$within` is 107 on any class.
        // A `userField:` rule reads its pointer field, so a `keys` that leaves it out projects it
        // anyway and the field is removed again after filtering (`DatabaseController.js:1865-1874`,
        // `:285`). Without it the rule never matched and the caller's own fields stayed
        // stripped.
        let mut keys = projection(&schema, &options);
        let mut temporary: Vec<String> = Vec::new();
        if let (Some(keys), Some(plan)) = (keys.as_mut(), protected.as_ref()) {
            for (field, _) in &plan.user_field_rules {
                if !keys.iter().any(|k| k == field) {
                    keys.push(field.clone());
                    temporary.push(field.clone());
                }
            }
        }
        let omit_fields = projected_away(&schema, keys.as_ref(), protected.as_ref());
        let query_options = QueryOptions {
            limit: options.limit,
            skip: options.skip,
            order,
            keys,
            omit_fields,
            case_insensitive: false,
            hint: options.hint.clone(),
            comment: options.comment.clone(),
        };
        let rows = ctx
            .storage
            .find(&schema, &query, &query_options)
            .await
            .map_err(|e| find_failure(e, ctx.options.error_detail))?;

        // 13.
        let is_read = matches!(op, Operation::Get | Operation::Find);
        Ok(rows
            .into_iter()
            .map(|row| {
                let mut row = raise_acl(row);
                filter_sensitive_data(
                    &mut row,
                    class_name,
                    ctx.scope,
                    protected.as_ref(),
                    is_read,
                    ctx.options,
                );
                // Removed where upstream removes them: everywhere but a caller's own `_User` row
                // under the owner exemption.
                let own_user_row = class_name == USER_CLASS
                    && ctx.options.protected_fields_owner_exempt
                    && ctx.scope.user_id().is_some_and(|uid| {
                        matches!(row.get("objectId"), Some(ParseValue::String(id)) if id == uid)
                    });
                if !own_user_row {
                    for field in &temporary {
                        row.shift_remove(field);
                    }
                }
                row
            })
            .collect())
    })
}

/// A storage failure on the read path, as `DatabaseController.find` reports it.
///
/// Anything that is not already a Parse error is rethrown as a sanitized
/// `INTERNAL_SERVER_ERROR` whose generic message is `An internal server error occurred`
/// (`DatabaseController.js:1583-1596`), the one call site that overrides `Permission denied`. So
/// a find the database refuses, a negative `skip` or a `hint` naming no index, answers
/// `{"code":1,"error":"An internal server error occurred"}`, not the bare
/// `{"code":1,"message":"Internal server error."}` a thrown `Error` gets elsewhere.
///
/// An error the adapter raised while building the query is left alone: upstream throws it
/// synchronously, before that `.catch` is attached, so it answers the bare 500. A `$geoWithin`
/// point with latitude 100 is the case that shows the difference.
fn find_failure(e: ParseError, detail: parse_rust_core::ErrorDetail) -> ParseError {
    if e.origin != parse_rust_core::ErrorOrigin::Internal || e.info.before_query {
        return e;
    }
    ParseError::sanitized(
        ErrorCode::InternalServerError,
        e.message,
        "An internal server error occurred",
        detail,
    )
}

/// Explain a find instead of running it.
///
/// The query is planned exactly as [`find`] plans it, so the explained query carries the same
/// ACL, CLP and pointer-permission constraints the real one would; only the storage call differs.
/// Upstream then returns the database's document as `results` and skips every post-processing
/// step: no ACL raising, no sensitive-data filtering, no `afterFind` (`DatabaseController.js:1561`,
/// `RestQuery.js:1125`).
///
/// Who may explain is decided by the route, before this is reached (`rest.js:39-48`).
///
/// **`verbosity` arrives unvalidated, as a result.** Upstream validates the value in the adapter's
/// `find` (`MongoStorageAdapter.js:728`), so an invalid one is refused only once the query reaches
/// storage: after the CLP gate, and never on a `limit=0` or pointer-denied read, which answer `[]`.
pub async fn explain<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    where_: ParsedWhere,
    options: FindOptions,
    verbosity: Result<parse_rust_storage::ExplainVerbosity, ParseError>,
) -> Result<serde_json::Value, ParseError> {
    // Before the CLP gate, the include pass and the database, as on a find.
    if options.limit == Some(0) {
        zero_limit_checks(ctx, class_name, where_, &options)?;
        return Ok(serde_json::Value::Array(Vec::new()));
    }
    let op = derived_op(&where_);
    let schema = ctx.snapshot.get_or_default(class_name);
    let plan = plan_read(
        ctx,
        class_name,
        &schema,
        where_,
        &options.order,
        op,
        ReadMethod::Find,
    )
    .await?;
    let (query, protected, order) = match plan {
        ReadPlan::Denied => {
            return if op == Operation::Get {
                Err(object_not_found())
            } else {
                Ok(serde_json::Value::Array(Vec::new()))
            };
        }
        ReadPlan::Run {
            query,
            protected,
            order,
        } => (query, protected, order),
    };
    deny_protected_index_fields(
        ctx,
        class_name,
        protected.as_ref(),
        &query,
        options.hint.as_ref(),
    )
    .await?;
    let verbosity = verbosity?;
    // **No [`find_failure`] here.** Upstream's explain branch returns `this.adapter.find(...)`
    // with no `.catch` (`DatabaseController.js:1561`); the sanitizing one belongs to the
    // non-explain branch beside it. So a refused explain, a `hint` naming no index or a negative
    // `skip`, answers the bare `{"code":1,"message":"Internal server error."}`.
    let query_options = QueryOptions {
        limit: options.limit,
        skip: options.skip,
        order,
        keys: projection(&schema, &options),
        omit_fields: None,
        case_insensitive: false,
        hint: options.hint,
        comment: options.comment,
    };
    let document = ctx
        .storage
        .explain(&schema, &query, &query_options, verbosity)
        .await?;
    // `include` walks `results` as rows, and an explain document is not rows, so upstream throws
    // inside the include pass and answers a bare 500. Measured at the pin. It runs after the
    // database answers (`RestQuery.js:298`), so a CLP refusal or a database error wins over it.
    if !options.include.is_empty() {
        return Err(ParseError::internal(
            "include on an explain; upstream throws walking the explain document",
        ));
    }
    Ok(document)
}

/// Protected fields the database need not return at all, since every row would lose them anyway.
///
/// A performance measure, not the protection: [`filter_sensitive_data`] still strips the same
/// fields from every row, which is what keeps a backend that ignores the option correct. Reading a
/// large protected field only to discard it was most of the cost of a read that protects one.
/// Upstream declines the projection outright (`DatabaseController.js:1498-1500`); this is
/// parse-rust's own, kept to the cases where it cannot change a response.
///
/// Only where the stripped set is the same for every row of the read. Not with explicit `keys`,
/// whose projection already decides what is read. Not on `_User`, where the owner of a row can be
/// exempt from its own protection. Not when any `userField:` rule exists, because such a rule
/// unprotects a field on the rows that point at the caller, which only the row can say.
///
/// **Only fields the schema declares, and never the four keys the row handling relies on.**
/// Protected names are not validated when they arrive by `PARSE_SERVER_PROTECTED_FIELDS` or a
/// hand-edited `_SCHEMA`, upstream included, so the set can hold an internal column, a dotted path
/// or a `$` name. Projected, those emptied the permission columns, dropped `_id`, removed a nested
/// field the strip would have kept, or made MongoDB refuse the read. A declared field is a plain
/// top-level column, so projecting it away removes exactly what the strip removes.
fn projected_away(
    schema: &ClassSchema,
    keys: Option<&Vec<String>>,
    protected: Option<&crate::clp::ProtectedFieldPlan>,
) -> Option<Vec<String>> {
    const ALWAYS_FETCHED: [&str; 4] = ["objectId", "createdAt", "updatedAt", "ACL"];
    let plan = protected?;
    if keys.is_some() || schema.class_name == USER_CLASS || !plan.user_field_rules.is_empty() {
        return None;
    }
    let mut fields: Vec<String> = Vec::new();
    for f in &plan.strip {
        if !ALWAYS_FETCHED.contains(&f.as_str()) && schema.field(f).is_some() && !fields.contains(f)
        {
            fields.push(f.clone());
        }
    }
    (!fields.is_empty()).then_some(fields)
}

/// `keys` and `excludeKeys` folded into one positive projection.
///
/// `handleExcludeKeys` (`RestQuery.js:1039-1054`) subtracts from `keys` when there is one, and
/// otherwise from the schema's field list, which is why this needs the schema.
fn projection(schema: &ClassSchema, options: &FindOptions) -> Option<Vec<String>> {
    // The four keys a projection can never drop (`AlwaysSelectedKeys`, `RestQuery.js:9`).
    const ALWAYS: [&str; 4] = ["objectId", "createdAt", "updatedAt", "ACL"];
    // The database is asked for each key's root: `owner.email` projects `owner`
    // (`RestQuery.js:869-872`). The dotted form is for an include's own `keys`, which
    // `include::keys_for_path` reads from the options; projecting it here dropped the field.
    let roots = options.keys.as_ref().map(|keys| {
        let mut out: Vec<String> = Vec::with_capacity(keys.len());
        for key in keys {
            let root = key.split('.').next().unwrap_or(key);
            if !out.iter().any(|k| k == root) {
                out.push(root.to_string());
            }
        }
        out
    });
    match (&roots, &options.exclude_keys) {
        (None, None) => None,
        (Some(keys), None) => {
            let mut out = keys.clone();
            for key in ALWAYS {
                if !out.iter().any(|k| k == key) {
                    out.push(key.to_string());
                }
            }
            Some(out)
        }
        (keys, Some(exclude)) => {
            // `excludeKeys` never removes an always-selected key.
            let exclude: Vec<&String> = exclude
                .iter()
                .filter(|k| !ALWAYS.contains(&k.as_str()))
                .collect();
            let base: Vec<String> = match keys {
                Some(keys) => {
                    let mut out = keys.clone();
                    for key in ALWAYS {
                        if !out.iter().any(|k| k == key) {
                            out.push(key.to_string());
                        }
                    }
                    out
                }
                None => schema.fields.keys().cloned().collect(),
            };
            Some(base.into_iter().filter(|k| !exclude.contains(&k)).collect())
        }
    }
}

/// Steps 5 and 6: turn a parsed where into a query, reading join tables where it has to.
fn resolve_where<'a, S: StorageAdapter>(
    ctx: &'a Ctx<'a, S>,
    class_name: &'a str,
    schema: &'a ClassSchema,
    where_: ParsedWhere,
) -> BoxFut<'a, Result<Query, ParseError>> {
    Box::pin(async move {
        let mut query = Query::new();
        // **Constraints on a `Relation` field are collected per field and resolved as a group**,
        // because upstream's gate is a truthiness test on `query[key]`, the whole operator
        // document, before it iterates that document's keys
        // (`DatabaseController.js:1085-1113`). The parser has already split
        // `{"$ne": false, "$in": [...]}` into two constraints on one field, so a per-constraint
        // decision cannot see the sibling that satisfies the gate. Deciding one at a time returned
        // every owner for a falsy `$ne`, where upstream returns none.
        //
        // Resolved after the loop rather than inside it, which also matches upstream:
        // `reduceInRelation` runs over the finished query and `addInObjectIdsIds` folds its result
        // into the constraints already there. Doing it inline meant an `objectId` constraint
        // appearing later in the same where document was never intersected with the join result.
        let mut relation_groups: IndexMap<String, Vec<Comparison>> = IndexMap::new();
        for clause in where_.clauses {
            match clause {
                ParsedClause::Field(constraint) => {
                    match schema.field(&constraint.field) {
                        // A `Relation` field has no column, so a constraint on one is the reverse
                        // join read (`DatabaseController.js:1051-1144`).
                        Some(FieldType::Relation { .. }) => {
                            relation_groups
                                .entry(constraint.field.clone())
                                .or_default()
                                .push(constraint.comparison);
                        }
                        _ => query.push_constraint(constraint),
                    }
                }
                ParsedClause::RelatedTo {
                    class_name: owning_class,
                    object_id: owning_id,
                    key,
                } => {
                    let outcome = resolve_related_to(ctx, &owning_class, &owning_id, &key).await?;
                    // A caller who cannot read the owning object gets an empty `objectId $in`
                    // rather than an error, so the relation is not a membership oracle.
                    relations::add_in_object_ids(&mut query, outcome.ids());
                }
                ParsedClause::Or(branches) => {
                    query.push(Clause::Or(
                        resolve_branches(ctx, class_name, schema, branches).await?,
                    ));
                }
                ParsedClause::And(branches) => {
                    query.push(Clause::And(
                        resolve_branches(ctx, class_name, schema, branches).await?,
                    ));
                }
                ParsedClause::Nor(branches) => {
                    // **This is a real difference, not an equivalent spelling.** Upstream's
                    // `reduceInRelation` recurses into `$or` and `$and` but not `$nor`
                    // (`DatabaseController.js:1055-1074`), so a relation constraint inside a
                    // `$nor` reaches the adapter naming a column no document carries. It matches
                    // nothing, and the `$nor` negates that into matching everything. parse-rust
                    // resolves the join here instead, so the negated clause is an `objectId $in`
                    // of the owning ids and the owners are excluded.
                    //
                    // The two agree only when the relation is empty. When it has members,
                    // parse-rust returns the narrower answer: upstream's row set minus the rows
                    // that are actually related. That is fail-closed, and it is the reason to
                    // prefer it over reproducing a constraint that silently evaluates to a
                    // tautology.
                    //
                    // Reasoned about from the upstream source, not measured against a running
                    // parse-server. A differential over `$nor` plus `$relatedTo` would settle it.
                    query.push(Clause::Nor(
                        resolve_branches(ctx, class_name, schema, branches).await?,
                    ));
                }
            }
        }

        // One group per relation field, each yielding as many reads as upstream builds queries:
        // `{"$in": [a], "$nin": [b]}` is an inclusion and an exclusion, applied independently.
        for (field, comparisons) in relation_groups {
            for constraint in relations::relation_constraints_for(&comparisons)? {
                match constraint {
                    RelationConstraint::OwnersOf(ids) => {
                        let owners =
                            relations::owning_ids(ctx.storage, class_name, &field, &ids).await?;
                        relations::add_in_object_ids(&mut query, &owners);
                    }
                    RelationConstraint::NotOwnersOf(ids) => {
                        let owners =
                            relations::owning_ids(ctx.storage, class_name, &field, &ids).await?;
                        relations::add_not_in_object_ids(&mut query, &owners);
                    }
                }
            }
        }
        Ok(query)
    })
}

async fn resolve_branches<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    schema: &ClassSchema,
    branches: Vec<ParsedWhere>,
) -> Result<Vec<Query>, ParseError> {
    let mut out = Vec::with_capacity(branches.len());
    for branch in branches {
        out.push(resolve_where(ctx, class_name, schema, branch).await?);
    }
    Ok(out)
}

/// `$relatedTo`, authorized against the owning class before the join table is read.
async fn resolve_related_to<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    owning_class: &str,
    owning_id: &str,
    key: &str,
) -> Result<relations::RelatedToOutcome, ParseError> {
    if ctx.scope.is_master() {
        let ids = relations::related_ids(ctx.storage, owning_class, key, owning_id).await?;
        return Ok(relations::RelatedToOutcome::Ids(ids));
    }
    ensure_in_snapshot(ctx, owning_class).await?;

    let owning_protected = plan_protected_fields(
        owning_class,
        ctx.snapshot.clp(owning_class),
        ctx.scope,
        Some(owning_id),
        ctx.options,
    )
    .map(|p| p.strip)
    .unwrap_or_default();

    let authorized = relations::authorize_related_to(
        owning_class,
        key,
        &owning_protected,
        ctx.options.error_detail,
        || async move {
            // A read with the caller's own auth, so the owning class's CLP, the object's ACL and
            // its pointer permissions all apply. Any denial or miss means "cannot read".
            let options = FindOptions {
                limit: Some(1),
                keys: Some(vec!["objectId".to_string()]),
                ..Default::default()
            };
            match find_core(
                ctx,
                owning_class,
                pinned_where(owning_id),
                options,
                Operation::Get,
                ReadMethod::Get,
            )
            .await
            {
                Ok(rows) => Ok(!rows.is_empty()),
                Err(e)
                    if e.code == ErrorCode::OperationForbidden
                        || e.code == ErrorCode::ObjectNotFound =>
                {
                    Ok(false)
                }
                Err(e) => Err(e),
            }
        },
    )
    .await?;

    if !authorized {
        return Ok(relations::RelatedToOutcome::DeniedYieldEmpty);
    }
    let ids = relations::related_ids(ctx.storage, owning_class, key, owning_id).await?;
    Ok(relations::RelatedToOutcome::Ids(ids))
}

/// Step 3: validate the sort and drop what the schema does not know.
fn validate_sort(
    schema: &ClassSchema,
    class_name: &str,
    order: &[(String, SortDirection)],
) -> Result<Vec<(String, SortDirection)>, ParseError> {
    // The sort is a JavaScript object upstream: a repeated key keeps its first position and its
    // last direction.
    let mut sort: IndexMap<String, SortDirection> = IndexMap::new();
    for (field, direction) in order {
        sort.insert(field.clone(), *direction);
    }
    // `_created_at` and `_updated_at` sort as `createdAt` and `updatedAt`
    // (`DatabaseController.js:1435-1445`): the alias is deleted and the public name assigned, which
    // keeps the public name's position if it was already there and appends it otherwise.
    for (alias, public) in [("_created_at", "createdAt"), ("_updated_at", "updatedAt")] {
        if let Some(direction) = sort.shift_remove(alias) {
            sort.insert(public.to_string(), direction);
        }
    }
    let mut out = Vec::new();
    for (field, direction) in &sort {
        if is_auth_data_id_path(field) {
            return Err(ParseError::invalid_key_name(format!(
                "Cannot sort by {field}"
            )));
        }
        let root = field.split('.').next().unwrap_or(field);
        if !field_name_is_valid(root, class_name) {
            return Err(ParseError::invalid_key_name(format!(
                "Invalid field name: {field}."
            )));
        }
        // A sort key the schema does not carry is dropped rather than refused. `score` survives
        // because it is a projected text-search rank rather than a column.
        if schema.field(root).is_none() && field != "score" {
            continue;
        }
        out.push((field.clone(), *direction));
    }
    Ok(out)
}

/// `^authData\.([a-zA-Z0-9_]+)\.id$`.
fn is_auth_data_id_path(field: &str) -> bool {
    let parts: Vec<&str> = field.split('.').collect();
    matches!(parts.as_slice(), ["authData", provider, "id"]
        if !provider.is_empty()
            && provider.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// Expand every `include` path, one query per target class per path.
///
/// **Concurrent the way upstream is.** `handleInclude` builds a tree of the paths and runs every
/// sibling at once, a child only after its parent (`RestQuery.js:1057-1101`), and `includePath`
/// queries its target classes at once (`RestQuery.js:1242-1266`). Here the paths arrive
/// materialized and sorted by depth, so each depth is one wave: every path and class in it is
/// queried together, then grafted in the original order before the next depth reads what was
/// grafted. A child therefore waits for its whole depth rather than for its own parent, which costs
/// time and changes nothing a client sees. Grafting in order keeps the key order of every result
/// what the sequential version produced.
///
/// Which error a client sees when two of the queries fail is the first in path order here and the
/// first to settle upstream; neither is a contract.
async fn expand_includes<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    results: &mut [ParseMap],
    options: &FindOptions,
) -> Result<(), ParseError> {
    if options.include.is_empty() || results.is_empty() {
        return Ok(());
    }
    let keys = options.keys.clone().unwrap_or_default();
    let exclude_keys = options.exclude_keys.clone().unwrap_or_default();
    // `auth.isMaster`, which the maintenance key does not set (`middlewares.js:439`).
    let master = ctx.scope.is_master() && !ctx.is_maintenance;

    let mut budget = include::GraftBudget::new(include::GraftBudget::DEFAULT);
    let mut remaining = options.include.as_slice();
    while let Some(first) = remaining.first() {
        let depth = first.len();
        let level_len = remaining
            .iter()
            .take_while(|path| path.len() == depth)
            .count();
        let (level, rest) = remaining.split_at(level_len);
        remaining = rest;

        // Every query of this depth, collected before any of them runs. Same-depth paths cannot
        // read what another one grafts, so collecting first is the same as collecting in turn.
        let mut reads = Vec::new();
        let mut has_pointers = vec![false; level.len()];
        for (index, path) in level.iter().enumerate() {
            for (target_class, ids) in include::collect_pointers(results, path) {
                has_pointers[index] = true;
                reads.push((index, target_class, ids));
            }
        }
        if reads.is_empty() {
            continue;
        }
        let fetches = reads.iter().map(|(index, target_class, ids)| {
            include_read(ctx, target_class, ids, &level[*index], &keys, &exclude_keys)
        });
        let outcomes = futures::future::join_all(fetches).await;

        let mut fetched: Vec<IndexMap<String, ParseMap>> = vec![IndexMap::new(); level.len()];
        for ((index, target_class, _), rows) in reads.iter().zip(outcomes) {
            for mut row in rows? {
                let Some(ParseValue::String(id)) = row.get("objectId").cloned() else {
                    continue;
                };
                include::shape_included(&mut row, target_class, master);
                fetched[*index].insert(id, row);
            }
        }
        for ((path, rows), has) in level.iter().zip(&fetched).zip(has_pointers) {
            if has {
                include::graft(results, path, rows, &mut budget)?;
            }
        }
    }
    Ok(())
}

/// A client reads and deletes only in a class whose name a client could use.
fn refuse_unnamed_class<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    operation: &str,
) -> Result<(), ParseError> {
    if ctx.scope.is_master() || parse_rust_schema::class_name_is_valid(class_name) {
        return Ok(());
    }
    Err(ParseError::permission_denied(
        ErrorCode::OperationForbidden,
        format!(
            "Clients aren't allowed to perform the {operation} operation on the {class_name} collection."
        ),
        ctx.options.error_detail,
    ))
}

/// Refuse to read `class_name` under a snapshot that lacks it while `_SCHEMA` has it.
///
/// The request's own class is loaded before the request runs. A class reached through the data,
/// an include target or a `$relatedTo` owner, is not, and a snapshot taken before another server
/// created it would read it with no CLP, which is unrestricted. A class that exists nowhere reads
/// as empty, as upstream reads it; one that exists sends the request back to be run on a rebuilt
/// snapshot. See [`ParseError::schema_stale`].
async fn ensure_in_snapshot<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
) -> Result<(), ParseError> {
    if ctx.snapshot.contains(class_name) || !ctx.storage.class_exists(class_name).await? {
        return Ok(());
    }
    Err(ParseError::schema_stale(class_name))
}

/// One include query: the rows of `target_class` that `path` points at.
async fn include_read<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    target_class: &str,
    ids: &[String],
    path: &[String],
    keys: &[String],
    exclude_keys: &[String],
) -> Result<Vec<ParseMap>, ParseError> {
    ensure_in_snapshot(ctx, target_class).await?;
    let mut where_ = ParsedWhere::default();
    // One id is an equality, several are an `$in` (`RestQuery.js:1244-1249`), and the same
    // count picks the method: `get` for one, `find` for several
    // (`RestQuery.js:1250-1251`). The CLP operation does **not** follow it. Upstream pins
    // that to `get` for every include regardless of how many ids it collected
    // (`RestQuery.js:1259`), so a class granting `get` and denying `find` still serves an
    // include of any size.
    //
    // What the method decides is `enforceRoleSecurity`: a multi-object include of
    // `_Installation` is refused where a single-object one is allowed.
    let method = if ids.len() == 1 {
        ReadMethod::Get
    } else {
        ReadMethod::Find
    };
    let constraint = if ids.len() == 1 {
        Constraint::equal("objectId", ParseValue::String(ids[0].clone()))
    } else {
        Constraint::one_of(
            "objectId",
            ids.iter()
                .map(|id| ParseValue::String(id.clone()))
                .collect(),
        )
    };
    where_.push(ParsedClause::Field(constraint));

    let nested = FindOptions {
        limit: Some(ids.len() as u32),
        skip: None,
        order: Vec::new(),
        keys: include::keys_for_path(keys, path),
        exclude_keys: include::exclude_keys_for_path(exclude_keys, path),
        include: Vec::new(),
        // An include's own read carries neither: upstream builds it from
        // `includeReadPreference` alone.
        hint: None,
        comment: None,
    };

    // The nested read is a full pipeline read with the caller's own scope, so the target
    // class's CLP, ACL and protected fields all apply. Grafting the row in without this
    // is the classic Parse data leak: the caller is authorized for the class holding the
    // pointer, not for the class it points at.
    find_core(ctx, target_class, where_, nested, Operation::Get, method).await
}

// ---------------------------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------------------------

/// Create an object.
pub async fn create<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    body: WriteBody,
) -> Result<CreateResponse, ParseError> {
    create_checked(ctx, class_name, body, None).await
}

/// A step run on a create's body once its defaults, required fields and the class's default ACL
/// are applied, before anything else about the object is checked or stored, returning the body to
/// store. A `_User` create's `transformUser` is one: it follows `setRequiredFieldsIfNeeded`
/// (`RestWrite.js:139-144`), so its identity checks see the defaulted body, a missing required
/// field is reported before a taken username, the password is hashed only after a `password`
/// default or requirement was applied to the plain value, and the owner's ACL entry is added to
/// the class's default ACL rather than replacing it.
pub type BeforeInsert<'a> =
    Box<dyn FnOnce(WriteBody) -> BoxFut<'a, Result<WriteBody, ParseError>> + Send + 'a>;

/// [`create`], with a [`BeforeInsert`] check.
pub async fn create_checked<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    mut body: WriteBody,
    before_insert: Option<BeforeInsert<'_>>,
) -> Result<CreateResponse, ParseError> {
    let class_exists = ctx.snapshot.contains(class_name);
    let mut schema = ctx.snapshot.resolve_for_write(class_name);
    let clp = ctx.snapshot.clp(class_name);
    let acl_group = ctx.scope.acl_group();
    let master = ctx.scope.is_master();

    // **The `create` gate comes first**, as `validateWritePermission` does in 9.10.3
    // (`RestWrite.js:794-805`, run at `:134` ahead of `validateSchema` at `:137`). Before it,
    // upstream checked `addField` and the required columns first and so did this; a body failing
    // two checks named the wrong one (parse-community/parse-server#10739).
    // 0.1.0 left creation ungated: `let _ = scope; // ACL does not gate creation; CLP would`.
    if !master {
        validate_permission(
            clp,
            class_name,
            &acl_group,
            Operation::Create,
            Some(WriteAction::Create),
            ctx.options.error_detail,
        )?;
    }

    // Then `canAddField`, which `validateSchema` reaches per field.
    if !master
        && adds_field(
            &schema,
            class_exists,
            body.keys().map(String::as_str),
            |key| matches!(body.get(key), Some(FieldWrite::Op(Op::Delete))),
        )
    {
        validate_permission(
            clp,
            class_name,
            &acl_group,
            Operation::AddField,
            Some(WriteAction::Create),
            ctx.options.error_detail,
        )?;
    }

    // The required-column check runs against the client body, before `ACL` is lowered into
    // `_rperm`/`_wperm` and before relation ops are stripped. `_Role`'s ACL requirement is the
    // load-bearing one: a role saved with no ACL is world-writable, so any client can add itself
    // to it.
    validate_required_columns(class_name, &as_plain_body(&body), false)?;

    // **Before the objectId is looked at, because `enforceClassExists` runs before every one of
    // `validateObject`'s per-field checks** (`SchemaController.js:1288`), and the objectId type
    // check below is one of them. With this after it, `{"objectId": 123}` against a class nobody
    // has written answered `INCORRECT_TYPE` and left no `_SCHEMA` row, where parse-server answers
    // the same error and leaves one. Measured against a running parse-server; Gate D asserts it.
    //
    // After the CLP gates and the required columns. The `create` gate matches upstream's position
    // as of 9.10.3. `addField` and the required columns still run before the class is created here
    // and after it upstream, where `enforceClassExists` opens `validateSchema`.
    //
    // **Do not move those two after this.** The rule this encodes is that a request parse-rust
    // refuses leaves no durable state, and `_SCHEMA` is durable state on a database a
    // parse-server node also reads. For an otherwise-valid body the client-visible answer is the
    // same denial either way, so nothing in the response shows the difference and no test that
    // only reads responses catches a regression here. Recorded under the deliberate differences in
    // `CHANGELOG.md`.
    ensure_class_exists(ctx, class_name, class_exists).await?;

    // The class's CLP-declared default ACL (`RestWrite.js:438-455`).
    //
    // **0.2.0 accepted this setting, stored it, echoed it back from `GET /schemas` and never
    // applied it**, so a class an operator had configured as private created world-readable rows:
    // no `ACL` on the body means no `_rperm` or `_wperm` columns, and an absent `_rperm` is public.
    // The configuration said one thing and the data did the other, which is worse than not
    // supporting the feature.
    //
    // Three conditions, all upstream's and all easy to get subtly wrong:
    //
    // - **Create only.** Upstream guards on `!this.query`, so [`update`] has no counterpart to
    //   this block. Stamping on update would silently revert an ACL a client changed on purpose.
    // - **The body's `ACL` is tested for falsiness, not for presence** (`!this.data.ACL`), so a
    //   client that sent `{"ACL": null}` gets the default, and only a truthy value suppresses it.
    //   An `{"__op":"Delete"}` is an object and therefore truthy, so it suppresses it too.
    // - **The public ACL is skipped**, by a key-order-sensitive comparison living in
    //   [`parse_rust_core::ClassLevelPermissions::default_acl`].
    //
    // Placed after `ensure_class_exists` and after the required-column check, which is upstream's
    // order: `validateSchema` runs both and precedes `setRequiredFieldsIfNeeded`. It matters for
    // `_Role`, whose ACL is a required column: a role created with no ACL is refused rather than
    // rescued by the class default.
    //
    // **The stamped ACL is returned in the create response**, which is a second thing the setting
    // owes a client and not a cosmetic one: the caller has no other way to learn the permissions
    // its object was given, and on a private class it cannot read the row back to find out.
    // Upstream pushes `'ACL'` onto `fieldsChangedByTrigger` at `RestWrite.js:454` for exactly this
    // reason. Measured against a parse-server at the pin: a create in such a class answers
    // `{"objectId":…,"createdAt":…,"ACL":{"<callerId>":{"read":true,"write":true}}}`, and an
    // anonymous create in the same class answers `"ACL":{}`. Both are reproduced, the empty object
    // included.
    let mut generated_acl = None;
    if let Some(declared) = clp.and_then(|c| c.default_acl()) {
        let suppressed = match body.get("ACL") {
            Some(FieldWrite::Value(v)) => parse_rust_core::is_js_truthy(v),
            Some(FieldWrite::Op(_)) => true,
            None => false,
        };
        if !suppressed {
            let acl = default_acl_for_create(declared, ctx.scope.user_id());
            generated_acl = Some(acl.clone());
            body.insert("ACL".to_string(), FieldWrite::Value(acl));
        }
    }

    // Signup pre-generates an objectId so it can build the user's private ACL before the write.
    // Honour one if it is already present rather than overwriting it, which would leave the ACL
    // pointing at an id the row does not have.
    //
    // **Falsy, not absent, is the test upstream applies** (`RestWrite.js:489-491`, literally
    // `if (!this.data.objectId)`). An empty string and a `null` are therefore replaced with a
    // generated id rather than used, which is reachable at the default setting because
    // `enforce_object_id_policy` refuses only *truthy* client ids there.
    //
    // A **truthy non-string** is the case that must not be replaced. `allowCustomObjectId` tests
    // truthiness and nothing else, so `{"objectId": 123}` passes it, stays on the body, and is
    // refused one step later by schema validation against the String type of the default column.
    // Substituting a generated id here instead would create the row, report success, and hand the
    // client an id it did not ask for, for a body upstream rejects.
    let object_id = match body.get("objectId") {
        None => new_object_id()?,
        Some(FieldWrite::Value(v)) if !parse_rust_core::is_js_truthy(v) => new_object_id()?,
        Some(FieldWrite::Value(ParseValue::String(id))) => id.clone(),
        Some(other) => {
            let got = match other {
                FieldWrite::Value(v) => infer_type(v),
                FieldWrite::Op(op) => infer_op_type(op)?,
            };
            // `enforceFieldExists` against `objectId`'s declared `String`
            // (`SchemaController.js:1288-1318`). Answered here rather than left to
            // `validate_write_fields` below, because by then the key has been overwritten.
            return Err(match got {
                Some(got) => schema_mismatch(class_name, "objectId", &FieldType::String, &got),
                // No inferable type, which upstream skips entirely (`if (!expected) continue`).
                //
                // **Reachable, and this is the arm that answers `{"__op":"Delete"}`.** An earlier
                // comment called it unreachable for a truthy value, which is wrong: a `Delete` is
                // truthy and has no inferred type. Upstream skips the check and answers 201, having
                // stored the row under a Mongo-generated `_id` while echoing the operation object
                // back as the `objectId`; parse-rust answers 107 instead. Recorded as a deliberate
                // difference and scoped for 0.3.0, which decides whether to keep it.
                None => ParseError::invalid_json("objectId is an invalid field name."),
            });
        }
    };
    let now = ParseDate::now();
    body.insert(
        "objectId".to_string(),
        FieldWrite::Value(ParseValue::String(object_id.clone())),
    );
    body.insert(
        "createdAt".to_string(),
        FieldWrite::Value(ParseValue::Date(now)),
    );
    body.insert(
        "updatedAt".to_string(),
        FieldWrite::Value(ParseValue::Date(now)),
    );

    // The schema delta is computed **before** the relation ops are stripped, because an
    // `AddRelation` is what reserves `Relation<Target>` for the field. Upstream reaches
    // `enforceFieldExists` through `validateSchema` while the op is still on the body, and
    // `collectRelationUpdates` only removes it on the way into the database controller. Stripping
    // first would leave a user-defined relation field with no `_SCHEMA` entry, which is invisible
    // until a `$relatedTo` against it returns nothing.
    let delta = validate_write_fields(&schema, &body)?;
    reserve_schema(ctx, class_name, &schema, &delta.added).await?;
    apply(&mut schema, &delta);
    let defaulted = apply_field_options(&schema, &mut body, true)?;
    // Upstream appends defaults to the body after its own default fields, and the Mongo transform
    // then moves `createdAt` and `updatedAt` to the end of the stored document
    // (`MongoTransform.js:481-488`), so a defaulted field is stored, and read back, ahead of them.
    if !defaulted.is_empty() {
        for key in ["objectId", "createdAt", "updatedAt"] {
            if let Some(value) = body.shift_remove(key) {
                body.insert(key.to_string(), value);
            }
        }
    }

    if let Some(step) = before_insert {
        body = step(body).await?;
        // A default ACL the step extended is echoed as stored, as upstream echoes the field's
        // final value.
        if generated_acl.is_some() {
            if let Some(FieldWrite::Value(acl)) = body.get("ACL") {
                generated_acl = Some(acl.clone());
            }
        }
    }

    // **An `ACL` carrying an operation is lowered as upstream lowers it, before relation ops are
    // collected** (`DatabaseController.js:922` then `:931`): `transformObjectACL` walks the op
    // object, finds no key carrying `read` or `write`, and writes two empty arrays, a master-only
    // row. An empty object reproduces every op shape, because an op's keys are `__op`, `objects`
    // and `amount` and none of them carries a permission. The update path collects relation ops
    // first upstream (`:581` then `:656`), and so does this pipeline.
    //
    // `_User` never reaches this: `ensure_user_identity_and_acl` has already turned an op into the
    // owner-only ACL that upstream's `ACL[objectId] = ...` produces there, or refused it.
    neutralise_acl_op(&mut body)?;

    let relation_updates = relations::collect_relation_updates(&mut body);

    // `ACL` is lowered after validation, because `_rperm` and `_wperm` are not fields and would
    // otherwise be validated as though a client had named them.
    let row = lower_acl(flatten_for_create(&body)?)?;
    ctx.storage.create(&schema, &row).await?;

    relations::apply_relation_updates(ctx.storage, class_name, &object_id, &relation_updates)
        .await?;

    // The operation echo, plus the ACL if this server generated one. `echo_response` reports only
    // what the *client* asked to echo, which is the right rule for the five result-bearing
    // operations and the wrong one here: the client did not ask, and upstream returns it anyway.
    let mut echoed = echo_response(&body, Some(&row));
    if let Some(acl) = generated_acl {
        echoed.insert("ACL".to_string(), acl);
    }
    // A default the server applied is reported as the default ACL is: both are pushed onto
    // `fieldsChangedByTrigger` (`RestWrite.js:427-430`), which the response echoes.
    for (field, value) in defaulted {
        echoed.insert(field, value);
    }

    Ok(CreateResponse {
        object_id,
        created_at: now,
        echoed,
    })
}

/// A field's schema options, `required` and `defaultValue`, applied to a write
/// (`setRequiredFieldsIfNeeded`, `RestWrite.js:408-436`, `:493-503`).
///
/// A field counts as unset when it is absent, `null`, `""` or a `Delete`. On a create every field
/// the schema declares is checked: an absent or deleted one takes its `defaultValue` when the
/// schema has one, and otherwise an unset `required` one is 142 `<field> is required`. A `null` or
/// `""` is never replaced by a default, so on a required field it is the error. On an update only
/// the fields the body names are checked, and no default is applied.
///
/// Runs after the body's fields are validated against the schema, as upstream's step follows
/// `validateSchema`. Returns the defaults applied, which the create response reports.
fn apply_field_options(
    schema: &ClassSchema,
    body: &mut WriteBody,
    create: bool,
) -> Result<Vec<(String, ParseValue)>, ParseError> {
    let Some(options) = schema.field_options.as_ref() else {
        return Ok(Vec::new());
    };
    let fields: Vec<String> = if create {
        schema.fields.keys().cloned().collect()
    } else {
        body.keys().cloned().collect()
    };
    let mut defaulted = Vec::new();
    for field in fields {
        let Some(ParseValue::Object(option)) = options.get(&field) else {
            continue;
        };
        let (unset, replaceable) = match body.get(&field) {
            None => (true, true),
            Some(FieldWrite::Op(Op::Delete)) => (true, true),
            Some(FieldWrite::Value(ParseValue::Null)) => (true, false),
            Some(FieldWrite::Value(ParseValue::String(s))) if s.is_empty() => (true, false),
            Some(_) => (false, false),
        };
        if !unset {
            continue;
        }
        let default = option
            .get("defaultValue")
            .filter(|v| !matches!(v, ParseValue::Null));
        match default {
            Some(value) if create && replaceable => {
                // Stored in `_SCHEMA` as the JSON a client would send, so it is decoded the way a
                // client's value is: a Pointer or Date default becomes that type rather than a
                // plain object.
                let value = parse_rust_core::classify(value.to_serde_json())?;
                body.insert(field.clone(), FieldWrite::Value(value.clone()));
                defaulted.push((field, value));
            }
            _ if matches!(option.get("required"), Some(ParseValue::Bool(true))) => {
                return Err(ParseError::new(
                    ErrorCode::ValidationError,
                    format!("{field} is required"),
                ));
            }
            _ => {}
        }
    }
    Ok(defaulted)
}

/// The query an update runs, carrying every authorization constraint a non-master caller is under:
/// pointer permissions for `update`, and for `addField` when the write introduces a field, then the
/// write ACL. Shared by [`update`] and [`authorize_update`], so the probe and the write cannot
/// disagree about who may write.
fn update_query<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    schema: &ClassSchema,
    object_id: &str,
    introduces_field: bool,
) -> Result<Query, ParseError> {
    let clp = ctx.snapshot.clp(schema.class_name.as_str());
    let acl_group = ctx.scope.acl_group();
    let mut query = Query::from_constraints(vec![Constraint::equal(
        "objectId",
        ParseValue::String(object_id.to_string()),
    )]);
    if ctx.scope.is_master() {
        return Ok(query);
    }
    match apply_pointer_permissions(schema, clp, Operation::Update, &acl_group, &query)? {
        PointerPermOutcome::Unconstrained => {}
        PointerPermOutcome::Constrained(narrowed) => query = narrowed,
        // An update denied here resolves with no result upstream, which the caller's
        // `if (!result)` turns into `OBJECT_NOT_FOUND` (`DatabaseController.js:606-608`,
        // `:694-697`).
        PointerPermOutcome::DenyAll => return Err(object_not_found()),
    }
    if introduces_field {
        // The `addField` clause is conjoined on top of the `update` one
        // (`DatabaseController.js:591-604`).
        match apply_pointer_permissions(schema, clp, Operation::AddField, &acl_group, &query)? {
            PointerPermOutcome::Unconstrained => {}
            PointerPermOutcome::Constrained(narrowed) => query = narrowed,
            PointerPermOutcome::DenyAll => return Err(object_not_found()),
        }
    }
    if let Some(constraint) = ctx.scope.write_constraint() {
        query.push_constraint(constraint);
    }
    Ok(query)
}

/// Could this caller update this object at all? `OBJECT_NOT_FOUND` if not.
///
/// Upstream's `authorizeUserUpdate` (`RestWrite.js:806-838`) runs this as a `validateOnly` update
/// with an empty body: the `update` CLP, pointer permissions and the write ACL, then a find
/// (`DatabaseController.js:660-666`). It exists so that nothing which reads the target account,
/// a uniqueness query above all, answers before authorization has.
pub async fn authorize_update<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    object_id: &str,
) -> Result<(), ParseError> {
    let schema = ctx.snapshot.resolve_for_write(class_name);
    update_gate(ctx, class_name)?;
    let query = update_query(ctx, &schema, object_id, false)?;
    if ctx
        .storage
        .count(
            &schema,
            &query,
            &parse_rust_storage::CountOptions::default(),
        )
        .await?
        == 0
    {
        return Err(object_not_found());
    }
    Ok(())
}

/// The class-level `update` gate alone, `validateWritePermission` (`RestWrite.js:794-805`).
///
/// Separate from [`authorize_update`] for the caller who owns the row: upstream skips the ACL probe
/// for them but still runs this gate before `transformUser`, so it has to precede any uniqueness
/// check that reads other rows.
pub fn update_gate<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
) -> Result<(), ParseError> {
    if ctx.scope.is_master() {
        return Ok(());
    }
    validate_permission(
        ctx.snapshot.clp(class_name),
        class_name,
        &ctx.scope.acl_group(),
        Operation::Update,
        Some(WriteAction::Update),
        ctx.options.error_detail,
    )
}

/// Update one object by id.
pub async fn update<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    object_id: &str,
    body: WriteBody,
) -> Result<UpdateResponse, ParseError> {
    update_checked(ctx, class_name, object_id, body, None).await
}

/// [`update`], with a [`BeforeInsert`] step run after the schema and the required fields are
/// checked, as `transformUser` follows `setRequiredFieldsIfNeeded` on an update too.
pub async fn update_checked<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    object_id: &str,
    mut body: WriteBody,
    before_write: Option<BeforeInsert<'_>>,
) -> Result<UpdateResponse, ParseError> {
    let class_exists = ctx.snapshot.contains(class_name);
    let mut schema = ctx.snapshot.resolve_for_write(class_name);
    let clp = ctx.snapshot.clp(class_name);
    let acl_group = ctx.scope.acl_group();
    let master = ctx.scope.is_master();

    // A client cannot move an object or rewrite its creation time.
    body.shift_remove("objectId");
    body.shift_remove("createdAt");

    // The `update` gate first, as `validateWritePermission` does in 9.10.3 (`RestWrite.js:794-805`);
    // see the create path.
    if !master {
        validate_permission(
            clp,
            class_name,
            &acl_group,
            Operation::Update,
            Some(WriteAction::Update),
            ctx.options.error_detail,
        )?;
    }

    let introduces_field = adds_field(
        &schema,
        class_exists,
        body.keys().map(String::as_str),
        |key| matches!(body.get(key), Some(FieldWrite::Op(Op::Delete))),
    );
    if !master && introduces_field {
        validate_permission(
            clp,
            class_name,
            &acl_group,
            Operation::AddField,
            Some(WriteAction::Update),
            ctx.options.error_detail,
        )?;
    }

    validate_required_columns(class_name, &as_plain_body(&body), true)?;

    let query = update_query(ctx, &schema, object_id, introduces_field)?;

    let updated_at = ParseDate::now();
    body.insert(
        "updatedAt".to_string(),
        FieldWrite::Value(ParseValue::Date(updated_at)),
    );

    // Before the relation ops are stripped. See the note on the create path.
    //
    // **An update to a class nobody has written yet still creates the class row**, and then
    // matches nothing and answers `OBJECT_NOT_FOUND`. That reads like a bug and it is upstream's:
    // `validateSchema` is one step of the write chain (`RestWrite.js:133-137`) whichever path the
    // write is on, it calls `validateObject`, and that calls `enforceClassExists` before looking
    // at a single field (`SchemaController.js:1288`).
    //
    // Worth reproducing rather than "fixing", because the schema row is visible through
    // `GET /schemas` and through any parse-server node on the same database. 0.2.0 asserted the
    // opposite and got a body-dependent result instead: an empty update left nothing behind while
    // an update naming a new field created the class as a side effect of reserving that field.
    //
    // **And it happens before the fields are validated, not after.** A second review found the
    // first fix in the wrong order: `{"bad-key": 1}` is refused with `INVALID_KEY_NAME` by
    // `validate_write_fields`, and with the creation behind it the outcome was still
    // body-dependent, just along a different axis. `enforceClassExists` runs first upstream.
    ensure_class_exists(ctx, class_name, class_exists).await?;
    let delta = validate_write_fields(&schema, &body)?;
    reserve_schema(ctx, class_name, &schema, &delta.added).await?;
    apply(&mut schema, &delta);
    apply_field_options(&schema, &mut body, false)?;
    if let Some(step) = before_write {
        body = step(body).await?;
    }

    let relation_updates = relations::collect_relation_updates(&mut body);

    // A `Batch` on `ACL` is upstream's bare 500, and `lower_update` would otherwise refuse it first
    // with the 108 it gives a `Batch` on any other field.
    if matches!(body.get("ACL"), Some(FieldWrite::Op(Op::Batch(_)))) {
        return Err(batch_acl_error());
    }
    let mut update = lower_update(&body)?;
    lower_acl_into_update(&mut body, &mut update)?;

    // Only an update carrying a result-bearing operation needs the post-image read back.
    let echoed = if echoed_keys(&body).is_empty() {
        let matched = ctx.storage.update(&schema, &query, &update).await?;
        if matched == 0 {
            return Err(object_not_found());
        }
        ParseMap::new()
    } else {
        let row = ctx
            .storage
            .update_one_returning(&schema, &query, &update)
            .await?;
        let Some(row) = row else {
            return Err(object_not_found());
        };
        echo_response(&body, Some(&row))
    };

    relations::apply_relation_updates(ctx.storage, class_name, object_id, &relation_updates)
        .await?;

    Ok(UpdateResponse { updated_at, echoed })
}

/// Move an `ACL` field out of the update and into the two storage columns.
///
/// UPSTREAM-QUIRK: `transformObjectACL` iterates whatever the `ACL` value happens to be
/// (`DatabaseController.js:93-110`), so an `{"__op":"Delete"}` on `ACL` produces two empty arrays
/// rather than unsetting the columns, which leaves the row readable and writable by master only.
fn lower_acl_into_update(
    body: &mut WriteBody,
    update: &mut parse_rust_storage::Update,
) -> Result<(), ParseError> {
    let Some(write) = body.shift_remove("ACL") else {
        return Ok(());
    };
    update.shift_remove("ACL");
    let value = match write {
        // `if (!ACL) return result` (`DatabaseController.js:94-96`): **every falsy ACL** is dropped
        // from the update rather than clearing the columns, so the row keeps the permissions it
        // had. Matching only `Null` here, which is what this did, let `false`, `0` and `""` fall
        // through to the unconditional write below and set both columns to empty arrays, which is
        // a master-only row the caller cannot undo.
        //
        // On `_User` that is worse than losing access to one row: `acl_is_explicitly_empty` reads
        // an empty ACL as a disabled account and refuses every later login, and
        // `force_owner_into_acl` does not defend against it because that only reinstates the owner
        // into an ACL that is an *object*. `{"ACL": {}}` is neutralised; `{"ACL": false}` was not.
        FieldWrite::Value(v) if !parse_rust_core::is_js_truthy(&v) => return Ok(()),
        FieldWrite::Value(value) => value,
        FieldWrite::Op(Op::Batch(_)) => return Err(batch_acl_error()),
        // An op envelope is a truthy object upstream, so it falls through to the loop that reads
        // `read`/`write` off each entry and finds none. See the quirk note above.
        FieldWrite::Op(_) => ParseValue::Object(ParseMap::new()),
    };
    let mut carrier = ParseMap::new();
    carrier.insert("ACL".to_string(), value);
    let lowered = lower_acl(carrier)?;
    for key in ["_rperm", "_wperm"] {
        let value = lowered
            .get(key)
            .cloned()
            .unwrap_or(ParseValue::Array(Vec::new()));
        update.insert(key.to_string(), UpdateValue::Set(value));
    }
    Ok(())
}

/// Replace an operation on `ACL` with the empty object upstream's lowering effectively sees.
///
/// A `Batch` is the exception: upstream answers a bare 500 for `{"__op":"Batch","ops":[]}` as an
/// `ACL` on every path and writes nothing, measured at the pin on a create, a `_User` signup and an
/// update alike. parse-rust's decoder accepts the op, so without this it answered 201.
fn neutralise_acl_op(body: &mut WriteBody) -> Result<(), ParseError> {
    match body.get("ACL") {
        Some(FieldWrite::Op(Op::Batch(_))) => Err(batch_acl_error()),
        Some(FieldWrite::Op(_)) => {
            body.insert(
                "ACL".to_string(),
                FieldWrite::Value(ParseValue::Object(ParseMap::new())),
            );
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn batch_acl_error() -> ParseError {
    ParseError::internal("a Batch operation on ACL; upstream throws before writing")
}

/// Delete one object by id.
pub async fn delete<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    object_id: &str,
) -> Result<(), ParseError> {
    let schema = ctx.snapshot.get_or_default(class_name);
    let clp = ctx.snapshot.clp(class_name);
    let acl_group = ctx.scope.acl_group();
    let master = ctx.scope.is_master();

    refuse_unnamed_class(ctx, class_name, "delete")?;

    if !master {
        validate_permission(
            clp,
            class_name,
            &acl_group,
            Operation::Delete,
            None,
            ctx.options.error_detail,
        )?;
    }

    let mut query = Query::from_constraints(vec![Constraint::equal(
        "objectId",
        ParseValue::String(object_id.to_string()),
    )]);
    if !master {
        match apply_pointer_permissions(&schema, clp, Operation::Delete, &acl_group, &query)? {
            PointerPermOutcome::Unconstrained => {}
            PointerPermOutcome::Constrained(narrowed) => query = narrowed,
            // A destroy denied here is `OBJECT_NOT_FOUND` (`DatabaseController.js:862-864`).
            PointerPermOutcome::DenyAll => return Err(object_not_found()),
        }
        if let Some(constraint) = ctx.scope.write_constraint() {
            query.push_constraint(constraint);
        }
    }

    let deleted = ctx.storage.delete(&schema, &query).await?;
    if deleted == 0 {
        return Err(object_not_found());
    }
    Ok(())
}

/// Reserve the class and every new field **before** the row is written.
///
/// `create_class` is the create path's `enforceClassExists`.
///
/// This is the fix for the concurrent first-write race 0.1.0 shipped with. `reserve_field` is a
/// conditional upsert, so the loser of a race fails the condition rather than overwriting the
/// winner's type, and the outcome is an enum rather than an error code to sniff.
///
/// The class itself is reserved even when the write adds no field at all, which is the third
/// failure mode: a body of nothing but nulls infers no type, so without this it would insert a
/// row into a class with no `_SCHEMA` entry.
/// `enforceClassExists` (`SchemaController.js:979-1005`).
///
/// **Its position is the whole reason it is a separate function.** `validateObject` calls it
/// before it inspects a single field (`:1288`), so a write refused for a bad field name still
/// leaves the class behind. Folding it into `reserve_schema`, which is what this did until a
/// review, put it after `validate_write_fields` and made the schema side effect depend on whether
/// the body happened to be valid.
///
/// Only the default columns are written. The per-field reservations stay the atomic ones.
///
/// **An invalid class name is refused here, and it is refused as `INVALID_JSON` (107).** That
/// looks like the wrong code and it is upstream's, through a chain worth reading once:
/// `addClassIfNotExists` rejects with `INVALID_CLASS_NAME` and the detailed `Invalid classname:`
/// message, the `.catch` swallows it and reloads, the reload does not conjure the class, and the
/// terminal `.catch` replaces whatever happened with the fixed string
/// `schema class name does not revalidate` (`SchemaController.js:987-1004`). So the 103 a client
/// gets from `POST /schemas` and the 107 it gets from `POST /classes/1Bad` are the same underlying
/// refusal reported by two routes, and only the schema route sees the useful message.
///
/// Checking here rather than leaving it to `validate_write_fields` is what keeps the row from
/// being written: without it parse-rust answered 103 **and** left a `1BadClass` entry in `_SCHEMA`,
/// on a database parse-server also reads.
async fn ensure_class_exists<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    class_exists: bool,
) -> Result<(), ParseError> {
    if class_exists {
        return Ok(());
    }
    validate_client_class_creation(ctx, class_name, true)?;
    if !parse_rust_schema::class_name_is_valid(class_name) {
        return Err(ParseError::invalid_json(
            "schema class name does not revalidate",
        ));
    }
    ctx.storage.upsert_schema(&default_schema(class_name)).await
}

/// `validateClientClassCreation` (`RestWrite.js:202-225`).
///
/// Refuses a write that would bring a class into existence, unless the caller is privileged, the
/// option is on, or the class is one Parse defines itself. Upstream's option defaults to `false`
/// (`Options/Definitions.js:67-72`), so this is the ordinary configuration rather than a hardened
/// one, and a server without the check is more permissive than a stock parse-server.
///
/// **Ordering note.** Upstream reaches this before `validateSchema`, and so does this: it sits at
/// the top of `ensure_class_exists`, which is itself the first thing that would write a `_SCHEMA`
/// row. Both the create and the update path go through here, which is what upstream gets by
/// calling it from `RestWrite`'s shared chain rather than per route.
///
/// The exemption is by class name and not by caller, so a client can still sign up: `_User` and the
/// other system classes are always allowed to come into existence
/// (`SchemaController.js:165-176`).
fn validate_client_class_creation<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    maintenance_is_exempt: bool,
) -> Result<(), ParseError> {
    // **The two call sites do not agree about maintenance, and that is upstream's shape.** The
    // write path tests `!isMaster && !isMaintenance` (`RestWrite.js:206-208`); the read path tests
    // `!isMaster` alone (`RestQuery.js:486-489`), so a maintenance-key *read* of a class that does
    // not exist is refused there. Sharing one predicate silently gave maintenance the write path's
    // exemption on reads too.
    let privileged = if maintenance_is_exempt {
        ctx.scope.is_master()
    } else {
        ctx.scope.is_master() && !ctx.is_maintenance
    };
    if ctx.options.allow_client_class_creation
        || privileged
        || parse_rust_schema::SYSTEM_CLASSES.contains(&class_name)
    {
        return Ok(());
    }
    // `createSanitizedError` (`RestWrite.js:215-219`), so the detailed string is withheld at
    // upstream's default and the class name reaches the log instead.
    Err(ParseError::permission_denied(
        ErrorCode::OperationForbidden,
        format!("This user is not allowed to access non-existent class: {class_name}"),
        ctx.options.error_detail,
    ))
}

async fn reserve_schema<S: StorageAdapter>(
    ctx: &Ctx<'_, S>,
    class_name: &str,
    schema: &ClassSchema,
    added: &[(String, FieldType)],
) -> Result<(), ParseError> {
    for (field_name, field_type) in added {
        match ctx
            .storage
            // No options: an ordinary write infers a type and never carries `required` or
            // `defaultValue`, which only the schema API can set.
            .reserve_field(class_name, field_name, field_type, None)
            .await?
        {
            AddFieldOutcome::Added | AddFieldOutcome::AlreadyPresentSameType => {}
            AddFieldOutcome::Conflict { existing } => {
                // The same `INCORRECT_TYPE` a plain type mismatch produces, because from the
                // client's side that is what happened: the field has a type and this write
                // disagrees with it.
                return Err(schema_mismatch(
                    &schema.class_name,
                    field_name,
                    &existing,
                    field_type,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query_parse::parse_where;
    use crate::testing::FakeStorage;
    use crate::write::decode_write_body;
    use parse_rust_core::op::OpPath;
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

    fn where_(json: &str) -> ParsedWhere {
        parse_where(&serde_json::from_str(json).expect("test literal")).expect("parse")
    }

    fn body(json: &str, path: OpPath) -> WriteBody {
        decode_write_body(&serde_json::from_str(json).expect("test literal"), path).expect("decode")
    }

    fn row(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
        let mut m = ParseMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        m
    }

    fn strings(values: &[&str]) -> ParseValue {
        ParseValue::Array(
            values
                .iter()
                .map(|v| ParseValue::String((*v).to_string()))
                .collect(),
        )
    }

    fn pointer(class: &str, id: &str) -> ParseValue {
        ParseValue::Pointer {
            class_name: class.to_string(),
            object_id: id.to_string(),
        }
    }

    async fn snapshot(storage: &FakeStorage) -> SchemaSnapshot {
        SchemaSnapshot::load(storage).await.expect("snapshot")
    }

    /// The default regime: `enableSanitizedErrorResponse` is `true` upstream, so every denial
    /// that goes through `createSanitizedError` says `Permission denied` and nothing else.
    fn opts() -> PermissionOptions {
        PermissionOptions::default()
    }

    /// `enableSanitizedErrorResponse: false`. The detailed strings are contract under it, so the
    /// denial tests assert both regimes rather than picking one.
    fn disclosing_opts() -> PermissionOptions {
        PermissionOptions {
            error_detail: parse_rust_core::ErrorDetail::Disclosed,
            ..PermissionOptions::default()
        }
    }

    // -----------------------------------------------------------------------------------------
    // The CLP gate
    // -----------------------------------------------------------------------------------------

    /// 0.1.0 left creation ungated. This is the regression test for that line.
    #[tokio::test]
    async fn create_runs_the_clp_gate() {
        let storage = FakeStorage::new().with_schema(
            default_schema("Post").with_clp(clp(r#"{"create":{"role:Writers":true}}"#)),
        );
        let snap = snapshot(&storage).await;
        let options = opts();

        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);
        let e = create(&ctx, "Post", body(r#"{"title":"x"}"#, OpPath::Create))
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);
        assert_eq!(e.message, "Permission denied");
        assert!(storage.rows("Post").is_empty(), "nothing was written");

        let disclosing = disclosing_opts();
        let ctx = Ctx::new(&storage, &snap, &anon, &disclosing);
        assert_eq!(
            create(&ctx, "Post", body(r#"{"title":"x"}"#, OpPath::Create))
                .await
                .unwrap_err()
                .message,
            "Permission denied for action create on class Post."
        );
        assert!(storage.rows("Post").is_empty(), "nothing was written");

        let writer = AclScope::user("u1", vec!["Writers".into()]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &writer, &options);
        assert!(
            create(&ctx, "Post", body(r#"{"title":"x"}"#, OpPath::Create))
                .await
                .is_ok()
        );
    }

    /// **The operation gate runs before `addField`**, as `validateWritePermission` does from 9.10.3
    /// (parse-community/parse-server#10739). With both denied, the message names the operation.
    /// Before it, both servers named `addField`.
    #[tokio::test]
    async fn the_operation_gate_precedes_add_field() {
        let mut existing = ParseMap::new();
        existing.insert("objectId".into(), ParseValue::String("p1".into()));
        let storage = FakeStorage::new()
            .with_schema(default_schema("Post").with_clp(clp(
                r#"{"create":{"role:Writers":true},"update":{"role:Writers":true},"addField":{"role:Writers":true}}"#,
            )))
            .with_row("Post", existing);
        let snap = snapshot(&storage).await;
        let options = disclosing_opts();
        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);

        let e = create(&ctx, "Post", body(r#"{"brandNew":1}"#, OpPath::Create))
            .await
            .unwrap_err();
        assert_eq!(
            e.message,
            "Permission denied for action create on class Post."
        );

        let e = update(
            &ctx,
            "Post",
            "p1",
            body(r#"{"brandNew":1}"#, OpPath::Update),
        )
        .await
        .unwrap_err();
        assert_eq!(
            e.message,
            "Permission denied for action update on class Post."
        );
    }

    /// The default-open rule, end to end. A class with no CLP block permits everything.
    #[tokio::test]
    async fn a_class_with_no_clp_is_unrestricted() {
        let storage = FakeStorage::new().with_schema(default_schema("Post"));
        let snap = snapshot(&storage).await;
        let options = opts();
        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);
        assert!(
            create(&ctx, "Post", body(r#"{"title":"x"}"#, OpPath::Create))
                .await
                .is_ok()
        );
        assert!(
            find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
                .await
                .is_ok()
        );
    }

    /// The code is 101, not 119, and the class must not confirm its own existence.
    #[tokio::test]
    async fn requires_authentication_denies_a_read_with_object_not_found() {
        let storage = FakeStorage::new()
            .with_schema(
                default_schema("Post").with_clp(clp(r#"{"find":{"requiresAuthentication":true}}"#)),
            )
            .with_row(
                "Post",
                row(vec![("objectId", ParseValue::String("p1".into()))]),
            );
        let snap = snapshot(&storage).await;
        let options = opts();

        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);
        let e = find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::ObjectNotFound);
        assert_eq!(e.message, "Permission denied");

        let disclosing = disclosing_opts();
        let disclosed = Ctx::new(&storage, &snap, &anon, &disclosing);
        let e = find(
            &disclosed,
            "Post",
            ParsedWhere::default(),
            FindOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::ObjectNotFound);
        assert_eq!(
            e.message,
            "Permission denied, user needs to be authenticated."
        );

        let user = AclScope::user("u1", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &user, &options);
        assert_eq!(
            find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
                .await
                .expect("allowed")
                .len(),
            1
        );
    }

    // -----------------------------------------------------------------------------------------
    // Pointer permissions
    // -----------------------------------------------------------------------------------------

    fn pointer_perm_storage() -> FakeStorage {
        let clp_json = r#"{
            "find":{"pointerFields":["owner"]},
            "get":{"pointerFields":["owner"]},
            "count":{"pointerFields":["owner"]},
            "update":{"pointerFields":["owner"]},
            "delete":{"pointerFields":["owner"]},
            "create":{"*":true}
        }"#;
        FakeStorage::new()
            .with_schema(
                default_schema("Post")
                    .with_field(
                        "owner",
                        FieldType::Pointer {
                            target_class: "_User".into(),
                        },
                    )
                    .with_field("title", FieldType::String)
                    .with_clp(clp(clp_json)),
            )
            .with_row(
                "Post",
                row(vec![
                    ("objectId", ParseValue::String("p1".into())),
                    ("owner", pointer("_User", "u1")),
                    ("title", ParseValue::String("mine".into())),
                ]),
            )
            .with_row(
                "Post",
                row(vec![
                    ("objectId", ParseValue::String("p2".into())),
                    ("owner", pointer("_User", "u2")),
                    ("title", ParseValue::String("theirs".into())),
                ]),
            )
    }

    /// The mitigation test the milestone names: **every** operation, anonymous caller, a class
    /// whose only permission is a pointer permission. Each must be empty or `OBJECT_NOT_FOUND`,
    /// never a full result set.
    #[tokio::test]
    async fn an_anonymous_caller_gets_nothing_from_a_pointer_permission_class() {
        let storage = pointer_perm_storage();
        let snap = snapshot(&storage).await;
        let options = opts();
        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);

        assert!(
            find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
                .await
                .expect("find resolves empty rather than erroring")
                .is_empty()
        );
        assert_eq!(
            get(&ctx, "Post", "p1", FindOptions::default())
                .await
                .unwrap_err()
                .code,
            ErrorCode::ObjectNotFound
        );
        assert_eq!(
            count(
                &ctx,
                "Post",
                ParsedWhere::default(),
                &[],
                &Default::default()
            )
            .await
            .expect("count resolves"),
            0
        );
        assert_eq!(
            update(&ctx, "Post", "p1", body(r#"{"title":"x"}"#, OpPath::Update))
                .await
                .unwrap_err()
                .code,
            ErrorCode::ObjectNotFound
        );
        assert_eq!(
            delete(&ctx, "Post", "p1").await.unwrap_err().code,
            ErrorCode::ObjectNotFound
        );
        assert_eq!(storage.rows("Post").len(), 2, "nothing was deleted");
    }

    #[tokio::test]
    async fn a_pointer_permission_narrows_a_user_to_their_own_rows() {
        let storage = pointer_perm_storage();
        let snap = snapshot(&storage).await;
        let options = opts();
        let u1 = AclScope::user("u1", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &u1, &options);

        let results = find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
            .await
            .expect("find");
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].get("objectId"), Some(ParseValue::String(id)) if id == "p1"));

        assert!(get(&ctx, "Post", "p1", FindOptions::default())
            .await
            .is_ok());
        assert_eq!(
            get(&ctx, "Post", "p2", FindOptions::default())
                .await
                .unwrap_err()
                .code,
            ErrorCode::ObjectNotFound
        );
        assert_eq!(
            count(
                &ctx,
                "Post",
                ParsedWhere::default(),
                &[],
                &Default::default()
            )
            .await
            .expect("count"),
            1
        );
        assert!(
            update(&ctx, "Post", "p1", body(r#"{"title":"x"}"#, OpPath::Update))
                .await
                .is_ok()
        );
        assert_eq!(
            update(&ctx, "Post", "p2", body(r#"{"title":"x"}"#, OpPath::Update))
                .await
                .unwrap_err()
                .code,
            ErrorCode::ObjectNotFound
        );
    }

    // -----------------------------------------------------------------------------------------
    // Protected fields
    // -----------------------------------------------------------------------------------------

    fn protected_storage() -> FakeStorage {
        FakeStorage::new()
            .with_schema(
                default_schema("Post")
                    .with_field("secret", FieldType::String)
                    .with_field("title", FieldType::String)
                    .with_clp(clp(r#"{"protectedFields":{"*":["secret"]}}"#)),
            )
            .with_row(
                "Post",
                row(vec![
                    ("objectId", ParseValue::String("p1".into())),
                    ("title", ParseValue::String("t".into())),
                    ("secret", ParseValue::String("s".into())),
                ]),
            )
    }

    #[tokio::test]
    async fn a_protected_field_is_absent_from_a_read_and_present_for_master() {
        let storage = protected_storage();
        let snap = snapshot(&storage).await;
        let options = opts();

        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);
        let results = find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
            .await
            .expect("find");
        assert!(results[0].get("secret").is_none());
        assert!(results[0].get("title").is_some());

        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);
        let results = find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
            .await
            .expect("find");
        assert!(results[0].get("secret").is_some());
    }

    #[tokio::test]
    async fn querying_or_ordering_by_a_protected_field_is_forbidden() {
        let storage = protected_storage();
        let snap = snapshot(&storage).await;
        let options = opts();
        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);

        let e = find(
            &ctx,
            "Post",
            where_(r#"{"secret":"s"}"#),
            FindOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);
        assert_eq!(e.message, "Permission denied");

        let disclosing = disclosing_opts();
        let disclosed = Ctx::new(&storage, &snap, &anon, &disclosing);
        assert_eq!(
            find(
                &disclosed,
                "Post",
                where_(r#"{"secret":"s"}"#),
                FindOptions::default()
            )
            .await
            .unwrap_err()
            .message,
            "This user is not allowed to query secret on class Post"
        );

        // Nested inside a logical clause, and by its dotted root.
        assert_eq!(
            find(
                &ctx,
                "Post",
                where_(r#"{"$or":[{"secret.a":"s"}]}"#),
                FindOptions::default()
            )
            .await
            .unwrap_err()
            .code,
            ErrorCode::OperationForbidden
        );

        let sorted = FindOptions {
            order: vec![("secret".to_string(), SortDirection::Ascending)],
            ..Default::default()
        };
        let e = find(&ctx, "Post", ParsedWhere::default(), sorted.clone())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);
        assert_eq!(e.message, "Permission denied");
        assert_eq!(
            find(&disclosed, "Post", ParsedWhere::default(), sorted)
                .await
                .unwrap_err()
                .message,
            "This user is not allowed to sort by secret on class Post"
        );

        // Master is exempt from the denial, not merely from the strip.
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);
        assert!(find(
            &ctx,
            "Post",
            where_(r#"{"secret":"s"}"#),
            FindOptions::default()
        )
        .await
        .is_ok());
    }

    /// `limit=0` skips the database, not the checks upstream runs before `runFind`.
    #[tokio::test]
    async fn a_zero_limit_still_runs_the_checks_before_the_find() {
        let storage = protected_storage();
        let snap = snapshot(&storage).await;
        let options = opts();
        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);
        let zero = FindOptions {
            limit: Some(0),
            ..Default::default()
        };

        let e = find(&ctx, "_Session", ParsedWhere::default(), zero.clone())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidSessionToken);

        let e = find(&ctx, "Post", where_(r#"{"secret":"s"}"#), zero.clone())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);

        let sorted = FindOptions {
            order: vec![("secret".to_string(), SortDirection::Ascending)],
            ..zero.clone()
        };
        let e = find(&ctx, "Post", ParsedWhere::default(), sorted)
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);

        // Nothing to refuse: still empty, and still no database call.
        assert!(find(&ctx, "Post", ParsedWhere::default(), zero)
            .await
            .expect("empty")
            .is_empty());
    }

    /// An explain takes the `limit=0` branch too: before the CLP gate, the include pass and the
    /// adapter's validation of the explain value. Each of those refuses the same request with any
    /// other limit.
    /// A where that will fail is refused at its position, never read as an empty where that
    /// matches every row. The CLP refusal comes first, and `limit=0` never reaches it.
    #[tokio::test]
    async fn a_deferred_where_failure_refuses_rather_than_matching_everything() {
        let mut row = ParseMap::new();
        row.insert("objectId".into(), ParseValue::String("p1".into()));
        let storage = FakeStorage::new()
            .with_schema(default_schema("Post"))
            .with_row("Post", row);
        let snap = snapshot(&storage).await;
        let options = opts();
        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);
        let bad = || crate::query_parse::parse_client_where(&serde_json::json!({"n": {"$in": 5}}));
        let e = find(&ctx, "Post", bad(), FindOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidJson);
        assert_eq!(e.message, "bad $in value");
        let zero = FindOptions {
            limit: Some(0),
            ..Default::default()
        };
        assert!(find(&ctx, "Post", bad(), zero)
            .await
            .expect("empty")
            .is_empty());
        let scalar = crate::query_parse::parse_client_where(&serde_json::json!(5));
        let e = find(&ctx, "Post", scalar, FindOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InternalServerError);

        let closed = FakeStorage::new()
            .with_schema(default_schema("Post").with_clp(clp(r#"{"find":{},"get":{}}"#)));
        let snap = snapshot(&closed).await;
        let ctx = Ctx::new(&closed, &snap, &anon, &options);
        let e = find(&ctx, "Post", bad(), FindOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);
    }

    #[test]
    fn an_index_on_an_internal_column_is_internal() {
        let fields = |f: &[&str]| f.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            internal_index_field(&fields(&["n", "_perishable_token"])),
            Some("_perishable_token")
        );
        assert_eq!(
            internal_index_field(&fields(&["authData"])),
            Some("authData")
        );
        assert_eq!(
            internal_index_field(&fields(&["objectId", "createdAt"])),
            None
        );
        assert_eq!(internal_index_field(&fields(&["_rperm", "_wperm"])), None);
    }

    #[tokio::test]
    async fn a_zero_limit_explain_answers_before_the_gate_include_and_verbosity() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("Post").with_clp(clp(r#"{"find":{},"get":{}}"#)));
        let snap = snapshot(&storage).await;
        let options = opts();
        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);
        let verbosity = || Ok(parse_rust_storage::ExplainVerbosity::AllPlansExecution);
        let invalid = || Err(ParseError::invalid_query("Invalid value for explain"));
        let zero = FindOptions {
            limit: Some(0),
            include: vec![vec!["x".to_string()]],
            ..Default::default()
        };
        for v in [verbosity(), invalid()] {
            let out = explain(&ctx, "Post", ParsedWhere::default(), zero.clone(), v)
                .await
                .expect("empty");
            assert_eq!(out, serde_json::json!([]));
        }

        let one = FindOptions {
            limit: Some(1),
            ..zero
        };
        for v in [verbosity(), invalid()] {
            let e = explain(&ctx, "Post", ParsedWhere::default(), one.clone(), v)
                .await
                .unwrap_err();
            assert_eq!(
                e.code,
                ErrorCode::OperationForbidden,
                "the gate comes first"
            );
        }
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);
        let e = explain(&ctx, "Post", ParsedWhere::default(), one.clone(), invalid())
            .await
            .unwrap_err();
        assert_eq!(e.message, "Invalid value for explain", "then the value");
        let e = explain(&ctx, "Post", ParsedWhere::default(), one, verbosity())
            .await
            .unwrap_err();
        assert_eq!(
            e.code,
            ErrorCode::InternalServerError,
            "then the include pass"
        );
    }

    // -----------------------------------------------------------------------------------------
    // ACL
    // -----------------------------------------------------------------------------------------

    #[tokio::test]
    async fn an_acl_hides_a_row_from_everyone_but_its_principals() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("Post"))
            .with_row(
                "Post",
                row(vec![
                    ("objectId", ParseValue::String("private".into())),
                    ("_rperm", strings(&["u1", "role:Admins"])),
                    ("_wperm", strings(&["u1"])),
                ]),
            )
            .with_row(
                "Post",
                row(vec![("objectId", ParseValue::String("public".into()))]),
            );
        let snap = snapshot(&storage).await;
        let options = opts();

        let owner = AclScope::user("u1", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &owner, &options);
        assert_eq!(
            find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
                .await
                .expect("find")
                .len(),
            2,
            "assert first that the owner can see its own row"
        );

        let admin = AclScope::user("u2", vec!["Admins".into()]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &admin, &options);
        assert_eq!(
            find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
                .await
                .expect("find")
                .len(),
            2,
            "a role: entry in _rperm must match a member"
        );

        let stranger = AclScope::user("u3", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &stranger, &options);
        let results = find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
            .await
            .expect("find");
        assert_eq!(results.len(), 1);
        assert!(
            matches!(results[0].get("objectId"), Some(ParseValue::String(id)) if id == "public")
        );
        assert_eq!(
            update(
                &ctx,
                "Post",
                "private",
                body(r#"{"title":"x"}"#, OpPath::Update)
            )
            .await
            .unwrap_err()
            .code,
            ErrorCode::ObjectNotFound
        );
        assert_eq!(
            delete(&ctx, "Post", "private").await.unwrap_err().code,
            ErrorCode::ObjectNotFound
        );
    }

    // -----------------------------------------------------------------------------------------
    // The CLP-declared default ACL
    //
    // Every assertion below is a read or a write rather than an inspection of `_rperm`, because
    // the failure being guarded is that no permission columns are written at all, and a test that
    // looks at a column and finds it missing has to decide what missing means. A request does not.
    // -----------------------------------------------------------------------------------------

    /// A class declared private, an object created by user A, and the two halves that a naive
    /// test would only get half of: user B is shut out, **and user A is not**. An implementation
    /// that wrote an empty ACL, or that stored the literal string `currentUser` as a principal,
    /// would deny B and pass the first half while locking out the owner.
    #[tokio::test]
    async fn a_declared_default_acl_isolates_the_creator_without_locking_them_out() {
        let storage = FakeStorage::new().with_schema(
            default_schema("Post")
                .with_clp(clp(r#"{"ACL":{"currentUser":{"read":true,"write":true}}}"#)),
        );
        let snap = snapshot(&storage).await;
        let options = opts();

        let a = AclScope::user("userA", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &a, &options);
        let created = create(&ctx, "Post", body(r#"{"title":"x"}"#, OpPath::Create))
            .await
            .expect("create");

        assert_eq!(
            find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
                .await
                .expect("find")
                .len(),
            1,
            "the creator must still be able to read its own object"
        );
        assert!(
            update(
                &ctx,
                "Post",
                &created.object_id,
                body(r#"{"title":"y"}"#, OpPath::Update)
            )
            .await
            .is_ok(),
            "and to write it: _wperm is a separate column and can be wrong on its own"
        );

        let b = AclScope::user("userB", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &b, &options);
        assert!(
            find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
                .await
                .expect("find")
                .is_empty(),
            "0.2.0 returned this object to every caller"
        );
        assert_eq!(
            update(
                &ctx,
                "Post",
                &created.object_id,
                body(r#"{"title":"z"}"#, OpPath::Update)
            )
            .await
            .unwrap_err()
            .code,
            ErrorCode::ObjectNotFound
        );
    }

    /// The control. Without it the test above passes against a pipeline that lost the ability to
    /// read anything at all.
    #[tokio::test]
    async fn a_class_with_no_declared_acl_still_creates_public_rows() {
        let storage = FakeStorage::new().with_schema(default_schema("Post"));
        let snap = snapshot(&storage).await;
        let options = opts();

        let a = AclScope::user("userA", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &a, &options);
        create(&ctx, "Post", body(r#"{"title":"x"}"#, OpPath::Create))
            .await
            .expect("create");

        let b = AclScope::user("userB", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &b, &options);
        assert_eq!(
            find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
                .await
                .expect("find")
                .len(),
            1
        );
    }

    /// **The `!this.query` guard.** Without it a server stamps the default on every write and
    /// passes everything above while silently reverting a permission change a client made on
    /// purpose. Nothing in the response shows it: the update succeeds either way.
    #[tokio::test]
    async fn the_default_applies_on_create_and_never_on_update() {
        let storage = FakeStorage::new().with_schema(
            default_schema("Post")
                .with_clp(clp(r#"{"ACL":{"currentUser":{"read":true,"write":true}}}"#)),
        );
        let snap = snapshot(&storage).await;
        let options = opts();

        // A supplies its own ACL, which suppresses the default: B may read, A may write.
        let a = AclScope::user("userA", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &a, &options);
        let created = create(
            &ctx,
            "Post",
            body(
                r#"{"title":"x","ACL":{"userA":{"read":true,"write":true},"userB":{"read":true}}}"#,
                OpPath::Create,
            ),
        )
        .await
        .expect("create");

        let b = AclScope::user("userB", vec![]).expect("scope");
        let b_ctx = Ctx::new(&storage, &snap, &b, &options);
        assert_eq!(
            find(
                &b_ctx,
                "Post",
                ParsedWhere::default(),
                FindOptions::default()
            )
            .await
            .expect("find")
            .len(),
            1,
            "the client's own ACL must win over the class default on create"
        );

        // An update to an unrelated field must not restamp the class default over it.
        update(
            &ctx,
            "Post",
            &created.object_id,
            body(r#"{"title":"y"}"#, OpPath::Update),
        )
        .await
        .expect("update");
        assert_eq!(
            find(
                &b_ctx,
                "Post",
                ParsedWhere::default(),
                FindOptions::default()
            )
            .await
            .expect("find")
            .len(),
            1,
            "the explicitly set ACL must survive an unrelated update"
        );
    }

    /// A falsy `ACL` on the body does not suppress the default, because upstream's test is
    /// `!this.data.ACL` rather than a presence check. `{"ACL": null}` from a client therefore
    /// lands on the class default rather than on a public row.
    #[tokio::test]
    async fn a_falsy_acl_on_the_body_does_not_suppress_the_default() {
        let storage = FakeStorage::new().with_schema(
            default_schema("Post").with_clp(clp(r#"{"ACL":{"currentUser":{"read":true}}}"#)),
        );
        let snap = snapshot(&storage).await;
        let options = opts();

        let a = AclScope::user("userA", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &a, &options);
        create(
            &ctx,
            "Post",
            body(r#"{"title":"x","ACL":null}"#, OpPath::Create),
        )
        .await
        .expect("create");

        let b = AclScope::user("userB", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &b, &options);
        assert!(
            find(&ctx, "Post", ParsedWhere::default(), FindOptions::default())
                .await
                .expect("find")
                .is_empty()
        );
    }

    /// **An `ACL` carrying an operation must not vanish.** `flatten_for_create` removes a `Delete`
    /// op from the body, so the key disappeared before `lower_acl` ran and the row was written
    /// with no permission columns, which is public. Upstream keeps the op object and writes two
    /// empty arrays, which is master-only. Measured at the pin on an ordinary class: an anonymous
    /// read of the created object answered 200 here and 404 there.
    ///
    /// Asserted on the stored columns rather than through a read, because "public" and
    /// "master-only" are the presence and the emptiness of the same two columns, and the
    /// distinction is exactly what a read cannot show for a master caller.
    #[tokio::test]
    async fn an_acl_operation_on_create_writes_empty_columns_rather_than_none() {
        for literal in [
            r#"{"title":"x","ACL":{"__op":"Delete"}}"#,
            r#"{"title":"x","ACL":{"__op":"Increment","amount":1}}"#,
        ] {
            let storage = FakeStorage::new().with_schema(default_schema("Post"));
            let snap = snapshot(&storage).await;
            let options = opts();
            let master = AclScope::Unrestricted;
            let ctx = Ctx::new(&storage, &snap, &master, &options);

            create(&ctx, "Post", body(literal, OpPath::Create))
                .await
                .expect("create");

            let rows = storage.rows("Post");
            assert_eq!(rows.len(), 1, "{literal}");
            for column in ["_rperm", "_wperm"] {
                assert!(
                    matches!(rows[0].get(column), Some(ParseValue::Array(a)) if a.is_empty()),
                    "{literal} must write an empty {column}, got {:?}",
                    rows[0].get(column)
                );
            }
        }
    }

    /// The control for the test above, and the reason it cannot simply assert "columns exist": an
    /// ordinary create with no `ACL` writes **no** columns, which is what makes a row public.
    #[tokio::test]
    async fn a_create_with_no_acl_still_writes_no_columns() {
        let storage = FakeStorage::new().with_schema(default_schema("Post"));
        let snap = snapshot(&storage).await;
        let options = opts();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        create(&ctx, "Post", body(r#"{"title":"x"}"#, OpPath::Create))
            .await
            .expect("create");

        let rows = storage.rows("Post");
        assert!(rows[0].get("_rperm").is_none());
        assert!(rows[0].get("_wperm").is_none());
    }

    /// `_Role`'s ACL is a required column, and the class default does not satisfy it: upstream
    /// runs `validateRequiredColumns` inside `validateSchema`, which precedes
    /// `setRequiredFieldsIfNeeded`. Asserting it here pins the ordering, which is otherwise
    /// invisible.
    #[tokio::test]
    async fn a_declared_default_does_not_satisfy_roles_required_acl() {
        let storage = FakeStorage::new().with_schema(
            default_schema("_Role").with_clp(clp(r#"{"ACL":{"currentUser":{"read":true}}}"#)),
        );
        let snap = snapshot(&storage).await;
        let options = opts();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        let e = create(&ctx, "_Role", body(r#"{"name":"Admins"}"#, OpPath::Create))
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::IncorrectType);
        assert_eq!(e.message, "ACL is required.");
        assert!(storage.rows("_Role").is_empty());
    }

    // -----------------------------------------------------------------------------------------
    // Atomic operations and schema reservation
    // -----------------------------------------------------------------------------------------

    /// The 0.1.0 gap: the op decoder existed and the write path never called it.
    #[tokio::test]
    async fn operations_reach_storage_as_operations() {
        let storage = FakeStorage::new();
        let snap = snapshot(&storage).await;
        let options = opts();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        let created = create(
            &ctx,
            "Post",
            body(
                r#"{"views":{"__op":"Increment","amount":2},"tags":{"__op":"Add","objects":["a"]}}"#,
                OpPath::Create,
            ),
        )
        .await
        .expect("create");

        let stored = storage.rows("Post");
        assert!(
            matches!(stored[0].get("views"), Some(ParseValue::Number(n)) if *n == 2.0),
            "an Increment must be flattened to a number, not stored as an op envelope"
        );
        assert!(matches!(stored[0].get("tags"), Some(ParseValue::Array(a)) if a.len() == 1));
        assert!(matches!(created.echoed.get("views"), Some(ParseValue::Number(n)) if *n == 2.0));

        let snap = snapshot(&storage).await;
        let ctx = Ctx::new(&storage, &snap, &master, &options);
        let updated = update(
            &ctx,
            "Post",
            &created.object_id,
            body(
                r#"{"views":{"__op":"Increment","amount":3},"title":"plain"}"#,
                OpPath::Update,
            ),
        )
        .await
        .expect("update");
        assert!(
            matches!(updated.echoed.get("views"), Some(ParseValue::Number(n)) if *n == 5.0),
            "the response carries the post-update value"
        );
        assert!(
            updated.echoed.get("title").is_none(),
            "a plain set is not echoed"
        );
        assert!(
            matches!(storage.rows("Post")[0].get("views"), Some(ParseValue::Number(n)) if *n == 5.0)
        );
    }

    #[tokio::test]
    async fn a_delete_op_unsets_the_field_and_echoes_nothing() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("Post").with_field("title", FieldType::String))
            .with_row(
                "Post",
                row(vec![
                    ("objectId", ParseValue::String("p1".into())),
                    ("title", ParseValue::String("t".into())),
                ]),
            );
        let snap = snapshot(&storage).await;
        let options = opts();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        let response = update(
            &ctx,
            "Post",
            "p1",
            body(r#"{"title":{"__op":"Delete"}}"#, OpPath::Update),
        )
        .await
        .expect("update");
        assert!(response.echoed.is_empty());
        assert!(storage.rows("Post")[0].get("title").is_none());
    }

    /// The field type is reserved atomically, before the row is written, so the loser of a race
    /// fails rather than overwriting the winner's type.
    #[tokio::test]
    async fn a_type_conflict_fails_the_write_before_the_row_is_inserted() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("Post").with_field("views", FieldType::Number));
        let snap = SchemaSnapshot::from_classes(vec![default_schema("Post")]);
        let options = opts();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        // The snapshot does not know about `views`, so validation passes and the reservation is
        // what catches the conflict. That is the race, reproduced deterministically.
        let e = create(&ctx, "Post", body(r#"{"views":"text"}"#, OpPath::Create))
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::IncorrectType);
        assert_eq!(
            e.message,
            "schema mismatch for Post.views; expected Number but got String"
        );
        assert!(storage.rows("Post").is_empty(), "no row was inserted");
    }

    #[tokio::test]
    async fn a_write_of_only_nulls_still_creates_the_class() {
        let storage = FakeStorage::new();
        let snap = snapshot(&storage).await;
        let options = opts();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        create(&ctx, "Post", body(r#"{"nothing":null}"#, OpPath::Create))
            .await
            .expect("create");
        let schema = storage
            .schema("Post")
            .expect("a null-only write must still leave a schema row behind");
        assert!(schema.field("objectId").is_some());
        assert!(schema.field("nothing").is_none(), "null infers no type");
    }

    // -----------------------------------------------------------------------------------------
    // Relations
    // -----------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_relation_write_lands_in_the_join_table_and_reads_back_through_related_to() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("_Role"))
            .with_schema(default_schema("_User"))
            .with_row(
                "_User",
                row(vec![("objectId", ParseValue::String("u1".into()))]),
            );
        let snap = snapshot(&storage).await;
        let options = opts();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        let created = create(
            &ctx,
            "_Role",
            body(
                r#"{"name":"admins","ACL":{"*":{"read":true}},
                    "users":{"__op":"AddRelation","objects":[
                        {"__type":"Pointer","className":"_User","objectId":"u1"}]}}"#,
                OpPath::Create,
            ),
        )
        .await
        .expect("create");

        let stored = storage.rows("_Role");
        assert!(
            stored[0].get("users").is_none(),
            "a Relation field has no column"
        );
        let joins = storage.rows("_Join:users:_Role");
        assert_eq!(joins.len(), 1);
        assert!(matches!(joins[0].get("relatedId"), Some(ParseValue::String(id)) if id == "u1"));
        assert!(
            matches!(joins[0].get("owningId"), Some(ParseValue::String(id)) if *id == created.object_id)
        );
        assert!(
            storage.schema("_Join:users:_Role").is_none(),
            "a join collection has no _SCHEMA row"
        );

        // The same membership added twice is one row.
        let snap = snapshot(&storage).await;
        let ctx = Ctx::new(&storage, &snap, &master, &options);
        update(
            &ctx,
            "_Role",
            &created.object_id,
            body(
                r#"{"users":{"__op":"AddRelation","objects":[
                    {"__type":"Pointer","className":"_User","objectId":"u1"}]}}"#,
                OpPath::Update,
            ),
        )
        .await
        .expect("update");
        assert_eq!(storage.rows("_Join:users:_Role").len(), 1);

        // And it reads back.
        let query = format!(
            r#"{{"$relatedTo":{{"object":{{"__type":"Pointer","className":"_Role","objectId":"{}"}},"key":"users"}}}}"#,
            created.object_id
        );
        let members = find(&ctx, "_User", where_(&query), FindOptions::default())
            .await
            .expect("find");
        assert_eq!(members.len(), 1);

        // Removing the membership empties it.
        update(
            &ctx,
            "_Role",
            &created.object_id,
            body(
                r#"{"users":{"__op":"RemoveRelation","objects":[
                    {"__type":"Pointer","className":"_User","objectId":"u1"}]}}"#,
                OpPath::Update,
            ),
        )
        .await
        .expect("update");
        assert!(storage.rows("_Join:users:_Role").is_empty());
    }

    /// A caller who cannot read the owning object gets an empty result, not an error, so the
    /// relation is not a membership oracle.
    #[tokio::test]
    async fn a_related_to_the_caller_cannot_read_yields_empty_rather_than_an_error() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("_Role"))
            .with_schema(default_schema("_User"))
            .with_row(
                "_Role",
                row(vec![
                    ("objectId", ParseValue::String("r1".into())),
                    ("_rperm", strings(&["u2"])),
                ]),
            )
            .with_row(
                "_User",
                row(vec![("objectId", ParseValue::String("u1".into()))]),
            )
            .with_row(
                "_Join:users:_Role",
                row(vec![
                    ("relatedId", ParseValue::String("u1".into())),
                    ("owningId", ParseValue::String("r1".into())),
                ]),
            );
        let snap = snapshot(&storage).await;
        let options = opts();
        let query = r#"{"$relatedTo":{"object":{"__type":"Pointer","className":"_Role","objectId":"r1"},"key":"users"}}"#;

        let outsider = AclScope::user("u3", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &outsider, &options);
        let results = find(&ctx, "_User", where_(query), FindOptions::default())
            .await
            .expect("a denied relation is empty, not an error");
        assert!(results.is_empty());

        // The caller who can read the role sees the membership, which is what proves the empty
        // result above was the authorization and not a broken join read.
        let insider = AclScope::user("u2", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &insider, &options);
        assert_eq!(
            find(&ctx, "_User", where_(query), FindOptions::default())
                .await
                .expect("find")
                .len(),
            1
        );
    }

    /// A protected relation key on the owning class is a refusal rather than an empty result,
    /// because the key itself is the disclosure.
    #[tokio::test]
    async fn a_related_to_on_a_protected_key_is_forbidden() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("_User"))
            .with_schema(
                default_schema("_Role")
                    .with_field(
                        "users",
                        FieldType::Relation {
                            target_class: "_User".into(),
                        },
                    )
                    .with_clp(clp(r#"{"protectedFields":{"*":["users"]}}"#)),
            )
            .with_row(
                "_Role",
                row(vec![("objectId", ParseValue::String("r1".into()))]),
            );
        let snap = snapshot(&storage).await;
        let options = opts();
        let user = AclScope::user("u1", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &user, &options);
        let query = r#"{"$relatedTo":{"object":{"__type":"Pointer","className":"_Role","objectId":"r1"},"key":"users"}}"#;
        let e = find(&ctx, "_User", where_(query), FindOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::OperationForbidden);
        assert_eq!(e.message, "Permission denied");

        let disclosing = disclosing_opts();
        let disclosed = Ctx::new(&storage, &snap, &user, &disclosing);
        assert_eq!(
            find(&disclosed, "_User", where_(query), FindOptions::default())
                .await
                .unwrap_err()
                .message,
            "This user is not allowed to query users on class _Role"
        );
    }

    #[tokio::test]
    async fn a_constraint_on_a_relation_field_is_the_reverse_join() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("_User"))
            .with_schema(default_schema("_Role").with_field(
                "users",
                FieldType::Relation {
                    target_class: "_User".into(),
                },
            ))
            .with_row(
                "_Role",
                row(vec![("objectId", ParseValue::String("r1".into()))]),
            )
            .with_row(
                "_Role",
                row(vec![("objectId", ParseValue::String("r2".into()))]),
            )
            .with_row(
                "_Join:users:_Role",
                row(vec![
                    ("relatedId", ParseValue::String("u1".into())),
                    ("owningId", ParseValue::String("r1".into())),
                ]),
            );
        let snap = snapshot(&storage).await;
        let options = opts();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        let results = find(
            &ctx,
            "_Role",
            where_(r#"{"users":{"__type":"Pointer","className":"_User","objectId":"u1"}}"#),
            FindOptions::default(),
        )
        .await
        .expect("find");
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].get("objectId"), Some(ParseValue::String(id)) if id == "r1"));
    }

    // -----------------------------------------------------------------------------------------
    // include
    // -----------------------------------------------------------------------------------------

    /// Ranked hazard 6: an included pointer is a full query against the target class with the
    /// caller's own auth. Grafting the row in without that is the classic Parse data leak.
    #[tokio::test]
    async fn include_applies_the_target_class_acl() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("_User").with_field("nickname", FieldType::String))
            .with_schema(default_schema("Post").with_field(
                "author",
                FieldType::Pointer {
                    target_class: "_User".into(),
                },
            ))
            .with_row(
                "Post",
                row(vec![
                    ("objectId", ParseValue::String("p1".into())),
                    ("author", pointer("_User", "u1")),
                ]),
            )
            .with_row(
                "_User",
                row(vec![
                    ("objectId", ParseValue::String("u1".into())),
                    ("nickname", ParseValue::String("nick".into())),
                    ("_hashed_password", ParseValue::String("hash".into())),
                    ("sessionToken", ParseValue::String("r:t".into())),
                    ("_rperm", strings(&["u1"])),
                ]),
            );
        let snap = snapshot(&storage).await;
        let options = opts();
        let include = FindOptions {
            include: vec![vec!["author".to_string()]],
            ..Default::default()
        };

        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);
        let results = find(&ctx, "Post", ParsedWhere::default(), include.clone())
            .await
            .expect("find");
        assert_eq!(results.len(), 1);
        assert!(
            results[0].get("author").is_none(),
            "an unreadable pointer is dropped rather than expanded or left as a pointer"
        );

        let owner = AclScope::user("u1", vec![]).expect("scope");
        let ctx = Ctx::new(&storage, &snap, &owner, &options);
        let results = find(&ctx, "Post", ParsedWhere::default(), include)
            .await
            .expect("find");
        match results[0].get("author") {
            Some(ParseValue::Object(author)) => {
                assert!(
                    matches!(author.get("nickname"), Some(ParseValue::String(n)) if n == "nick")
                );
                assert!(author.get("_hashed_password").is_none());
                assert!(author.get("sessionToken").is_none());
                assert!(
                    matches!(author.get("__type"), Some(ParseValue::String(t)) if t == "Object")
                );
            }
            other => panic!("expected an expanded author, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_dotted_include_resolves_parents_before_children() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("Company").with_field("name", FieldType::String))
            .with_schema(default_schema("_User").with_field(
                "company",
                FieldType::Pointer {
                    target_class: "Company".into(),
                },
            ))
            .with_schema(default_schema("Post").with_field(
                "author",
                FieldType::Pointer {
                    target_class: "_User".into(),
                },
            ))
            .with_row(
                "Post",
                row(vec![
                    ("objectId", ParseValue::String("p1".into())),
                    ("author", pointer("_User", "u1")),
                ]),
            )
            .with_row(
                "_User",
                row(vec![
                    ("objectId", ParseValue::String("u1".into())),
                    ("company", pointer("Company", "c1")),
                ]),
            )
            .with_row(
                "Company",
                row(vec![
                    ("objectId", ParseValue::String("c1".into())),
                    ("name", ParseValue::String("Acme".into())),
                ]),
            );
        let snap = snapshot(&storage).await;
        let options = opts();
        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);

        let results = find(
            &ctx,
            "Post",
            ParsedWhere::default(),
            FindOptions {
                include: crate::query_parse::parse_include("author.company").expect("include"),
                ..Default::default()
            },
        )
        .await
        .expect("find");

        let Some(ParseValue::Object(author)) = results[0].get("author") else {
            panic!("author should be expanded");
        };
        let Some(ParseValue::Object(company)) = author.get("company") else {
            panic!("company should be expanded");
        };
        assert!(matches!(company.get("name"), Some(ParseValue::String(n)) if n == "Acme"));
    }

    /// `allowClientClassCreation`, whose default is `false`. A server missing this check is more
    /// permissive than a stock parse-server, so the assertion that matters is that the *default*
    /// options refuse, not that the option works when set.
    #[tokio::test]
    async fn a_client_cannot_bring_a_class_into_existence_at_the_default() {
        let storage = FakeStorage::new();
        let snap = snapshot(&storage).await;
        let options = opts();
        let anon = AclScope::Anonymous;
        let ctx = Ctx::new(&storage, &snap, &anon, &options);

        let err = create(&ctx, "BrandNew", body(r#"{"x":1}"#, OpPath::Create))
            .await
            .expect_err("a client must not create a class at the default");
        assert_eq!(err.code, ErrorCode::OperationForbidden);
        assert!(
            storage.schema("BrandNew").is_none(),
            "the refusal must leave no _SCHEMA row behind"
        );
    }

    /// The three exemptions, each for a different reason: the option, the master key, and the
    /// classes Parse defines itself. The last one is what keeps signup working with the option off.
    #[tokio::test]
    async fn master_the_option_and_the_system_classes_are_all_exempt() {
        for (label, scope, allow, class) in [
            ("option on", AclScope::Anonymous, true, "BrandNew"),
            ("master", AclScope::Unrestricted, false, "BrandNew"),
            ("system class", AclScope::Anonymous, false, "_User"),
        ] {
            let storage = FakeStorage::new();
            let snap = snapshot(&storage).await;
            let options = PermissionOptions {
                allow_client_class_creation: allow,
                ..PermissionOptions::default()
            };
            let ctx = Ctx::new(&storage, &snap, &scope, &options);
            create(&ctx, class, body(r#"{"x":1}"#, OpPath::Create))
                .await
                .unwrap_or_else(|e| panic!("{label} should be allowed to create {class}: {e:?}"));
        }
    }
}

#[cfg(test)]
mod relation_schema_tests {
    use super::tests_support::*;
    use super::*;
    use crate::testing::FakeStorage;
    use parse_rust_core::op::OpPath;

    /// An `AddRelation` reserves `Relation<Target>` for the field, which is what makes a later
    /// `$relatedTo` against a user-defined class resolve at all. The op is stripped from the row
    /// write, but only after the schema has been reserved from it.
    #[tokio::test]
    async fn a_relation_op_reserves_the_field_type_before_it_is_stripped() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("_User"))
            .with_row("_User", single("objectId", ParseValue::String("u1".into())));
        let snap = SchemaSnapshot::load(&storage).await.expect("snapshot");
        let options = PermissionOptions::default();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        let created = create(
            &ctx,
            "Team",
            decode(
                r#"{"name":"core","members":{"__op":"AddRelation","objects":[
                    {"__type":"Pointer","className":"_User","objectId":"u1"}]}}"#,
                OpPath::Create,
            ),
        )
        .await
        .expect("create");

        let schema = storage.schema("Team").expect("class reserved");
        assert_eq!(
            schema.field("members"),
            Some(&FieldType::Relation {
                target_class: "_User".into()
            }),
            "without this a $relatedTo against Team.members resolves to nothing forever"
        );
        assert!(storage.rows("Team")[0].get("members").is_none());
        assert_eq!(storage.rows("_Join:members:Team").len(), 1);

        // And the reverse read works, which is the observable consequence.
        let snap = SchemaSnapshot::load(&storage).await.expect("snapshot");
        let ctx = Ctx::new(&storage, &snap, &master, &options);
        let query = format!(
            r#"{{"$relatedTo":{{"object":{{"__type":"Pointer","className":"Team","objectId":"{}"}},"key":"members"}}}}"#,
            created.object_id
        );
        assert_eq!(
            find(
                &ctx,
                "_User",
                parse_json_where(&query),
                FindOptions::default()
            )
            .await
            .expect("find")
            .len(),
            1
        );
    }
}

#[cfg(test)]
mod tests_support {
    use super::*;
    use crate::query_parse::parse_where;
    use crate::write::decode_write_body;
    use parse_rust_core::op::OpPath;

    pub fn single(key: &str, value: ParseValue) -> ParseMap {
        let mut m = ParseMap::new();
        m.insert(key.to_string(), value);
        m
    }

    pub fn decode(json: &str, path: OpPath) -> WriteBody {
        decode_write_body(&serde_json::from_str(json).expect("test literal"), path).expect("decode")
    }

    pub fn parse_json_where(json: &str) -> ParsedWhere {
        parse_where(&serde_json::from_str(json).expect("test literal")).expect("parse")
    }
}

#[cfg(test)]
mod write_edge_tests {
    use super::tests_support::*;
    use super::*;
    use crate::testing::FakeStorage;
    use parse_rust_core::op::OpPath;

    /// A **falsy** `ACL` leaves the stored permissions alone rather than clearing them. Clearing
    /// them would lock every principal out of a row they still own, and on `_User` it disables the
    /// account outright: an empty ACL reads as "disabled" and refuses every later login.
    ///
    /// **The loop is the test.** This asserted `null` alone until a review, and the other three
    /// falsy values fell through to an unconditional write that set both columns to `[]`.
    /// Upstream's test is `if (!ACL)`, so all four behave the same there. Checking one value is
    /// exactly what let the other three through.
    #[tokio::test]
    async fn a_falsy_acl_on_an_update_does_not_clear_the_permissions() {
        for body in [
            r#"{"ACL":null,"title":"t"}"#,
            r#"{"ACL":false,"title":"t"}"#,
            r#"{"ACL":0,"title":"t"}"#,
            r#"{"ACL":"","title":"t"}"#,
        ] {
            assert_falsy_acl_preserves_permissions(body).await;
        }
    }

    async fn assert_falsy_acl_preserves_permissions(body: &str) {
        let mut existing = single("objectId", ParseValue::String("p1".into()));
        existing.insert(
            "_rperm".to_string(),
            ParseValue::Array(vec![ParseValue::String("u1".into())]),
        );
        existing.insert(
            "_wperm".to_string(),
            ParseValue::Array(vec![ParseValue::String("u1".into())]),
        );
        let storage = FakeStorage::new()
            .with_schema(default_schema("Post").with_field("title", FieldType::String))
            .with_row("Post", existing);
        let snap = SchemaSnapshot::load(&storage).await.expect("snapshot");
        let options = PermissionOptions::default();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        update(&ctx, "Post", "p1", decode(body, OpPath::Update))
            .await
            .expect("update");

        let stored = &storage.rows("Post")[0];
        assert!(
            matches!(stored.get("_rperm"), Some(ParseValue::Array(a)) if a.len() == 1),
            "the existing permissions must survive a falsy ACL: {body}"
        );
    }

    /// An update to a class nobody has written yet answers `OBJECT_NOT_FOUND` **and leaves the
    /// class behind**, whatever the body contains.
    ///
    /// This test asserted the opposite until a review caught it, and the assertion was wrong in a
    /// way that hid a second problem: the outcome was body-dependent. An empty update really did
    /// leave nothing, while an update naming a new field created the class as a side effect of
    /// reserving the field. Upstream has one answer for both, because `enforceClassExists` runs
    /// from `validateSchema` before any field is looked at (`SchemaController.js:1288`,
    /// `RestWrite.js:133-137`).
    #[tokio::test]
    async fn an_update_to_a_missing_class_creates_the_class_and_then_finds_nothing() {
        // Including a body that is **rejected**, which is the case the first version of this fix
        // still got wrong: the class creation sat behind `validate_write_fields`, so a bad field
        // name skipped it. Upstream's `enforceClassExists` runs before any field is inspected, so
        // all three of these leave the class behind and only the error differs.
        for body in [r#"{}"#, r#"{"title":"a"}"#, r#"{"bad-key":1}"#] {
            let storage = FakeStorage::new();
            let snap = SchemaSnapshot::load(&storage).await.expect("snapshot");
            let options = PermissionOptions::default();
            let master = AclScope::Unrestricted;
            let ctx = Ctx::new(&storage, &snap, &master, &options);

            let e = update(&ctx, "Ghost", "p1", decode(body, OpPath::Update))
                .await
                .unwrap_err();
            let expected = if body.contains("bad-key") {
                ErrorCode::InvalidKeyName
            } else {
                ErrorCode::ObjectNotFound
            };
            assert_eq!(e.code, expected, "for body {body}");
            assert!(
                storage.schema("Ghost").is_some(),
                "the schema row survives the failed update, for body {body}"
            );
        }
    }

    /// An ACL written on a create round-trips through the two storage columns.
    #[tokio::test]
    async fn an_acl_on_an_update_replaces_both_columns() {
        let storage = FakeStorage::new()
            .with_schema(default_schema("Post"))
            .with_row("Post", single("objectId", ParseValue::String("p1".into())));
        let snap = SchemaSnapshot::load(&storage).await.expect("snapshot");
        let options = PermissionOptions::default();
        let master = AclScope::Unrestricted;
        let ctx = Ctx::new(&storage, &snap, &master, &options);

        update(
            &ctx,
            "Post",
            "p1",
            decode(
                r#"{"ACL":{"u1":{"read":true,"write":true},"*":{"read":true}}}"#,
                OpPath::Update,
            ),
        )
        .await
        .expect("update");

        let stored = &storage.rows("Post")[0];
        assert!(stored.get("ACL").is_none(), "ACL is not a stored column");
        assert!(matches!(stored.get("_rperm"), Some(ParseValue::Array(a)) if a.len() == 2));
        assert!(matches!(stored.get("_wperm"), Some(ParseValue::Array(a)) if a.len() == 1));
    }
}

#[cfg(test)]
mod field_option_tests {
    use super::*;

    /// A class with `d`, defaulted to `"x"`, and `r`, required.
    fn schema() -> ClassSchema {
        let mut s = ClassSchema::new("C")
            .with_field("d", FieldType::String)
            .with_field("r", FieldType::String);
        let option = |pairs: Vec<(&str, ParseValue)>| {
            ParseValue::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
        };
        let mut options = ParseMap::new();
        options.insert(
            "d".into(),
            option(vec![("defaultValue", ParseValue::String("x".into()))]),
        );
        options.insert(
            "r".into(),
            option(vec![("required", ParseValue::Bool(true))]),
        );
        s.field_options = Some(options);
        s
    }

    fn body(pairs: Vec<(&str, FieldWrite)>) -> WriteBody {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    fn present(r: &str) -> (&str, FieldWrite) {
        ("r", FieldWrite::Value(ParseValue::String(r.into())))
    }

    #[test]
    fn a_create_defaults_an_absent_or_deleted_field_and_keeps_a_null_or_empty_one() {
        let mut absent = body(vec![present("y")]);
        let applied = apply_field_options(&schema(), &mut absent, true).expect("applies");
        assert!(matches!(&applied[..], [(f, ParseValue::String(v))] if f == "d" && v == "x"));

        let mut deleted = body(vec![present("y"), ("d", FieldWrite::Op(Op::Delete))]);
        apply_field_options(&schema(), &mut deleted, true).expect("applies");
        assert!(
            matches!(deleted.get("d"), Some(FieldWrite::Value(ParseValue::String(v))) if v == "x")
        );

        for kept in [ParseValue::Null, ParseValue::String(String::new())] {
            let mut b = body(vec![present("y"), ("d", FieldWrite::Value(kept))]);
            let applied = apply_field_options(&schema(), &mut b, true).expect("applies");
            assert!(
                applied.is_empty(),
                "a null or empty value is not replaced by the default"
            );
        }
    }

    #[test]
    fn a_required_field_that_is_null_empty_absent_or_deleted_is_142_on_create() {
        for r in [
            None,
            Some(FieldWrite::Value(ParseValue::Null)),
            Some(FieldWrite::Value(ParseValue::String(String::new()))),
            Some(FieldWrite::Op(Op::Delete)),
        ] {
            let mut b = body(vec![]);
            if let Some(r) = r {
                b.insert("r".into(), r);
            }
            let e = apply_field_options(&schema(), &mut b, true).expect_err("required");
            assert_eq!(e.code, ErrorCode::ValidationError);
            assert_eq!(e.message, "r is required");
        }
    }

    #[test]
    fn an_update_checks_only_what_it_names_and_applies_no_default() {
        let mut untouched = body(vec![("other", FieldWrite::Value(ParseValue::Number(1.0)))]);
        assert!(apply_field_options(&schema(), &mut untouched, false).is_ok());

        let mut cleared = body(vec![("d", FieldWrite::Op(Op::Delete))]);
        let applied = apply_field_options(&schema(), &mut cleared, false).expect("not required");
        assert!(applied.is_empty(), "no default on an update");

        for r in [
            FieldWrite::Value(ParseValue::Null),
            FieldWrite::Value(ParseValue::String(String::new())),
            FieldWrite::Op(Op::Delete),
        ] {
            let mut b = body(vec![("r", r)]);
            let e = apply_field_options(&schema(), &mut b, false).expect_err("required");
            assert_eq!(e.message, "r is required");
        }
    }
}

#[cfg(test)]
mod projection_exclusion_tests {
    use super::*;
    use crate::clp::ProtectedFieldPlan;

    fn plan(strip: &[&str], user_field: bool) -> ProtectedFieldPlan {
        ProtectedFieldPlan {
            strip: strip.iter().map(|s| s.to_string()).collect(),
            user_field_rules: if user_field {
                vec![("owner".to_string(), vec!["secret".to_string()])]
            } else {
                Vec::new()
            },
        }
    }

    fn post() -> ClassSchema {
        ClassSchema::new("Post")
            .with_field("secret", FieldType::String)
            .with_field("notes", FieldType::String)
            .with_field("address", FieldType::Object)
    }

    #[test]
    fn a_fixed_protected_set_is_projected_away() {
        let p = plan(&["secret", "notes"], false);
        assert_eq!(
            projected_away(&post(), None, Some(&p)),
            Some(vec!["secret".to_string(), "notes".to_string()])
        );
    }

    /// Each guard alone keeps the field in the read.
    #[test]
    fn the_projection_is_skipped_where_the_set_is_not_fixed() {
        let p = plan(&["secret"], false);
        let keys = vec!["title".to_string()];
        assert_eq!(projected_away(&post(), Some(&keys), Some(&p)), None, "keys");
        let user = ClassSchema::new("_User").with_field("secret", FieldType::String);
        assert_eq!(projected_away(&user, None, Some(&p)), None, "_User");
        assert_eq!(
            projected_away(&post(), None, Some(&plan(&["secret"], true))),
            None,
            "userField rule"
        );
        // Master and maintenance have no plan at all.
        assert_eq!(projected_away(&post(), None, None), None, "no plan");
        assert_eq!(
            projected_away(&post(), None, Some(&plan(&[], false))),
            None,
            "empty"
        );
    }

    /// Only declared fields, never the always-read keys, and never a name the schema does not
    /// declare: an internal column, a path, an operator.
    #[test]
    fn only_declared_fields_outside_the_always_read_set_are_projected() {
        let p = plan(
            &[
                "objectId",
                "createdAt",
                "updatedAt",
                "ACL",
                "_rperm",
                "_wperm",
                "_id",
                "address.street",
                "$x",
                "missing",
                "address",
                "secret",
                "secret",
            ],
            false,
        );
        assert_eq!(
            projected_away(&post(), None, Some(&p)),
            Some(vec!["address".to_string(), "secret".to_string()])
        );
        assert_eq!(
            projected_away(
                &post(),
                None,
                Some(&plan(&["address.street", "_rperm"], false))
            ),
            None
        );
    }
}
