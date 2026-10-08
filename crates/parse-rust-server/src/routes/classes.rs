//! The five `/classes` verbs, and the cores every other class-shaped route reuses.
//!
//! Upstream: `src/Routers/ClassesRouter.js`. Response shapes are wire contract and narrower than
//! they look: a create returns `{objectId, createdAt}`, an update returns `{updatedAt}`, and a
//! delete returns `{}`. Returning the whole object would be more helpful and would not match.
//!
//! `RolesRouter` and `SessionsRouter` are `ClassesRouter` with `className()` pinned
//! (`RolesRouter.js:4-6`, `SessionsRouter.js:8-10`), so they call the cores below with a fixed
//! class name rather than reimplementing them. `/batch` dispatches into the same cores, which is
//! what makes a sub-request and a top-level request the same code path rather than two that drift.

use parse_rust_core::{ErrorCode, ParseError, ParseMap, ParseValue};
use parse_rust_rest::{FindOptions, ParsedClause, ParsedWhere};
use parse_rust_storage::{Constraint, ExplainVerbosity, StorageAdapter};
use serde_json::{json, Value as Json};

use crate::auth::Authority;
use crate::params::Params;
use crate::request::RequestContext;
use crate::state::AppState;

/// The class sessions live in.
///
/// A non-master read of it is narrowed to the caller's own sessions, but that happens in
/// `parse_rust_rest`'s read pipeline rather than here. See `pipeline::narrow_sessions` for why the
/// layer matters.
pub const SESSION_CLASS: &str = "_Session";

/// [`body_of`] for a row that is not needed afterwards, which a find's results are not.
pub fn into_body(row: ParseMap) -> Json {
    ParseValue::Object(parse_rust_rest::into_response_body(row)).to_serde_json()
}

/// Convert a Parse-format map into a JSON response body.
///
/// Strips every `_`-prefixed key and flattens the top-level timestamps. This is the single audit
/// point for "nothing internal reaches a client", and it runs on every response body this module
/// produces.
pub fn body_of(row: &ParseMap) -> Json {
    let row = parse_rust_rest::to_response_body(row);
    ParseValue::Object(row).to_serde_json()
}

/// Decode a JSON request body into a write body.
fn decode_body(
    value: &Json,
    path: parse_rust_core::op::OpPath,
) -> Result<parse_rust_rest::WriteBody, ParseError> {
    let body = parse_rust_rest::decode_write_body(value, path)?;
    // A client must not supply a server-internal column. Without this, a caller could write its
    // own `_rperm` and grant itself read access to a row.
    parse_rust_rest::reject_reserved_keys_in(body.keys().map(String::as_str))?;
    Ok(body)
}

// -------------------------------------------------------------------------------------------
// Cores
// -------------------------------------------------------------------------------------------

pub async fn find_core(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    class_name: &str,
    params: &Params,
) -> Result<Json, ParseError> {
    // Upstream's order: `handleFind` checks the parameter names and decodes `where`
    // (`ClassesRouter.js:23-37`), `rest.find` enforces class security (`rest.js:136`), then the
    // explain gate (`rest.js:39-48`), and only `RestQuery` reads `where` as a query and parses
    // `include`. So an unknown parameter on a class a client may not find is 102, not 119.
    params.reject_unknown_find_keys()?;
    let where_json = params.where_json()?;
    parse_rust_rest::enforce_class_security(
        class_name,
        authority.is_privileged(),
        "find",
        rc.options.error_detail,
    )?;
    let explaining = params.js_explain_requested();
    // **`explain` ships with its authorization boundary.** A caller without the master key is
    // refused unless `databaseOptions.allowPublicExplain` says otherwise (`rest.js:39-48`), and
    // that check precedes the value's own validation, which upstream leaves to the adapter. The
    // maintenance key is not the master key here, as upstream's `auth.isMaster` is not.
    if explaining && !authority.is_master() && !state.config().allow_public_explain {
        return Err(ParseError::invalid_query(
            "Using the explain query parameter requires the master key",
        ));
    }

    let where_ = match where_json {
        // Read as upstream reads it, with any failure carried to upstream's position.
        Some(value) => parse_rust_rest::parse_client_where(&value),
        None => parse_rust_rest::ParsedWhere::default(),
    };
    let options = params.find_options(&state.config().limit_policy())?;
    let wants_count = params.wants_count();
    // The count beside the results takes the same `hint` and `comment` the find does
    // (`DatabaseController.js:1525-1535`).
    let count_options = parse_rust_storage::CountOptions {
        hint: options.hint.clone(),
        comment: options.comment.clone(),
    };
    let order = options.order.clone();
    let ctx = rc.ctx(state.storage());

    let mut body = if explaining {
        // Validated where the adapter validates it; see `parse_rust_rest::explain`.
        let verbosity = params
            .explain()
            .map(|v| v.unwrap_or(ExplainVerbosity::AllPlansExecution));
        let explained =
            parse_rust_rest::explain(&ctx, class_name, where_.clone(), options, verbosity).await?;
        json!({ "results": explained })
    } else {
        let results = parse_rust_rest::find(&ctx, class_name, where_.clone(), options).await?;
        json!({ "results": results.into_iter().map(into_body).collect::<Vec<_>>() })
    };
    if wants_count {
        let n = parse_rust_rest::count(&ctx, class_name, where_, &order, &count_options).await?;
        body["count"] = json!(n);
    }
    Ok(body)
}

pub async fn get_core(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    class_name: &str,
    object_id: &str,
    params: &Params,
) -> Result<Json, ParseError> {
    // `handleGet` checks the parameter names (`ClassesRouter.js:58-62`) before `rest.get`
    // enforces class security (`rest.js:150`).
    params.reject_unknown_get_keys()?;
    parse_rust_rest::enforce_class_security(
        class_name,
        authority.is_privileged(),
        "get",
        rc.options.error_detail,
    )?;

    // `handleGet` is `rest.get`, which pins the query to an objectId **and carries the `get`
    // method** (`rest.js:150`, `:183`). Routing it through `find` instead would re-derive the
    // method as `find` inside the pipeline, and `enforceRoleSecurity` distinguishes the two: a
    // client may `get` an installation and may not `find` one.
    //
    // The `_Session` narrowing this needs is applied by the pipeline, because upstream applies it
    // in the query constructor (`RestQuery.js:116-134`) rather than at a route handler.
    let options = FindOptions {
        limit: Some(1),
        ..params.get_options()?
    };
    let ctx = rc.ctx(state.storage());
    let row = parse_rust_rest::get(&ctx, class_name, object_id, options).await?;
    let mut out = body_of(&row);
    // **A caller fetching their own `_User` row gets their session token back**
    // (`ClassesRouter.js:97-106`). Any stored `sessionToken` is deleted first, then the token this
    // request presented is assigned, so it is the last key. On `/classes/_User/:id` and
    // `/users/:id` alike, because both are this handler upstream. Master has no user, so it gets
    // none.
    if class_name == crate::routes::users::USER_CLASS {
        if let Json::Object(map) = &mut out {
            map.shift_remove("sessionToken");
            let own = rc.user_id.is_some()
                && map.get("objectId").and_then(Json::as_str) == rc.user_id.as_deref();
            if own {
                map.insert(
                    "sessionToken".to_string(),
                    rc.session_token.clone().map_or(Json::Null, Json::String),
                );
            }
        }
    }
    Ok(out)
}

pub async fn create_core(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    class_name: &str,
    body: &Json,
) -> Result<Json, ParseError> {
    // **Upstream's order, which is three layers deep.** `handleCreate`'s `role:` guard runs in the
    // router, before anything (`ClassesRouter.js:111-118`); `rest.create` then enforces class
    // security (`rest.js:263`); the `RestWrite` constructor applies the objectId policy
    // (`RestWrite.js:50-65`); and only then does `execute` reach `handleInstallation` (`:107`).
    if class_name == crate::routes::users::USER_CLASS {
        crate::routes::users::reject_role_prefixed_object_id(body, rc)?;
    }
    parse_rust_rest::enforce_class_security(
        class_name,
        authority.is_privileged(),
        "create",
        rc.options.error_detail,
    )?;
    let mut body = decode_body(body, parse_rust_core::op::OpPath::Create)?;
    // Runs on the client's body before any server-side identity is folded in.
    parse_rust_rest::enforce_object_id_policy(&body, state.config().allow_custom_object_id)?;
    if class_name == crate::routes::installations::INSTALLATION_CLASS {
        crate::routes::installations::prepare(&mut body, true, rc.installation_id.as_deref())?;
    }
    if class_name == crate::routes::users::USER_CLASS {
        // Upstream's `!this.query && !hasAuthData` guard is not gated on the caller
        // (`RestWrite.js:528`), so the master key does not buy an exemption from it. Before
        // the uniqueness query and the hash, as upstream orders those stages.
        crate::routes::users::require_create_credentials(&body)?;
        // **`transformUser` is not gated on the caller**, so a master create through this route
        // gets the same username and email validation a signup does (`RestWrite.js:895-899`).
        // Without it, `POST /classes/_User` with the master key admitted case-only duplicate
        // usernames and malformed email addresses that `POST /users` refuses. The dashboard
        // creates users through this route. There is no self to exclude on a create, which is
        // what the empty objectId means here.
    }
    let ctx = rc.ctx(state.storage());
    // The identity validation runs inside the create, after defaults; see `identity_check`.
    let check = (class_name == crate::routes::users::USER_CLASS)
        .then(|| crate::routes::users::identity_check(state, rc));
    let res = parse_rust_rest::create_checked(&ctx, class_name, body, check)
        .await
        // Same relabelling the update path does, and `_User` only: a collision on the unique index
        // is 202 or 203 to a client, not a bare 137.
        .map_err(|e| {
            if class_name == crate::routes::users::USER_CLASS {
                crate::routes::users::map_duplicate(e)
            } else {
                e
            }
        })?;

    let mut out = json!({
        "objectId": res.object_id,
        "createdAt": res.created_at.to_iso(),
    });
    merge_echo(&mut out, res.echoed, rc, class_name);
    // A `_User` created through this route gets a session as a signup does, by the same rule.
    if class_name == crate::routes::users::USER_CLASS {
        let token =
            crate::routes::users::mint_create_session(state, rc, authority, &res.object_id).await?;
        if let (Json::Object(map), Some(token)) = (&mut out, token) {
            map.insert("sessionToken".into(), Json::String(token));
        }
    }
    Ok(out)
}

pub async fn update_core(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    class_name: &str,
    object_id: &str,
    body: &Json,
) -> Result<Json, ParseError> {
    let out = update_inner(state, rc, authority, class_name, object_id, body).await;
    if class_name == crate::routes::users::USER_CLASS {
        return out.map_err(|e| crate::routes::users::as_session_missing(e, rc, authority));
    }
    out
}

async fn update_inner(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    class_name: &str,
    object_id: &str,
    body: &Json,
) -> Result<Json, ParseError> {
    parse_rust_rest::enforce_class_security(
        class_name,
        authority.is_privileged(),
        "update",
        rc.options.error_detail,
    )?;
    let is_user = class_name == crate::routes::users::USER_CLASS;
    // **Authorization before the body is read as a write.** `authorizeUserUpdate` is the fifth
    // stage of `execute` (`RestWrite.js:113`) and nothing before it decodes an operation, so a
    // non-owner sending a malformed body is told it may not modify the user, not what is wrong
    // with the body.
    if is_user {
        crate::routes::users::authorize_user_update(state, rc, authority, object_id, body).await?;
    }
    let mut body = decode_body(body, parse_rust_core::op::OpPath::Update)?;
    if class_name == crate::routes::installations::INSTALLATION_CLASS {
        crate::routes::installations::prepare(&mut body, false, rc.installation_id.as_deref())?;
        crate::routes::installations::check_update(
            state.storage(),
            &rc.snapshot,
            object_id,
            &body,
            authority.is_privileged(),
            rc.installation_id.as_deref(),
        )
        .await?;
    }

    // Whether this write changes the password, decided before `prepare_user_write` replaces the
    // key with its hash. **Only a string counts**, because only a string is a password: a
    // `{"password": null}` body previously read as "no password" to the hasher and as "a password
    // change" to the followup below, so it revoked every session and issued a replacement while
    // leaving the old password working. The policy check refuses that body outright now, and this
    // stays narrow so the two cannot disagree again.
    let changes_password = is_user
        && matches!(
            body.get("password"),
            Some(parse_rust_core::FieldWrite::Value(ParseValue::String(_)))
        );

    if is_user {
        crate::routes::users::require_update_credentials(&body)?;
        crate::routes::users::enforce_user_update_policy(&body, rc, authority, object_id)?;
        crate::routes::users::owner_update_gate(state, rc, authority, object_id)?;
    }
    // `transformUser`, after the schema and required-field checks as upstream orders them: the
    // identity checks, the owner's ACL entry, and the password hash.
    let privileged = authority.is_privileged();
    let step: Option<parse_rust_rest::BeforeInsert<'_>> = is_user.then(|| {
        let step: parse_rust_rest::BeforeInsert<'_> = Box::new(move |mut body| {
            Box::pin(async move {
                crate::routes::users::validate_user_identity(state, rc, &body, object_id).await?;
                crate::routes::users::force_owner_into_acl(&mut body, object_id, privileged)?;
                crate::routes::users::prepare_user_write(&mut body, false).await?;
                Ok(body)
            })
        });
        step
    });
    let ctx = rc.ctx(state.storage());
    let res = parse_rust_rest::update_checked(&ctx, class_name, object_id, body, step)
        .await
        // **`_User` only.** The relabelling turns a duplicate-key error into 202 or 203 by reading
        // the index name, and an ordinary class is free to carry its own unique index called
        // `username_1`. Applying it everywhere reported somebody else's collision as
        // `Account already exists for this username.`, where upstream leaves a non-`_User`
        // collision as 137.
        .map_err(|e| {
            if is_user {
                crate::routes::users::map_duplicate(e)
            } else {
                e
            }
        })?;

    // **The operation results first, then `updatedAt`.** Upstream's response starts as what the
    // database update returned, the result-bearing operations, and `updatedAt` is assigned onto it
    // afterwards (`RestWrite.js:1806-1808`), so it is the last key. Found by the benchmark
    // correctness gate comparing an `Increment` and an `AddUnique` update on both servers.
    let mut out = json!({});
    merge_echo(&mut out, res.echoed, rc, class_name);
    out["updatedAt"] = json!(res.updated_at.to_iso());

    // **A password change revokes every session and, for a non-master caller, mints a replacement**
    // (`RestWrite.js:1284-1303`). Both halves matter and they are not symmetric: revoking is what
    // makes a password change mean anything, and the new token is what stops the caller logging
    // themselves out by changing their own password. Master gets the revocation and no new token,
    // because upstream gates `generateNewSession` on the caller not being master.
    //
    // Runs after the write, as upstream's `handleFollowup` does. A failure here leaves the password
    // changed and the old sessions alive, which is the safe direction to fail in only because the
    // caller can retry; it is not silent, because the error reaches the client.
    if changes_password {
        parse_rust_auth::revoke_all_for_user(state.storage(), object_id).await?;
        if !authority.is_privileged() {
            let session = parse_rust_auth::create_session(
                state.storage(),
                &state.config().session,
                parse_rust_auth::NewSession {
                    user_object_id: object_id,
                    // **No `createdWith`.** `setCreatedWith` computes `login` only when an auth
                    // provider is in storage and `signup` only on a create; a password update is
                    // neither, so it returns before setting anything and upstream's replacement
                    // session carries no such column (`RestWrite.js:952-962`). Writing
                    // `{"action":"login"}` here would be visible through `/sessions/me` and would
                    // describe a login that did not happen.
                    created_with: None,
                    installation_id: rc.installation_id.as_deref(),
                },
            )
            .await?;
            out["sessionToken"] = json!(session.session_token);
        }
    }
    Ok(out)
}

pub async fn delete_core(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    class_name: &str,
    object_id: &str,
) -> Result<Json, ParseError> {
    // Upstream's refusals of a `_User` delete that parse-rust would refuse anyway, with upstream's
    // codes. An anonymous caller is `SESSION_MISSING` before any class check, unsanitized
    // (`rest.js:168-170`). Another user's row is not found under the caller's ACL and
    // `handleSessionMissingError` reports that as `SESSION_MISSING` too (`rest.js:316-331`). An
    // owner deleting their own row still meets the class refusal below.
    if class_name == crate::routes::users::USER_CLASS && !authority.is_privileged() {
        match rc.user_id.as_deref() {
            None => {
                return Err(ParseError::new(
                    ErrorCode::SessionMissing,
                    "Insufficient auth to delete user",
                ))
            }
            Some(uid) if uid != object_id => {
                // The class's CLP is checked before the row is looked for, so a CLP that denies
                // `delete` answers 119 before the not-found becomes `SESSION_MISSING`.
                parse_rust_rest::validate_permission(
                    rc.snapshot.clp(class_name),
                    class_name,
                    &rc.scope.acl_group(),
                    parse_rust_core::Operation::Delete,
                    None,
                    rc.options.error_detail,
                )?;
                return Err(crate::routes::users::as_session_missing(
                    ParseError::new(ErrorCode::ObjectNotFound, "Object not found."),
                    rc,
                    authority,
                ));
            }
            Some(_) => {}
        }
    }
    parse_rust_rest::enforce_class_security(
        class_name,
        authority.is_privileged(),
        "delete",
        rc.options.error_detail,
    )?;
    let ctx = rc.ctx(state.storage());
    parse_rust_rest::delete(&ctx, class_name, object_id)
        .await
        .map_err(|e| {
            if class_name == crate::routes::users::USER_CLASS {
                crate::routes::users::as_session_missing(e, rc, authority)
            } else {
                e
            }
        })?;
    // Upstream answers an empty object, not 204.
    Ok(json!({}))
}

/// Fold the post-write value of any operation the request carried into the response.
///
/// `protectedFieldsSaveResponseExempt` decides whether a protected field survives that fold. It
/// defaults to `true` (`Options/Definitions.js:513-518`), which is the pass-through case; set to
/// `false` the echo is stripped the same way a query result is.
pub(crate) fn merge_echo(out: &mut Json, echoed: ParseMap, rc: &RequestContext, class_name: &str) {
    if echoed.is_empty() {
        return;
    }
    let mut echoed = echoed;
    if !rc.save_response_exempt && !rc.is_master() {
        if let Some(plan) = parse_rust_rest::clp::plan_protected_fields(
            class_name,
            rc.snapshot.clp(class_name),
            &rc.scope,
            None,
            &rc.options,
        ) {
            for field in plan.strip {
                echoed.shift_remove(&field);
            }
        }
    }
    let Json::Object(map) = out else { return };
    if let Json::Object(rendered) = body_of(&echoed) {
        for (key, value) in rendered {
            map.insert(key, value);
        }
    }
}

/// `DELETE /sessions/:objectId`, which is narrower than an ordinary class delete.
///
/// `rest.del` reads the row first for `_Session` and then re-checks the owner explicitly
/// (`rest.js:181-197`), because `_Session` rows carry no ACL and the ordinary write constraint
/// therefore excludes nothing. A miss is `Object not found for delete.`, which is that path's
/// message rather than the class router's `Object not found.`
pub async fn delete_session_core(
    state: &AppState,
    rc: &RequestContext,
    object_id: &str,
) -> Result<Json, ParseError> {
    let mut where_ = ParsedWhere::default();
    where_.push(ParsedClause::Field(Constraint::equal(
        "objectId",
        ParseValue::String(object_id.to_string()),
    )));

    let ctx = rc.ctx(state.storage());
    let rows = parse_rust_rest::find(
        &ctx,
        SESSION_CLASS,
        where_,
        FindOptions {
            limit: Some(1),
            ..Default::default()
        },
    )
    .await?;
    if rows.is_empty() {
        return Err(ParseError::new(
            ErrorCode::ObjectNotFound,
            "Object not found for delete.",
        ));
    }

    // The delete itself is master-scoped, because the narrowing above has already established
    // that this row belongs to the caller and `_Session` carries no `_wperm` for the ordinary
    // write constraint to match.
    let schema = rc.snapshot.get_or_default(SESSION_CLASS);
    let query = parse_rust_storage::Query::from_constraints(vec![Constraint::equal(
        "objectId",
        ParseValue::String(object_id.to_string()),
    )]);
    state.storage().delete(&schema, &query).await?;
    Ok(json!({}))
}
