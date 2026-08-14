//! The five `/classes` verbs.
//!
//! Upstream: `src/Routers/ClassesRouter.js`. Response shapes are wire contract and narrower than
//! they look: a create returns `{objectId, createdAt}`, an update returns `{updatedAt}`, and a
//! delete returns `{}`. Returning the whole object would be more helpful and would not match.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use parse_rust_core::{ErrorCode, ParseError, ParseMap, ParseValue};
use parse_rust_rest::AclScope;
use parse_rust_storage::QueryOptions;
use serde_json::{json, Value as Json_};
use std::collections::HashMap;

use crate::auth::Authority;
use crate::response::ParseErrorResponse;
use crate::state::AppState;

/// Map request authority onto an ACL scope.
///
/// Master and maintenance are unrestricted. A session token would produce
/// `AclScope::User`, but session resolution lands with `_User`; until then a client-key request
/// is anonymous, which is the fail-closed direction.
fn scope_for(authority: &Authority, state: &AppState) -> Result<AclScope, ParseError> {
    Ok(match authority {
        Authority::Master | Authority::Maintenance => AclScope::Unrestricted,
        Authority::Client { session_token } => match session_token {
            // A token that does not resolve is an error, not anonymity. See `AppState`.
            Some(token) => state.scope_for_session(token)?,
            None => AclScope::Anonymous,
        },
    })
}

/// Convert a Parse-format map into a JSON response body.
///
/// Strips every `_`-prefixed key first. This is the single audit point for "nothing internal
/// reaches a client", and it runs on every response body this router produces.
fn body_of(row: &ParseMap) -> Json_ {
    let row = parse_rust_rest::to_response_body(row);
    serde_json::from_str(&ParseValue::Object(row).to_json()).unwrap_or(Json_::Null)
}

fn err(e: ParseError) -> Response {
    ParseErrorResponse(e).into_response()
}

/// Decode a JSON request body into Parse values.
fn decode_body(value: Json_) -> Result<ParseMap, ParseError> {
    let map = match parse_rust_core::classify(value)? {
        ParseValue::Object(map) => map,
        _ => return Err(ParseError::invalid_json("body must be an object")),
    };
    // A client must not supply a server-internal column. Without this, a caller could write its
    // own `_rperm` and grant itself read access to a row.
    parse_rust_rest::reject_reserved_keys(&map)?;
    Ok(map)
}

pub async fn create(
    State(state): State<AppState>,
    authority: Authority,
    Path(class_name): Path<String>,
    Json(body): Json<Json_>,
) -> Response {
    if let Err(e) = enforce_class_security(&class_name, &authority, "create") {
        return err(e);
    }
    let scope = match scope_for(&authority, &state) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let mut body = match decode_body(body) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    if class_name == "_User" {
        if let Err(e) = super::users::hash_user_password(&mut body) {
            return err(e);
        }
        super::users::ensure_user_identity_and_acl(&mut body);
    }
    match parse_rust_rest::create(state.storage(), &class_name, body, &scope).await {
        Ok(res) => (
            axum::http::StatusCode::CREATED,
            Json(json!({
                "objectId": res.object_id,
                "createdAt": res.created_at.to_iso(),
            })),
        )
            .into_response(),
        Err(e) => err(e),
    }
}

pub async fn find(
    State(state): State<AppState>,
    authority: Authority,
    Path(class_name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(e) = enforce_class_security(&class_name, &authority, "find") {
        return err(e);
    }
    let scope = match scope_for(&authority, &state) {
        Ok(s) => s,
        Err(e) => return err(e),
    };

    let constraints = match params.get("where") {
        Some(raw) => match serde_json::from_str::<Json_>(raw) {
            Ok(v) => match parse_rust_rest::parse_where(&v) {
                Ok(c) => c,
                Err(e) => return err(e),
            },
            Err(_) => {
                return err(ParseError::invalid_query(
                    "where must be valid JSON".to_string(),
                ))
            }
        },
        None => Vec::new(),
    };

    // `count=1` asks for the count instead of, or alongside, the results.
    let wants_count = params.get("count").map(|c| c == "1").unwrap_or(false);

    let options = QueryOptions {
        // An absent or unparsable `limit` falls back to Parse's default of 100 rather than to
        // "no limit". `limit=0` is a legitimate request for zero rows, usually paired with
        // `count=1`, and must not be read as unlimited either.
        limit: Some(
            params
                .get("limit")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(parse_rust_storage::query::DEFAULT_LIMIT),
        ),
        skip: params.get("skip").and_then(|v| v.parse().ok()),
        order: params
            .get("order")
            .map(|o| QueryOptions::parse_order(o))
            .unwrap_or_default(),
        keys: params
            .get("keys")
            .map(|k| k.split(',').map(str::trim).map(str::to_string).collect()),
    };

    let results = match parse_rust_rest::find(
        state.storage(),
        &class_name,
        constraints.clone(),
        options,
        &scope,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };

    let mut body = json!({ "results": results.iter().map(body_of).collect::<Vec<_>>() });
    if wants_count {
        match parse_rust_rest::count(state.storage(), &class_name, constraints, &scope).await {
            Ok(n) => {
                body["count"] = json!(n);
            }
            Err(e) => return err(e),
        }
    }
    Json(body).into_response()
}

pub async fn get(
    State(state): State<AppState>,
    authority: Authority,
    Path((class_name, object_id)): Path<(String, String)>,
) -> Response {
    if let Err(e) = enforce_class_security(&class_name, &authority, "get") {
        return err(e);
    }
    let scope = match scope_for(&authority, &state) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    match parse_rust_rest::get(state.storage(), &class_name, &object_id, &scope).await {
        Ok(row) => Json(body_of(&row)).into_response(),
        Err(e) => err(e),
    }
}

pub async fn update(
    State(state): State<AppState>,
    authority: Authority,
    Path((class_name, object_id)): Path<(String, String)>,
    Json(body): Json<Json_>,
) -> Response {
    if let Err(e) = enforce_class_security(&class_name, &authority, "update") {
        return err(e);
    }
    let scope = match scope_for(&authority, &state) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let mut body = match decode_body(body) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    if class_name == "_User" {
        if let Err(e) = super::users::hash_user_password(&mut body) {
            return err(e);
        }
    }
    match parse_rust_rest::update(state.storage(), &class_name, &object_id, body, &scope).await {
        Ok(res) => Json(json!({ "updatedAt": res.updated_at.to_iso() })).into_response(),
        Err(e) => err(e),
    }
}

pub async fn delete(
    State(state): State<AppState>,
    authority: Authority,
    Path((class_name, object_id)): Path<(String, String)>,
) -> Response {
    if let Err(e) = enforce_class_security(&class_name, &authority, "delete") {
        return err(e);
    }
    let scope = match scope_for(&authority, &state) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    match parse_rust_rest::delete(state.storage(), &class_name, &object_id, &scope).await {
        // Upstream answers an empty object, not 204.
        Ok(()) => Json(json!({})).into_response(),
        Err(e) => err(e),
    }
}

/// Classes a client may not address through `/classes`.
///
/// `_User` has its own router upstream. A non-master write through `/classes` skips signup and
/// session creation, so it is refused here. Master and maintenance writes are legitimate, but the
/// handlers still run their password and ACL data through the shared user preparation path.
///
/// The master key is exempt, matching upstream: `enforceRoleSecurity` gates non-master callers
/// only, and the dashboard legitimately reads `_User` through the class routes.
fn enforce_class_security(
    class_name: &str,
    authority: &Authority,
    operation: &str,
) -> Result<(), ParseError> {
    if matches!(authority, Authority::Master | Authority::Maintenance) {
        return Ok(());
    }
    // **`_User` writes are refused. This is a deliberate difference from upstream.**
    //
    // Upstream permits `POST /classes/_User` and makes it safe in `RestWrite`, which special-cases
    // `className === "_User"` regardless of route. The allowed master path above mirrors that by
    // sharing password and ACL preparation with signup.
    //
    // Refusing is the fail-closed choice and costs a client only the ability to create a user
    // without a session token. Reads are *not* refused: upstream allows them, they are ACL
    // filtered, and blocking them would break legitimate user queries.
    let write_only_forbidden =
        class_name == "_User" && matches!(operation, "create" | "update" | "delete");

    let forbidden = write_only_forbidden
        || class_name.starts_with("_Join:")
        || matches!(
            class_name,
            "_Session"
                | "_Role"
                | "_Installation"
                | "_JobStatus"
                | "_PushStatus"
                | "_Hooks"
                | "_GlobalConfig"
                | "_GraphQLConfig"
                | "_JobSchedule"
                | "_Audience"
                | "_Idempotency"
        );
    if forbidden {
        return Err(ParseError::new(
            ErrorCode::OperationForbidden,
            format!(
                "Clients aren't allowed to perform the {operation} operation on the {class_name} collection."
            ),
        ));
    }
    Ok(())
}

/// `POST` dispatcher for the collection route.
///
/// The JavaScript SDK sends every request as a `POST` and puts the real method in `_method`.
/// axum matches on the transport method before middleware can rewrite it, so the dispatch happens
/// here, where it is explicit and testable. See `body_credentials`.
pub async fn dispatch_collection(
    state: State<AppState>,
    authority: Authority,
    path: Path<String>,
    query: Query<HashMap<String, String>>,
    method: Option<axum::Extension<crate::body_credentials::MethodOverride>>,
    body: Option<Json<Json_>>,
) -> Response {
    match method.map(|m| m.0 .0) {
        Some(m) if m == axum::http::Method::GET => find(state, authority, path, query).await,
        // No override at all: a genuine POST, which on the collection route is a create.
        None => match body {
            Some(b) => create(state, authority, path, b).await,
            // A body that failed to parse must not become an empty create. `Option<Json<_>>` is
            // `None` for a malformed or oversized body as well as an absent one, so treating that
            // as `{}` turned a rejection into a write.
            None => err(ParseError::invalid_json("body must be a JSON object")),
        },
        // An override we do not implement is an error, not a silent fallthrough to create.
        Some(other) => err(ParseError::new(
            ErrorCode::CommandUnavailable,
            format!("unsupported method override: {other}"),
        )),
    }
}

/// `POST` dispatcher for the object route.
pub async fn dispatch_object(
    state: State<AppState>,
    authority: Authority,
    path: Path<(String, String)>,
    method: Option<axum::Extension<crate::body_credentials::MethodOverride>>,
    body: Option<Json<Json_>>,
) -> Response {
    // There is no POST verb on an object route. A bare POST with no override used to fall through
    // to `update`, so an unrelated request could mutate a row.
    let Some(m) = method.map(|m| m.0 .0) else {
        return err(ParseError::new(
            ErrorCode::CommandUnavailable,
            "POST is not supported on an object route; use PUT, DELETE, or _method",
        ));
    };
    if m == axum::http::Method::GET {
        return get(state, authority, path).await;
    }
    if m == axum::http::Method::DELETE {
        return delete(state, authority, path).await;
    }
    if m != axum::http::Method::PUT {
        return err(ParseError::new(
            ErrorCode::CommandUnavailable,
            format!("unsupported method override: {m}"),
        ));
    }
    match body {
        Some(b) => update(state, authority, path, b).await,
        None => err(ParseError::invalid_json("body must be a JSON object")),
    }
}
