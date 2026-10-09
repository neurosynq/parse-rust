//! The axum layer: extractors in, [`dispatch`] out.
//!
//! No behavior lives here. Each handler resolves the request context once, names the route it
//! matched, and dispatches. `/batch` reaches the same dispatcher with the same context, which is
//! what keeps a sub-request and a top-level request from being two implementations.
//!
//! **The method override is dispatched explicitly rather than rewritten by middleware.** The
//! JavaScript SDK sends every request as a `POST` with the real method in `_method`, and axum
//! matches on the transport method before a `Router::layer` runs. Verified by observation: a POST
//! carrying `_method: "PUT"` produced a 405 no matter where the layer was attached. So the
//! intended method travels in an extension and is read here. See `body_credentials`.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::Value as Json_;

use crate::auth::Authority;
use crate::body_credentials::{BodyParams, MethodOverride, ParsedBody};
use crate::params::Params;
use crate::response::{HttpError, ParseErrorResponse};
use crate::routes::dispatch::{self, Incoming, Route, RouteError};
use crate::schema_cache::Freshness;
use crate::state::AppState;

/// Run a request's work to completion whether or not its client stays connected.
///
/// axum drops a handler's future when the client disconnects, which cancels it at its next await,
/// part way through a write. Express does not stop a request when its socket closes, so upstream's
/// writes complete. Cancelling mid-way is worse than either outcome: a schema write could land at
/// the database after its cache invalidation had already been consumed, leaving this node serving
/// the old permissions, and a batch could stop with an arbitrary subset of its sub-requests
/// applied. A spawned task is not cancelled by dropping its handle.
///
/// Spawned on the server's task tracker, so a graceful shutdown waits for it even after its client
/// has gone; a plain spawned task was dropped when the process exited, part way through its writes.
async fn detached<F>(state: &AppState, work: F) -> Response
where
    F: std::future::Future<Output = Response> + Send + 'static,
{
    // The benchmark build's per-request database tally lives in a task-local; carry it across.
    #[cfg(feature = "bench-instrumentation")]
    let work = parse_rust_mongo::bench::carry(work);
    match state.tasks().spawn(work).await {
        Ok(response) => response,
        // The task panicked, which no request path is allowed to do; answer as for any internal
        // failure rather than propagate it.
        Err(_) => ParseErrorResponse(parse_rust_core::ParseError::internal(
            "request task failed".to_string(),
        ))
        .into_response(),
    }
}

/// Resolve the context and run one route, detached from the client's connection.
async fn run(state: &AppState, authority: &Authority, incoming: Incoming) -> Response {
    let (owned, authority) = (state.clone(), authority.clone());
    detached(state, async move {
        run_attached(&owned, &authority, incoming).await
    })
    .await
}

/// Resolve the context and run one route.
async fn run_attached(state: &AppState, authority: &Authority, incoming: Incoming) -> Response {
    // **A session token attached to `/login` is discarded before it is resolved**
    // (`middlewares.js:267-268`). Upstream deletes it in `handleParseHeaders`, after the client-key
    // check and before any `Auth` is built, so the token is never looked up at all.
    //
    // Without this, a client holding an expired or revoked token cannot log back in: the generic
    // resolver validates whatever token arrived and answers `Invalid session token` before the
    // credentials in the body are ever read. That is the one situation where the client's only
    // recovery is the route being refused. SDKs keep sending the stored token until a login
    // succeeds, so the failure is self-sustaining rather than transient.
    //
    // Credentials are untouched: only the token is dropped. A master-key login is still a master
    // request, and `/loginAs`, which requires master, is a different route and unaffected.
    //
    // Keyed on the route rather than the path string, and applied here rather than inside the
    // login handler, so it holds for the SDK's `POST`-everything form as well. `/batch` is
    // deliberately not covered: upstream's middleware runs once on the outer HTTP request, so a
    // `/login` nested in a batch sees the outer request's token exactly as it does upstream.
    let authority = &match incoming.route {
        Route::Login => Authority {
            session_token: None,
            ..authority.clone()
        },
        _ => authority.clone(),
    };

    // One snapshot, one role expansion, per HTTP request.
    let rc = match state
        .request_context(authority, incoming.route.schema_freshness())
        .await
    {
        Ok(rc) => rc,
        Err(e) => return ParseErrorResponse(e).into_response(),
    };
    let mut outcome = dispatch::dispatch(state, &rc, authority, &incoming).await;
    // A read reached a class this snapshot predates. Only reads raise it, so running the request
    // again on a rebuilt snapshot repeats no write.
    if matches!(&outcome, Err(RouteError::Parse(e)) if e.is_schema_stale()) {
        outcome = match rc.with_rebuilt_schemas(state).await {
            Ok(fresh) => dispatch::dispatch(state, &fresh, authority, &incoming).await,
            Err(e) => Err(RouteError::Parse(e)),
        };
    }
    match outcome {
        Ok(response) => (response.status, Json(response.body)).into_response(),
        Err(RouteError::Parse(e)) => ParseErrorResponse(e).into_response(),
        Err(RouteError::Http(e)) => e.into_response(),
        // Express answers a bare 404 for a path no router claims, with an HTML body no client
        // parses. The status is what matters and is what a client branches on; the body is the
        // `code`-less HTTP envelope, because inventing a Parse code for "this route does not
        // exist" would make an absent feature look like a rejected request.
        Err(RouteError::NotFound { method, path }) => HttpError {
            status: http::StatusCode::NOT_FOUND,
            message: format!("cannot route {method} {path}"),
        }
        .into_response(),
    }
}

/// Express's answer for a method no route on the path serves: a 404, in the `code`-less envelope.
fn not_found(method: &http::Method, path: &str) -> Response {
    HttpError {
        status: http::StatusCode::NOT_FOUND,
        message: format!("cannot route {method} {path}"),
    }
    .into_response()
}

/// The method a request is really asking for: the `_method` override when the body layer set one,
/// otherwise the transport method. An override that does not parse as a method was already turned
/// into one no route serves, so it answers 404 rather than falling back to the transport method.
fn effective_method(
    transport: http::Method,
    override_: Option<axum::Extension<MethodOverride>>,
) -> http::Method {
    match override_ {
        Some(axum::Extension(MethodOverride(m))) => m,
        // Express serves HEAD with a path's GET handler and sends no body; the HTTP layer drops
        // the body here too.
        None if transport == http::Method::HEAD => http::Method::GET,
        None => transport,
    }
}

/// A read's parameters: the query string over whatever the body carried as [`BodyParams`],
/// merged as upstream merges them. One extractor for both, so a handler cannot take one and
/// forget the other.
pub struct ReadParams(Params);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ReadParams {
    type Rejection = axum::extract::rejection::QueryRejection;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Query(query) =
            Query::<HashMap<String, String>>::from_request_parts(parts, state).await?;
        let body = parts
            .extensions
            .get::<BodyParams>()
            .map(|BodyParams(map)| Json_::Object(map.clone()));
        Ok(Self(Params::merged(query, body.as_ref())))
    }
}

/// A request's JSON body, or none.
///
/// A write's object body arrives already parsed, as [`ParsedBody`]. Anything else is parsed here,
/// and a body that is not JSON is no body, so the response stays in Parse's shape. Not
/// `Option<Json<_>>`: since axum 0.8 that rejects a body whose content type is not JSON with
/// axum's own plain-text 415 before the handler runs.
pub struct JsonBody(pub Option<Json_>);

impl<S: Send + Sync> axum::extract::FromRequest<S> for JsonBody {
    type Rejection = std::convert::Infallible;

    async fn from_request(
        mut request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        if let Some(ParsedBody(body)) = request.extensions_mut().remove::<ParsedBody>() {
            return Ok(Self(Some(body)));
        }
        Ok(Self(
            Json::<Json_>::from_request(request, state)
                .await
                .ok()
                .map(|Json(body)| body),
        ))
    }
}

// -------------------------------------------------------------------------------------------
// Handlers
// -------------------------------------------------------------------------------------------

pub async fn health(State(state): State<AppState>) -> Response {
    // Credential-free upstream, and the endpoint every bring-up script polls, so it does not go
    // through the dispatcher's context resolution: a health check must answer while the database
    // is unreachable, which is the state a caller most wants to distinguish.
    let _ = state;
    Json(crate::routes::health::body()).into_response()
}

pub async fn server_info(
    State(state): State<AppState>,
    authority: Authority,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
) -> Response {
    // GET only (`FeaturesRouter.js`), reached by a `POST` overridden to `GET` too.
    let method = effective_method(transport, method);
    if method != http::Method::GET {
        return not_found(&method, "/serverInfo");
    }
    // The one route that needs no request context: it reads config and nothing else, so it stays
    // answerable when the database is down.
    if !authority.is_master() {
        return HttpError::master_key_required(state.config().error_detail()).into_response();
    }
    Json(crate::routes::features::server_info_body(state.config())).into_response()
}

pub async fn users_collection(
    State(state): State<AppState>,
    authority: Authority,
    ReadParams(params): ReadParams,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    JsonBody(body): JsonBody,
) -> Response {
    let method = effective_method(transport, method);
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::Users,
            params,
            body,
            path: "/users".to_string(),
        },
    )
    .await
}

pub async fn users_object(
    State(state): State<AppState>,
    authority: Authority,
    Path(object_id): Path<String>,
    ReadParams(params): ReadParams,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    JsonBody(body): JsonBody,
) -> Response {
    let method = effective_method(transport, method);
    let path = format!("/users/{object_id}");
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::UserObject { object_id },
            params,
            body,
            path,
        },
    )
    .await
}

pub async fn users_me(
    State(state): State<AppState>,
    authority: Authority,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    ReadParams(params): ReadParams,
    JsonBody(body): JsonBody,
) -> Response {
    // The SDK reaches this as a POST carrying `_method: "GET"`.
    let method = effective_method(transport, method);
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::UsersMe,
            // Any method but GET reaches the objectId route with `me` (see `Route::for_method`),
            // which reads the request's parameters and body like any other.
            params,
            body,
            path: "/users/me".to_string(),
        },
    )
    .await
}

pub async fn login(
    State(state): State<AppState>,
    authority: Authority,
    Query(query): Query<HashMap<String, String>>,
    method: Option<axum::Extension<MethodOverride>>,
    body_params: Option<axum::Extension<BodyParams>>,
    transport: http::Method,
    JsonBody(body): JsonBody,
) -> Response {
    let method = effective_method(transport, method);
    // An overridden `GET` had its body moved into [`BodyParams`]; upstream's `req.body` is still
    // that body, so it is put back here.
    let body = match body_params {
        Some(axum::Extension(BodyParams(map))) => Some(Json_::Object(map)),
        None => body,
    };
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::Login,
            params: Params::default(),
            body: Some(login_payload(body, query)),
            path: "/login".to_string(),
        },
    )
    .await
}

/// The object a login reads its credentials from (`UsersRouter.js:72-80`).
///
/// The body, unless it lacks a truthy `username` and the query string has one, or lacks a truthy
/// `email` and the query string has one; then the query string, whole. That is what serves
/// `GET /login?username=..&password=..` and a `POST` that carries its credentials in the URL. The
/// two are never merged: a password in the body does not survive the switch.
fn login_payload(body: Option<Json_>, query: HashMap<String, String>) -> Json_ {
    let body = match body {
        Some(Json_::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    let truthy = |key: &str| match body.get(key) {
        None | Some(Json_::Null) | Some(Json_::Bool(false)) => false,
        Some(Json_::String(s)) => !s.is_empty(),
        Some(Json_::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(_) => true,
    };
    let in_query = |key: &str| query.get(key).is_some_and(|v| !v.is_empty());
    let use_query =
        (!truthy("username") && in_query("username")) || (!truthy("email") && in_query("email"));
    if use_query {
        Json_::Object(
            query
                .into_iter()
                .map(|(k, v)| (k, Json_::String(v)))
                .collect(),
        )
    } else {
        Json_::Object(body)
    }
}

pub async fn logout(
    State(state): State<AppState>,
    authority: Authority,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
) -> Response {
    let method = effective_method(transport, method);
    if method != http::Method::POST {
        return not_found(&method, "/logout");
    }
    run(
        &state,
        &authority,
        Incoming {
            method: http::Method::POST,
            route: Route::Logout,
            params: Params::default(),
            body: None,
            path: "/logout".to_string(),
        },
    )
    .await
}

pub async fn classes_collection(
    State(state): State<AppState>,
    authority: Authority,
    Path(class_name): Path<String>,
    ReadParams(params): ReadParams,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    JsonBody(body): JsonBody,
) -> Response {
    let method = effective_method(transport, method);
    let path = format!("/classes/{class_name}");
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::Classes { class_name },
            params,
            body,
            path,
        },
    )
    .await
}

pub async fn classes_object(
    State(state): State<AppState>,
    authority: Authority,
    Path((class_name, object_id)): Path<(String, String)>,
    ReadParams(params): ReadParams,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    JsonBody(body): JsonBody,
) -> Response {
    // There is no POST verb on an object route. A bare POST with no override used to fall through
    // to `update`, so an unrelated request could mutate a row; an override-free POST now reaches
    // the dispatcher as POST and finds no arm.
    let method = effective_method(transport, method);
    let path = format!("/classes/{class_name}/{object_id}");
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::ClassObject {
                class_name,
                object_id,
            },
            params,
            body,
            path,
        },
    )
    .await
}

pub async fn roles_collection(
    State(state): State<AppState>,
    authority: Authority,
    ReadParams(params): ReadParams,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    JsonBody(body): JsonBody,
) -> Response {
    let method = effective_method(transport, method);
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::Roles,
            params,
            body,
            path: "/roles".to_string(),
        },
    )
    .await
}

pub async fn roles_object(
    State(state): State<AppState>,
    authority: Authority,
    Path(object_id): Path<String>,
    ReadParams(params): ReadParams,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    JsonBody(body): JsonBody,
) -> Response {
    let method = effective_method(transport, method);
    let path = format!("/roles/{object_id}");
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::RoleObject { object_id },
            params,
            body,
            path,
        },
    )
    .await
}

pub async fn sessions_collection(
    State(state): State<AppState>,
    authority: Authority,
    ReadParams(params): ReadParams,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
) -> Response {
    let method = effective_method(transport, method);
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::Sessions,
            params,
            body: None,
            path: "/sessions".to_string(),
        },
    )
    .await
}

pub async fn sessions_me(
    State(state): State<AppState>,
    authority: Authority,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    ReadParams(params): ReadParams,
    JsonBody(body): JsonBody,
) -> Response {
    let method = effective_method(transport, method);
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::SessionsMe,
            // Any method but GET reaches the objectId route with `me` (see `Route::for_method`),
            // which reads the request's parameters and body like any other.
            params,
            body,
            path: "/sessions/me".to_string(),
        },
    )
    .await
}

pub async fn sessions_object(
    State(state): State<AppState>,
    authority: Authority,
    Path(object_id): Path<String>,
    ReadParams(params): ReadParams,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
) -> Response {
    let method = effective_method(transport, method);
    let path = format!("/sessions/{object_id}");
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::SessionObject { object_id },
            params,
            body: None,
            path,
        },
    )
    .await
}

pub async fn schemas_collection(
    State(state): State<AppState>,
    authority: Authority,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    JsonBody(body): JsonBody,
) -> Response {
    let method = effective_method(transport, method);
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::Schemas,
            params: Params::default(),
            body,
            path: "/schemas".to_string(),
        },
    )
    .await
}

pub async fn schemas_class(
    State(state): State<AppState>,
    authority: Authority,
    Path(class_name): Path<String>,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    JsonBody(body): JsonBody,
) -> Response {
    let method = effective_method(transport, method);
    let path = format!("/schemas/{class_name}");
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::SchemaClass { class_name },
            params: Params::default(),
            body,
            path,
        },
    )
    .await
}

pub async fn purge(
    State(state): State<AppState>,
    authority: Authority,
    Path(class_name): Path<String>,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
) -> Response {
    let method = effective_method(transport, method);
    let path = format!("/purge/{class_name}");
    run(
        &state,
        &authority,
        Incoming {
            method,
            route: Route::Purge { class_name },
            params: Params::default(),
            body: None,
            path,
        },
    )
    .await
}

/// `POST /batch`.
///
/// Not routed through [`dispatch`], because a batch is the thing that *calls* the dispatcher. The
/// context is resolved here, once, and shared by every sub-request.
pub async fn batch(
    State(state): State<AppState>,
    authority: Authority,
    method: Option<axum::Extension<MethodOverride>>,
    transport: http::Method,
    original_url: Option<axum::Extension<crate::OriginalUrl>>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    JsonBody(body): JsonBody,
) -> Response {
    let method = effective_method(transport, method);
    if method != http::Method::POST {
        return not_found(&method, "/batch");
    }
    // The URL before `express_path` rewrote it. An embedder that routes this handler without that
    // layer has no extension, and then the URI axum saw before nesting is the same thing.
    let original_url = original_url
        .map(|axum::Extension(crate::OriginalUrl(url))| url)
        .unwrap_or_else(|| {
            uri.path_and_query()
                .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string())
        });
    // The session first, as upstream's middleware resolves it before the batch handler runs. The
    // classes the sub-requests name are loaded by `handle` once the batch has been validated, so a
    // batch refused for its size or shape costs no schema lookup.
    let tracker = state.clone();
    detached(&tracker, async move {
        let mut rc = match state.request_context(&authority, Freshness::Cached).await {
            Ok(rc) => rc,
            Err(e) => return ParseErrorResponse(e).into_response(),
        };
        match crate::routes::batch::handle(
            &state,
            &mut rc,
            &authority,
            &original_url,
            body.as_ref(),
        )
        .await
        {
            Ok(results) => Json(results).into_response(),
            Err(e) => ParseErrorResponse(e).into_response(),
        }
    })
    .await
}
