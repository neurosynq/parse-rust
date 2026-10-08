//! Parse Server as a library: router, middleware, config.
//!
//! **A library first, with a thin binary on top.** Native Rust triggers require the deployment
//! to compile its own binary, and adapters are registered through a builder rather than resolved
//! from a module name, so the primary artifact is something you link against. `parse-rust-cli`
//! is a separate package rather than a feature of this one: feature unification means a sibling
//! crate enabling a `cli` feature would pull its dependencies back in even for an embedder that
//! set `default-features = false`, and a separate package cannot be re-enabled by anyone else's
//! feature choice.
//!
//! Scope today: `/health` and `/serverInfo`; signup, login, `/users/me` and logout; the five
//! `/classes` verbs and the five `/roles` verbs; the five `/schemas` verbs and
//! `DELETE /purge/:className`, all master-key only; four `/sessions` reads; and `POST /batch`.
//! Everything else answers 404.
//!
//! **Two things are resolved once per HTTP request and shared by every operation in it**: the
//! schema snapshot and the caller's expanded role list. See [`request`]. A `/batch` of twenty
//! writes therefore expands roles once and cannot see two different schemas mid-flight, which is
//! a correctness property rather than a performance one.
//!
//! **An embedder that builds the router itself must call [`AppState::ensure_indexes`] first.**
//! [`serve`] does it for you. Mounting [`router`] into your own axum app does not, and without
//! those indexes duplicate usernames are accepted silently, which is a data problem rather than
//! an error anyone sees.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod auth;
#[cfg(feature = "bench-instrumentation")]
pub mod bench;
pub mod body_credentials;
pub mod config;
pub mod cors;
#[cfg(feature = "test-harness")]
pub mod harness;
pub mod ip_allowlist;
pub mod location;
pub mod lockout;
pub mod params;
pub mod request;
pub mod response;
pub mod routes;
pub mod schema_cache;
pub mod state;

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;

pub use auth::{Authority, Credentials, HeaderRejection, Peer};
pub use config::{ProtectedFieldsConfig, ServerConfig};
pub use ip_allowlist::{InvalidIpEntry, IpAllowlist};
pub use request::RequestContext;
pub use state::AppState;

/// Extract [`Authority`] from request headers and the connection's peer address.
///
/// Implemented as an extractor so a route cannot forget it: a handler that wants to know who is
/// calling has to name `Authority` in its signature, and one that does not name it cannot
/// accidentally read a half-validated identity off the request.
///
/// The peer address comes from `ConnectInfo`, which [`serve`] installs. An embedder that builds
/// the router itself and serves it without `into_make_service_with_connect_info` gets
/// [`Peer::Unknown`], and every master-key and maintenance-key request is then refused. That is
/// the intended direction: the alternative, treating an absent address as unfiltered, is the
/// 0.2.0 behavior this release exists to remove.
impl<S> FromRequestParts<S> for Authority
where
    Arc<ServerConfig>: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let config = <Arc<ServerConfig> as axum::extract::FromRef<S>>::from_ref(state);
        auth::resolve_with_peer(&config, &parts.headers, peer_of(parts)).map_err(
            |HeaderRejection::Unauthorized| response::HttpError::unauthorized().into_response(),
        )
    }
}

/// The connection's peer address, read from the extension `ConnectInfo` inserts.
///
/// **Deliberately not a header.** `X-Forwarded-For` and `Forwarded` are written by the caller, and
/// an allowlist that consults them admits anyone who can spell an address. Upstream is the same:
/// `getClientIp` is `req.ip` (`middlewares.js:358-360`) and parse-server never enables Express's
/// `trust proxy`.
fn peer_of(parts: &http::request::Parts) -> Peer {
    parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| Peer::from(info.0))
        .unwrap_or(Peer::Unknown)
}

/// Build the router.
///
/// The mount path is applied here, from config, and is never inferred from the request path.
///
/// A mount path [`ServerConfig::check_mount_path`] refuses gets a router that serves nothing, so
/// every request is a 404, and the refusal is written to standard error. [`serve`] and the binary
/// refuse such a path before getting here; an embedder calling this directly should check first.
///
/// **The router carries its own fallback**, an empty 404 for an unrouted path, and at a root mount
/// the API is itself the fallback service. So nest it with `nest` or `nest_service`; do not `merge`
/// it into a router that has a fallback, which axum refuses by panicking, and do not call
/// `.fallback()` on it, which at a root mount replaces the whole API.
pub fn router(state: AppState) -> Router {
    if let Err(why) = state.config().check_mount_path() {
        eprintln!("parse-rust: serving nothing: {why}");
        return Router::new();
    }
    let mount = state.config().mount_path.clone();
    // Cloned before `with_state` consumes it below, so the CORS layer can read the same config.
    let cors_state = state.clone();
    #[cfg(feature = "test-harness")]
    let harness_state = state.clone();

    // The 0.2.0 surface, and nothing else: anything not registered here is a 404. Every route
    // that a client can reach through a `_method` override also accepts `POST`, because the
    // JavaScript SDK transports everything that way.
    //
    // Known differences from Express's routing, none reproduced yet: Express matches paths
    // case-insensitively, so `/Classes/Foo` is a read upstream and a 404 here; it serves a `HEAD`,
    // including one asked for by `_method`, through the `GET` route; and it resolves an invalid
    // session token before routing, so an unrouted path with a bad token is 209 upstream and 404
    // here.
    let api = Router::new()
        .route("/serverInfo", any(routes::http::server_info))
        // `/health` is credential-free upstream and is the endpoint every bring-up script polls.
        // The SDK transports even a health check as POST with `_method: "GET"`, so accepting
        // only GET returned 405 to `Parse.getServerHealth()`.
        .route("/health", any(routes::http::health))
        // Users. `POST /users` is signup and is deliberately not reachable through /classes.
        .route("/users", any(routes::http::users_collection))
        .route("/users/me", any(routes::http::users_me))
        .route("/users/{objectId}", any(routes::http::users_object))
        .route("/login", any(routes::http::login))
        .route("/logout", any(routes::http::logout))
        // Classes.
        .route(
            "/classes/{className}",
            any(routes::http::classes_collection),
        )
        .route(
            "/classes/{className}/{objectId}",
            any(routes::http::classes_object),
        )
        // Roles: `ClassesRouter` with `className()` pinned to `_Role` (`RolesRouter.js:3-25`).
        .route("/roles", any(routes::http::roles_collection))
        .route("/roles/{objectId}", any(routes::http::roles_object))
        // Sessions. `/sessions/me` is registered before `/sessions/:objectId` because upstream
        // depends on registration order (`SessionsRouter.js:113-121`). axum matches a literal
        // segment ahead of a parameter regardless, which the route tests assert; the order is
        // kept anyway so the two files read the same way.
        .route("/sessions/me", any(routes::http::sessions_me))
        .route("/sessions", any(routes::http::sessions_collection))
        .route("/sessions/{objectId}", any(routes::http::sessions_object))
        // Schemas and purge, master key only.
        .route("/schemas", any(routes::http::schemas_collection))
        .route("/schemas/{className}", any(routes::http::schemas_class))
        .route("/purge/{className}", any(routes::http::purge))
        .route("/batch", any(routes::http::batch))
        // axum's `Json` extractor has its own 2 MB default, under the 20 MB `maxUploadSize` the body
        // layer enforces, so a body between the two was refused as not JSON.
        .layer(axum::extract::DefaultBodyLimit::max(
            body_credentials::MAX_BODY,
        ))
        .fallback(not_found)
        .with_state(state);

    // The normalization layer wraps the *whole* router rather than the routes inside it, because
    // it rewrites the request method. A layer applied to the inner router runs after axum has
    // already matched on the original method, which turns the SDK's `POST` plus `_method: "PUT"`
    // into a 405 instead of an update.
    // CORS is the outermost layer, matching upstream, where `allowCrossDomain` is the first
    // middleware on the router (`ParseServer.ts:312`). Outermost is what makes the headers appear
    // on error responses too, and what lets an `OPTIONS` preflight be answered before anything
    // downstream can reject it for lacking credentials it is not allowed to send yet.
    // Trimmed as `body_credentials` trims it. Mounted as an opaque service, because `nest` and
    // `merge` copy the API's routes into this router, where they are matched before the layers
    // below run, and those layers rewrite the method and the path. At the root it is the fallback
    // service, since `nest_service` refuses a root or empty prefix by panicking.
    let app = match mount.trim_end_matches('/') {
        "" => Router::new().fallback_service(api),
        prefix => Router::new().nest_service(prefix, api).fallback(not_found),
    };
    // Inside the body layer, so it sees the method a `_method` override asked for.
    let app = app.layer(axum::middleware::from_fn_with_state(
        mount.clone(),
        location::stamp,
    ));
    // The conformance control plane, in a harness build only. See `harness` for the two stages.
    #[cfg(feature = "test-harness")]
    let app = app
        .merge(harness::routes(harness_state))
        .layer(axum::middleware::from_fn(harness::count_tagged));
    // Innermost of the outer layers, so the timing covers the request's own work only.
    #[cfg(feature = "bench-instrumentation")]
    let app = app.layer(axum::middleware::from_fn(bench::instrument));
    app.layer(axum::middleware::from_fn_with_state(mount, express_path))
        .layer(axum::middleware::from_fn_with_state(
            cors_state.clone(),
            body_credentials::extract,
        ))
        .layer(axum::middleware::from_fn_with_state(
            cors_state,
            cors::layer,
        ))
}

/// An unrouted path: an empty 404. Since axum 0.8 the default one omits `content-length` on a
/// `HEAD`, where it used to send `0` as it does for every other method, so it is stated here.
async fn not_found() -> Response {
    (
        http::StatusCode::NOT_FOUND,
        [(http::header::CONTENT_LENGTH, "0")],
    )
        .into_response()
}

/// Where a request path lands below the mount, by the rules [`express_path`] applies.
pub(crate) enum BelowMount<'a> {
    /// Not below the mount at all.
    Outside,
    /// Below it, but matching no route: an empty segment remains.
    NoRoute,
    /// The path after the mount, normalized: `""` or starting with `/`.
    At(&'a str),
}

/// The one normalization, shared by routing and by the body layer's `/health` test, so the two
/// cannot disagree about which route a path is.
pub(crate) fn below_mount<'a>(path: &'a str, mount: &str) -> BelowMount<'a> {
    let prefix = mount.trim_end_matches('/');
    let Some(rest) = path
        .strip_prefix(prefix)
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
    else {
        return BelowMount::Outside;
    };
    let rest = rest
        .strip_prefix('/')
        .filter(|r| r.starts_with('/'))
        .unwrap_or(rest);
    let rest = match rest.strip_suffix('/') {
        Some(trimmed) if !trimmed.is_empty() => trimmed,
        _ => rest,
    };
    if rest.contains("//") {
        BelowMount::NoRoute
    } else {
        BelowMount::At(rest)
    }
}

/// The request's path and query as the client sent them, before `express_path` rewrote them:
/// Express's `req.originalUrl`, which the batch route reads.
#[derive(Debug, Clone)]
pub struct OriginalUrl(pub String);

/// Match paths below the mount as Express does, which axum does not by default.
///
/// Three rules, applied to the part after the mount only, so a mount that itself contains `//`
/// is matched literally. `allowDoubleForwardSlash` strips one leading `/` (`middlewares.js:
/// 863-866`), so `/parse//classes/X` is `/parse/classes/X`. Express routes are non-strict, so one
/// trailing slash is optional. And a `:param` matches one or more characters, so an empty segment
/// that remains matches no route: `/classes//abc` is a 404 there, where axum would hand a route an
/// empty class name.
async fn express_path(
    axum::extract::State(mount): axum::extract::State<String>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let original = request.uri().path_and_query().map_or_else(
        || request.uri().path().to_string(),
        |pq| pq.as_str().to_string(),
    );
    request.extensions_mut().insert(OriginalUrl(original));

    let prefix = mount.trim_end_matches('/');
    let path = request.uri().path();
    let rest = match below_mount(path, &mount) {
        BelowMount::Outside => return next.run(request).await,
        BelowMount::NoRoute => return not_found().await,
        BelowMount::At(rest) => rest,
    };
    let rewritten_path = format!("{prefix}{rest}");
    if rewritten_path != path {
        let rewritten = match request.uri().query() {
            Some(query) => format!("{rewritten_path}?{query}"),
            None => rewritten_path,
        };
        let mut parts = request.uri().clone().into_parts();
        match rewritten.parse() {
            Ok(path_and_query) => parts.path_and_query = Some(path_and_query),
            Err(_) => return not_found().await,
        }
        match http::Uri::from_parts(parts) {
            Ok(uri) => *request.uri_mut() = uri,
            Err(_) => return not_found().await,
        }
    }
    next.run(request).await
}

/// Bind and serve. Returns the bound address, which matters when the caller asked for port 0.
///
/// Creates the unique indexes before binding. That used to live in the binary, which meant an
/// embedder got a server whose `_User` collection accepted duplicate usernames: the write
/// succeeded, no error reached the client, and the collision only surfaced later as two accounts
/// answering to one name. Index creation is part of boot upstream too, so doing it here matches
/// rather than extends. A failure is fatal for the same reason it is fatal upstream.
///
/// **Served with connect info**, because `masterKeyIps` filters on the connection's peer address
/// and there is nowhere else to get it. Without it the two privileged keys are refused outright.
pub async fn serve(
    state: AppState,
    addr: std::net::SocketAddr,
) -> std::io::Result<(
    std::net::SocketAddr,
    impl std::future::Future<Output = std::io::Result<()>>,
)> {
    state
        .config()
        .check_mount_path()
        .map_err(|why| std::io::Error::new(std::io::ErrorKind::InvalidInput, why))?;
    state
        .ensure_indexes()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let app = router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    Ok((bound, async move { axum::serve(listener, app).await }))
}
