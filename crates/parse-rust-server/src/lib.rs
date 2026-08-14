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
//! Scope today: `/health`, `/serverInfo`, the five `/classes` verbs, and signup, login,
//! `/users/me` and logout. `GET /serverInfo` was built first because it is the smallest thing
//! that forces the whole request path into existence: mount path, header parsing, client-key
//! validation, the master-key gate, and both error envelopes.
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
pub mod body_credentials;
pub mod config;
pub mod response;
pub mod routes;
pub mod sessions;
pub mod state;

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

pub use auth::{Authority, HeaderRejection};
pub use config::ServerConfig;
pub use state::AppState;

/// Extract [`Authority`] from request headers.
///
/// Implemented as an extractor so a route cannot forget it: a handler that wants to know who is
/// calling has to name `Authority` in its signature, and one that does not name it cannot
/// accidentally read a half-validated identity off the request.
#[axum::async_trait]
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
        auth::resolve(&config, &parts.headers).map_err(|HeaderRejection::Unauthorized| {
            response::HttpError::unauthorized().into_response()
        })
    }
}

/// Build the router.
///
/// The mount path is applied here, from config, and is never inferred from the request path.
pub fn router(state: AppState) -> Router {
    let mount = state.config().mount_path.clone();

    let api = Router::new()
        .route("/serverInfo", get(routes::features::server_info))
        // `/health` is credential-free upstream and is the endpoint every bring-up script polls.
        // It reports liveness only until there are dependencies to report on.
        // The SDK transports even a health check as POST with `_method: "GET"`, so accepting
        // only GET returned 405 to `Parse.getServerHealth()`.
        .route(
            "/health",
            get(routes::health::health).post(routes::health::health),
        )
        // Users. `POST /users` is signup and is deliberately not reachable through /classes.
        .route("/users", axum::routing::post(routes::users::signup))
        .route("/users/me", get(routes::users::me).post(routes::users::me))
        .route("/login", axum::routing::post(routes::users::login))
        .route("/logout", axum::routing::post(routes::users::logout))
        // Classes.
        .route(
            "/classes/:className",
            get(routes::classes::find).post(routes::classes::dispatch_collection),
        )
        .route(
            "/classes/:className/:objectId",
            get(routes::classes::get)
                .put(routes::classes::update)
                .delete(routes::classes::delete)
                // The SDK reaches PUT and DELETE through a POST carrying `_method`.
                .post(routes::classes::dispatch_object),
        )
        .with_state(state);

    // The normalization layer wraps the *whole* router rather than the routes inside it, because
    // it rewrites the request method. A layer applied to the inner router runs after axum has
    // already matched on the original method, which turns the SDK's `POST` plus `_method: "PUT"`
    // into a 405 instead of an update.
    Router::new()
        .nest(&mount, api)
        .layer(axum::middleware::from_fn(body_credentials::extract))
}

/// Bind and serve. Returns the bound address, which matters when the caller asked for port 0.
///
/// Creates the unique indexes before binding. That used to live in the binary, which meant an
/// embedder got a server whose `_User` collection accepted duplicate usernames: the write
/// succeeded, no error reached the client, and the collision only surfaced later as two accounts
/// answering to one name. Index creation is part of boot upstream too, so doing it here matches
/// rather than extends. A failure is fatal for the same reason it is fatal upstream.
pub async fn serve(
    state: AppState,
    addr: std::net::SocketAddr,
) -> std::io::Result<(
    std::net::SocketAddr,
    impl std::future::Future<Output = std::io::Result<()>>,
)> {
    state
        .ensure_indexes()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let app = router(state);
    Ok((bound, async move { axum::serve(listener, app).await }))
}
