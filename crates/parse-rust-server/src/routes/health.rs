//! `GET /health`. Credential-free upstream, and the endpoint every bring-up script polls.
//!
//! It reports liveness only, and that is now a known gap rather than a pending one: storage has
//! landed, so this must learn to distinguish "process up" from "database reachable". A health
//! endpoint that returns ok before its dependencies are connected turns every startup race into a
//! mystery test failure, because the harness stops polling exactly when the server is least ready.

use axum::response::{IntoResponse, Response};
use serde_json::json;

pub async fn health() -> Response {
    axum::Json(json!({ "status": "ok" })).into_response()
}
