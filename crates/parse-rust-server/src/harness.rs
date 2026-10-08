//! The conformance harness's control plane. Compiled only with the `test-harness` feature.
//!
//! **Two stages decide whether it answers, and they are different on purpose.** Without the feature there is no handler and no path, so a release binary answers
//! these with the ordinary 404 for an unrouted path. With the feature compiled in but
//! `PARSE_RUST_TESTING` unset, the routes exist and refuse with `OPERATION_FORBIDDEN`, so a harness
//! build started without the variable fails loudly instead of quietly serving a control plane.
//!
//! What lives here is accounting, not behavior. Nothing in this module changes how a request is
//! answered; it records which conformance block sent it, so the harness can prove a passing block
//! reached this server rather than something else.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use parse_rust_core::{ErrorCode, ParseError};
use serde_json::json;

/// The header the harness's REST controller wrapper sets: `<block key>;<phase>`, where the phase is
/// `body` for a request the block's own function sent and `lifecycle` for one a `beforeEach` or
/// `afterEach` sent.
pub const BLOCK_HEADER: &str = "x-parse-conformance-block";

#[derive(Default)]
struct Counts {
    body: u64,
    lifecycle: u64,
}

fn stats() -> &'static Mutex<HashMap<String, Counts>> {
    static STATS: OnceLock<Mutex<HashMap<String, Counts>>> = OnceLock::new();
    STATS.get_or_init(Mutex::default)
}

/// Whether the control plane is switched on for this process.
pub fn enabled() -> bool {
    std::env::var("PARSE_RUST_TESTING").is_ok_and(|v| v == "1" || v == "true")
}

/// Count a tagged request, then serve it untouched.
pub async fn count_tagged(request: Request, next: Next) -> Response {
    if let Some(tag) = request
        .headers()
        .get(BLOCK_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        let (key, phase) = tag.split_once(';').unwrap_or((tag, "body"));
        if let Ok(mut map) = stats().lock() {
            let entry = map.entry(key.to_string()).or_default();
            if phase == "lifecycle" {
                entry.lifecycle += 1;
            } else {
                entry.body += 1;
            }
        }
    }
    next.run(request).await
}

async fn get_stats() -> Response {
    if !enabled() {
        return refused();
    }
    let blocks: serde_json::Map<String, serde_json::Value> = stats()
        .lock()
        .map(|map| {
            map.iter()
                .map(|(k, c)| {
                    (
                        k.clone(),
                        json!({ "body": c.body, "lifecycle": c.lifecycle }),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Json(json!({ "blocks": blocks })).into_response()
}

/// Upstream's `afterEach` between spec blocks: every row gone, then `SchemaCache.clear()`
/// (`spec/helper.js:284-290`). Done in process because the cache is: a reset from outside would
/// leave this server serving the previous block's classes.
async fn reset(state: &crate::state::AppState) -> Response {
    let result = state.storage().delete_all_rows().await;
    state.schema_cache().clear();
    match result {
        Ok(()) => Json(json!({})).into_response(),
        Err(e) => crate::response::ParseErrorResponse(e).into_response(),
    }
}

fn refused() -> Response {
    crate::response::ParseErrorResponse(ParseError::new(
        ErrorCode::OperationForbidden,
        "The control plane is compiled in and PARSE_RUST_TESTING is not set.",
    ))
    .into_response()
}

/// The options this process is running with, in upstream's names, for the harness to compare
/// against what it asked a reconfigure for (Gate H). An option missing here is
/// one the harness cannot verify, so it refuses to map it.
fn resolved(config: &crate::config::ServerConfig) -> serde_json::Value {
    json!({
        "appId": config.app_id,
        "defaultLimit": config.default_limit,
        "maxLimit": config.max_limit,
        "databaseOptions": {
            "allowPublicExplain": config.allow_public_explain,
            "schemaCacheTtl": config.schema_cache_ttl.map(|d| d.as_millis() as u64),
        },
        "allowClientClassCreation": config.allow_client_class_creation,
        "allowCustomObjectId": config.allow_custom_object_id,
        "enableSanitizedErrorResponse": config.enable_sanitized_error_response,
        "accountLockout": config.account_lockout.as_ref().map(|l| json!({
            "duration": l.duration,
            "threshold": l.threshold,
            "unlockOnPasswordReset": l.unlock_on_password_reset,
        })),
        "protectedFieldsOwnerExempt": config.protected_fields_owner_exempt,
        "protectedFieldsSaveResponseExempt": config.protected_fields_save_response_exempt,
        "requestComplexity": { "batchRequestLimit": config.batch_request_limit },
        "masterKeyIps": config.master_key_ips.entries(),
    })
}

/// The control routes, mounted at the root rather than under the API's mount path, so no client
/// route can collide with them.
pub fn routes(state: crate::state::AppState) -> Router {
    let config = state.config_arc();
    Router::new()
        .route("/_control/stats", get(get_stats))
        .route(
            "/_control/reset",
            post(move || {
                let state = state.clone();
                async move {
                    if !enabled() {
                        return refused();
                    }
                    reset(&state).await
                }
            }),
        )
        .route(
            "/_control/config",
            get(move || {
                let config = config.clone();
                async move {
                    if !enabled() {
                        return refused();
                    }
                    Json(resolved(&config)).into_response()
                }
            }),
        )
}
