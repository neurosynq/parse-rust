//! Normalizing what the JavaScript SDK actually sends.
//!
//! The SDK does not speak the REST API the documentation describes. Everything is a `POST` with a
//! `text/plain` body, and the method, the credentials and the query parameters all travel inside
//! that body. It does this so a browser never sends a CORS preflight.
//!
//! Upstream normalizes all of it before routing, in three places:
//!
//! - `allowMethodOverride` (`middlewares.js:425-433`) rewrites the method from `_method`.
//! - `handleParseHeaders` (`:111-198`) reads `_ApplicationId`, `_JavaScriptKey`, `_MasterKey`,
//!   `_SessionToken`, `_InstallationId`, `_ContentType` and friends from the body, and **deletes
//!   them**, which is why a saved Parse object never grows an `_ApplicationId` field.
//! - `ClassesRouter` merges `req.body` with the decoded query string, so a `where` sent in the
//!   body reaches the same code as one sent in the URL.
//!
//! Doing all three here, in one layer, is deliberate. Spreading it across the extractor and each
//! route is how a check ends up applied on one path and forgotten on another.

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use serde_json::Value as Json;

use crate::auth::headers;

/// The method the client asked for through `_method`, when it differs from the transport method.
///
/// Read by the `POST` dispatchers on the class and user routes.
#[derive(Debug, Clone)]
pub struct MethodOverride(pub http::Method);

/// The parameters a read carried in its body, still typed as the JSON they arrived as.
///
/// Kept apart from the query string rather than merged into it, because the two are decoded
/// differently upstream: `JSONFromQuery` parses each query value as JSON, and a body value is
/// already JSON (`ClassesRouter.js:23`, `:148-158`). Flattening a body string into the URL made a
/// body `{"comment":"123"}` the number 123 and a body `{"explain":"true"}` the boolean `true`.
#[derive(Debug, Clone, Default)]
pub struct BodyParams(pub serde_json::Map<String, Json>);

/// Body key to header name.
const CREDENTIALS: [(&str, &str); 6] = [
    ("_ApplicationId", headers::APP_ID),
    ("_JavaScriptKey", headers::JAVASCRIPT_KEY),
    ("_MasterKey", headers::MASTER_KEY),
    ("_MaintenanceKey", headers::MAINTENANCE_KEY),
    ("_SessionToken", headers::SESSION_TOKEN),
    ("_InstallationId", headers::INSTALLATION_ID),
];

/// Keys that carry no authority but must still be removed, or they become fields on saved objects.
const DISCARDED: [&str; 4] = [
    "_ClientVersion",
    "_RevocableSession",
    "_noBody",
    "_ContentType",
];

/// Upper bound on a buffered body. Without one, a request could exhaust memory.
const MAX_BODY: usize = 20 * 1024 * 1024;

pub async fn extract(request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();

    let bytes = match to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return next.run(Request::from_parts(parts, Body::empty())).await,
    };

    // Not a JSON object body: nothing to normalize. Covers every GET.
    let Ok(Json::Object(mut map)) = serde_json::from_slice::<Json>(&bytes) else {
        return next
            .run(Request::from_parts(parts, Body::from(bytes)))
            .await;
    };

    // 1. Credentials into headers. An explicit header wins, because upstream consults the body
    //    only when the header appId is missing or unknown.
    for (body_key, header_name) in CREDENTIALS {
        let Some(Json::String(value)) = map.shift_remove(body_key) else {
            continue;
        };
        if parts.headers.contains_key(header_name) {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            http::HeaderName::from_bytes(header_name.as_bytes()),
            http::HeaderValue::from_str(&value),
        ) {
            parts.headers.insert(name, val);
        }
    }
    for key in DISCARDED {
        map.shift_remove(key);
    }

    // 2. Method override. The SDK sends every read as `POST` with `_method: "GET"`.
    //
    // **The method is NOT rewritten here, and that is not a stylistic choice.** axum matches the
    // request method before a `Router::layer` runs, verified by observation: a POST carrying
    // `_method: "PUT"` produced a 405 no matter where the layer was attached. So the intended
    // method travels in an extension and the routes dispatch on it explicitly, which is
    // deterministic and testable rather than dependent on middleware ordering inside the
    // framework.
    let overridden = match map.shift_remove("_method") {
        Some(Json::String(m)) => m.parse::<http::Method>().ok(),
        _ => None,
    };
    if let Some(method) = overridden.clone() {
        parts.extensions.insert(MethodOverride(method));
    }

    // 3. For a read, the remaining body keys are query parameters. They travel to the route as
    //    an extension, typed, and the route merges them under the query string. See
    //    [`BodyParams`].
    let effective = overridden.clone().unwrap_or_else(|| parts.method.clone());
    if effective == http::Method::GET || effective == http::Method::DELETE {
        if !map.is_empty() {
            parts.extensions.insert(BodyParams(map));
        }
        // A GET carries no body.
        let trace = std::env::var("PARSE_RUST_TRACE").is_ok();
        let (m, u) = (parts.method.clone(), parts.uri.clone());
        let res = next.run(Request::from_parts(parts, Body::empty())).await;
        if trace {
            eprintln!("[trace] {m} {u} -> {}", res.status());
        }
        return res;
    }

    // The body has just been shown to parse as JSON, so declaring it as such is a statement of
    // fact. axum's `Json` extractor requires the header; Express's parser does not, and the SDK
    // sends `text/plain`.
    parts.headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );

    let body = match serde_json::to_vec(&Json::Object(map)) {
        Ok(v) => Body::from(v),
        Err(_) => Body::from(bytes),
    };
    let trace = std::env::var("PARSE_RUST_TRACE").is_ok();
    let (m, u) = (parts.method.clone(), parts.uri.clone());
    let res = next.run(Request::from_parts(parts, body)).await;
    if trace {
        eprintln!("[trace] {m} {u} -> {}", res.status());
    }
    res
}
