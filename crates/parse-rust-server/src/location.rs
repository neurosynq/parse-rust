//! The `Location` header on a create.
//!
//! Upstream's create answers 201 with `Location` set to the new object's URL (`PromiseRouter.js:174-175`),
//! built by `RestWrite.location` as the request's mount plus `/users/` for a `_User` or
//! `/classes/<className>/` for anything else, plus the objectId (`RestWrite.js:1984-1988`). The
//! mount is `req.protocol + '://' + req.get('host') + mountPath` (`middlewares.js:21-25`); without
//! `trustProxy`, which parse-rust does not implement, the protocol is the connection's.
//!
//! A response middleware rather than a route concern: it needs the request's host and mount and
//! nothing a route knows beyond the class and the new objectId, both readable from the path and the
//! response.

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::body_credentials::MethodOverride;
use crate::routes::dispatch::{route_of, Route};

pub async fn stamp(State(mount): State<String>, request: Request, next: Next) -> Response {
    let method = request
        .extensions()
        .get::<MethodOverride>()
        .map(|MethodOverride(m)| m.clone())
        .unwrap_or_else(|| request.method().clone());
    let host = request
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let prefix = mount.trim_end_matches('/').to_string();
    let middle = request
        .uri()
        .path()
        .strip_prefix(prefix.as_str())
        .and_then(route_of)
        .and_then(|route| match route {
            Route::Classes { class_name } if class_name == "_User" => Some("/users/".to_string()),
            Route::Classes { class_name } => Some(format!("/classes/{class_name}/")),
            Route::Users => Some("/users/".to_string()),
            Route::Roles => Some("/classes/_Role/".to_string()),
            _ => None,
        });

    let response = next.run(request).await;
    let (Some(middle), Some(host)) = (middle, host) else {
        return response;
    };
    if method != http::Method::POST || response.status() != http::StatusCode::CREATED {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    // Unbounded: this is the server's own response, already built, and a create echoes back
    // whatever its operations and defaults produced, which has no size of its own. A limit here
    // turned a large echo into an empty 201 after the write had succeeded.
    let Ok(bytes) = to_bytes(body, usize::MAX).await else {
        return Response::from_parts(parts, Body::empty());
    };
    let object_id = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.get("objectId")
                .and_then(|id| id.as_str())
                .map(str::to_string)
        });
    if let Some(id) = object_id {
        let location = format!("http://{host}{prefix}{middle}{id}");
        if let Ok(value) = http::HeaderValue::from_str(&location) {
            parts.headers.insert(http::header::LOCATION, value);
        }
    }
    Response::from_parts(parts, Body::from(bytes))
}
