//! `POST /batch`.
//!
//! Upstream: `src/batch.js`. The body is `{requests: [{method, path, body}, ...]}` and the
//! response is the results **array itself**, not an object wrapping it (`batch.js:195`).
//!
//! Sub-requests share one auth, one role expansion and one schema snapshot with the request that
//! carried them, which is upstream's `request.auth = req.auth` (`batch.js:168`) plus the fact that
//! everything downstream takes the schema controller it was handed. Twenty writes in one batch
//! therefore cannot see two different schemas mid-flight.
//!
//! **`transaction: true` is refused rather than accepted and ignored.** Upstream opens a real
//! transactional session for it (`batch.js:156-157`) and rolls the whole batch back on any error.
//! parse-rust has no transaction support, and a client that asked for all-or-nothing and silently
//! got per-operation semantics is the failure mode this milestone names by name.

use parse_rust_core::{ErrorCode, ErrorOrigin, ParseError};
use serde_json::{json, Value as Json};

use crate::auth::Authority;
use crate::params::Params;
use crate::request::RequestContext;
use crate::routes::dispatch::{self, RouteError};
use crate::state::AppState;

/// `/batch`, as a routable path. The suffix stripped from the request URL to find the API prefix.
const BATCH_PATH: &str = "/batch";

/// Run a batch.
///
/// `mount_path` is the configured mount, which is what upstream derives by removing the trailing
/// `/batch` from `req.originalUrl` (`batch.js:27-28`). Taking it from config rather than
/// reconstructing it is the same rule that applies to every other generated path: the mount is a
/// builder input, never inferred from the request.
pub async fn handle(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    mount_path: &str,
    body: Option<&Json>,
) -> Result<Json, ParseError> {
    let Some(Json::Object(body)) = body else {
        return Err(ParseError::invalid_json("requests must be an array"));
    };

    if matches!(body.get("transaction"), Some(Json::Bool(true))) {
        return Err(ParseError::new(
            ErrorCode::CommandUnavailable,
            "Batch transactions are not supported yet. Retry without `transaction: true`; \
             the sub-requests will be applied independently and reported per operation.",
        ));
    }

    let Some(Json::Array(requests)) = body.get("requests") else {
        return Err(ParseError::invalid_json("requests must be an array"));
    };

    // `batchRequestLimit` defaults to -1, which disables it. Master and maintenance bypass it
    // (`batch.js:72-78`).
    let limit = state.config().batch_request_limit;
    if limit > -1 && !authority.is_privileged() && requests.len() as i64 > limit {
        return Err(ParseError::invalid_json(format!(
            "Batch request contains {} sub-requests, which exceeds the limit of {limit}.",
            requests.len()
        )));
    }

    // Both validation passes run over the whole array before anything executes, so a batch with
    // one malformed element performs none of the others (`batch.js:79-83`, `:104-108`).
    let mut parsed = Vec::with_capacity(requests.len());
    for request in requests {
        let Json::Object(request) = request else {
            return Err(ParseError::invalid_json(
                "batch request path must be a string",
            ));
        };
        let Some(Json::String(path)) = request.get("path") else {
            return Err(ParseError::invalid_json(
                "batch request path must be a string",
            ));
        };
        let method = match request.get("method") {
            Some(Json::String(m)) => m.to_uppercase(),
            _ => "GET".to_string(),
        };
        let routable = routable_path(path, mount_path)?;
        if method == "POST" && routable == BATCH_PATH {
            return Err(ParseError::invalid_json(
                "nested batch requests are not allowed",
            ));
        }
        parsed.push((method, routable, request.get("body").cloned()));
    }

    let mut results = Vec::with_capacity(parsed.len());
    for (method, path, body) in parsed {
        results.push(run_one(state, rc, authority, &method, &path, body.as_ref()).await);
    }
    Ok(Json::Array(results))
}

/// One sub-request, rendered as `{success: ...}` or `{error: {code, error}}` (`batch.js:172-179`).
async fn run_one(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    method: &str,
    path: &str,
    body: Option<&Json>,
) -> Json {
    let Ok(method) = method.parse::<http::Method>() else {
        return json!({ "error": {
            "code": ErrorCode::InvalidJson.as_i32(),
            "error": format!("cannot route {method} {path}"),
        }});
    };
    let Some(route) = dispatch::route_of(path) else {
        return json!({ "error": {
            "code": ErrorCode::InvalidJson.as_i32(),
            "error": format!("cannot route {method} {path}"),
        }});
    };

    // A sub-request has no URL, so its query parameters are its body. That is why upstream's
    // `handleFind` merges the two before reading either (`ClassesRouter.js:23`).
    let params = if matches!(method, http::Method::GET | http::Method::DELETE) {
        Params::from_json(body)
    } else {
        Params::default()
    };

    let incoming = dispatch::Incoming {
        method,
        route,
        path: path.to_string(),
        params,
        body: body.cloned(),
    };
    match dispatch::dispatch(state, rc, authority, &incoming).await {
        Ok(response) => json!({ "success": response.body }),
        // A sub-request's failure is rendered as `{code, error}` (`batch.js:176-178`). parse-rust
        // withholds the detail of an internal error on every path, inside a batch as well as
        // outside one. The shape stays upstream's, meaning no `code` key, and only the message is
        // the generic one.
        Err(RouteError::Parse(e)) if e.origin == ErrorOrigin::Internal => {
            json!({ "error": { "error": crate::response::INTERNAL_SERVER_ERROR_MESSAGE }})
        }
        Err(RouteError::Parse(e)) => json!({ "error": {
            "code": e.code.as_i32(),
            "error": e.message,
        }}),
        // UPSTREAM-QUIRK: the batch error branch reads `error.code` off whatever was thrown
        // (`batch.js:177`), and an HTTP-level rejection has none. `JSON.stringify` drops the
        // resulting `undefined`, so the master-key gate answers a `code`-less error object inside
        // a batch and a `code`-less body outside one. Reproduced rather than given a code, because
        // a client branching on the key's presence would see an invented one.
        Err(RouteError::Http(e)) => json!({ "error": { "error": e.message }}),
        // Inside a batch an unroutable sub-request is a `Parse.Error`, because that is what
        // `tryRouteRequest` throws (`PromiseRouter.js:123-125`). Outside one it is a 404.
        Err(RouteError::NotFound { method, path }) => json!({ "error": {
            "code": ErrorCode::InvalidJson.as_i32(),
            "error": format!("cannot route {method} {path}"),
        }}),
    }
}

/// Strip the API prefix from a sub-request path (`batch.js:30-36`).
///
/// A path outside the prefix is `INVALID_JSON` `cannot route batch path <path>`. The result is
/// joined onto `/`, so `/parse` alone becomes `/` rather than the empty string.
fn routable_path(path: &str, mount_path: &str) -> Result<String, ParseError> {
    let prefix = mount_path.trim_end_matches('/');
    let rest = if prefix.is_empty() {
        Some(path)
    } else {
        path.strip_prefix(prefix)
    };
    let Some(rest) = rest else {
        return Err(ParseError::invalid_json(format!(
            "cannot route batch path {path}"
        )));
    };
    // `path.posix.join('/', x)`: a leading slash is guaranteed and a trailing one is dropped
    // unless the whole path is `/`.
    let trimmed = rest.trim_matches('/');
    if trimmed.is_empty() {
        return Ok("/".to_string());
    }
    Ok(format!("/{trimmed}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prefix_is_the_configured_mount_and_nothing_else() {
        assert_eq!(
            routable_path("/parse/classes/Post", "/parse").expect("routes"),
            "/classes/Post"
        );
        assert_eq!(routable_path("/parse", "/parse").expect("routes"), "/");
        assert_eq!(
            routable_path("/classes/Post", "/").expect("routes"),
            "/classes/Post"
        );
    }

    #[test]
    fn a_path_outside_the_prefix_is_refused_by_name() {
        let e = routable_path("/other/classes/Post", "/parse").unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidJson);
        assert_eq!(e.message, "cannot route batch path /other/classes/Post");
    }

    /// The prefix is a string prefix upstream, so a mount of `/parse` also accepts `/parsexyz`.
    /// Reproduced: the routable path then fails to match any route and reports that instead.
    #[test]
    fn a_prefix_that_only_looks_like_the_mount_still_fails_to_route() {
        let routable = routable_path("/parsexyz/classes/Post", "/parse").expect("prefix matches");
        assert_eq!(routable, "/xyz/classes/Post");
        assert!(dispatch::route_of(&routable).is_none());
    }
}
