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
    rc: &mut RequestContext,
    authority: &Authority,
    mount_path: &str,
    original_url: &str,
    body: Option<&Json>,
) -> Result<Json, ParseError> {
    let Some(Json::Object(body)) = body else {
        return Err(ParseError::invalid_json("requests must be an array"));
    };

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
    let mut checked = Vec::with_capacity(requests.len());
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
        checked.push((request, path));
    }
    // UPSTREAM-QUIRK: `batch.js:90-92`. Upstream recovers its mount by stripping `/batch` off
    // `req.originalUrl`, and throws a bare string when the URL does not end with it. Express routes
    // `/batch/` and `/batch?x=1` to the handler all the same, so both are a bare 500 with nothing
    // run, after the shape checks above. Running them instead would perform writes upstream never
    // does.
    if !original_url.ends_with(BATCH_PATH) {
        return Err(ParseError::internal(
            "internal routing problem - expected url to end with batch",
        ));
    }
    // A second pass, as upstream's is a second loop: every path is a string before any is
    // routed or any method normalized.
    let mut parsed = Vec::with_capacity(checked.len());
    for (request, path) in checked {
        let routable = routable_path(path, mount_path)?;
        // `(restRequest.method || 'GET').toUpperCase()`: the nested-batch check normalizes the
        // method. Routing, below, does not. A truthy method that is not a string has no
        // `toUpperCase`, so upstream's pre-flight throws a `TypeError` before any sub-request runs
        // and the batch is a bare 500 (`batch.js:106`). Converting it to text instead made
        // `"method": ["DELETE"]` an executable delete.
        let normalized = match request.get("method") {
            Some(Json::String(m)) if !m.is_empty() => m.to_uppercase(),
            Some(m) if js_truthy(m) => {
                return Err(ParseError::internal(
                    "batch sub-request method is not a string".to_string(),
                ));
            }
            _ => "GET".to_string(),
        };
        if normalized == "POST" && routable == BATCH_PATH {
            return Err(ParseError::invalid_json(
                "nested batch requests are not allowed",
            ));
        }
        parsed.push((
            js_method(request.get("method")),
            routable,
            request.get("body").cloned(),
        ));
    }

    // **The sub-requests run concurrently**, as upstream starts them all from one `map` and awaits
    // them with `Promise.all` (`batch.js:161-182`). Results keep request order whatever order they
    // finish in. Two sub-requests touching the same object therefore have no defined order between
    // them, which is upstream's contract too: a non-transactional batch never promised one.
    //
    // **An unroutable sub-request fails the whole batch.** `tryRouteRequest` throws synchronously
    // inside that `map` (`PromiseRouter.js:121-125`), so the sub-requests before it were already
    // started and the ones after it never are, and the batch answers 400 `cannot route <M> <p>`
    // with no results array. Here the ones before it run to completion before the refusal is
    // returned, where upstream can answer while they are still writing; a client sees the same
    // response either way, and the writes it did not wait for are no less durable.
    //
    // The method is matched exactly as sent, as `PromiseRouter.match` compares it
    // (`PromiseRouter.js:90-93`), so `post` and a missing method do not route.
    // Where upstream opens its transactional session: after every check of the batch's shape, so a
    // malformed transactional batch answers as a malformed batch (`batch.js:154-157`).
    if matches!(body.get("transaction"), Some(Json::Bool(true))) {
        return Err(ParseError::new(
            ErrorCode::CommandUnavailable,
            "Batch transactions are not supported yet. Retry without `transaction: true`; \
             the sub-requests will be applied independently and reported per operation.",
        ));
    }
    let mut runnable = Vec::with_capacity(parsed.len());
    let mut unroutable = None;
    for (method, path, body) in parsed {
        match routable(&method, &path) {
            Some(route) => runnable.push((route, path, body)),
            None => {
                unroutable = Some(format!("cannot route {method} {path}"));
                break;
            }
        }
    }
    // Every class the sub-requests that will run name is in the snapshot before any of them runs,
    // as a direct request's is. Taking the cache as it stood let a sub-request read or write a
    // class another server had created since with no CLP at all, which is unrestricted.
    let mut classes: Vec<String> = Vec::new();
    let mut reload = false;
    for ((_, route), _, _) in &runnable {
        match route.schema_freshness() {
            crate::schema_cache::Freshness::Containing(class) => {
                if !classes.iter().any(|c| c == class) {
                    classes.push(class.to_string());
                }
            }
            crate::schema_cache::Freshness::Reload => reload = true,
            _ => {}
        }
    }
    if reload || !classes.iter().all(|c| rc.snapshot.contains(c)) {
        let freshness = if reload {
            crate::schema_cache::Freshness::Reload
        } else {
            crate::schema_cache::Freshness::ContainingAll(&classes)
        };
        rc.snapshot = state.schema_snapshot(freshness).await?;
    }
    let rc: &RequestContext = rc;
    let results = futures::future::join_all(runnable.iter().map(|(route, path, body)| {
        run_one(state, rc, authority, route.clone(), path, body.as_ref())
    }))
    .await;
    if let Some(message) = unroutable {
        return Err(ParseError::invalid_json(message));
    }
    Ok(Json::Array(results))
}

/// JavaScript truthiness, for the `||` in the method normalization.
fn js_truthy(value: &Json) -> bool {
    match value {
        Json::Null => false,
        Json::Bool(b) => *b,
        Json::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Json::String(s) => !s.is_empty(),
        Json::Array(_) | Json::Object(_) => true,
    }
}

/// `restRequest.method` as JavaScript would print it in `'cannot route ' + method`.
///
/// Absent is `undefined`. A string is itself, case untouched, because the router compares it
/// verbatim. Anything else is an approximation of its `String()` form, which only reaches the
/// message: none of those can match a route.
fn js_method(value: Option<&Json>) -> String {
    match value {
        None => "undefined".to_string(),
        Some(Json::String(m)) => m.clone(),
        Some(Json::Object(_)) => "[object Object]".to_string(),
        Some(Json::Array(items)) => items
            .iter()
            .map(|v| js_method(Some(v)))
            .collect::<Vec<_>>()
            .join(","),
        Some(other) => other.to_string(),
    }
}

/// The route a sub-request names, or `None` when upstream's router would find no match for the
/// method and path together.
///
/// Only the four methods `PromiseRouter.route` accepts can ever match, and only in upper case.
/// Whether the path serves that method is the dispatcher's table, asked through
/// [`dispatch::serves`] so the two cannot disagree.
fn routable(method: &str, path: &str) -> Option<(http::Method, dispatch::Route)> {
    if !["GET", "POST", "PUT", "DELETE"].contains(&method) {
        return None;
    }
    let method = method.parse::<http::Method>().ok()?;
    let route = dispatch::route_of(path)?;
    dispatch::serves(&route, &method).then_some((method, route))
}

/// One sub-request, rendered as `{success: ...}` or `{error: {code, error}}` (`batch.js:172-179`).
async fn run_one(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    (method, route): (http::Method, dispatch::Route),
    path: &str,
    body: Option<&Json>,
) -> Json {
    // A sub-request has no URL, so its query parameters are its body. That is why upstream's
    // `handleFind` merges the two before reading either (`ClassesRouter.js:23`).
    let method_of_incoming = method.clone();
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
        // An absent sub-request body reaches upstream's handlers as `undefined`, and a write reads
        // that as no fields (`batch.js:166`), so it is the empty object here.
        body: match body {
            Some(b) => Some(b.clone()),
            None if !matches!(method_of_incoming, http::Method::GET | http::Method::DELETE) => {
                Some(Json::Object(serde_json::Map::new()))
            }
            None => None,
        },
    };
    let mut outcome = dispatch::dispatch(state, rc, authority, &incoming).await;
    // As over HTTP: a read that reached a class the batch's snapshot predates runs again on a
    // rebuilt one. Only that sub-request; the others keep the snapshot they share.
    if matches!(&outcome, Err(RouteError::Parse(e)) if e.is_schema_stale()) {
        outcome = match rc.with_rebuilt_schemas(state).await {
            Ok(fresh) => dispatch::dispatch(state, &fresh, authority, &incoming).await,
            Err(e) => Err(RouteError::Parse(e)),
        };
    }
    match outcome {
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
    // unless the whole path is `/`. The join also normalizes, so `.` segments go and `..` removes
    // the segment before it, never climbing above the root.
    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    if segments.is_empty() {
        return Ok("/".to_string());
    }
    Ok(format!("/{}", segments.join("/")))
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

    /// `path.posix.join` normalizes, so dot segments resolve before routing.
    #[test]
    fn dot_segments_resolve_as_a_posix_join_does() {
        assert_eq!(
            routable_path("/parse/./classes/../classes/Dot", "/parse").expect("routes"),
            "/classes/Dot"
        );
        assert_eq!(
            routable_path("/parse/../../classes/X", "/parse").expect("routes"),
            "/classes/X"
        );
        assert_eq!(
            routable_path("/parse/classes/..", "/parse").expect("routes"),
            "/"
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
