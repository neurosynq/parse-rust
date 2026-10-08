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
//!   them**, which is why a saved Parse object never grows an `_ApplicationId` field. It does so
//!   only for a request whose headers do not already name the app, and it reads exactly that set:
//!   see [`Mode`].
//! - `ClassesRouter` merges `req.body` with the decoded query string, so a `where` sent in the
//!   body reaches the same code as one sent in the URL.
//!
//! Doing all three here, in one layer, is deliberate. Spreading it across the extractor and each
//! route is how a check ends up applied on one path and forgotten on another.

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value as Json;

use crate::auth::headers;
use crate::response::HttpError;
use crate::state::AppState;

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

/// Body key to header name, for the three a body may carry beside the app id
/// (`middlewares.js:152-172`). Each is read only when truthy, and refused when truthy and not a
/// string.
const CREDENTIALS: [(&str, &str); 3] = [
    ("_InstallationId", headers::INSTALLATION_ID),
    ("_SessionToken", headers::SESSION_TOKEN),
    ("_MasterKey", headers::MASTER_KEY),
];

/// How a request names its app, which decides whether the body is read for credentials at all.
///
/// Upstream reads the body only when the `X-Parse-Application-Id` header is missing or names no
/// app (`middlewares.js:119`). With a valid header the body's underscore keys are left where they
/// are, so a write carrying one is refused as an invalid field name rather than authenticated.
/// Nothing reads a maintenance key from the body in either mode.
enum Mode {
    /// The header names this app. The body is not consulted.
    Header,
    /// The body names this app, so its credentials are read.
    Body,
    /// Neither does. The header layer refuses the request.
    Neither,
}

fn mode(
    parts: &http::request::Parts,
    map: Option<&serde_json::Map<String, Json>>,
    state: &AppState,
) -> Mode {
    let config = state.config();
    let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
    if header(headers::APP_ID) == Some(config.app_id.as_str()) {
        return Mode::Header;
    }
    let Some(map) = map else { return Mode::Neither };
    // A master key header that disagrees with the app the body names refuses the body
    // (`middlewares.js:143`).
    let master_agrees = header(headers::MASTER_KEY).is_none_or(|k| k == config.master_key);
    match map.get("_ApplicationId") {
        Some(Json::String(id)) if *id == config.app_id && master_agrees => Mode::Body,
        _ => Mode::Neither,
    }
}

/// JavaScript truthiness, for the `if (req.body._X)` guards.
fn truthy(value: &Json) -> bool {
    match value {
        Json::Null => false,
        Json::Bool(b) => *b,
        Json::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Json::String(s) => !s.is_empty(),
        Json::Array(_) | Json::Object(_) => true,
    }
}

fn set_header(parts: &mut http::request::Parts, name: &str, value: &str) {
    if let (Ok(name), Ok(val)) = (
        http::HeaderName::from_bytes(name.as_bytes()),
        http::HeaderValue::from_str(value),
    ) {
        parts.headers.insert(name, val);
    }
}

/// Why the body branch refused a request.
enum Refusal {
    /// Upstream's `invalidRequest`, the bare 403.
    Unauthorized,
    /// Upstream's `malformedContext`.
    MalformedContext,
}

/// `malformedContext` (`middlewares.js:850-853`): 400, `INVALID_JSON`.
fn malformed_context() -> Response {
    crate::response::ParseErrorResponse(parse_rust_core::ParseError::new(
        parse_rust_core::ErrorCode::InvalidJson,
        "Invalid object for context.",
    ))
    .into_response()
}

/// A context is a JSON object, and only an object: `Object.prototype.toString` is
/// `[object Object]` for nothing else, so an array or a scalar is malformed.
fn is_context_object(text: &str) -> bool {
    matches!(serde_json::from_str::<Json>(text), Ok(Json::Object(_)))
}

/// Move the body's credentials into headers, upstream's body branch (`middlewares.js:139-193`).
fn read_body_credentials(
    parts: &mut http::request::Parts,
    map: &mut serde_json::Map<String, Json>,
) -> Result<(), Refusal> {
    if let Some(Json::String(id)) = map.shift_remove("_ApplicationId") {
        set_header(parts, headers::APP_ID, &id);
    }
    // `info.javascriptKey = req.body._JavaScriptKey || ''`: the body's key replaces any header.
    match map.shift_remove("_JavaScriptKey") {
        Some(Json::String(k)) if !k.is_empty() => set_header(parts, headers::JAVASCRIPT_KEY, &k),
        _ => {
            parts.headers.remove(headers::JAVASCRIPT_KEY);
        }
    }
    map.shift_remove("_ClientVersion");
    for (body_key, header_name) in CREDENTIALS {
        match map.get(body_key) {
            Some(value) if truthy(value) => {
                let Some(Json::String(value)) = map.shift_remove(body_key) else {
                    return Err(Refusal::Unauthorized);
                };
                set_header(parts, header_name, &value);
            }
            // Falsy: neither read nor deleted, as upstream leaves it.
            _ => {}
        }
    }
    // No context reaches a route yet, so a valid one is removed and goes nowhere. Validated as
    // upstream validates it (`middlewares.js:173-186`): an object is taken as is, which includes an
    // array because `Utils.isObject` is `typeof === 'object'`, and anything else must be a string
    // that parses to a plain object. `JSON.parse` of a number or `true` returns it unchanged, which
    // fails the object test, so those are malformed too.
    if let Some(context) = map.get("_context").filter(|v| truthy(v)) {
        let valid = match context {
            Json::Object(_) | Json::Array(_) => true,
            Json::String(text) => is_context_object(text),
            _ => false,
        };
        if !valid {
            return Err(Refusal::MalformedContext);
        }
        map.shift_remove("_context");
    }
    match map.get("_ContentType") {
        Some(value) if truthy(value) => {
            if !value.is_string() {
                return Err(Refusal::Unauthorized);
            }
            map.shift_remove("_ContentType");
        }
        _ => {}
    }
    Ok(())
}

/// `req.is('multipart/form-data')`, which `express.json` leaves unparsed.
/// body-parser's strict-mode message: V8's `JSON.parse` error for the body with its first character
/// named (body-parser's `createStrictSyntaxError`). V8 quotes a long source only in part; this
/// quotes it whole, so the message matches for short bodies only.
fn strict_violation(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let first = text.trim_start().chars().next().unwrap_or(' ');
    format!("Unexpected token '{first}', \"{text}\" is not valid JSON")
}

fn is_multipart(parts: &http::request::Parts) -> bool {
    parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.trim_start()
                .to_ascii_lowercase()
                .starts_with("multipart/form-data")
        })
}

/// A method no route serves, standing in for an override that is not a valid method token.
fn unroutable_method() -> http::Method {
    http::Method::from_bytes(b"UNROUTABLE").unwrap_or(http::Method::OPTIONS)
}

/// Upper bound on a buffered body. Without one, a request could exhaust memory.
pub(crate) const MAX_BODY: usize = 20 * 1024 * 1024;

/// A write's JSON object body, parsed once here and read by the route's
/// [`JsonBody`](crate::routes::http::JsonBody) extractor.
#[derive(Debug, Clone)]
pub struct ParsedBody(pub Json);

/// The health endpoint: the mount plus `/health`, with or without a trailing slash. Express's
/// `api.use('/health', ...)` also matches any path below it, `/health/foo`, which this does not;
/// only the exact path reaches the health route here, so only it skips the body checks. A suffix
/// test also matched `/classes/health`.
fn is_health(parts: &http::request::Parts, state: &AppState) -> bool {
    let mount = state.config().mount_path.trim_end_matches('/');
    parts
        .uri
        .path()
        .strip_prefix(mount)
        // One extra leading slash is ignored, as `allowDoubleForwardSlash` ignores it before
        // routing, so `//health` is the health route too.
        .map(|rest| {
            if rest.starts_with("//") {
                &rest[1..]
            } else {
                rest
            }
        })
        .is_some_and(|rest| rest == "/health" || rest == "/health/")
}

/// `PARSE_RUST_TRACE`, read once rather than from the environment on every request.
fn tracing_enabled() -> bool {
    static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRACE.get_or_init(|| std::env::var("PARSE_RUST_TRACE").is_ok())
}

pub async fn extract(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();

    // `X-Parse-Cloud-Context` is the first thing `handleParseHeaders` reads, before any credential
    // (`middlewares.js:76-86`), so a malformed one is refused whoever sent it. `/health` is mounted
    // ahead of that middleware upstream and is not checked.
    if let Some(value) = parts.headers.get(headers::CLOUD_CONTEXT) {
        let health = is_health(&parts, &state);
        if !health && !value.to_str().is_ok_and(is_context_object) {
            return malformed_context();
        }
    }

    let bytes = match to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        // `express.json({ limit: maxUploadSize })` refuses the request with body-parser's 413
        // (`ParseServer.ts:332`), which `handleParseErrors` renders as `{error}` from the error's
        // own status and message. Passing the request on with an empty body let a write over the
        // limit reach its route with no body and no sign it had been dropped.
        Err(_) => {
            return HttpError {
                status: http::StatusCode::PAYLOAD_TOO_LARGE,
                message: "request entity too large".to_string(),
            }
            .into_response()
        }
    };

    // `express.json` parses every body that is not multipart (`ParseServer.ts:332`), and it runs
    // after `/health` is mounted, so a health check's body is never read.
    let parsed = if is_health(&parts, &state) || is_multipart(&parts) {
        None
    } else if bytes.is_empty() {
        // body-parser's empty body is `{}`, so a create, a schema create, a signup or an update
        // sent with no body at all is the empty object rather than a malformed request.
        Some(Json::Object(serde_json::Map::new()))
    } else {
        match serde_json::from_slice::<Json>(&bytes) {
            // body-parser's strict mode, the default, takes only an object or an array at the top
            // level and answers anything else with its 400, before the route sees it.
            Ok(value @ (Json::Object(_) | Json::Array(_))) => Some(value),
            Ok(_) => {
                return HttpError {
                    status: http::StatusCode::BAD_REQUEST,
                    message: strict_violation(&bytes),
                }
                .into_response()
            }
            // body-parser's 400, rendered by `handleParseErrors` as `{error}` from the error's
            // own status and message. The message is the parser's and so is not upstream's
            // V8 text; the status and the envelope are.
            Err(e) => {
                return HttpError {
                    status: http::StatusCode::BAD_REQUEST,
                    message: e.to_string(),
                }
                .into_response()
            }
        }
    };

    // Not a JSON object body: nothing to normalize. Covers every GET.
    let Some(Json::Object(mut map)) = parsed else {
        // A multipart body is never parsed upstream, so a write reaches its route with no fields
        // and stores an empty object, measured at the pin as a 201. Handing the route `{}` does
        // the same; the raw multipart bytes would fail the route's JSON extraction instead.
        if is_multipart(&parts) && !is_health(&parts, &state) {
            parts.headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            return next.run(Request::from_parts(parts, Body::from("{}"))).await;
        }
        return next
            .run(Request::from_parts(parts, Body::from(bytes)))
            .await;
    };

    // 1. Credentials into headers, from a body that names the app and only from one.
    // The Unity SDK's marker goes in every mode (`middlewares.js:111-115`).
    map.shift_remove("_noBody");
    match mode(&parts, Some(&map), &state) {
        Mode::Header | Mode::Neither => {}
        Mode::Body => {
            map.shift_remove("_RevocableSession");
            match read_body_credentials(&mut parts, &mut map) {
                Ok(()) => {}
                Err(Refusal::Unauthorized) => return HttpError::unauthorized().into_response(),
                Err(Refusal::MalformedContext) => return malformed_context(),
            }
        }
    }

    // 2. Method override. The SDK sends every read as `POST` with `_method: "GET"`.
    //
    // **The method is NOT rewritten here, and that is not a stylistic choice.** axum matches the
    // request method before a `Router::layer` runs, verified by observation: a POST carrying
    // `_method: "PUT"` produced a 405 no matter where the layer was attached. So the intended
    // method travels in an extension and the routes dispatch on it explicitly, which is
    // deterministic and testable rather than dependent on middleware ordering inside the
    // framework.
    //
    // Only a `POST` is overridden, and the name is upper-cased (`allowMethodOverride`,
    // `middlewares.js:425-433`). Any other transport keeps `_method` in its body, where a write
    // refuses it as a field name.
    let overridden = if parts.method == http::Method::POST && map.get("_method").is_some_and(truthy)
    {
        // A name that is not a valid method token still replaces the method upstream, and then
        // matches no route: Express answers 404. Falling back to the transport `POST` ran the
        // request as a create instead.
        match map.shift_remove("_method") {
            Some(Json::String(m)) => Some(
                m.to_uppercase()
                    .parse::<http::Method>()
                    .unwrap_or_else(|_| unroutable_method()),
            ),
            _ => None,
        }
    } else {
        None
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
        let trace = tracing_enabled();
        let (m, u) = (parts.method.clone(), parts.uri.clone());
        let res = next.run(Request::from_parts(parts, Body::empty())).await;
        if trace {
            eprintln!("[trace] {m} {u} -> {}", res.status());
        }
        return res;
    }

    // The parsed body travels as an extension rather than being serialized again. Serializing
    // can lengthen it, `1e5` becoming `100000.0`, so a body accepted under the limit above could
    // exceed it on the way to the route and be refused there as not JSON at all.
    parts.extensions.insert(ParsedBody(Json::Object(map)));
    let trace = tracing_enabled();
    let (m, u) = (parts.method.clone(), parts.uri.clone());
    let res = next.run(Request::from_parts(parts, Body::empty())).await;
    if trace {
        eprintln!("[trace] {m} {u} -> {}", res.status());
    }
    res
}
