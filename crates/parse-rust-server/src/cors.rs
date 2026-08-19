//! `allowCrossDomain`: the CORS headers every response carries, and the preflight answer.
//!
//! Upstream mounts this as the **first** middleware on the API router (`ParseServer.ts:312`), and
//! the ordering matters: the headers are set on every response, including error responses, and the
//! `OPTIONS` short-circuit happens before anything else can reject the request.
//!
//! **Why this is not optional, given that the JavaScript SDK never triggers a preflight.** The SDK
//! sends everything as a `text/plain` `POST` precisely to stay inside the CORS "simple request"
//! rules, so no `OPTIONS` is ever issued. That is the fact that makes it tempting to skip this
//! layer, and it is only half the mechanism: a simple request is *sent* without a preflight, but
//! the browser still refuses to hand the **response** to the page unless
//! `Access-Control-Allow-Origin` is on it. Without these headers a browser-hosted SDK sees a
//! network error on every call while the server log shows 200s. Any client that does preflight,
//! which includes parse-dashboard and anything sending `X-Parse-*` headers directly, gets a 405
//! from the router instead, because `OPTIONS` is registered on no route.
//!
//! The four headers and the exact `OPTIONS` behavior are reproduced from `middlewares.js:399-422`.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::HeaderValue;
use http::StatusCode;

use crate::state::AppState;

/// `DEFAULT_ALLOWED_HEADERS` (`middlewares.js:18-19`), verbatim and in upstream's order.
///
/// **The order and spelling are contract in practice even though CORS is case-insensitive**, since
/// this string is echoed to the browser and some proxies match on it literally. `X-Requested-With`
/// is in the list and is not a Parse header; it is there because older clients send it.
pub const DEFAULT_ALLOWED_HEADERS: &str = "X-Parse-Master-Key, X-Parse-REST-API-Key, \
     X-Parse-Javascript-Key, X-Parse-Application-Id, X-Parse-Client-Version, \
     X-Parse-Session-Token, X-Requested-With, X-Parse-Revocable-Session, X-Parse-Request-Id, \
     Content-Type, Pragma, Cache-Control";

/// `Access-Control-Allow-Methods` (`middlewares.js:413`).
///
/// Upstream's literal, which notably does **not** include `PATCH`. parse-rust serves no `PATCH`
/// route either, so advertising one would be a promise the router does not keep.
const ALLOW_METHODS: &str = "GET,PUT,POST,DELETE,OPTIONS";

/// `Access-Control-Expose-Headers` (`middlewares.js:415`).
///
/// Both headers belong to subsystems parse-rust does not have yet, and both are listed anyway.
/// This value tells a browser which response headers a page may *read*; a client that stops seeing
/// a header it used to see is a broken client, so the list is the one place where advertising
/// ahead of the implementation is the compatible choice rather than a false claim.
const EXPOSE_HEADERS: &str = "X-Parse-Job-Status-Id, X-Parse-Push-Status-Id";

/// Set the CORS headers on every response, and answer a preflight directly.
///
/// `Access-Control-Allow-Origin` follows upstream's rule exactly (`middlewares.js:407-412`): the
/// configured list defaults to `["*"]`, and if the request's `Origin` is in the list it is echoed
/// back, otherwise the **first** configured entry is sent. Echoing the request origin rather than
/// sending the list is required, because the header takes one value and a browser compares it to
/// its own origin.
///
/// Note what this does not do: there is no `Access-Control-Allow-Credentials`, because upstream
/// does not send one. Parse carries its credentials in headers or in the body rather than in
/// cookies, so the browser never needs to be told to attach them, and sending it would make `*` an
/// illegal origin value.
pub async fn layer(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let config = state.config();
    let allow_origin = resolve_origin(
        &config.allow_origin,
        request.headers().get(http::header::ORIGIN),
    );
    let allow_headers = join_allowed_headers(&config.allow_headers);

    let mut response = if request.method() == http::Method::OPTIONS {
        // `res.sendStatus(200)` (`middlewares.js:418`): the preflight is answered here and never
        // reaches the router. Without this it would 405, because no route registers `OPTIONS`.
        //
        // `sendStatus` writes the status's reason phrase as the body, so upstream's preflight
        // carries `OK` rather than nothing. No browser reads a preflight body, but a differential
        // runner comparing bytes does.
        (StatusCode::OK, "OK".to_string()).into_response()
    } else {
        next.run(request).await
    };

    let headers = response.headers_mut();
    for (name, value) in [
        (http::header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin),
        (
            http::header::ACCESS_CONTROL_ALLOW_METHODS,
            ALLOW_METHODS.to_string(),
        ),
        (http::header::ACCESS_CONTROL_ALLOW_HEADERS, allow_headers),
        (
            http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
            EXPOSE_HEADERS.to_string(),
        ),
    ] {
        // A configured value that cannot be a header value is dropped rather than panicking. This
        // is a request path, and a bad `allowOrigin` in the config must not take a worker down.
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(name, value);
        }
    }
    response
}

/// Upstream's origin selection (`middlewares.js:407-412`).
///
/// The `unwrap_or("*")` is the unconfigured default only. A configured list containing one empty
/// string is **not** an empty list: it echoes back an empty origin, which matches no browser, and
/// that is how an operator turns browser access off. See `list` in the CLI, which must not drop
/// that entry.
fn resolve_origin(configured: &[String], request_origin: Option<&HeaderValue>) -> String {
    // **An empty list is not an absent one.** Upstream's `config?.allowOrigin ?? ['*']` falls back
    // only on null or undefined, so an explicit `allowOrigin: []` stays empty and `baseOrigins[0]`
    // is `undefined`: the header does not name an origin, and no browser matches it. Defaulting an
    // empty list to `*` here reverses an operator's closed configuration into an open one, which is
    // the one direction a CORS bug must never fail in. The *unconfigured* default is still `*`, and
    // it is carried by `ServerConfig`'s `vec!["*"]` rather than by this fallback.
    let first = configured.first().map(String::as_str).unwrap_or("");
    let Some(origin) = request_origin.and_then(|v| v.to_str().ok()) else {
        return first.to_string();
    };
    if configured.iter().any(|allowed| allowed == origin) {
        origin.to_string()
    } else {
        first.to_string()
    }
}

/// `DEFAULT_ALLOWED_HEADERS` plus the configured additions (`middlewares.js:402-405`).
fn join_allowed_headers(extra: &[String]) -> String {
    if extra.is_empty() {
        return DEFAULT_ALLOWED_HEADERS.to_string();
    }
    format!("{DEFAULT_ALLOWED_HEADERS}, {}", extra.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(value: &str) -> HeaderValue {
        HeaderValue::from_str(value).expect("test literal")
    }

    #[test]
    fn the_default_list_is_upstreams_twelve_headers() {
        let names: Vec<&str> = DEFAULT_ALLOWED_HEADERS.split(", ").collect();
        assert_eq!(names.len(), 12, "{DEFAULT_ALLOWED_HEADERS}");
        // The four an SDK cannot work without, spelled as upstream spells them.
        for required in [
            "X-Parse-Application-Id",
            "X-Parse-Session-Token",
            "X-Parse-Master-Key",
            "Content-Type",
        ] {
            assert!(names.contains(&required), "missing {required}");
        }
        // `Javascript`, not `JavaScript`. Upstream's casing, and a client matching the string
        // literally would see the difference.
        assert!(names.contains(&"X-Parse-Javascript-Key"));
    }

    #[test]
    fn an_unconfigured_server_allows_every_origin() {
        // The wildcard default is carried by `ServerConfig`'s `vec!["*"]`, not by this function.
        assert_eq!(
            resolve_origin(&["*".to_string()], Some(&origin("https://app.example"))),
            "*"
        );
        assert_eq!(resolve_origin(&["*".to_string()], None), "*");
    }

    /// An **explicitly empty** allowlist is a closed one, not an unconfigured one.
    ///
    /// This asserted `*` until a review, which is the fail-open direction: an operator who sets
    /// `allowOrigin: []` to shut browsers out got every origin allowed instead. Upstream's
    /// `?? ['*']` fires only on null or undefined, so an explicit `[]` leaves the header naming no
    /// origin.
    #[test]
    fn an_explicitly_empty_allowlist_is_closed_not_open() {
        assert_eq!(resolve_origin(&[], None), "");
        assert_eq!(
            resolve_origin(&[], Some(&origin("https://app.example"))),
            ""
        );
    }

    /// The rule that makes a configured allowlist work: a browser compares the header against its
    /// own origin, so a listed origin has to be echoed rather than the list returned.
    #[test]
    fn a_listed_origin_is_echoed_and_an_unlisted_one_gets_the_first_entry() {
        let configured = vec![
            "https://a.example".to_string(),
            "https://b.example".to_string(),
        ];
        assert_eq!(
            resolve_origin(&configured, Some(&origin("https://b.example"))),
            "https://b.example"
        );
        assert_eq!(
            resolve_origin(&configured, Some(&origin("https://evil.example"))),
            "https://a.example",
            "an unlisted origin must not be echoed back"
        );
        assert_eq!(resolve_origin(&configured, None), "https://a.example");
    }

    #[test]
    fn configured_headers_append_to_the_defaults_rather_than_replacing_them() {
        let joined = join_allowed_headers(&["X-Custom".to_string(), "X-Other".to_string()]);
        assert!(joined.starts_with(DEFAULT_ALLOWED_HEADERS));
        assert!(joined.ends_with("X-Custom, X-Other"));
        assert_eq!(join_allowed_headers(&[]), DEFAULT_ALLOWED_HEADERS);
    }
}
