//! CORS: the headers a browser needs before it will hand a response to the page.
//!
//! Written against raw sockets rather than the shared helper, because the subject is the exact
//! response headers and the helper sends no `Origin`. A browser is the only client that enforces
//! any of this, so the assertions are about what a browser would do with what is on the wire.
//!
//! `#[ignore]`d because they need a MongoDB on 27017. `tools/test.sh` runs them.

mod common;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One raw request, returning the whole response including headers.
async fn raw(host: &str, request: &str) -> String {
    let mut socket = tokio::net::TcpStream::connect(host).await.expect("connect");
    socket
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = String::new();
    socket
        .read_to_string(&mut response)
        .await
        .expect("read response");
    response
}

/// Case-insensitive header lookup, since a header name's case is not contract.
fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let head = response.split("\r\n\r\n").next()?;
    head.lines()
        .skip(1)
        .find_map(|line| {
            line.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        })
        .map(|(_, v)| v.trim())
}

fn status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {response}"))
}

/// The whole point of the layer. A browser discards the response of even a preflight-free request
/// unless this header is present, so its absence is a total outage for a browser-hosted SDK while
/// the server log shows nothing but 200s.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn every_response_carries_the_headers_a_browser_needs() {
    let server = common::boot().await;
    let host = &server.host;

    let response = raw(
        host,
        &format!(
            "GET /parse/health HTTP/1.1\r\nHost: {host}\r\nOrigin: https://app.example\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;

    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(
        header(&response, "Access-Control-Allow-Origin"),
        Some("*"),
        "{response}"
    );
    assert_eq!(
        header(&response, "Access-Control-Allow-Methods"),
        Some("GET,PUT,POST,DELETE,OPTIONS"),
        "{response}"
    );
    assert_eq!(
        header(&response, "Access-Control-Expose-Headers"),
        Some("X-Parse-Job-Status-Id, X-Parse-Push-Status-Id"),
        "{response}"
    );
    let allowed = header(&response, "Access-Control-Allow-Headers").expect("allow-headers");
    for required in [
        "X-Parse-Application-Id",
        "X-Parse-Session-Token",
        "X-Parse-Master-Key",
        "Content-Type",
    ] {
        assert!(
            allowed.contains(required),
            "{required} missing from {allowed}"
        );
    }
}

/// An error response needs them too, which is what mounting the layer outermost buys. A browser
/// that cannot read a 403 reports a network error instead, and the client cannot tell an
/// authorization failure from an unreachable server.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_error_response_carries_them_as_well() {
    let server = common::boot().await;
    let host = &server.host;

    // No credentials at all, so this is refused before it reaches a route handler.
    let response = raw(
        host,
        &format!(
            "GET /parse/classes/Post HTTP/1.1\r\nHost: {host}\r\nOrigin: https://app.example\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;

    assert_ne!(status(&response), 200, "this request should be refused");
    assert_eq!(
        header(&response, "Access-Control-Allow-Origin"),
        Some("*"),
        "an error response must still be readable by the page: {response}"
    );
}

/// The preflight. Nothing registers `OPTIONS` on any route, so without the short-circuit this is a
/// 405 and every client that preflights, which includes parse-dashboard, fails on the first call.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_preflight_is_answered_rather_than_routed() {
    let server = common::boot().await;
    let host = &server.host;

    for path in ["/parse/classes/Post", "/parse/users", "/parse/nonexistent"] {
        let response = raw(
            host,
            &format!(
                "OPTIONS {path} HTTP/1.1\r\nHost: {host}\r\nOrigin: https://app.example\r\n\
                 Access-Control-Request-Method: POST\r\n\
                 Access-Control-Request-Headers: X-Parse-Application-Id\r\n\
                 Connection: close\r\n\r\n"
            ),
        )
        .await;

        assert_eq!(status(&response), 200, "preflight on {path}: {response}");
        assert_eq!(
            header(&response, "Access-Control-Allow-Origin"),
            Some("*"),
            "{response}"
        );
        assert!(
            header(&response, "Access-Control-Allow-Headers")
                .expect("allow-headers")
                .contains("X-Parse-Application-Id"),
            "the preflight must allow the header it was asked about: {response}"
        );
    }
}

/// A configured allowlist. The header takes one value and the browser compares it to its own
/// origin, so a listed origin has to be echoed back and an unlisted one must not be.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_configured_allowlist_echoes_a_listed_origin_and_refuses_an_unlisted_one() {
    let server = common::boot_fresh_with(|mut config| {
        config.allow_origin = vec![
            "https://a.example".to_string(),
            "https://b.example".to_string(),
        ];
        config.allow_headers = vec!["X-Custom".to_string()];
        config
    })
    .await;
    let host = &server.host;

    let listed = raw(
        host,
        &format!(
            "GET /parse/health HTTP/1.1\r\nHost: {host}\r\nOrigin: https://b.example\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(
        header(&listed, "Access-Control-Allow-Origin"),
        Some("https://b.example"),
        "{listed}"
    );

    let unlisted = raw(
        host,
        &format!(
            "GET /parse/health HTTP/1.1\r\nHost: {host}\r\nOrigin: https://evil.example\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(
        header(&unlisted, "Access-Control-Allow-Origin"),
        Some("https://a.example"),
        "an unlisted origin must never be echoed back: {unlisted}"
    );

    // A configured header is added to the defaults, not substituted for them.
    let allowed = header(&listed, "Access-Control-Allow-Headers").expect("allow-headers");
    assert!(allowed.contains("X-Custom"), "{allowed}");
    assert!(allowed.contains("X-Parse-Application-Id"), "{allowed}");
}

/// An explicitly empty allowlist closes browser access instead of opening it.
///
/// Upstream's `config?.allowOrigin ?? ['*']` falls back only on null or undefined, so an explicit
/// `allowOrigin: []` leaves `baseOrigins[0]` undefined and the header names no origin. Defaulting
/// an empty list to `*` reverses a closed configuration into an open one, which is the single
/// direction a CORS bug must never fail in.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_explicitly_empty_allow_origin_is_not_a_wildcard() {
    let server = common::boot_fresh_with(|mut c| {
        c.allow_origin = Vec::new();
        c
    })
    .await;
    let host = &server.host;

    let response = raw(
        host,
        &format!(
            "GET /parse/health HTTP/1.1\r\nHost: {host}\r\nOrigin: https://evil.example\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;

    let allowed = header(&response, "Access-Control-Allow-Origin");
    assert_ne!(
        allowed,
        Some("*"),
        "an explicitly empty allowlist must not echo a wildcard: {response}"
    );
    assert_ne!(
        allowed,
        Some("https://evil.example"),
        "and must not echo an origin it does not list: {response}"
    );
}
