//! Request transport: body sizes, content types, the `Location` header and the `/me` routes.
//!
//! `#[ignore]`d because they need a MongoDB. `tools/test.sh` runs them.

mod common;

use common::As;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One request with a body given as bytes and a content type of the caller's choosing.
///
/// The body is written on its own task and the response read concurrently, so a server that
/// answers before the upload ends, as a 413 does, still has its answer read.
async fn raw(
    host: &str,
    method: &str,
    path: &str,
    content_type: &str,
    body: Vec<u8>,
) -> (u16, Value) {
    let head = format!(
        "{method} /parse{path} HTTP/1.1\r\nHost: {host}\r\nX-Parse-Application-Id: {}\r\n\
         X-Parse-REST-API-Key: {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        common::APP_ID,
        common::REST_KEY,
        body.len()
    );
    let socket = tokio::net::TcpStream::connect(host).await.expect("connect");
    let (mut read, mut write) = socket.into_split();
    let writer = tokio::spawn(async move {
        let _ = write.write_all(head.as_bytes()).await;
        let _ = write.write_all(&body).await;
        // Dropping the half would shut the write side down, and a server reading a half-closed
        // connection may drop the response it was about to send.
        write.forget();
    });
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match read.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    writer.abort();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {text}"));
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_body_between_two_and_twenty_megabytes_is_accepted() {
    let server = common::boot().await;
    let body = serde_json::to_vec(&json!({ "blob": "x".repeat(3 * 1024 * 1024) })).expect("json");
    let (status, out) = raw(
        &server.host,
        "POST",
        "/classes/Big",
        "application/json",
        body,
    )
    .await;
    assert_eq!(status, 201, "{out}");
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_body_over_twenty_megabytes_is_413() {
    let server = common::boot().await;
    let body = serde_json::to_vec(&json!({ "blob": "x".repeat(21 * 1024 * 1024) })).expect("json");
    let (status, out) = raw(
        &server.host,
        "POST",
        "/classes/Big",
        "application/json",
        body,
    )
    .await;
    assert_eq!(status, 413, "{out}");
    assert_eq!(out["error"], json!("request entity too large"));
}

/// A body under the limit reaches its route whatever its numbers look like once parsed.
///
/// The body is parsed once, before the route. Serializing it again for the route lengthened it,
/// `1e5` becoming `100000.0`, so this body, under 10 MB as sent and over 20 MB as rewritten, was
/// refused as not JSON at all.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_body_under_the_limit_is_not_measured_after_parsing() {
    let server = common::boot().await;
    let mut body = br#"{"requests":[],"pad":["#.to_vec();
    let count = 2_400_000;
    for i in 0..count {
        body.extend_from_slice(if i + 1 == count { b"1e5" } else { b"1e5," });
    }
    body.extend_from_slice(b"]}");
    assert!(body.len() < 10 * 1024 * 1024);
    let (status, out) = raw(&server.host, "POST", "/batch", "application/json", body).await;
    assert_eq!((status, out), (200, json!([])));
}

/// `express.json` leaves a multipart body unparsed, so the route sees `{}`.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_multipart_body_is_the_empty_object() {
    let server = common::boot().await;
    let (status, out) = raw(
        &server.host,
        "POST",
        "/classes/Multi",
        "multipart/form-data; boundary=x",
        b"--x--\r\n".to_vec(),
    )
    .await;
    assert_eq!(status, 201, "{out}");
}

/// body-parser's strict mode refuses a top-level value that is not an object or an array.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_scalar_body_is_400() {
    let server = common::boot().await;
    let (status, out) = raw(
        &server.host,
        "POST",
        "/classes/S",
        "application/json",
        b"5".to_vec(),
    )
    .await;
    assert_eq!(status, 400, "{out}");
    assert!(
        out["error"]
            .as_str()
            .is_some_and(|e| e.contains("is not valid JSON")),
        "{out}"
    );
}

/// `/sessions/me` and `/users/me` serve `GET` only; other methods reach `/:objectId` with `me`.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_me_routes_serve_get_only() {
    let server = common::boot().await;
    let host = &server.host;
    let (_, token) = common::signup(host, "me_routes", "pw").await;
    let r = common::delete(host, "/sessions/me", &As::user(&token)).await;
    assert_eq!(r.code(), Some(101), "{}", r.raw);
    for method in ["PUT", "DELETE"] {
        let r = common::request(host, method, "/users/me", &As::master(), Some(&json!({}))).await;
        assert_eq!(r.code(), Some(101), "{method} /users/me: {}", r.raw);
    }
    let r = common::get(host, "/users/me", &As::user(&token)).await;
    assert_eq!(r.status, 200, "{}", r.raw);
}

/// `RestWrite.location`: `/users/` for a `_User`, `/classes/<className>/` otherwise.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn location_names_users_and_roles_as_upstream_does() {
    let server = common::boot().await;
    let host = &server.host;
    let location = |raw: &str| {
        raw.lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("location: ")
                    .map(|_| l["location: ".len()..].trim().to_string())
            })
            .unwrap_or_default()
    };
    let user = common::post(
        host,
        "/users",
        &As::anonymous(),
        &json!({"username": "loc", "password": "pw"}),
    )
    .await;
    assert_eq!(user.status, 201, "{}", user.raw);
    let id = user.body["objectId"].as_str().expect("objectId");
    assert_eq!(
        location(&user.raw),
        format!("http://{host}/parse/users/{id}")
    );

    let role = common::post(
        host,
        "/roles",
        &As::master(),
        &json!({"name": "Locators", "ACL": {"*": {"read": true}}}),
    )
    .await;
    assert_eq!(role.status, 201, "{}", role.raw);
    let id = role.body["objectId"].as_str().expect("objectId");
    assert_eq!(
        location(&role.raw),
        format!("http://{host}/parse/classes/_Role/{id}")
    );
}

/// HEAD is served by a path's GET handler, as Express serves it, with no body.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn head_is_served_as_get() {
    let server = common::boot().await;
    let r = common::request(&server.host, "HEAD", "/serverInfo", &As::master(), None).await;
    assert_eq!(r.status, 200, "{}", r.raw);
}

/// `/health` is read before the body parser, and `//health` is `/health` once one leading slash is
/// ignored, so neither refuses a malformed body.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn health_ignores_a_malformed_body_with_a_double_slash_too() {
    let server = common::boot().await;
    for path in ["/health", "//health"] {
        let (status, out) = raw(
            &server.host,
            "POST",
            path,
            "application/json",
            b"{not json".to_vec(),
        )
        .await;
        assert_eq!(status, 200, "{path}: {out}");
    }
}

/// A regex atom nested far deeper than any call stack allows is checked without one: the read
/// answers, and the server is still there for the next request.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_deeply_nested_regex_does_not_take_the_server_down() {
    let server = common::boot().await;
    let depth = 100_000;
    let deep = format!("^\\Q{}{}\\E", "(?:".repeat(depth), ")".repeat(depth));
    let body = serde_json::to_vec(&json!({
        "_method": "GET",
        "where": { "tags": { "$all": [{ "$regex": deep }] } },
    }))
    .expect("json");
    let (status, out) = raw(
        &server.host,
        "POST",
        "/classes/Deep",
        "application/json",
        body,
    )
    .await;
    // JavaScript accepts the pattern; MongoDB's regex engine does not nest that deep, and refuses it
    // inside the read, which is the sanitized storage failure upstream would answer as well.
    assert_eq!(
        (status, out),
        (
            500,
            json!({"code": 1, "error": "An internal server error occurred"})
        )
    );
    let (status, _) = raw(
        &server.host,
        "GET",
        "/health",
        "application/json",
        Vec::new(),
    )
    .await;
    assert_eq!(status, 200);
}
