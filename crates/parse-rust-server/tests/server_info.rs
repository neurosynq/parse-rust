//! End-to-end over real HTTP against a real listener.
//!
//! Deliberately not `oneshot` against the router. The behaviors under test are header parsing,
//! status codes and exact response bodies, and a oneshot bypasses the parts of the stack most
//! likely to differ from Express. If it does not go over a socket it is not testing the thing
//! that has to match.

use parse_rust_mongo::MongoAdapter;
use parse_rust_server::{AppState, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Boot on an ephemeral port and return `host:port`.
async fn boot() -> String {
    let config = ServerConfig::new("test", "test")
        .rest_api_key("rest")
        .mount_path("/parse");
    // A per-process database so parallel batteries cannot collide.
    let db = format!("parse_rust_srv_{}", std::process::id());
    let storage = MongoAdapter::connect("mongodb://127.0.0.1:27017", &db)
        .await
        .expect("MongoDB must be running on 27017");
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let (bound, server) = parse_rust_server::serve(AppState::new(config, storage), addr)
        .await
        .expect("bind failed");
    tokio::spawn(server);
    bound.to_string()
}

/// A minimal HTTP/1.1 GET, written by hand so the test has no HTTP client dependency and so
/// the exact bytes on the wire are visible in the test itself.
async fn get(host: &str, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");

    let mut s = tokio::net::TcpStream::connect(host).await.expect("connect");
    s.write_all(req.as_bytes()).await.expect("write");
    let mut buf = String::new();
    s.read_to_string(&mut buf).await.expect("read");

    let status = buf
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .expect("status line");
    let body = buf.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("body was not JSON: {e}: {body}"))
}

/// `spec/features.spec.js`, block 1: "should return the serverInfo".
#[tokio::test]
async fn server_info_with_master_key() {
    let host = boot().await;
    let (status, body) = get(
        &host,
        "/parse/serverInfo",
        &[
            ("X-Parse-Application-Id", "test"),
            ("X-Parse-REST-API-Key", "rest"),
            ("X-Parse-Master-Key", "test"),
        ],
    )
    .await;

    assert_eq!(status, 200, "body: {body}");
    let v = json(&body);
    assert!(v.get("features").is_some(), "features missing");
    assert!(
        v.get("parseServerVersion").is_some(),
        "parseServerVersion missing"
    );
    // The one `false` in the capability block, and so the one a transcription would flip.
    assert_eq!(
        v["features"]["schemas"]["exportClass"],
        serde_json::json!(false)
    );
}

/// Capabilities `/serverInfo` advertises must exist.
///
/// **This test lives here rather than in the conformance runner on purpose.** It is the one
/// assertion in this area that would *fail* against real parse-server, because upstream hardcodes
/// these to `true` and implements them. `tools/spec/features.spec.mjs` may hold only assertions
/// that pass against both servers, or its promise that a failure means parse-rust diverged stops
/// being true. So the differential half checks the shape there, and the honesty half is checked
/// here.
///
/// Parse Dashboard renders controls from this object, so an advertised capability with no route
/// behind it becomes a button that 404s. Each of these flips to `true` in the commit that lands
/// its subsystem, and this test is what makes forgetting to flip it visible.
#[tokio::test]
async fn unimplemented_capabilities_are_not_advertised() {
    let host = boot().await;
    let (status, body) = get(
        &host,
        "/parse/serverInfo",
        &[
            ("X-Parse-Application-Id", "test"),
            ("X-Parse-REST-API-Key", "rest"),
            ("X-Parse-Master-Key", "test"),
        ],
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    let v = json(&body);

    for (subsystem, path) in [
        ("the schema API", ["schemas", "addClass"]),
        ("the schema API", ["schemas", "editClassLevelPermissions"]),
        ("hooks", ["hooks", "create"]),
        ("global config", ["globalConfig", "read"]),
        ("the log API", ["logs", "level"]),
        ("cloud jobs", ["cloudCode", "jobs"]),
        ("push audiences", ["push", "pushAudiences"]),
    ] {
        assert_eq!(
            v["features"][path[0]][path[1]],
            serde_json::json!(false),
            "features.{}.{} advertises {} , which has no route. Either the subsystem landed and \
             this test should be updated in that commit, or a client is being told about a \
             capability that will 404.",
            path[0],
            path[1],
            subsystem,
        );
    }
}

/// `spec/features.spec.js`, block 2, HTTP half: "requires the master key to get features".
/// The logger-spy half of that block reaches into the Node module graph and is not reproducible
/// over HTTP by any harness, so it is out of scope rather than silently dropped.
#[tokio::test]
async fn server_info_without_master_key_is_permission_denied() {
    let host = boot().await;
    let (status, body) = get(
        &host,
        "/parse/serverInfo",
        &[
            ("X-Parse-Application-Id", "test"),
            ("X-Parse-REST-API-Key", "rest"),
        ],
    )
    .await;

    assert_eq!(status, 403, "body: {body}");
    let v = json(&body);
    assert_eq!(v["error"], serde_json::json!("Permission denied"));
    // The envelope carries no `code`. SDKs branch on that to tell an HTTP rejection from a
    // Parse error, so its absence is contract rather than omission.
    assert!(v.get("code").is_none(), "must not carry a code: {body}");
}

/// Two 403s that look alike and are not: the header layer says `unauthorized`, the master-key
/// gate says `Permission denied`.
#[tokio::test]
async fn the_header_layer_rejects_differently_than_the_master_key_gate() {
    let host = boot().await;
    let (status, body) = get(
        &host,
        "/parse/serverInfo",
        &[("X-Parse-Master-Key", "test")], // no appId
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(json(&body)["error"], serde_json::json!("unauthorized"));
}

/// A configured client key is mandatory for a non-master caller.
///
/// Worth a test because the failure is confusing rather than obvious: omitting the key produces a
/// bare 403 that looks like an authorization problem with the request, not a missing header.
#[tokio::test]
async fn a_configured_client_key_is_required_for_non_master_requests() {
    let host = boot().await;
    let (status, body) = get(
        &host,
        "/parse/serverInfo",
        &[("X-Parse-Application-Id", "test")], // rest key configured but not presented
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(json(&body)["error"], serde_json::json!("unauthorized"));
}

#[tokio::test]
async fn health_needs_no_credentials() {
    let host = boot().await;
    let (status, body) = get(&host, "/parse/health", &[]).await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(json(&body)["status"], serde_json::json!("ok"));
}

/// The mount path is a builder input and is never inferred from the request path.
#[tokio::test]
async fn nothing_is_served_off_the_mount_path() {
    let host = boot().await;
    let (status, _) = get(
        &host,
        "/serverInfo",
        &[
            ("X-Parse-Application-Id", "test"),
            ("X-Parse-Master-Key", "test"),
        ],
    )
    .await;
    assert_eq!(
        status, 404,
        "route must not be reachable off the mount path"
    );
}
