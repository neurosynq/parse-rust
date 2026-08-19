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
///
/// **Binds the router directly instead of calling [`parse_rust_server::serve`], and that is the
/// point of this file rather than an optimization.** Every route exercised here answers from
/// config alone: `/serverInfo` and `/health` never read the database. These are the only tests in
/// the workspace that hold that property, so they are the only ones not marked `#[ignore]`, which
/// is what lets `cargo test --workspace` mean something on a machine with no MongoDB.
///
/// `serve` calls `ensure_indexes` before binding, which is correct for a real server and is a
/// round trip. Going through it made this file need a database in order to test routes that do
/// not use one, and the failure read as "MongoDB must be running" rather than as a lost guarantee.
/// `MongoAdapter::connect` stays because `AppState` needs a storage value; it builds a lazy client
/// and does not contact the server, so no connection is opened unless a route asks for one.
///
/// **Serves with connect info, which is the one thing `serve` does that cannot be skipped here.**
/// `masterKeyIps` filters on the connection's peer address and there is nowhere else to read it,
/// so a router served plainly refuses every master-key request. That is deliberate and it is
/// asserted separately, by [`boot_without_connect_info`].
async fn boot() -> String {
    let listener = bind().await;
    let bound = listener.local_addr().expect("local_addr");
    let app = parse_rust_server::router(state().await)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await });
    bound.to_string()
}

/// The embedder who mounts the router and serves it plainly.
async fn boot_without_connect_info() -> String {
    let listener = bind().await;
    let bound = listener.local_addr().expect("local_addr");
    let app = parse_rust_server::router(state().await);
    tokio::spawn(async move { axum::serve(listener, app).await });
    bound.to_string()
}

async fn bind() -> tokio::net::TcpListener {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    tokio::net::TcpListener::bind(addr).await.expect("bind")
}

async fn state() -> AppState {
    let config = ServerConfig::new("test", "test")
        .rest_api_key("rest")
        .mount_path("/parse");
    // A per-process database so parallel batteries cannot collide.
    let db = format!("parse_rust_srv_{}", std::process::id());
    let storage = MongoAdapter::connect("mongodb://127.0.0.1:27017", &db)
        .await
        .expect("building a lazy Mongo client cannot fail for a valid URI");
    AppState::new(config, storage)
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

    // The other half of the same rule: a capability that *is* advertised must have a route behind
    // it. Each of these is exercised over HTTP by `tests/schemas.rs`, so flipping one on without a
    // working route turns that file red rather than shipping a button that 404s.
    for capability in [
        "addField",
        "removeField",
        "addClass",
        "removeClass",
        "clearAllDataFromClass",
        "editClassLevelPermissions",
        "editPointerPermissions",
    ] {
        assert_eq!(
            v["features"]["schemas"][capability],
            serde_json::json!(true),
            "the schema API landed in 0.2.0, so features.schemas.{capability} is advertised"
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

/// **Failing closed when the transport gives no peer address.**
///
/// `masterKeyIps` filters on the connection's address, so a router mounted into an embedder's own
/// axum app without `into_make_service_with_connect_info` has nothing to filter on. The two
/// privileged keys are refused rather than admitted, which is loud and recoverable; admitting them
/// would silently restore the behavior 0.2.1 exists to remove.
///
/// Everything else still works, so the failure is confined to the keys that are actually gated.
#[tokio::test]
async fn a_router_served_without_connect_info_refuses_the_master_key() {
    let host = boot_without_connect_info().await;

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
    assert_eq!(status, 403, "body: {body}");
    assert_eq!(json(&body)["error"], serde_json::json!("unauthorized"));

    let (status, body) = get(&host, "/parse/health", &[]).await;
    assert_eq!(status, 200, "an unprivileged route is unaffected: {body}");
}
