//! Path matching below the mount, as Express does it.
//!
//! `#[ignore]`d because they need a MongoDB. `tools/test.sh` runs them.

mod common;

use common::As;
use serde_json::json;

/// Express routes are non-strict, so one trailing slash is optional.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_trailing_slash_is_optional() {
    let server = common::boot().await;
    let made = common::post(
        &server.host,
        "/classes/Slash",
        &As::master(),
        &json!({"n": 1}),
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.raw);
    for path in ["/classes/Slash/", "/classes/Slash/?limit=1"] {
        let r = common::get(&server.host, path, &As::master()).await;
        assert_eq!((r.status, r.results().len()), (200, 1), "{path}: {}", r.raw);
    }
}

/// `allowDoubleForwardSlash` strips one leading `/` after the mount (`middlewares.js:863-866`).
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_double_slash_after_the_mount_is_routed() {
    let server = common::boot().await;
    let made = common::post(
        &server.host,
        "/classes/Double",
        &As::master(),
        &json!({"n": 1}),
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.raw);
    let health = common::get(&server.host, "//health", &As::master()).await;
    assert_eq!(
        (health.status, health.body.clone()),
        (200, json!({"status": "ok"}))
    );
    let info = common::get(&server.host, "//serverInfo", &As::master()).await;
    assert_eq!(info.status, 200, "{}", info.raw);
    assert!(
        info.body.get("parseServerVersion").is_some(),
        "{}",
        info.raw
    );
    let rows = common::get(&server.host, "//classes/Double", &As::master()).await;
    assert_eq!(
        (rows.status, rows.results().len()),
        (200, 1),
        "{}",
        rows.raw
    );
    assert_eq!(rows.results()[0]["n"], json!(1));
}

/// A `:param` matches one or more characters, so an empty segment matches no route.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_empty_segment_matches_no_route() {
    let server = common::boot().await;
    for path in ["/classes//abc", "/classes/Empty//", "///health"] {
        let r = common::get(&server.host, path, &As::master()).await;
        assert_eq!(r.status, 404, "{path}: {}", r.raw);
    }
}

/// An unrouted `HEAD` states its empty body, as every other method does.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_unrouted_head_has_content_length_zero() {
    let server = common::boot().await;
    for method in ["HEAD", "GET"] {
        let r = common::request(&server.host, method, "/nowhere", &As::master(), None).await;
        assert_eq!(r.status, 404, "{method}: {}", r.raw);
        assert!(
            r.raw.to_ascii_lowercase().contains("content-length: 0"),
            "{method}: {}",
            r.raw
        );
    }
}

/// UPSTREAM-QUIRK: `batch.js:90-92`. A batch whose URL does not end with `/batch` is a bare 500,
/// and none of its sub-requests run.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_batch_url_not_ending_in_batch_runs_nothing() {
    let server = common::boot().await;
    let body = json!({"requests": [
        {"method": "POST", "path": "/parse/classes/Quirk", "body": {"n": 1}}
    ]});
    for path in ["/batch/", "/batch?x=1"] {
        let r = common::post(&server.host, path, &As::master(), &body).await;
        assert_eq!(
            (r.status, r.body.clone()),
            (500, json!({"code": 1, "message": "Internal server error."})),
            "{path}"
        );
    }
    let rows = common::get(&server.host, "/classes/Quirk", &As::master()).await;
    assert_eq!(rows.results().len(), 0, "{}", rows.raw);
    // Ends with `/batch`, but the prefix it leaves is `/parse/batch/?x=`, which no sub-request
    // path starts with: refused before anything runs.
    let r = common::post(&server.host, "/batch/?x=/batch", &As::master(), &body).await;
    assert_eq!(
        (r.status, r.body.clone()),
        (
            400,
            json!({"code": 107, "error": "cannot route batch path /parse/classes/Quirk"})
        )
    );
    let rows = common::get(&server.host, "/classes/Quirk", &As::master()).await;
    assert_eq!(rows.results().len(), 0, "{}", rows.raw);
    // `//batch` still ends with `/batch`, so it runs.
    let r = common::post(&server.host, "//batch", &As::master(), &body).await;
    assert_eq!(r.status, 200, "{}", r.raw);
}

/// `serve` refuses a mount path that is route syntax rather than starting with it.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn serve_refuses_a_mount_path_that_is_route_syntax() {
    for mount in ["/:app", "/{app}", "parse", "/parse?x"] {
        let config = parse_rust_server::ServerConfig::new("a", "m").mount_path(mount);
        let storage =
            parse_rust_mongo::MongoAdapter::connect(&common::mongo_uri(), "parse_rust_it_mount")
                .await
                .expect("MongoDB must be reachable at PARSE_RUST_TEST_MONGO");
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let refused =
            parse_rust_server::serve(parse_rust_server::AppState::new(config, storage), addr).await;
        let Err(e) = refused else {
            panic!("{mount} was served");
        };
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{mount}: {e}");
    }
}

/// A server on its own mount, for the cases the shared harness, which always mounts `/parse`,
/// cannot reach.
async fn boot_at(mount: &str) -> String {
    let database = format!("parse_rust_it_mount_{}_{}", std::process::id(), mount.len());
    let config = parse_rust_server::ServerConfig::new(common::APP_ID, common::MASTER_KEY)
        .rest_api_key(common::REST_KEY)
        .mount_path(mount);
    let storage = parse_rust_mongo::MongoAdapter::connect(&common::mongo_uri(), &database)
        .await
        .expect("MongoDB must be reachable at PARSE_RUST_TEST_MONGO");
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let (bound, server) =
        parse_rust_server::serve(parse_rust_server::AppState::new(config, storage), addr)
            .await
            .expect("bind failed");
    tokio::spawn(server);
    bound.to_string()
}

/// One request to an exact path, with a body of the caller's choosing. Returns status and body.
async fn raw(host: &str, method: &str, path: &str, body: &[u8]) -> (u16, serde_json::Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nX-Parse-Application-Id: {}\r\n\
         X-Parse-Master-Key: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        common::APP_ID,
        common::MASTER_KEY,
        body.len()
    );
    let mut socket = tokio::net::TcpStream::connect(host).await.expect("connect");
    socket.write_all(head.as_bytes()).await.expect("write");
    socket.write_all(body).await.expect("write");
    let mut text = String::new();
    socket.read_to_string(&mut text).await.expect("read");
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {text}"));
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or(serde_json::Value::Null);
    (status, body)
}

/// At the root mount: `//health` is the health route, exempt from the body checks; `//classes`
/// routes; and a batch through `//batch` takes its prefix from that URL, `/`, so a sub-request
/// path without its leading slash is refused, as upstream refuses it.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_root_mount_follows_the_same_rules() {
    let host = boot_at("/").await;
    assert_eq!(raw(&host, "POST", "//health", b"{not json").await.0, 200);
    assert_eq!(
        raw(&host, "POST", "/classes/Root", br#"{"n":1}"#).await.0,
        201
    );
    let (status, body) = raw(&host, "GET", "//classes/Root", b"").await;
    assert_eq!(
        (status, body["results"].as_array().map(Vec::len)),
        (200, Some(1))
    );
    let batch = br#"{"requests":[{"method":"POST","path":"classes/Root","body":{"n":2}}]}"#;
    let (status, body) = raw(&host, "POST", "//batch", batch).await;
    assert_eq!(
        (status, body),
        (
            400,
            json!({"code": 107, "error": "cannot route batch path classes/Root"})
        )
    );
    let (_, body) = raw(&host, "GET", "/classes/Root", b"").await;
    assert_eq!(body["results"].as_array().map(Vec::len), Some(1));
}

/// A mount that itself contains `//` is matched literally; the path rules apply below it.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_mount_containing_a_double_slash_is_served() {
    let host = boot_at("/api//v1").await;
    let (status, body) = raw(&host, "GET", "/api//v1/health", b"").await;
    assert_eq!((status, body), (200, json!({"status": "ok"})));
    assert_eq!(
        raw(&host, "POST", "/api//v1/classes/Mounted", br#"{"n":1}"#)
            .await
            .0,
        201
    );
    let (status, body) = raw(&host, "GET", "/api//v1/classes/Mounted/", b"").await;
    assert_eq!(
        (status, body["results"].as_array().map(Vec::len)),
        (200, Some(1))
    );
    assert_eq!(raw(&host, "GET", "/api/v1/health", b"").await.0, 404);
}

/// An unreachable database is reported as that at startup, with the address and the driver's
/// reason, and without the URI's credentials. It used to be `1: Database error` after a 30 s wait.
/// Needs no MongoDB: nothing listens on port 1.
#[tokio::test]
async fn serve_names_an_unreachable_database_and_why() {
    let uri = "mongodb://someone:hunter2@127.0.0.1:1/?serverSelectionTimeoutMS=300";
    let storage = parse_rust_mongo::MongoAdapter::connect(uri, "unreachable")
        .await
        .expect("connect does not contact the server");
    let config = parse_rust_server::ServerConfig::new("a", "m");
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let Err(e) =
        parse_rust_server::serve(parse_rust_server::AppState::new(config, storage), addr).await
    else {
        panic!("served without a database");
    };
    let message = e.to_string();
    assert!(message.starts_with("cannot reach MongoDB: "), "{message}");
    assert!(message.contains("127.0.0.1:1"), "{message}");
    assert!(!message.contains("hunter2"), "{message}");
}

/// A graceful stop waits for a request whose client has already gone. The batch is sent, and once
/// its first rows are in the client drops the connection and the stop is triggered; the server
/// future must not resolve before every row is written. The process used to exit with the batch
/// part done, because only open connections were waited for. A client that leaves before its
/// request reaches a handler abandons it before anything is written, which is hyper's behavior and
/// leaves nothing half done.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_graceful_stop_finishes_a_request_whose_client_left() {
    use tokio::io::AsyncWriteExt;
    let database = format!("parse_rust_it_drain_{}", std::process::id());
    let config = parse_rust_server::ServerConfig::new(common::APP_ID, common::MASTER_KEY)
        .mount_path("/parse");
    let storage = parse_rust_mongo::MongoAdapter::connect(&common::mongo_uri(), &database)
        .await
        .expect("MongoDB must be reachable at PARSE_RUST_TEST_MONGO");
    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let stopping = stop.clone();
    let (bound, server) = parse_rust_server::serve_with_shutdown(
        parse_rust_server::AppState::new(config, storage),
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        async move { stopping.notified().await },
    )
    .await
    .expect("bind");
    let server = tokio::spawn(server);

    let rows = 2000;
    let requests: Vec<serde_json::Value> = (0..rows)
        .map(|n| json!({"method": "POST", "path": "/parse/classes/Drain", "body": {"n": n}}))
        .collect();
    let body = serde_json::to_vec(&json!({ "requests": requests })).expect("json");
    let head = format!(
        "POST /parse/batch HTTP/1.1\r\nHost: {bound}\r\nX-Parse-Application-Id: {}\r\n\
         X-Parse-Master-Key: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        common::APP_ID,
        common::MASTER_KEY,
        body.len()
    );
    let mut socket = tokio::net::TcpStream::connect(bound)
        .await
        .expect("connect");
    socket.write_all(head.as_bytes()).await.expect("write");
    socket.write_all(&body).await.expect("write");

    let client = mongodb::Client::with_uri_str(common::mongo_uri())
        .await
        .expect("MongoDB");
    let collection = client
        .database(&database)
        .collection::<bson::Document>("Drain");
    let count = || async {
        collection
            .count_documents(bson::doc! {})
            .await
            .expect("count")
    };
    let started = std::time::Instant::now();
    while count().await == 0 {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "the batch never started"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    // The work is under way: the client leaves, then the server is told to stop.
    drop(socket);
    stop.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(30), server)
        .await
        .expect("the stop finished")
        .expect("joined")
        .expect("served");
    assert_eq!(count().await, rows);
}
