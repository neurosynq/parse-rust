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
    for path in ["//health", "//serverInfo", "//classes/Double"] {
        let r = common::get(&server.host, path, &As::master()).await;
        assert_eq!(r.status, 200, "{path}: {}", r.raw);
    }
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
