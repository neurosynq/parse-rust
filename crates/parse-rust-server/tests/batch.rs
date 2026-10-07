//! `POST /batch`, over HTTP.
//!
//! `#[ignore]`d because they need a MongoDB on 27017. `tools/test.sh` runs them.

mod common;

use common::{get, post, signup, As};
use serde_json::json;

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn mixed_success_and_failure_in_one_request() {
    let server = common::boot().await;
    let host = &server.host;
    let (owner_id, token) = signup(host, "batch_user", "pw").await;

    // A row only the owner may write, so the second sub-request below fails on ACL alone.
    let locked = post(
        host,
        "/classes/Item",
        &As::user(&token),
        &json!({ "name": "locked", "ACL": { owner_id.clone(): { "read": true, "write": true } } }),
    )
    .await;
    let locked_id = locked.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();

    let response = post(
        host,
        "/batch",
        &As::anonymous(),
        &json!({
            "requests": [
                { "method": "POST", "path": "/parse/classes/Item", "body": { "name": "one" } },
                { "method": "PUT", "path": format!("/parse/classes/Item/{locked_id}"),
                  "body": { "name": "hijacked" } },
                { "method": "GET", "path": "/parse/classes/Item",
                  "body": { "where": { "name": "one" } } },
            ],
        }),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.raw);

    // The whole body is the array itself, not an object wrapping it.
    let results = response.body.as_array().expect("an array body").clone();
    assert_eq!(results.len(), 3, "{}", response.raw);

    assert!(
        results[0]["success"]["objectId"].is_string(),
        "{}",
        response.raw
    );
    assert!(results[0]["success"]["createdAt"].is_string());

    assert_eq!(results[1]["error"]["code"], json!(101), "{}", response.raw);
    assert_eq!(results[1]["error"]["error"], json!("Object not found."));
    assert!(results[1].get("success").is_none());

    // The sub-requests ran in order against one shared context, so the read sees the write.
    let found = results[2]["success"]["results"]
        .as_array()
        .expect("results array");
    assert_eq!(found.len(), 1, "{}", response.raw);
    assert_eq!(found[0]["name"], json!("one"));

    // The failure did not land.
    let after = get(
        host,
        &format!("/classes/Item/{locked_id}"),
        &As::user(&token),
    )
    .await;
    assert_eq!(after.body["name"], json!("locked"), "{}", after.raw);
}

/// A batch runs under the auth the outer request carried, once.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn sub_requests_inherit_the_outer_auth() {
    let server = common::boot().await;
    let host = &server.host;
    let (_id, token) = signup(host, "batch_auth", "pw").await;

    // `/schemas` is master only, so it succeeds with the master key and is refused without it.
    let as_master = post(
        host,
        "/batch",
        &As::master(),
        &json!({ "requests": [{ "method": "GET", "path": "/parse/schemas" }] }),
    )
    .await;
    let results = as_master.body.as_array().expect("array").clone();
    assert!(
        results[0]["success"]["results"].is_array(),
        "{}",
        as_master.raw
    );

    let as_user = post(
        host,
        "/batch",
        &As::user(&token),
        &json!({ "requests": [{ "method": "GET", "path": "/parse/schemas" }] }),
    )
    .await;
    let results = as_user.body.as_array().expect("array").clone();
    assert_eq!(results[0]["error"]["error"], json!("Permission denied"));
    // The master-key gate throws an error with no `code`, and `JSON.stringify` drops the
    // resulting `undefined`. Reproduced rather than given an invented code.
    assert!(results[0]["error"].get("code").is_none(), "{}", as_user.raw);
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_malformed_shapes_are_refused_before_anything_runs() {
    let server = common::boot().await;
    let host = &server.host;

    for (body, code, message) in [
        (json!({}), 107, "requests must be an array"),
        (json!({ "requests": {} }), 107, "requests must be an array"),
        (
            json!({ "requests": [{ "method": "POST" }] }),
            107,
            "batch request path must be a string",
        ),
        (
            json!({ "requests": ["nope"] }),
            107,
            "batch request path must be a string",
        ),
        (
            json!({ "requests": [{ "method": "POST", "path": "/parse/batch" }] }),
            107,
            "nested batch requests are not allowed",
        ),
        (
            json!({ "requests": [{ "method": "GET", "path": "/elsewhere/classes/Post" }] }),
            107,
            "cannot route batch path /elsewhere/classes/Post",
        ),
    ] {
        let r = post(host, "/batch", &As::master(), &body).await;
        assert_eq!(r.code(), Some(code), "{}", r.raw);
        assert_eq!(r.error(), message, "{}", r.raw);
    }

    // A batch whose first element is malformed writes nothing.
    let mixed = post(
        host,
        "/batch",
        &As::master(),
        &json!({
            "requests": [
                { "method": "POST", "path": "/parse/classes/Never", "body": { "n": 1 } },
                { "method": "POST" },
            ],
        }),
    )
    .await;
    assert_eq!(mixed.code(), Some(107), "{}", mixed.raw);
    let listed = get(host, "/classes/Never", &As::master()).await;
    assert!(
        listed.results().is_empty(),
        "validation runs over the whole array before anything executes: {}",
        listed.raw
    );
}

/// Refused rather than accepted and silently run without one. That is the failure mode the
/// milestone names by name.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_transactional_batch_is_refused() {
    let server = common::boot().await;
    let host = &server.host;

    let r = post(
        host,
        "/batch",
        &As::master(),
        &json!({
            "transaction": true,
            "requests": [{ "method": "POST", "path": "/parse/classes/Tx", "body": { "n": 1 } }],
        }),
    )
    .await;
    assert_eq!(r.code(), Some(108), "{}", r.raw);
    assert!(
        r.error().contains("transaction"),
        "the message has to name the limitation: {}",
        r.raw
    );

    let listed = get(host, "/classes/Tx", &As::master()).await;
    assert!(listed.results().is_empty(), "nothing ran: {}", listed.raw);
}

/// An unroutable sub-request is a per-operation error, not a 404 for the whole batch.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_unroutable_sub_request_fails_only_itself() {
    let server = common::boot().await;
    let host = &server.host;

    let r = post(
        host,
        "/batch",
        &As::master(),
        &json!({
            "requests": [
                { "method": "POST", "path": "/parse/functions/nope", "body": {} },
                { "method": "POST", "path": "/parse/classes/Fine", "body": { "n": 1 } },
            ],
        }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.raw);
    let results = r.body.as_array().expect("array").clone();
    assert_eq!(results[0]["error"]["code"], json!(107), "{}", r.raw);
    assert_eq!(
        results[0]["error"]["error"],
        json!("cannot route POST /functions/nope")
    );
    assert!(results[1]["success"]["objectId"].is_string(), "{}", r.raw);
}

/// `batchRequestLimit` defaults to `-1`, which disables it.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_batch_request_limit_is_disabled_by_default_and_master_bypasses_it() {
    let server = common::boot().await;
    let requests: Vec<_> = (0..5)
        .map(|n| json!({ "method": "POST", "path": "/parse/classes/Many", "body": { "n": n } }))
        .collect();
    let r = post(
        &server.host,
        "/batch",
        &As::anonymous(),
        &json!({ "requests": requests.clone() }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.raw);
    assert_eq!(r.body.as_array().map(Vec::len), Some(5));

    // With a limit set, a non-privileged caller is refused and master is not.
    let limited = {
        let mut config = parse_rust_server::ServerConfig::new(common::APP_ID, common::MASTER_KEY);
        config.batch_request_limit = 2;
        common::boot_with(&server.database, config).await
    };
    let refused = post(
        &limited,
        "/batch",
        &As::anonymous(),
        &json!({ "requests": requests.clone() }),
    )
    .await;
    assert_eq!(refused.code(), Some(107), "{}", refused.raw);
    assert_eq!(
        refused.error(),
        "Batch request contains 5 sub-requests, which exceeds the limit of 2."
    );

    let allowed = post(
        &limited,
        "/batch",
        &As::master(),
        &json!({ "requests": requests }),
    )
    .await;
    assert_eq!(
        allowed.status, 200,
        "master bypasses the limit: {}",
        allowed.raw
    );
}
