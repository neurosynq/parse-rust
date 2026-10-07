//! The schema cache, over HTTP: what refreshes it and what deliberately does not.
//!
//! The changes "made elsewhere" are written straight into `_SCHEMA` through the driver, which is
//! what another node sharing the database looks like from here. A CLP is the probe throughout,
//! because a stale CLP is the case the cache's design is about.
//!
//! `#[ignore]`d because they need a MongoDB. `tools/test.sh` runs them.

mod common;

use std::time::{Duration, Instant};

use bson::doc;
use common::{get, post, put, As};
use serde_json::json;

/// A CLP block that denies every operation, in `_SCHEMA`'s stored form.
fn closed_clp() -> bson::Document {
    doc! {
        "find": {}, "count": {}, "get": {}, "create": {}, "update": {}, "delete": {},
        "addField": {}, "protectedFields": {},
    }
}

async fn schema_collection(database: &str) -> mongodb::Collection<bson::Document> {
    mongodb::Client::with_uri_str(common::mongo_uri())
        .await
        .expect("mongo")
        .database(database)
        .collection("_SCHEMA")
}

/// Close `class` behind the server's back.
async fn close_elsewhere(database: &str, class: &str) {
    schema_collection(database)
        .await
        .update_one(
            doc! { "_id": class },
            doc! { "$set": { "_metadata.class_permissions": closed_clp() } },
        )
        .await
        .expect("update _SCHEMA");
}

/// `None` when the find is served, the Parse error code when it is refused.
async fn anonymous_find(host: &str, class: &str) -> Option<i64> {
    let r = get(host, &format!("/classes/{class}"), &As::anonymous()).await;
    match r.status {
        200 => None,
        _ => Some(r.code().unwrap_or(-1)),
    }
}

/// `OPERATION_FORBIDDEN`, what a closed CLP answers.
const DENIED: Option<i64> = Some(119);

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_schema_change_made_here_is_seen_by_the_next_request() {
    let server = common::boot().await;
    let host = &server.host;
    let r = post(
        host,
        "/classes/Post",
        &As::anonymous(),
        &json!({"title": "a"}),
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.raw);
    assert_eq!(anonymous_find(host, "Post").await, None);

    let r = put(
        host,
        "/schemas/Post",
        &As::master(),
        &json!({"classLevelPermissions": {"find": {}, "get": {}}}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.raw);
    assert_eq!(
        anonymous_find(host, "Post").await,
        DENIED,
        "a CLP tightened through this server must apply to the very next request"
    );
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn without_a_ttl_a_change_made_elsewhere_waits_for_get_schemas() {
    let server = common::boot().await;
    let host = &server.host;
    let r = post(
        host,
        "/classes/Post",
        &As::anonymous(),
        &json!({"title": "a"}),
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.raw);
    assert_eq!(anonymous_find(host, "Post").await, None);

    close_elsewhere(&server.database, "Post").await;
    // Upstream's default: the cache never expires, so another node's change is not seen. This is
    // the assertion that the cache exists at all.
    assert_eq!(anonymous_find(host, "Post").await, None);
    assert_eq!(anonymous_find(host, "Post").await, None);

    // The schema routes load with `clearCache: true`.
    let r = get(host, "/schemas", &As::master()).await;
    assert_eq!(r.status, 200, "{}", r.raw);
    assert_eq!(anonymous_find(host, "Post").await, DENIED);
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_ttl_bounds_how_long_a_change_made_elsewhere_stays_unseen() {
    let ttl = Duration::from_millis(400);
    let server = common::boot_fresh_with(|mut c| {
        c.schema_cache_ttl = Some(ttl);
        c
    })
    .await;
    let host = &server.host;
    let r = post(
        host,
        "/classes/Post",
        &As::anonymous(),
        &json!({"title": "a"}),
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.raw);
    assert_eq!(anonymous_find(host, "Post").await, None);

    close_elsewhere(&server.database, "Post").await;
    let changed = Instant::now();
    assert_eq!(
        anonymous_find(host, "Post").await,
        None,
        "inside the TTL the cached schema is served"
    );

    // Poll, rather than sleep a fixed time: the TTL is the subject, so wait for its effect.
    let deadline = changed + Duration::from_secs(10);
    loop {
        if anonymous_find(host, "Post").await == DENIED {
            break;
        }
        assert!(Instant::now() < deadline, "the TTL never expired");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        changed.elapsed() >= ttl,
        "the change was seen before the TTL could have expired"
    );
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_class_created_elsewhere_is_seen_on_first_use() {
    let server = common::boot().await;
    let host = &server.host;
    // Fill the cache first, so the class below is a miss rather than a cold load.
    let r = post(
        host,
        "/classes/Post",
        &As::anonymous(),
        &json!({"title": "a"}),
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.raw);
    assert_eq!(anonymous_find(host, "Post").await, None);

    schema_collection(&server.database)
        .await
        .insert_one(doc! {
            "_id": "Other",
            "objectId": "string", "updatedAt": "date", "createdAt": "date",
            "_metadata": { "class_permissions": closed_clp() },
        })
        .await
        .expect("insert _SCHEMA");

    // Missing from the cache, so it reloads, as `getOneSchema` does, and the CLP applies. A cache
    // that served the miss would treat the class as absent and therefore unrestricted.
    assert_eq!(anonymous_find(host, "Other").await, DENIED);
}
