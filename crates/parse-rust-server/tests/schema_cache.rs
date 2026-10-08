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
    let ttl = Duration::from_secs(1);
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
    // The create wrote `_SCHEMA`, so this read loads the cache, and the TTL runs from that load.
    // Taken before the request, so it is no later than the load.
    let loaded_by = Instant::now();
    assert_eq!(anonymous_find(host, "Post").await, None);

    close_elsewhere(&server.database, "Post").await;
    // Only meaningful while the TTL cannot have run out, which a slow machine could exceed.
    let still_cached = anonymous_find(host, "Post").await;
    if loaded_by.elapsed() < ttl {
        assert_eq!(
            still_cached, None,
            "inside the TTL the cached schema is served"
        );
    }

    // Poll, rather than sleep a fixed time: the TTL is the subject, so wait for its effect.
    let deadline = loaded_by + Duration::from_secs(15);
    loop {
        if anonymous_find(host, "Post").await == DENIED {
            break;
        }
        assert!(Instant::now() < deadline, "the TTL never expired");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        loaded_by.elapsed() >= ttl,
        "the change was seen before the TTL measured from the load could have expired"
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

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_miss_on_a_class_that_exists_rebuilds_every_class() {
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

    // Two changes elsewhere: one to a cached class, one creating a class.
    close_elsewhere(&server.database, "Post").await;
    schema_collection(&server.database)
        .await
        .insert_one(doc! {
            "_id": "Other",
            "objectId": "string", "updatedAt": "date", "createdAt": "date",
            "_metadata": { "class_permissions": closed_clp() },
        })
        .await
        .expect("insert _SCHEMA");

    // A class that exists and is not cached means the schema changed, so everything reloads.
    assert_eq!(anonymous_find(host, "Other").await, DENIED);
    assert_eq!(
        anonymous_find(host, "Post").await,
        DENIED,
        "the rebuild a found class triggers also picks up the change to Post"
    );
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_miss_on_a_class_that_does_not_exist_keeps_the_cache() {
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
    // Nobody has written `Nothing`: an empty answer, and no rebuild.
    assert_eq!(anonymous_find(host, "Nothing").await, None);
    assert_eq!(
        anonymous_find(host, "Post").await,
        None,
        "a miss on a class that does not exist must not rebuild the cache"
    );
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_schema_change_here_rebuilds_every_class() {
    let server = common::boot().await;
    let host = &server.host;
    for class in ["Post", "Note"] {
        let r = post(
            host,
            &format!("/classes/{class}"),
            &As::anonymous(),
            &json!({"title": "a"}),
        )
        .await;
        assert_eq!(r.status, 201, "{}", r.raw);
    }
    assert_eq!(anonymous_find(host, "Post").await, None);

    close_elsewhere(&server.database, "Post").await;
    assert_eq!(anonymous_find(host, "Post").await, None, "still cached");

    // A new field on `Note`, through this server, is a schema write.
    let r = post(
        host,
        "/classes/Note",
        &As::anonymous(),
        &json!({"body": "b"}),
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.raw);
    assert_eq!(
        anonymous_find(host, "Post").await,
        DENIED,
        "a schema write rebuilds every class, so the change made elsewhere is now seen"
    );
}

/// A class another server creates after this one's cache was loaded, with a closed CLP and a row.
async fn create_closed_class_elsewhere(database: &str, class: &str) {
    schema_collection(database)
        .await
        .insert_one(doc! {
            "_id": class,
            "objectId": "string", "updatedAt": "date", "createdAt": "date", "secret": "string",
            "_metadata": { "class_permissions": closed_clp() },
        })
        .await
        .expect("insert _SCHEMA");
    mongodb::Client::with_uri_str(common::mongo_uri())
        .await
        .expect("mongo")
        .database(database)
        .collection::<bson::Document>(class)
        .insert_one(doc! { "_id": "hidden1", "secret": "s3cret" })
        .await
        .expect("insert row");
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_batch_loads_the_classes_it_names_before_running() {
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
    create_closed_class_elsewhere(&server.database, "Vault").await;

    let r = post(
        host,
        "/batch",
        &As::anonymous(),
        &json!({"requests": [{"method": "GET", "path": "/parse/classes/Vault"}]}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.raw);
    assert!(
        !r.raw.contains("s3cret"),
        "a batch must not read a class under a snapshot that predates it: {}",
        r.raw
    );
    assert_eq!(r.body[0]["error"]["code"], json!(119), "{}", r.raw);
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_include_into_a_class_the_snapshot_predates_applies_its_clp() {
    let server = common::boot().await;
    let host = &server.host;
    let pointer = json!({"__type": "Pointer", "className": "Vault", "objectId": "hidden1"});
    let r = post(
        host,
        "/classes/Post",
        &As::anonymous(),
        &json!({"title": "a", "v": pointer}),
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.raw);
    assert_eq!(anonymous_find(host, "Post").await, None);
    create_closed_class_elsewhere(&server.database, "Vault").await;

    // The include runs as a `get` on `Vault` (`RestQuery.js:1255-1259`), whose CLP denies it, so
    // the whole read is 119, as upstream answers. Under the stale snapshot it grafted the row.
    let r = get(host, "/classes/Post?include=v", &As::anonymous()).await;
    assert_eq!(r.code(), Some(119), "{}", r.raw);
    assert!(
        !r.raw.contains("s3cret"),
        "an include must not graft a row its class's CLP denies: {}",
        r.raw
    );
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_reload_that_finds_no_schemas_drops_the_cache() {
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
    let r = put(
        host,
        "/schemas/Post",
        &As::master(),
        &json!({"classLevelPermissions": {"find": {}, "get": {}}}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.raw);
    assert_eq!(anonymous_find(host, "Post").await, DENIED);

    // Every schema removed elsewhere; the reload `GET /schemas` triggers finds none.
    schema_collection(&server.database)
        .await
        .delete_many(doc! {})
        .await
        .expect("clear _SCHEMA");
    let r = get(host, "/schemas", &As::master()).await;
    assert_eq!(r.status, 200, "{}", r.raw);
    assert_eq!(
        anonymous_find(host, "Post").await,
        None,
        "the old CLP must not outlive the schemas it came from"
    );
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_related_to_owner_the_snapshot_predates_applies_its_clp() {
    let server = common::boot().await;
    let host = &server.host;
    // A public row, readable by anyone: only the owner's CLP can keep it out of the answer.
    let made = post(
        host,
        "/classes/Post",
        &As::anonymous(),
        &json!({"title": "member"}),
    )
    .await;
    let post_id = made.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();
    assert_eq!(anonymous_find(host, "Post").await, None);

    // An owning class created elsewhere, closed, whose relation names that row.
    schema_collection(&server.database)
        .await
        .insert_one(doc! {
            "_id": "Vault",
            "objectId": "string", "updatedAt": "date", "createdAt": "date",
            "members": "relation<Post>",
            "_metadata": { "class_permissions": closed_clp() },
        })
        .await
        .expect("insert _SCHEMA");
    let db = mongodb::Client::with_uri_str(common::mongo_uri())
        .await
        .expect("mongo")
        .database(&server.database);
    db.collection::<bson::Document>("Vault")
        .insert_one(doc! { "_id": "hidden1" })
        .await
        .expect("owner row");
    db.collection::<bson::Document>("_Join:members:Vault")
        .insert_one(doc! { "owningId": "hidden1", "relatedId": &post_id })
        .await
        .expect("join row");

    let where_ = common::where_query(json!({"$relatedTo": {
        "object": {"__type": "Pointer", "className": "Vault", "objectId": "hidden1"},
        "key": "members",
    }}));
    let r = get(host, &format!("/classes/Post{where_}"), &As::anonymous()).await;
    assert_eq!(r.status, 200, "{}", r.raw);
    assert!(
        r.results().is_empty(),
        "a relation whose owner's CLP denies the caller must not answer its members: {}",
        r.raw
    );
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_batch_read_reaching_a_class_its_snapshot_predates_runs_again() {
    let server = common::boot().await;
    let host = &server.host;
    let pointer = json!({"__type": "Pointer", "className": "Vault", "objectId": "hidden1"});
    let r = post(
        host,
        "/classes/Post",
        &As::anonymous(),
        &json!({"title": "a", "v": pointer}),
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.raw);
    assert_eq!(anonymous_find(host, "Post").await, None);
    create_closed_class_elsewhere(&server.database, "Vault").await;

    // The batch's snapshot has `Post`, which it names, and not `Vault`, which only the include
    // reaches. The sub-request runs again on a rebuilt snapshot and meets `Vault`'s CLP.
    let r = post(
        host,
        "/batch",
        &As::anonymous(),
        &json!({"requests": [{"method": "GET", "path": "/parse/classes/Post", "body": {"include": "v"}}]}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.raw);
    assert!(!r.raw.contains("s3cret"), "{}", r.raw);
    assert_eq!(r.body[0]["error"]["code"], json!(119), "{}", r.raw);
}
