//! Sessions and the role graph against a real MongoDB.
//!
//! The unit tests use an in-memory adapter, which proves the logic and nothing about the stored
//! form. These prove the stored form, which is the half a mixed fleet depends on: a `_Session`
//! row parse-server can read has its token under `_session_token`, its user under `_p_user` as
//! `_User$<id>` and its `expiresAt` as a BSON Date, and role membership lives in
//! `_Join:users:_Role` documents that are exactly `{relatedId, owningId}`.
//!
//! Each test uses its own database, named from the process id and the test, so several batteries
//! can run at once without crosstalk. Each drops its database on the way out.
//!
//! `#[ignore]` because it needs a MongoDB on 27017. Run via `tools/test.sh`.
//!
//! **Two of the role tests are red against a defect in `parse-rust-mongo`, not in this crate.**
//! Reading any join collection fails because the transform rejects a generated BSON ObjectId
//! `_id`. The details and the fix are on
//! [`the_role_graph_expands_through_real_join_collections`]. The session tests pass.

use bson::Document;
use parse_rust_auth::{
    create_session, expand_roles, resolve_session, revoke, revoke_all_for_user, CreatedWith,
    NewSession, RolePrincipal, SessionConfig,
};
use parse_rust_core::{ParseMap, ParseValue};
use parse_rust_mongo::MongoAdapter;
use parse_rust_schema::default_schema;
use parse_rust_storage::{join_schema, join_table_name, Constraint, Query, StorageAdapter};

/// `PARSE_RUST_TEST_MONGO`, or the local default, so the suite can run against each supported
/// server version.
fn uri() -> String {
    std::env::var("PARSE_RUST_TEST_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017".to_string())
}

async fn adapter(test: &str) -> (MongoAdapter, String) {
    let db = format!("parse_rust_auth_it_{}_{}", std::process::id(), test);
    let a = MongoAdapter::connect(&uri(), &db)
        .await
        .expect("MongoDB must be running on 27017 for this test");
    (a, db)
}

async fn drop_db(db: &str) {
    if let Ok(client) = mongodb::Client::with_uri_str(uri()).await {
        let _ = client.database(db).drop().await;
    }
}

/// The raw stored documents, bypassing the Parse transform entirely. This is what a parse-server
/// on the same database sees.
async fn raw_docs(db: &str, collection: &str) -> Vec<Document> {
    use futures::TryStreamExt;
    let client = mongodb::Client::with_uri_str(uri()).await.expect("client");
    let cursor = client
        .database(db)
        .collection::<Document>(collection)
        .find(Document::new())
        .await
        .expect("find");
    cursor.try_collect().await.expect("collect")
}

fn row(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
    let mut m = ParseMap::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    m
}

/// Add one membership to `_Join:<key>:_Role`. The filter is the pair itself, because a membership
/// added twice is one row.
async fn join(a: &MongoAdapter, key: &str, related_id: &str, owning_id: &str) {
    let schema = join_schema("_Role", key);
    let doc = row(vec![
        ("relatedId", ParseValue::String(related_id.into())),
        ("owningId", ParseValue::String(owning_id.into())),
    ]);
    let filter = Query::from_constraints(vec![
        Constraint::equal("relatedId", ParseValue::String(related_id.into())),
        Constraint::equal("owningId", ParseValue::String(owning_id.into())),
    ]);
    a.upsert_one(&schema, &filter, &doc).await.expect("join");
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn a_session_row_uses_upstreams_stored_column_names() {
    let (a, db) = adapter("session_columns").await;

    let created = create_session(
        &a,
        &SessionConfig::default(),
        NewSession {
            user_object_id: "user000001",
            created_with: Some(CreatedWith::signup(None)),
            installation_id: Some("install-1"),
        },
    )
    .await
    .expect("create");

    let docs = raw_docs(&db, "_Session").await;
    assert_eq!(docs.len(), 1);
    let doc = &docs[0];

    assert_eq!(
        doc.get_str("_session_token").expect("_session_token"),
        created.session_token,
        "the token column is _session_token, not sessionToken"
    );
    assert_eq!(
        doc.get_str("_p_user").expect("_p_user"),
        "_User$user000001",
        "a Pointer column is _p_<field> holding <Class>$<id>"
    );
    assert_eq!(doc.get_str("_id").expect("_id"), created.object_id);
    assert_eq!(
        doc.get_str("installationId").expect("installationId"),
        "install-1"
    );
    assert!(
        doc.get_datetime("expiresAt").is_ok(),
        "expiresAt is a BSON Date, not a string: {doc:?}"
    );
    assert!(doc.get_datetime("_created_at").is_ok());
    assert!(doc.get_datetime("_updated_at").is_ok());

    let created_with = doc.get_document("createdWith").expect("createdWith");
    assert_eq!(created_with.get_str("action").expect("action"), "signup");
    assert_eq!(
        created_with.get_str("authProvider").expect("authProvider"),
        "password"
    );

    assert!(
        doc.get("ACL").is_none() && doc.get("_rperm").is_none() && doc.get("_wperm").is_none(),
        "a _Session row carries no ACL"
    );

    drop_db(&db).await;
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn a_session_with_no_expiry_stores_no_expires_at_key() {
    let (a, db) = adapter("session_no_expiry").await;

    create_session(
        &a,
        &SessionConfig {
            expire_inactive_sessions: false,
            ..SessionConfig::default()
        },
        NewSession {
            user_object_id: "u1",
            created_with: Some(CreatedWith::login(None)),
            installation_id: None,
        },
    )
    .await
    .expect("create");

    let docs = raw_docs(&db, "_Session").await;
    assert!(docs[0].get("expiresAt").is_none());
    assert!(docs[0].get("installationId").is_none());

    drop_db(&db).await;
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn a_token_round_trips_through_storage() {
    let (a, db) = adapter("session_roundtrip").await;

    let created = create_session(
        &a,
        &SessionConfig::default(),
        NewSession {
            user_object_id: "user000001",
            created_with: Some(CreatedWith::login(None)),
            installation_id: None,
        },
    )
    .await
    .expect("create");

    let resolved = resolve_session(&a, &created.session_token)
        .await
        .expect("resolve");
    assert_eq!(resolved.user_object_id, "user000001");
    assert_eq!(resolved.object_id, created.object_id);
    assert_eq!(resolved.expires_at, created.expires_at);

    assert!(revoke(&a, &created.session_token).await.expect("revoke"));
    assert!(resolve_session(&a, &created.session_token).await.is_err());

    drop_db(&db).await;
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn duplicate_destruction_and_bulk_revocation_work_against_real_storage() {
    let (a, db) = adapter("session_revoke").await;
    let cfg = SessionConfig::default();
    let mk = |user: &'static str, install: Option<&'static str>| NewSession {
        user_object_id: user,
        created_with: Some(CreatedWith::login(None)),
        installation_id: install,
    };

    let phone1 = create_session(&a, &cfg, mk("alice", Some("phone")))
        .await
        .expect("c");
    let tablet = create_session(&a, &cfg, mk("alice", Some("tablet")))
        .await
        .expect("c");
    let bob = create_session(&a, &cfg, mk("bob", Some("phone")))
        .await
        .expect("c");
    let phone2 = create_session(&a, &cfg, mk("alice", Some("phone")))
        .await
        .expect("c");

    assert!(resolve_session(&a, &phone1.session_token).await.is_err());
    assert!(resolve_session(&a, &phone2.session_token).await.is_ok());
    assert!(resolve_session(&a, &tablet.session_token).await.is_ok());
    assert!(resolve_session(&a, &bob.session_token).await.is_ok());

    assert_eq!(revoke_all_for_user(&a, "alice").await.expect("revoke"), 2);
    assert!(resolve_session(&a, &phone2.session_token).await.is_err());
    assert!(resolve_session(&a, &tablet.session_token).await.is_err());
    assert!(
        resolve_session(&a, &bob.session_token).await.is_ok(),
        "another user's sessions must survive a bulk revoke"
    );

    drop_db(&db).await;
}

/// **Currently red, and the defect is not in this crate.**
///
/// A join document written by `upsert_one` (and by parse-server's `addRelation`) has no explicit
/// `_id`, so MongoDB generates a BSON ObjectId for it. `parse_rust_mongo::transform`'s
/// `mongo_object_to_parse` routes `_id` through `bson_to_parse_value`, which rejects the ObjectId
/// type, so **every read of a join collection fails** with
/// `unsupported BSON type in stored document`. Upstream stringifies instead:
/// `restObject['objectId'] = '' + mongoObject[key]` (`MongoTransform.js:1149-1151`).
///
/// This test is deliberately not weakened to pass. Giving the join documents an explicit
/// `objectId` would make it green against a document shape parse-server never writes, which is
/// the kind of green check that proves nothing. It goes green when the transform handles a
/// BSON ObjectId `_id`, and the same fix unblocks `$relatedTo` in the query pipeline.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn the_role_graph_expands_through_real_join_collections() {
    let (a, db) = adapter("role_graph").await;
    let role_schema = default_schema("_Role");

    for (id, name) in [("r1", "Members"), ("r2", "Moderators"), ("r3", "Admins")] {
        a.create(
            &role_schema,
            &row(vec![
                ("objectId", ParseValue::String(id.into())),
                ("name", ParseValue::String(name.into())),
            ]),
        )
        .await
        .expect("create role");
    }

    join(&a, "users", "u1", "r1").await;
    for (child, parent) in [("r1", "r2"), ("r2", "r3"), ("r3", "r1")] {
        join(&a, "roles", child, parent).await;
    }

    // r1 -> r2 -> r3 -> r1 is a cycle. It must terminate and return all three.
    let roles = expand_roles(&a, RolePrincipal::User("u1"))
        .await
        .expect("expand");
    let names: Vec<&str> = roles.iter().map(|r| r.as_str()).collect();
    assert_eq!(names, vec!["Members", "Moderators", "Admins"]);

    // The join documents are exactly two string columns plus Mongo's own `_id`, with no _SCHEMA
    // row of their own.
    let docs = raw_docs(&db, &join_table_name("_Role", "users")).await;
    assert_eq!(docs.len(), 1);
    let mut keys: Vec<&str> = docs[0].keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["_id", "owningId", "relatedId"]);

    let schemas = a.all_schemas().await.expect("schemas");
    assert!(
        !schemas.iter().any(|s| s.class_name.starts_with("_Join:")),
        "join collections must not get a _SCHEMA row"
    );

    drop_db(&db).await;
}

/// Blocked by the same ObjectId `_id` defect as
/// [`the_role_graph_expands_through_real_join_collections`]. See its note.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn a_user_in_more_than_a_hundred_roles_gets_all_of_them() {
    let (a, db) = adapter("role_page").await;
    let role_schema = default_schema("_Role");

    for i in 0..250 {
        let id = format!("role{i:04}");
        a.create(
            &role_schema,
            &row(vec![
                ("objectId", ParseValue::String(id.clone())),
                ("name", ParseValue::String(format!("Role{i:04}"))),
            ]),
        )
        .await
        .expect("create role");
        join(&a, "users", "u1", &id).await;
    }

    let roles = expand_roles(&a, RolePrincipal::User("u1"))
        .await
        .expect("expand");
    assert_eq!(
        roles.len(),
        250,
        "Parse's 100-row page size must not reach the join or role reads"
    );

    drop_db(&db).await;
}
