//! The Mongo adapter against a real MongoDB.
//!
//! Not mocked. A mocked storage adapter tests that the mock behaves like the mock; every failure
//! this layer can have (filter shape, index options, duplicate-key mapping, pointer storage form)
//! only appears against a real server.
//!
//! Each test uses its own database, named from the process id and the test, so several test
//! batteries can run at once without crosstalk. Each drops its database on the way out.
//!
//! `#[ignore]` because it needs a MongoDB on 27017. Run via `tools/test.sh`.

use parse_rust_core::{ErrorCode, ParseMap, ParseValue};
use parse_rust_mongo::MongoAdapter;
use parse_rust_schema::default_schema;
use parse_rust_storage::{
    ClassSchema, Comparison, Constraint, FieldType, QueryOptions, SortDirection, StorageAdapter,
};

const URI: &str = "mongodb://127.0.0.1:27017";

async fn adapter(test: &str) -> (MongoAdapter, String) {
    let db = format!("parse_rust_it_{}_{}", std::process::id(), test);
    let a = MongoAdapter::connect(URI, &db)
        .await
        .expect("MongoDB must be running on 27017 for this test");
    (a, db)
}

async fn drop_db(db: &str) {
    if let Ok(client) = mongodb::Client::with_uri_str(URI).await {
        let _ = client.database(db).drop().await;
    }
}

fn row(pairs: Vec<(&str, ParseValue)>) -> ParseMap {
    let mut m = ParseMap::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    m
}

fn post_schema() -> ClassSchema {
    let mut s = default_schema("Post");
    s.fields.insert("title".into(), FieldType::String);
    s.fields.insert("views".into(), FieldType::Number);
    s.fields.insert(
        "author".into(),
        FieldType::Pointer {
            target_class: "_User".into(),
        },
    );
    s
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn create_then_find_round_trips() {
    let (a, db) = adapter("roundtrip").await;
    let schema = post_schema();

    a.create(
        &schema,
        &row(vec![
            ("objectId", ParseValue::String("oid0000001".into())),
            ("title", ParseValue::String("hello".into())),
            ("views", ParseValue::Number(7.0)),
        ]),
    )
    .await
    .expect("create");

    let found = a
        .find(&schema, &[], &QueryOptions::default())
        .await
        .expect("find");
    assert_eq!(found.len(), 1);
    assert!(matches!(found[0].get("title"), Some(ParseValue::String(s)) if s == "hello"));
    assert!(matches!(found[0].get("views"), Some(ParseValue::Number(n)) if *n == 7.0));
    assert!(matches!(found[0].get("objectId"), Some(ParseValue::String(s)) if s == "oid0000001"));

    drop_db(&db).await;
}

/// Pointers store as `"Class$id"`, so a pointer query must compare against that string. Getting
/// it wrong returns nothing, silently.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn a_pointer_query_matches_the_stored_form() {
    let (a, db) = adapter("pointerquery").await;
    let schema = post_schema();
    let author = ParseValue::Pointer {
        class_name: "_User".into(),
        object_id: "u123".into(),
    };

    a.create(
        &schema,
        &row(vec![
            ("objectId", ParseValue::String("oid0000002".into())),
            ("author", author.clone()),
        ]),
    )
    .await
    .expect("create");

    let found = a
        .find(
            &schema,
            &[Constraint::equal("author", author)],
            &QueryOptions::default(),
        )
        .await
        .expect("find");
    assert_eq!(
        found.len(),
        1,
        "a pointer query must find the row it stored"
    );

    drop_db(&db).await;
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn constraints_on_one_field_merge_into_a_range() {
    let (a, db) = adapter("range").await;
    let schema = post_schema();
    for (i, id) in [(1.0, "a"), (5.0, "b"), (9.0, "c")] {
        a.create(
            &schema,
            &row(vec![
                ("objectId", ParseValue::String(format!("oid000000{id}"))),
                ("views", ParseValue::Number(i)),
            ]),
        )
        .await
        .expect("create");
    }

    // Two constraints on `views`. If they overwrote each other this would return the wrong set.
    let found = a
        .find(
            &schema,
            &[
                Constraint {
                    field: "views".into(),
                    comparison: Comparison::GreaterThan(ParseValue::Number(1.0)),
                },
                Constraint {
                    field: "views".into(),
                    comparison: Comparison::LessThan(ParseValue::Number(9.0)),
                },
            ],
            &QueryOptions::default(),
        )
        .await
        .expect("find");
    assert_eq!(
        found.len(),
        1,
        "range must be the intersection, not the last constraint"
    );
    assert!(matches!(found[0].get("views"), Some(ParseValue::Number(n)) if *n == 5.0));

    drop_db(&db).await;
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn order_limit_and_skip() {
    let (a, db) = adapter("orderlimit").await;
    let schema = post_schema();
    for (n, id) in [(3.0, "a"), (1.0, "b"), (2.0, "c")] {
        a.create(
            &schema,
            &row(vec![
                ("objectId", ParseValue::String(format!("oid000000{id}"))),
                ("views", ParseValue::Number(n)),
            ]),
        )
        .await
        .expect("create");
    }

    let opts = QueryOptions {
        order: vec![("views".into(), SortDirection::Descending)],
        limit: Some(2),
        ..Default::default()
    };
    let found = a.find(&schema, &[], &opts).await.expect("find");
    let views: Vec<f64> = found
        .iter()
        .filter_map(|r| match r.get("views") {
            Some(ParseValue::Number(n)) => Some(*n),
            _ => None,
        })
        .collect();
    assert_eq!(views, vec![3.0, 2.0]);

    drop_db(&db).await;
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn update_and_delete_report_matched_counts() {
    let (a, db) = adapter("updatedelete").await;
    let schema = post_schema();
    a.create(
        &schema,
        &row(vec![
            ("objectId", ParseValue::String("oid0000003".into())),
            ("title", ParseValue::String("before".into())),
        ]),
    )
    .await
    .expect("create");

    let matched = a
        .update(
            &schema,
            &[Constraint::equal(
                "objectId",
                ParseValue::String("oid0000003".into()),
            )],
            &row(vec![("title", ParseValue::String("after".into()))]),
        )
        .await
        .expect("update");
    assert_eq!(matched, 1);

    let found = a
        .find(&schema, &[], &QueryOptions::default())
        .await
        .expect("find");
    assert!(matches!(found[0].get("title"), Some(ParseValue::String(s)) if s == "after"));

    // A miss reports zero rather than erroring, so the REST layer can decide what that means.
    let missed = a
        .update(
            &schema,
            &[Constraint::equal(
                "objectId",
                ParseValue::String("nope000000".into()),
            )],
            &row(vec![("title", ParseValue::String("x".into()))]),
        )
        .await
        .expect("update");
    assert_eq!(missed, 0);

    let deleted = a
        .delete(
            &schema,
            &[Constraint::equal(
                "objectId",
                ParseValue::String("oid0000003".into()),
            )],
        )
        .await
        .expect("delete");
    assert_eq!(deleted, 1);
    assert_eq!(a.count(&schema, &[]).await.expect("count"), 0);

    drop_db(&db).await;
}

/// Signup depends on this: a `username_1` collision must surface as `DUPLICATE_VALUE` so the REST
/// layer can turn it into 202 "username taken" rather than a generic failure.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn a_unique_index_collision_maps_to_duplicate_value() {
    let (a, db) = adapter("uniqueindex").await;
    let mut schema = default_schema("_User");
    schema.fields.insert("username".into(), FieldType::String);

    a.ensure_unique_index("_User", &["username"], None)
        .await
        .expect("index");

    a.create(
        &schema,
        &row(vec![
            ("objectId", ParseValue::String("u000000001".into())),
            ("username", ParseValue::String("alice".into())),
        ]),
    )
    .await
    .expect("first create");

    let err = a
        .create(
            &schema,
            &row(vec![
                ("objectId", ParseValue::String("u000000002".into())),
                ("username", ParseValue::String("alice".into())),
            ]),
        )
        .await
        .expect_err("second create must collide");
    assert_eq!(err.code, ErrorCode::DuplicateValue);
    // The index name is in the message, which is how upstream recovers which field collided.
    assert!(
        err.message.contains("username_1"),
        "the auto-generated index name must appear in the error: {}",
        err.message
    );

    drop_db(&db).await;
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn schemas_round_trip_through_the_schema_collection() {
    let (a, db) = adapter("schemaroundtrip").await;
    let schema = post_schema();
    a.upsert_schema(&schema).await.expect("upsert");

    let loaded = a.all_schemas().await.expect("all_schemas");
    let post = loaded
        .iter()
        .find(|s| s.class_name == "Post")
        .expect("Post schema");

    assert_eq!(post.field("title"), Some(&FieldType::String));
    assert_eq!(post.field("views"), Some(&FieldType::Number));
    assert_eq!(
        post.field("author"),
        Some(&FieldType::Pointer {
            target_class: "_User".into()
        }),
        "a pointer's target class must survive the _SCHEMA round trip"
    );
    // ACL is injected on read and never stored.
    assert_eq!(post.field("ACL"), Some(&FieldType::Acl));

    drop_db(&db).await;
}
