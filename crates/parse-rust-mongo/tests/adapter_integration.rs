//! The Mongo adapter against a real MongoDB.
//!
//! Not mocked. A mocked storage adapter tests that the mock behaves like the mock; every failure
//! this layer can have (filter shape, index options, duplicate-key mapping, pointer storage form,
//! the conditional upsert behind `reserve_field`) only appears against a real server.
//!
//! Each test uses its own database, named from the process id and the test, so several test
//! batteries can run at once without crosstalk. Each drops its database on the way out.
//!
//! `#[ignore]` because it needs a MongoDB on 27017. Run via `tools/test.sh`.

use parse_rust_core::{ClassLevelPermissions, ErrorCode, ParseMap, ParseValue};
use parse_rust_mongo::MongoAdapter;
use parse_rust_schema::default_schema;
use parse_rust_storage::{
    join_schema, join_table_name, AddFieldOutcome, ClassSchema, Clause, Comparison, Constraint,
    FieldType, Query, QueryOptions, SortDirection, StorageAdapter, Update, UpdateValue,
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

fn by_id(object_id: &str) -> Query {
    Query::from_constraints(vec![Constraint::equal(
        "objectId",
        ParseValue::String(object_id.into()),
    )])
}

fn update(pairs: Vec<(&str, UpdateValue)>) -> Update {
    let mut u = Update::new();
    for (k, v) in pairs {
        u.insert(k.to_string(), v);
    }
    u
}

fn post_schema() -> ClassSchema {
    let mut s = default_schema("Post");
    s.fields.insert("title".into(), FieldType::String);
    s.fields.insert("views".into(), FieldType::Number);
    s.fields.insert("tags".into(), FieldType::Array);
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
        .find(&schema, &Query::new(), &QueryOptions::default())
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
            &Query::from_constraints(vec![Constraint::equal("author", author)]),
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
            &Query::from_constraints(vec![
                Constraint {
                    field: "views".into(),
                    comparison: Comparison::GreaterThan(ParseValue::Number(1.0)),
                },
                Constraint {
                    field: "views".into(),
                    comparison: Comparison::LessThan(ParseValue::Number(9.0)),
                },
            ]),
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

/// The disjunction pointer permissions compile to. Against a real server rather than only against
/// the compiled document, because a filter can be shaped correctly and still match nothing.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn a_disjunction_returns_the_union_of_its_branches() {
    let (a, db) = adapter("disjunction").await;
    let schema = post_schema();
    for (title, id) in [("a", "a"), ("b", "b"), ("c", "c")] {
        a.create(
            &schema,
            &row(vec![
                ("objectId", ParseValue::String(format!("oid000000{id}"))),
                ("title", ParseValue::String(title.into())),
            ]),
        )
        .await
        .expect("create");
    }

    let mut q = Query::new();
    q.push(Clause::Or(vec![
        Query::from_constraints(vec![Constraint::equal(
            "title",
            ParseValue::String("a".into()),
        )]),
        Query::from_constraints(vec![Constraint::equal(
            "title",
            ParseValue::String("c".into()),
        )]),
    ]));

    let found = a
        .find(&schema, &q, &QueryOptions::default())
        .await
        .expect("find");
    assert_eq!(found.len(), 2);

    drop_db(&db).await;
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn regex_and_all_reach_the_server_in_a_shape_it_accepts() {
    let (a, db) = adapter("regexall").await;
    let schema = post_schema();
    a.create(
        &schema,
        &row(vec![
            ("objectId", ParseValue::String("oid0000010".into())),
            ("title", ParseValue::String("Hello".into())),
            (
                "tags",
                ParseValue::Array(vec![
                    ParseValue::String("x".into()),
                    ParseValue::String("y".into()),
                ]),
            ),
        ]),
    )
    .await
    .expect("create");

    let regex = Query::from_constraints(vec![Constraint {
        field: "title".into(),
        comparison: Comparison::Regex {
            pattern: "^hel".into(),
            options: Some("i".into()),
        },
    }]);
    assert_eq!(
        a.count(&schema, &regex).await.expect("count"),
        1,
        "$options must reach the server, or the case-insensitive match fails"
    );

    let all = Query::from_constraints(vec![Constraint {
        field: "tags".into(),
        comparison: Comparison::All(vec![
            ParseValue::String("x".into()),
            ParseValue::String("y".into()),
        ]),
    }]);
    assert_eq!(a.count(&schema, &all).await.expect("count"), 1);

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
    let found = a.find(&schema, &Query::new(), &opts).await.expect("find");
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
            &by_id("oid0000003"),
            &update(vec![(
                "title",
                UpdateValue::Set(ParseValue::String("after".into())),
            )]),
        )
        .await
        .expect("update");
    assert_eq!(matched, 1);

    let found = a
        .find(&schema, &Query::new(), &QueryOptions::default())
        .await
        .expect("find");
    assert!(matches!(found[0].get("title"), Some(ParseValue::String(s)) if s == "after"));

    // A miss reports zero rather than erroring, so the REST layer can decide what that means.
    let missed = a
        .update(
            &schema,
            &by_id("nope000000"),
            &update(vec![(
                "title",
                UpdateValue::Set(ParseValue::String("x".into())),
            )]),
        )
        .await
        .expect("update");
    assert_eq!(missed, 0);

    let deleted = a
        .delete(&schema, &by_id("oid0000003"))
        .await
        .expect("delete");
    assert_eq!(deleted, 1);
    assert_eq!(a.count(&schema, &Query::new()).await.expect("count"), 0);

    drop_db(&db).await;
}

/// The post-image is what tells the client what an `Increment` produced. Reading the *before*
/// image would report the old value and make the op look like it did nothing.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn update_one_returning_reports_the_post_image() {
    let (a, db) = adapter("postimage").await;
    let schema = post_schema();
    a.create(
        &schema,
        &row(vec![
            ("objectId", ParseValue::String("oid0000004".into())),
            ("views", ParseValue::Number(5.0)),
            (
                "tags",
                ParseValue::Array(vec![ParseValue::String("a".into())]),
            ),
        ]),
    )
    .await
    .expect("create");

    let after = a
        .update_one_returning(
            &schema,
            &by_id("oid0000004"),
            &update(vec![
                ("views", UpdateValue::Increment(3.0)),
                (
                    "tags",
                    UpdateValue::AddUnique(vec![ParseValue::String("b".into())]),
                ),
            ]),
        )
        .await
        .expect("update")
        .expect("a row matched");

    assert!(matches!(after.get("views"), Some(ParseValue::Number(n)) if *n == 8.0));
    match after.get("tags") {
        Some(ParseValue::Array(items)) => assert_eq!(items.len(), 2),
        other => panic!("tags must be an array of two, got {other:?}"),
    }

    // Nothing matched is `None`, not an error.
    assert!(a
        .update_one_returning(
            &schema,
            &by_id("nope000000"),
            &update(vec![("views", UpdateValue::Increment(1.0))]),
        )
        .await
        .expect("update")
        .is_none());

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

    a.ensure_index("_User", &["username"], None, true, false)
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
    // Which field collided rides out of band, recovered from the auto-generated index name.
    assert_eq!(err.duplicated_field(), Some("username"));
    // And the message is upstream's fixed one, so the database name and the colliding value
    // never leave the process. This is the assertion that catches a regression to driver text.
    assert_eq!(err.message, parse_rust_core::DUPLICATE_VALUE_MESSAGE);
    assert!(!err.message.contains(&db), "{}", err.message);
    assert!(!err.message.contains("alice"), "{}", err.message);

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
    // No CLP was written, so the key is absent and stays absent. Synthesizing `defaultCLPS` here
    // would make an unset block indistinguishable from an explicitly-public one.
    assert!(post.clp.is_none());

    drop_db(&db).await;
}

/// The failure this guards against is a field-adding save deleting a class's permissions, which
/// is silent, wire-visible only later, and shared with every parse-server reading the database.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn an_ordinary_schema_save_does_not_clobber_class_permissions() {
    let (a, db) = adapter("clpsurvives").await;
    let mut schema = post_schema();
    a.upsert_schema(&schema).await.expect("upsert");

    let mut raw = ParseMap::new();
    let mut find = ParseMap::new();
    find.insert("*".into(), ParseValue::Bool(true));
    raw.insert("find".into(), ParseValue::Object(find));
    a.set_class_permissions("Post", Some(&ClassLevelPermissions::from_map(raw)))
        .await
        .expect("set clp");

    // A later save that knows nothing about the CLP: `clp` is `None` simply because nothing
    // loaded one.
    schema.fields.insert("extra".into(), FieldType::String);
    schema.clp = None;
    a.upsert_schema(&schema).await.expect("second upsert");

    let loaded = a.all_schemas().await.expect("all_schemas");
    let post = loaded
        .iter()
        .find(|s| s.class_name == "Post")
        .expect("Post schema");
    let clp = post.clp.as_ref().expect("the CLP must survive");
    assert!(clp.raw().contains_key("find"));
    // The merge base is `emptyCLPS`, so an operation the stored block never mentioned reads back
    // as deny-all rather than as absent.
    assert!(matches!(
        clp.raw().get("update"),
        Some(ParseValue::Object(m)) if m.is_empty()
    ));

    // `None` removes the key rather than storing an empty block.
    a.set_class_permissions("Post", None)
        .await
        .expect("unset clp");
    let loaded = a.all_schemas().await.expect("all_schemas");
    let post = loaded
        .iter()
        .find(|s| s.class_name == "Post")
        .expect("Post schema");
    assert!(post.clp.is_none(), "an unset CLP reads back as absent");

    drop_db(&db).await;
}

/// The 0.1.0 race fix. Two writers inferring a type for the same new field: the loser must not
/// overwrite the winner, and both must be told which happened.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn reserve_field_is_atomic_under_a_race() {
    let (a, db) = adapter("reserve").await;

    // First reservation creates the class document.
    assert_eq!(
        a.reserve_field("Race", "score", &FieldType::Number, None)
            .await
            .expect("reserve"),
        AddFieldOutcome::Added
    );

    // Same type again: not an error. Both concurrent writers succeed upstream when they agree.
    assert_eq!(
        a.reserve_field("Race", "score", &FieldType::Number, None)
            .await
            .expect("reserve"),
        AddFieldOutcome::AlreadyPresentSameType
    );

    // Different type: the reservation stands and the caller is told what it is.
    assert_eq!(
        a.reserve_field("Race", "score", &FieldType::String, None)
            .await
            .expect("reserve"),
        AddFieldOutcome::Conflict {
            existing: FieldType::Number
        }
    );

    // The stored type is still the winner's.
    let loaded = a.all_schemas().await.expect("all_schemas");
    let race = loaded
        .iter()
        .find(|s| s.class_name == "Race")
        .expect("Race schema");
    assert_eq!(race.field("score"), Some(&FieldType::Number));

    // Concurrently, with the class document already present. Exactly one caller may see `Added`.
    let uri = URI.to_string();
    let db_name = db.clone();
    let mut handles = Vec::new();
    for ty in [
        FieldType::Number,
        FieldType::Number,
        FieldType::Number,
        FieldType::Number,
    ] {
        let uri = uri.clone();
        let db_name = db_name.clone();
        handles.push(tokio::spawn(async move {
            let a = MongoAdapter::connect(&uri, &db_name)
                .await
                .expect("connect");
            a.reserve_field("Race", "racy", &ty, None)
                .await
                .expect("reserve")
        }));
    }
    let mut added = 0;
    for h in handles {
        match h.await.expect("join") {
            AddFieldOutcome::Added => added += 1,
            AddFieldOutcome::AlreadyPresentSameType => {}
            other => panic!("agreeing writers must not conflict, got {other:?}"),
        }
    }
    assert_eq!(added, 1, "exactly one writer may reserve the field");

    drop_db(&db).await;
}

/// A join membership is idempotent: adding a user to a role twice is one row, and the join
/// collection must never acquire a `_SCHEMA` document.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn upsert_one_is_idempotent_and_writes_no_schema() {
    let (a, db) = adapter("joinupsert").await;
    let schema = join_schema("_Role", "users");
    assert_eq!(schema.class_name, "_Join:users:_Role");

    let doc = row(vec![
        ("relatedId", ParseValue::String("u1".into())),
        ("owningId", ParseValue::String("r1".into())),
    ]);
    let filter = Query::from_constraints(vec![
        Constraint::equal("relatedId", ParseValue::String("u1".into())),
        Constraint::equal("owningId", ParseValue::String("r1".into())),
    ]);

    a.upsert_one(&schema, &filter, &doc).await.expect("first");
    a.upsert_one(&schema, &filter, &doc).await.expect("second");

    assert_eq!(
        a.count(&schema, &Query::new()).await.expect("count"),
        1,
        "a membership added twice is one row"
    );

    let loaded = a.all_schemas().await.expect("all_schemas");
    assert!(
        !loaded
            .iter()
            .any(|s| s.class_name == join_table_name("_Role", "users")),
        "join collections have no _SCHEMA row upstream, and inventing one adds a class \
         parse-server does not expect"
    );

    drop_db(&db).await;
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn delete_class_removes_rows_schema_and_join_collections() {
    let (a, db) = adapter("deleteclass").await;
    let mut schema = default_schema("_Role");
    schema.fields.insert("name".into(), FieldType::String);
    schema.fields.insert(
        "users".into(),
        FieldType::Relation {
            target_class: "_User".into(),
        },
    );
    a.upsert_schema(&schema).await.expect("upsert schema");
    a.create(
        &schema,
        &row(vec![
            ("objectId", ParseValue::String("r000000001".into())),
            ("name", ParseValue::String("Admins".into())),
        ]),
    )
    .await
    .expect("create");

    let join = join_schema("_Role", "users");
    a.upsert_one(
        &join,
        &Query::from_constraints(vec![Constraint::equal(
            "relatedId",
            ParseValue::String("u1".into()),
        )]),
        &row(vec![
            ("relatedId", ParseValue::String("u1".into())),
            ("owningId", ParseValue::String("r000000001".into())),
        ]),
    )
    .await
    .expect("join upsert");

    a.delete_class(&schema).await.expect("delete_class");

    assert_eq!(a.count(&schema, &Query::new()).await.expect("count"), 0);
    assert_eq!(
        a.count(&join, &Query::new()).await.expect("count"),
        0,
        "a Relation's join collection goes with the class"
    );
    let loaded = a.all_schemas().await.expect("all_schemas");
    assert!(!loaded.iter().any(|s| s.class_name == "_Role"));

    // Dropping a class that is not there is not an error.
    a.delete_class(&schema).await.expect("second delete_class");

    drop_db(&db).await;
}

#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn delete_fields_removes_the_column_and_the_schema_entry() {
    let (a, db) = adapter("deletefields").await;
    let schema = post_schema();
    a.upsert_schema(&schema).await.expect("upsert schema");
    a.create(
        &schema,
        &row(vec![
            ("objectId", ParseValue::String("oid0000005".into())),
            ("title", ParseValue::String("x".into())),
            (
                "author",
                ParseValue::Pointer {
                    class_name: "_User".into(),
                    object_id: "u1".into(),
                },
            ),
        ]),
    )
    .await
    .expect("create");

    a.delete_fields(&schema, &["title".to_string(), "author".to_string()])
        .await
        .expect("delete_fields");

    // Read back with a schema that still declares them, so a surviving column would show up.
    let found = a
        .find(&schema, &Query::new(), &QueryOptions::default())
        .await
        .expect("find");
    assert!(found[0].get("title").is_none());
    assert!(
        found[0].get("author").is_none(),
        "a Pointer's column is _p_<name>, and that is what has to go"
    );

    let loaded = a.all_schemas().await.expect("all_schemas");
    let post = loaded
        .iter()
        .find(|s| s.class_name == "Post")
        .expect("Post schema");
    assert!(post.field("title").is_none());
    assert!(post.field("author").is_none());

    drop_db(&db).await;
}

/// The `_Role.name` index, and specifically its **name**.
///
/// Upstream creates it with `ensureUniqueness('_Role', requiredRoleFields, ['name'])`
/// (`DatabaseController.js:2045-2050`) and passes no index name, so MongoDB auto-generates
/// `name_1`. That string is contract rather than cosmetic: both adapters recover
/// `duplicated_field` by regex over the index name, and the Mongo regex
/// (`MongoStorageAdapter.js:582`) matches only the auto-generated `<field>_1` form. Naming the
/// index ourselves would change the error a client sees.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn the_role_name_index_is_auto_named_and_unique() {
    use futures::stream::TryStreamExt;

    let (a, db) = adapter("roleindex").await;
    a.ensure_index("_Role", &["name"], None, true, false)
        .await
        .expect("index");

    let client = mongodb::Client::with_uri_str(URI)
        .await
        .expect("MongoDB must be running on 27017 for this test");
    let indexes: Vec<mongodb::IndexModel> = client
        .database(&db)
        .collection::<bson::Document>("_Role")
        .list_indexes()
        .await
        .expect("list_indexes")
        .try_collect()
        .await
        .expect("collect");

    let created = indexes
        .iter()
        .find(|i| i.keys.contains_key("name"))
        .expect("an index on `name` must exist");
    let options = created.options.as_ref().expect("options");
    assert_eq!(
        options.name.as_deref(),
        Some("name_1"),
        "the auto-generated name is what the duplicated_field regex matches"
    );
    assert_eq!(options.unique, Some(true));
    assert_eq!(options.sparse, Some(true));

    drop_db(&db).await;
}

/// Two `_Role` rows may not share a name.
///
/// Without the index an ACL entry of `role:X` grants every member of every row called `X`, so a
/// caller who can create a role can join any role by name. The rejection is the storage layer's
/// `DUPLICATE_VALUE` (137), which is what upstream's `ensureUniqueness` collision produces too.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn a_duplicate_role_name_is_rejected() {
    let (a, db) = adapter("rolename").await;
    let mut schema = default_schema("_Role");
    schema.fields.insert("name".into(), FieldType::String);

    a.ensure_index("_Role", &["name"], None, true, false)
        .await
        .expect("index");

    a.create(
        &schema,
        &row(vec![
            ("objectId", ParseValue::String("r000000001".into())),
            ("name", ParseValue::String("Admins".into())),
        ]),
    )
    .await
    .expect("first role");

    let err = a
        .create(
            &schema,
            &row(vec![
                ("objectId", ParseValue::String("r000000002".into())),
                ("name", ParseValue::String("Admins".into())),
            ]),
        )
        .await
        .expect_err("a second role of the same name must collide");
    assert_eq!(err.code, ErrorCode::DuplicateValue);
    assert_eq!(err.duplicated_field(), Some("name"));
    assert_eq!(err.message, parse_rust_core::DUPLICATE_VALUE_MESSAGE);
    assert!(!err.message.contains(&db), "{}", err.message);
    assert!(!err.message.contains("Admins"), "{}", err.message);

    drop_db(&db).await;
}

/// A field's options are written **with its type, under the same guard, and by path**.
///
/// Upstream puts both in one `$set` beneath the one `{field: {$exists: false}}` filter
/// (`MongoSchemaCollection.js:251-269`). Two properties follow, and this asserts both because
/// getting either wrong is silent:
///
/// - a reservation that loses the race changes nothing, **including the options**, so a caller
///   cannot reserve a type and then have its options replaced by the winner's;
/// - a second field's options land beside the first's rather than replacing the block, which is
///   what makes concurrent additions of different fields safe.
#[tokio::test]
#[ignore = "requires MongoDB on 27017; run via tools/test.sh"]
async fn field_options_are_reserved_with_the_type_and_addressed_per_field() {
    let (a, db) = adapter("field_options").await;

    let options = |value: &str| {
        let mut m = ParseMap::new();
        m.insert("required".to_string(), ParseValue::Bool(true));
        m.insert(
            "defaultValue".to_string(),
            ParseValue::String(value.to_string()),
        );
        m
    };

    assert_eq!(
        a.reserve_field("Opt", "alpha", &FieldType::String, Some(&options("a")))
            .await
            .expect("reserve alpha"),
        AddFieldOutcome::Added
    );
    assert_eq!(
        a.reserve_field("Opt", "beta", &FieldType::String, Some(&options("b")))
            .await
            .expect("reserve beta"),
        AddFieldOutcome::Added
    );

    async fn stored(a: &MongoAdapter) -> ClassSchema {
        a.all_schemas()
            .await
            .expect("schemas")
            .into_iter()
            .find(|s| s.class_name == "Opt")
            .expect("the class exists")
    }

    let opts = stored(&a).await.field_options.expect("options stored");
    for (field, expected) in [("alpha", "a"), ("beta", "b")] {
        let Some(ParseValue::Object(entry)) = opts.get(field) else {
            panic!("{field} has no options entry: {opts:?}");
        };
        assert!(
            matches!(entry.get("defaultValue"), Some(ParseValue::String(v)) if v == expected),
            "adding one field's options must not disturb the other's: {entry:?}"
        );
    }

    // A losing reservation writes nothing at all. Without the options in the same `$set` this
    // would still report the conflict while having replaced `alpha`'s options on the way.
    assert_eq!(
        a.reserve_field(
            "Opt",
            "alpha",
            &FieldType::Number,
            Some(&options("clobbered"))
        )
        .await
        .expect("reserve"),
        AddFieldOutcome::Conflict {
            existing: FieldType::String
        }
    );
    let after = stored(&a).await.field_options.expect("options survive");
    let Some(ParseValue::Object(entry)) = after.get("alpha") else {
        panic!("alpha lost its options: {after:?}");
    };
    assert!(
        matches!(entry.get("defaultValue"), Some(ParseValue::String(v)) if v == "a"),
        "a reservation that lost the race must not have written its options: {entry:?}"
    );

    // And an explicit options update touches one field's path and leaves the sibling alone.
    a.set_field_options("Opt", "alpha", &options("updated"))
        .await
        .expect("set options");
    let final_opts = stored(&a).await.field_options.expect("options");
    let Some(ParseValue::Object(alpha)) = final_opts.get("alpha") else {
        panic!("alpha missing");
    };
    let Some(ParseValue::Object(beta)) = final_opts.get("beta") else {
        panic!("beta missing: {final_opts:?}");
    };
    assert!(matches!(alpha.get("defaultValue"), Some(ParseValue::String(v)) if v == "updated"));
    assert!(
        matches!(beta.get("defaultValue"), Some(ParseValue::String(v)) if v == "b"),
        "one field's options update must not rewrite the block: {beta:?}"
    );

    drop_db(&db).await;
}
