//! `/schemas` and `DELETE /purge/:className`, over HTTP.
//!
//! Every capability `/serverInfo` advertises under `features.schemas` is exercised here, which is
//! the other half of the rule that an advertised capability must have a route behind it.
//!
//! `#[ignore]`d because they need a MongoDB on 27017. `tools/test.sh` runs them.

mod common;

use common::{delete, get, post, put, signup, As};
use serde_json::json;

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn every_schema_route_is_master_key_only() {
    let server = common::boot().await;
    let host = &server.host;
    let (_id, token) = signup(host, "schema_user", "pw").await;

    for who in [As::anonymous(), As::user(&token)] {
        for (method, path) in [
            ("GET", "/schemas"),
            ("GET", "/schemas/Post"),
            ("PUT", "/schemas/Post"),
            ("DELETE", "/schemas/Post"),
            ("DELETE", "/purge/Post"),
        ] {
            let r = common::request(host, method, path, &who, Some(&json!({}))).await;
            assert_eq!(r.status, 403, "{method} {path}: {}", r.raw);
            assert_eq!(r.error(), "Permission denied");
            // The master-key gate uses the `code`-less envelope. SDKs branch on that to tell an
            // HTTP rejection from a Parse error.
            assert_eq!(r.code(), None, "{method} {path}: {}", r.raw);
        }
    }
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_class_round_trips_through_the_schema_api() {
    let server = common::boot().await;
    let host = &server.host;

    // addClass
    let created = post(
        host,
        "/schemas/Article",
        &As::master(),
        &json!({
            "fields": {
                "title": { "type": "String" },
                "views": { "type": "Number" },
                "author": { "type": "Pointer", "targetClass": "_User" },
            },
            "classLevelPermissions": {
                "find": { "*": true },
                "get": { "*": true },
                "create": { "requiresAuthentication": true },
            },
        }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);
    assert_eq!(created.body["className"], json!("Article"));
    assert_eq!(created.body["fields"]["title"], json!({ "type": "String" }));
    assert_eq!(
        created.body["fields"]["author"],
        json!({ "type": "Pointer", "targetClass": "_User" }),
        "not the `*_User` storage spelling"
    );

    let fetched = get(host, "/schemas/Article", &As::master()).await;
    assert_eq!(fetched.status, 200, "{}", fetched.raw);
    assert_eq!(fetched.body["fields"]["views"], json!({ "type": "Number" }));
    assert_eq!(
        fetched.body["classLevelPermissions"]["create"],
        json!({ "requiresAuthentication": true })
    );
    assert_eq!(
        fetched.body["classLevelPermissions"]["delete"],
        json!({}),
        "a present block is merged over emptyCLPS, so an unspecified operation is {{}}"
    );
    assert!(
        fetched.body["classLevelPermissions"].get("ACL").is_none(),
        "emptyCLPS has no ACL key: {}",
        fetched.raw
    );

    // The listing carries it too.
    let listed = get(host, "/schemas", &As::master()).await;
    assert!(
        listed
            .results()
            .iter()
            .any(|s| s["className"] == json!("Article")),
        "{}",
        listed.raw
    );

    // addField and removeField, in one request.
    let updated = put(
        host,
        "/schemas/Article",
        &As::master(),
        &json!({
            "fields": {
                "slug": { "type": "String" },
                "views": { "__op": "Delete" },
            },
        }),
    )
    .await;
    assert_eq!(updated.status, 200, "{}", updated.raw);
    assert_eq!(updated.body["fields"]["slug"], json!({ "type": "String" }));
    assert!(
        updated.body["fields"].get("views").is_none(),
        "{}",
        updated.raw
    );

    // Re-read from `_SCHEMA` rather than trusting the response the mutation built, because the
    // response is assembled in the router and would report a delete that never reached storage.
    let after = get(host, "/schemas/Article", &As::master()).await;
    assert_eq!(after.body["fields"]["slug"], json!({ "type": "String" }));
    assert!(
        after.body["fields"].get("views").is_none(),
        "removeField has to reach `_SCHEMA`: {}",
        after.raw
    );
    // The CLP survived a field-only update: `classLevelPermissions` absent from the body means
    // "leave the stored block alone", which is not the same as an empty block.
    assert_eq!(
        after.body["classLevelPermissions"]["create"],
        json!({ "requiresAuthentication": true }),
        "{}",
        after.raw
    );
}

/// A CLP has to survive an ordinary object write to the same class. `upsert_schema` reaches the
/// adapter with `clp: None` on every field-adding save, and rewriting `_metadata` from that would
/// silently delete the class's permissions.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_clp_survives_an_ordinary_object_write() {
    let server = common::boot().await;
    let host = &server.host;

    post(
        host,
        "/schemas/Ledger",
        &As::master(),
        &json!({
            "fields": { "amount": { "type": "Number" } },
            "classLevelPermissions": {
                "find": { "*": true },
                "get": { "*": true },
                "create": { "*": true },
                // `addField` has to be spelled out: the write below introduces a field, and a
                // present CLP block leaves every unspecified operation denied.
                "addField": { "*": true },
                "protectedFields": { "*": ["amount"] },
            },
        }),
    )
    .await;

    // A write that also introduces a new field, which is the path that reserves schema entries.
    let created = post(
        host,
        "/classes/Ledger",
        &As::anonymous(),
        &json!({ "amount": 10, "memo": "new field" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);

    let after = get(host, "/schemas/Ledger", &As::master()).await;
    assert_eq!(
        after.body["classLevelPermissions"]["protectedFields"],
        json!({ "*": ["amount"] }),
        "the CLP must survive an object write: {}",
        after.raw
    );
    assert_eq!(after.body["fields"]["memo"], json!({ "type": "String" }));

    // And it is still enforced.
    let read = get(host, "/classes/Ledger", &As::anonymous()).await;
    assert!(read.results()[0].get("amount").is_none(), "{}", read.raw);
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_error_shapes_are_upstreams() {
    let server = common::boot().await;
    let host = &server.host;

    // Unknown class is INVALID_CLASS_NAME (103), not a 404.
    let unknown = get(host, "/schemas/NoSuchClass", &As::master()).await;
    assert_eq!(unknown.code(), Some(103), "{}", unknown.raw);
    assert_eq!(unknown.error(), "Class NoSuchClass does not exist.");
    assert_eq!(unknown.status, 400, "not a 404: {}", unknown.raw);

    // Class name mismatch between the path and the body.
    post(host, "/schemas/Widget", &As::master(), &json!({})).await;
    let mismatch = put(
        host,
        "/schemas/Widget",
        &As::master(),
        &json!({ "className": "Gadget" }),
    )
    .await;
    assert_eq!(mismatch.code(), Some(103), "{}", mismatch.raw);
    assert_eq!(
        mismatch.error(),
        "Class name mismatch between Gadget and Widget."
    );

    // `POST /schemas` with no class name anywhere is code 135.
    let nameless = post(host, "/schemas", &As::master(), &json!({})).await;
    assert_eq!(nameless.code(), Some(135), "{}", nameless.raw);
    assert_eq!(nameless.error(), "POST /schemas needs a class name.");

    // A duplicate class.
    let again = post(host, "/schemas/Widget", &As::master(), &json!({})).await;
    assert_eq!(again.code(), Some(103), "{}", again.raw);
    assert_eq!(again.error(), "Class Widget already exists.");
}

/// Dropping a non-empty class is code 255, and the count is in the message.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_non_empty_class_cannot_be_dropped_and_purge_empties_it() {
    let server = common::boot().await;
    let host = &server.host;

    post(host, "/classes/Temp", &As::master(), &json!({ "n": 1 })).await;
    post(host, "/classes/Temp", &As::master(), &json!({ "n": 2 })).await;

    let refused = delete(host, "/schemas/Temp", &As::master()).await;
    assert_eq!(refused.code(), Some(255), "{}", refused.raw);
    assert_eq!(
        refused.error(),
        "Class Temp is not empty, contains 2 objects, cannot drop schema."
    );

    // `clearAllDataFromClass`: rows go, the class and its schema entry stay.
    let purged = delete(host, "/purge/Temp", &As::master()).await;
    assert_eq!(purged.status, 200, "{}", purged.raw);
    assert_eq!(purged.body, json!({}));

    let empty = get(host, "/classes/Temp", &As::master()).await;
    assert!(empty.results().is_empty(), "{}", empty.raw);
    let still_there = get(host, "/schemas/Temp", &As::master()).await;
    assert_eq!(
        still_there.status, 200,
        "purge keeps the class and its schema entry: {}",
        still_there.raw
    );

    // removeClass, now that it is empty.
    let dropped = delete(host, "/schemas/Temp", &As::master()).await;
    assert_eq!(dropped.status, 200, "{}", dropped.raw);
    assert_eq!(dropped.body, json!({}));
    assert_eq!(
        get(host, "/schemas/Temp", &As::master()).await.code(),
        Some(103)
    );
}

/// `editPointerPermissions` is advertised, so the class-wide arrays have to be settable and
/// enforced, not only the per-operation `pointerFields`.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn read_user_fields_is_accepted_and_enforced() {
    let server = common::boot().await;
    let host = &server.host;
    let (a_id, a_token) = signup(host, "ruf_a", "pw").await;
    let (b_id, _b_token) = signup(host, "ruf_b", "pw").await;

    for owner in [&a_id, &b_id] {
        post(
            host,
            "/classes/Scoped",
            &As::master(),
            &json!({
                "owner": { "__type": "Pointer", "className": "_User", "objectId": owner },
            }),
        )
        .await;
    }

    let set = put(
        host,
        "/schemas/Scoped",
        &As::master(),
        &json!({ "classLevelPermissions": { "readUserFields": ["owner"] } }),
    )
    .await;
    assert_eq!(
        set.status, 200,
        "a CLP using readUserFields must be accepted: {}",
        set.raw
    );

    let mine = get(host, "/classes/Scoped", &As::user(&a_token)).await;
    assert_eq!(mine.results().len(), 1, "{}", mine.raw);
    assert_eq!(mine.results()[0]["owner"]["objectId"], json!(a_id));

    let anonymous = get(host, "/classes/Scoped", &As::anonymous()).await;
    assert!(anonymous.results().is_empty(), "{}", anonymous.raw);
}

/// An index request has to reach the database, not just `_SCHEMA`.
///
/// This is the finding that matters most for the claim 0.2.0 makes. A `_metadata.indexes` block
/// naming an index that was never built is read by a parse-server node on the same database as
/// proof the index exists, so neither server ever creates it. The assertion is therefore against
/// MongoDB's own index catalogue rather than against the response body.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_index_request_builds_the_index_and_then_records_it() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/schemas/Indexed",
        &As::master(),
        &json!({
            "fields": { "tag": { "type": "String" }, "rank": { "type": "Number" } },
            "indexes": { "by_tag": { "tag": 1 } }
        }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);
    assert_eq!(created.body["indexes"]["by_tag"]["tag"], json!(1));
    // **No `_id_` on a create, and a create is the one case where there is none.** Measured
    // against parse-server 9.10.1-alpha.6: `POST /schemas/Indexed` carrying an `indexes` block
    // answers `{"by_tag":{"tag":1}}`, where a `PUT` onto a class with no recorded block answers
    // `{"_id_":{"_id":1},"by_tag":{"tag":1}}` and stores the same. The asymmetry is an ordering
    // detail rather than a rule: `setIndexesWithSchemaFormat` runs before `insertSchema` on the
    // create path (`MongoStorageAdapter.js:449-451`) and its trailing write has no upsert, so it
    // matches nothing and the submitted block is what the insert carries.
    //
    // This assertion previously required `_id_` here, which put a phantom index into
    // `_metadata.indexes` on a database parse-server also reads.
    assert!(
        created.body["indexes"].get("_id_").is_none(),
        "a create records the submitted block only: {}",
        created.raw
    );

    assert!(
        common::index_names(&server.database, "Indexed")
            .await
            .contains(&"by_tag".to_string()),
        "the index has to exist in MongoDB, not only in _SCHEMA"
    );

    // Adding a second index leaves the first alone, and re-adding one is refused.
    let again = put(
        host,
        "/schemas/Indexed",
        &As::master(),
        &json!({ "indexes": { "by_tag": { "tag": -1 } } }),
    )
    .await;
    assert_eq!(again.code(), Some(102), "{}", again.raw);
    assert_eq!(again.error(), "Index by_tag exists, cannot update.");

    let added = put(
        host,
        "/schemas/Indexed",
        &As::master(),
        &json!({ "indexes": { "by_rank": { "rank": -1 } } }),
    )
    .await;
    assert_eq!(added.status, 200, "{}", added.raw);
    let names = common::index_names(&server.database, "Indexed").await;
    assert!(names.contains(&"by_tag".to_string()) && names.contains(&"by_rank".to_string()));

    // A delete drops the real index, not just the claim.
    let dropped = put(
        host,
        "/schemas/Indexed",
        &As::master(),
        &json!({ "indexes": { "by_rank": { "__op": "Delete" } } }),
    )
    .await;
    assert_eq!(dropped.status, 200, "{}", dropped.raw);
    assert!(
        dropped.body["indexes"].get("by_rank").is_none(),
        "{}",
        dropped.raw
    );
    assert!(!common::index_names(&server.database, "Indexed")
        .await
        .contains(&"by_rank".to_string()));
}

/// An index on a field the schema does not have is refused, and refused before anything is built.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_index_on_an_unknown_field_is_refused_and_leaves_nothing_behind() {
    let server = common::boot().await;
    let host = &server.host;

    let refused = post(
        host,
        "/schemas/Unindexed",
        &As::master(),
        &json!({
            "fields": { "tag": { "type": "String" } },
            "indexes": { "by_ghost": { "ghost": 1 } }
        }),
    )
    .await;
    assert_eq!(refused.code(), Some(102), "{}", refused.raw);
    assert_eq!(
        refused.error(),
        "Field ghost does not exist, cannot add index."
    );

    // The class itself is not created either: the refusal happens before the schema write.
    let after = get(host, "/schemas/Unindexed", &As::master()).await;
    assert_eq!(after.code(), Some(103), "{}", after.raw);
}

/// Two concurrent creates for one class, and exactly one may win.
///
/// The sequential case is asserted above and passes either way, because a read-then-upsert also
/// sees the earlier class. This is the case that separates them: with a read-then-upsert every
/// request passes the read before any of them writes, so all four report success and the last
/// one's fields and CLP replace the winner's. `insert_schema` makes the database answer instead.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn concurrent_class_creation_has_exactly_one_winner() {
    let server = common::boot().await;
    let host = &server.host;

    // Four bodies distinguishable by their field type, so the survivor can be identified.
    let master = As::master();
    let bodies: Vec<_> = ["String", "Number", "Boolean", "Date"]
        .iter()
        .map(|ty| json!({ "fields": { "shape": { "type": ty } } }))
        .collect();
    let results = futures::future::join_all(
        bodies
            .iter()
            .map(|body| post(host, "/schemas/Contended", &master, body)),
    )
    .await;

    let winners: Vec<_> = results.iter().filter(|r| r.status == 200).collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one create may win: {:?}",
        results.iter().map(|r| &r.raw).collect::<Vec<_>>()
    );
    for loser in results.iter().filter(|r| r.status != 200) {
        assert_eq!(loser.code(), Some(103), "{}", loser.raw);
        assert_eq!(loser.error(), "Class Contended already exists.");
    }

    // The stored schema is the winner's, not a mixture, and the CLP block it never carried is
    // still absent rather than half-written.
    let stored = get(host, "/schemas/Contended", &As::master()).await;
    assert_eq!(
        stored.body["fields"]["shape"]["type"], winners[0].body["fields"]["shape"]["type"],
        "{}",
        stored.raw
    );
}

/// Two concurrent field additions of one name with two types, and exactly one may win.
///
/// Folding additions into a cloned schema and writing them with one unconditional `$set` makes
/// both succeed and the later write silently redefine the field. Every row already validated
/// against the first type is then validated against the second.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_concurrently_added_field_cannot_be_redefined() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/schemas/Contested",
        &As::master(),
        &json!({ "fields": { "tag": { "type": "String" } } }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);

    let master = As::master();
    let bodies: Vec<_> = ["String", "Number", "Boolean", "Date"]
        .iter()
        .map(|ty| json!({ "fields": { "added": { "type": ty } } }))
        .collect();
    let results = futures::future::join_all(
        bodies
            .iter()
            .map(|body| put(host, "/schemas/Contested", &master, body)),
    )
    .await;

    let winners: Vec<_> = results.iter().filter(|r| r.status == 200).collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one type may be reserved: {:?}",
        results.iter().map(|r| &r.raw).collect::<Vec<_>>()
    );
    let winning_type = winners[0].body["fields"]["added"]["type"].clone();

    // A loser is refused at one of two places, and which one depends on the interleaving rather
    // than on anything under test. A request that re-read the schema after the winner wrote fails
    // `updateClass`'s pre-check with 255 (`SchemaController.js:884-889`); one that read before it
    // passes the pre-check and loses the reservation, which reports the type conflict as an
    // ordinary mismatch. Both are correct refusals, and asserting only one would make this test
    // fail on timing rather than on behavior.
    for loser in results.iter().filter(|r| r.status != 200) {
        match loser.code() {
            Some(255) => assert_eq!(loser.error(), "Field added exists, cannot update."),
            Some(111) => assert!(
                loser
                    .error()
                    .starts_with("schema mismatch for Contested.added;"),
                "{}",
                loser.raw
            ),
            _ => panic!(
                "a losing addition must be refused as 255 or 111: {}",
                loser.raw
            ),
        }
    }

    // And the stored type is the winner's, so no losing write landed underneath it.
    let stored = get(host, "/schemas/Contested", &As::master()).await;
    assert_eq!(
        stored.body["fields"]["added"]["type"], winning_type,
        "{}",
        stored.raw
    );
    assert_eq!(
        stored.body["fields"]["tag"]["type"],
        json!("String"),
        "{}",
        stored.raw
    );
}

/// A malformed `indexes` value is refused rather than ignored.
///
/// Silently ignoring it was the worse half of the same defect the index tests above cover: a
/// client that asked for indexes and got a 200 has no way to learn none were built.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_malformed_indexes_block_is_refused_and_creates_nothing() {
    let server = common::boot().await;
    let host = &server.host;

    for malformed in [json!("x"), json!([]), json!(7), json!(true), json!(null)] {
        let refused = post(
            host,
            "/schemas/BadIndexes",
            &As::master(),
            &json!({ "fields": { "tag": { "type": "String" } }, "indexes": malformed }),
        )
        .await;
        assert_eq!(
            refused.code(),
            Some(102),
            "for {malformed}: {}",
            refused.raw
        );
        assert_eq!(
            refused.error(),
            "Invalid indexes for class BadIndexes: expected an object."
        );
    }

    // The refusal precedes the schema write, so nothing was created along the way.
    let after = get(host, "/schemas/BadIndexes", &As::master()).await;
    assert_eq!(after.code(), Some(103), "{}", after.raw);

    // An absent block is not a malformed one, and an empty object is a real block.
    let created = post(
        host,
        "/schemas/BadIndexes",
        &As::master(),
        &json!({ "fields": { "tag": { "type": "String" } }, "indexes": {} }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);
}

/// A `PUT /schemas` writes only what the request named, so a concurrent deletion is not undone.
///
/// The interleaving: request A deletes field `old` while request B, holding a snapshot taken
/// before that landed, adds an unrelated field. A whole-schema upsert on B's way out `$set`s every
/// field it loaded, `old` among them, and the deleted field is back in `_SCHEMA` with no row
/// carrying it. Upstream never writes a field it was not asked about
/// (`SchemaController.js:930-934`).
///
/// **One-sided by construction.** It reproduces the ordering by racing rather than by forcing it,
/// so it can fail only when the delta property is violated, never because the timing went the
/// other way. Eight adders against one deleter is enough that at least one holds a stale snapshot.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_concurrent_field_addition_does_not_resurrect_a_deleted_field() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/schemas/Deltas",
        &As::master(),
        &json!({ "fields": { "old": { "type": "String" }, "keep": { "type": "Number" } } }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);

    let master = As::master();
    let deletion = json!({ "fields": { "old": { "__op": "Delete" } } });
    let additions: Vec<_> = (0..8)
        .map(|i| json!({ "fields": { format!("added{i}"): { "type": "String" } } }))
        .collect();

    let mut all = vec![put(host, "/schemas/Deltas", &master, &deletion)];
    all.extend(
        additions
            .iter()
            .map(|body| put(host, "/schemas/Deltas", &master, body)),
    );
    let results = futures::future::join_all(all).await;
    for r in &results {
        assert_eq!(r.status, 200, "every request should succeed: {}", r.raw);
    }

    let stored = get(host, "/schemas/Deltas", &As::master()).await;
    assert!(
        stored.body["fields"].get("old").is_none(),
        "a deleted field must not come back through an unrelated write: {}",
        stored.raw
    );
    assert_eq!(
        stored.body["fields"]["keep"]["type"],
        json!("Number"),
        "{}",
        stored.raw
    );
    for i in 0..8 {
        assert_eq!(
            stored.body["fields"][format!("added{i}")]["type"],
            json!("String"),
            "every addition landed: {}",
            stored.raw
        );
    }
}

/// Two concurrent additions of different fields, each carrying options, and neither may lose them.
///
/// A whole-schema upsert replaces `_metadata.fields_options` wholesale, so the second writer erases
/// the first field's options while leaving its type in place: a `required` field that is silently
/// no longer required. Upstream sets the type and `_metadata.fields_options.<field>` together, per
/// field (`MongoSchemaCollection.js:251-269`).
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn concurrent_additions_do_not_erase_each_others_field_options() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/schemas/Opts",
        &As::master(),
        &json!({ "fields": { "seed": { "type": "Number" } } }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);

    let master = As::master();
    let bodies: Vec<_> = (0..6)
        .map(|i| {
            json!({ "fields": {
                format!("opt{i}"): { "type": "String", "required": true, "defaultValue": format!("d{i}") }
            }})
        })
        .collect();
    let results = futures::future::join_all(
        bodies
            .iter()
            .map(|body| put(host, "/schemas/Opts", &master, body)),
    )
    .await;
    for r in &results {
        assert_eq!(r.status, 200, "{}", r.raw);
    }

    let stored = get(host, "/schemas/Opts", &As::master()).await;
    for i in 0..6 {
        let field = &stored.body["fields"][format!("opt{i}")];
        assert_eq!(field["type"], json!("String"), "{}", stored.raw);
        assert_eq!(
            field["required"],
            json!(true),
            "opt{i} kept its type but lost its options: {}",
            stored.raw
        );
        assert_eq!(
            field["defaultValue"],
            json!(format!("d{i}")),
            "{}",
            stored.raw
        );
    }
}

/// Options on a field that already exists: cleared by omission, and still type-checked.
///
/// Both halves were missing. The plan recorded options only when non-empty, so resubmitting a
/// field without them did nothing and a `required` field could never be made optional again; and
/// option validation was gated on the field being new, so an invalid `defaultValue` on an existing
/// field was stored rather than refused.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_existing_fields_options_can_be_cleared_and_are_still_validated() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/schemas/Existing",
        &As::master(),
        &json!({ "fields": { "title": { "type": "String", "required": true } } }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);
    assert_eq!(created.body["fields"]["title"]["required"], json!(true));

    // Resubmitted without the option. `updateFieldOptions` writes what is left after `type` and
    // `targetClass` come off, which here is nothing.
    let cleared = put(
        host,
        "/schemas/Existing",
        &As::master(),
        &json!({ "fields": { "title": { "type": "String" } } }),
    )
    .await;
    assert_eq!(cleared.status, 200, "{}", cleared.raw);
    assert!(
        cleared.body["fields"]["title"].get("required").is_none(),
        "resubmitting without the option clears it: {}",
        cleared.raw
    );

    // And it is gone from storage, not just from this response.
    let reread = get(host, "/schemas/Existing", &As::master()).await;
    assert!(
        reread.body["fields"]["title"].get("required").is_none(),
        "{}",
        reread.raw
    );

    // A default value whose type disagrees with the stored field type is refused, not stored.
    let bad = put(
        host,
        "/schemas/Existing",
        &As::master(),
        &json!({ "fields": { "title": { "type": "String", "defaultValue": 10 } } }),
    )
    .await;
    assert_eq!(bad.code(), Some(111), "{}", bad.raw);
    assert_eq!(
        bad.error(),
        "schema mismatch for Existing.title default value; expected String but got Number"
    );
    let after = get(host, "/schemas/Existing", &As::master()).await;
    assert!(
        after.body["fields"]["title"].get("defaultValue").is_none(),
        "the refused option must not have been stored: {}",
        after.raw
    );
}

/// A request that fails at its indexes keeps the CLP change it also carried.
///
/// `updateClass` calls `setPermissions` before `setIndexesWithSchemaFormat`
/// (`SchemaController.js:938-947`), so the two halves of a partly-invalid body do not both fail.
/// Writing indexes first would keep the index and drop the permissions, which is the more
/// dangerous half to lose.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_clp_survives_a_request_whose_indexes_are_refused() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/schemas/Partial",
        &As::master(),
        &json!({ "fields": { "tag": { "type": "String" } } }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);

    let refused = put(
        host,
        "/schemas/Partial",
        &As::master(),
        &json!({
            "classLevelPermissions": { "find": { "requiresAuthentication": true } },
            "indexes": { "by_ghost": { "ghost": 1 } }
        }),
    )
    .await;
    assert_eq!(refused.code(), Some(102), "{}", refused.raw);
    assert_eq!(
        refused.error(),
        "Field ghost does not exist, cannot add index."
    );

    let stored = get(host, "/schemas/Partial", &As::master()).await;
    assert_eq!(
        stored.body["classLevelPermissions"]["find"]["requiresAuthentication"],
        json!(true),
        "the CLP is written before the indexes, so it survives their refusal: {}",
        stored.raw
    );
    assert!(
        stored.body.get("indexes").is_none() || stored.body["indexes"].get("by_ghost").is_none(),
        "the refused index must not have been recorded: {}",
        stored.raw
    );
}

/// A malformed `fields` block must not read as "no fields".
///
/// The third member of the family alongside `indexes` and `classLevelPermissions`, and the last
/// one still collapsing absent and malformed. `"fields": "typo"` created a class with only its
/// default columns, and made a `PUT` a successful no-op, in response to a request that was trying
/// to define fields.
///
/// Upstream's outcome is decided by JSON type, measured against parse-server 9.10.1-alpha.6: a
/// string or non-empty array answers 105 `invalid field name: 0`, a number, boolean or empty array
/// answers 200 having created the class with no fields, and null answers a 500.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_malformed_fields_block_is_refused_and_creates_nothing() {
    let server = common::boot().await;
    let host = &server.host;

    for bad in [
        json!("typo"),
        json!(7),
        json!(true),
        json!([]),
        json!(["a"]),
    ] {
        let created = post(
            host,
            "/schemas/FieldsTypo",
            &As::master(),
            &json!({ "className": "FieldsTypo", "fields": bad }),
        )
        .await;
        assert_eq!(
            created.code(),
            Some(107),
            "a non-object fields block is refused, not read as absent: {} for {bad}",
            created.raw
        );
        let fetched = get(host, "/schemas/FieldsTypo", &As::master()).await;
        assert_eq!(
            fetched.code(),
            Some(103),
            "and the class must not exist: {}",
            fetched.raw
        );
    }

    // The same on update, where the silent outcome was a successful no-op.
    let made = post(
        host,
        "/schemas/FieldsReal",
        &As::master(),
        &json!({ "className": "FieldsReal", "fields": { "a": { "type": "String" } } }),
    )
    .await;
    assert_eq!(made.status, 200, "{}", made.raw);

    let updated = put(
        host,
        "/schemas/FieldsReal",
        &As::master(),
        &json!({ "className": "FieldsReal", "fields": "typo" }),
    )
    .await;
    assert_eq!(updated.code(), Some(107), "{}", updated.raw);
}

/// A truthy non-string `className` is a mismatch, not an absent field.
///
/// Reading it as absent lets the path's name win, so a body naming one class silently edits
/// another. Upstream's check is truthiness plus `!==` (`SchemasRouter.js:82-86`), and the rendered
/// value in the message is JavaScript's string conversion, which is why `["Gadget"]` reports
/// `Gadget`. Falsy values really are absent: `null` and `""` both proceed on the path's name.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_non_string_class_name_in_the_body_is_a_mismatch() {
    let server = common::boot().await;
    let host = &server.host;

    let made = post(
        host,
        "/schemas/Widget",
        &As::master(),
        &json!({ "className": "Widget" }),
    )
    .await;
    assert_eq!(made.status, 200, "{}", made.raw);

    for (bad, rendered) in [
        (json!(["Gadget"]), "Gadget"),
        (json!(7), "7"),
        (json!(true), "true"),
        (json!({"a": 1}), "[object Object]"),
    ] {
        let r = put(
            host,
            "/schemas/Widget",
            &As::master(),
            &json!({ "className": bad, "fields": {} }),
        )
        .await;
        assert_eq!(r.code(), Some(103), "{} for {bad}", r.raw);
        assert_eq!(
            r.error(),
            format!("Class name mismatch between {rendered} and Widget."),
            "the message renders the value as JavaScript would: {}",
            r.raw
        );
    }

    // Falsy is absent, which is upstream exactly.
    for ok in [json!(null), json!("")] {
        let r = put(
            host,
            "/schemas/Widget",
            &As::master(),
            &json!({ "className": ok, "fields": {} }),
        )
        .await;
        assert_eq!(r.status, 200, "a falsy className is absent: {}", r.raw);
    }
}

/// A stored `defaultValue` may contain a `$` key, because metadata is not a row.
///
/// `_metadata.fields_options` carries no row-write policy: its keys are not fields and its values
/// are not column values, so the nested-key guard and the storage forms do not apply to it.
///
/// **This does not assert byte fidelity, and must not be read as doing so.** A value carrying a
/// `__type` envelope is decoded before it reaches storage, so an offset instant arrives as UTC and
/// an extra envelope key is already gone. That is an open parity gap recorded in the register; what
/// this covers is that nothing further is applied on the way down.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_default_value_containing_a_dollar_key_is_stored_verbatim() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/schemas/MetaDefault",
        &As::master(),
        &json!({
            "className": "MetaDefault",
            "fields": {
                "pattern": { "type": "Object", "defaultValue": { "$regex": "literal" } }
            }
        }),
    )
    .await;
    assert_eq!(
        created.status, 200,
        "a defaultValue is metadata, not a row value: {}",
        created.raw
    );

    let read_back = get(host, "/schemas/MetaDefault", &As::master()).await;
    assert_eq!(read_back.status, 200, "{}", read_back.raw);
    assert_eq!(
        read_back.body["fields"]["pattern"]["defaultValue"],
        json!({ "$regex": "literal" }),
        "and it round-trips: {}",
        read_back.raw
    );
}

/// Retargeting an existing Pointer is a mismatch, not a silent no-op.
///
/// `Pointer<_User>` and `Pointer<Other>` share a discriminant, so the "field exists, cannot update"
/// gate lets them past. The full-type refusal was documented as happening at field reservation,
/// which runs only for fields the request is creating, so a retarget answered 200 and kept the
/// original target. Measured against parse-server 9.10.1-alpha.6.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn retargeting_an_existing_pointer_is_refused() {
    let server = common::boot().await;
    let host = &server.host;

    let made = post(
        host,
        "/schemas/PtrX",
        &As::master(),
        &json!({
            "className": "PtrX",
            "fields": { "owner": { "type": "Pointer", "targetClass": "_User" } }
        }),
    )
    .await;
    assert_eq!(made.status, 200, "{}", made.raw);

    let retarget = put(
        host,
        "/schemas/PtrX",
        &As::master(),
        &json!({
            "className": "PtrX",
            "fields": { "owner": { "type": "Pointer", "targetClass": "Other" } }
        }),
    )
    .await;
    assert_eq!(retarget.code(), Some(111), "{}", retarget.raw);
    assert_eq!(
        retarget.error(),
        "schema mismatch for PtrX.owner; expected Pointer<_User> but got Pointer<Other>"
    );

    // A Relation retarget is the same shape.
    post(
        host,
        "/schemas/RelX",
        &As::master(),
        &json!({
            "className": "RelX",
            "fields": { "items": { "type": "Relation", "targetClass": "_User" } }
        }),
    )
    .await;
    let rel = put(
        host,
        "/schemas/RelX",
        &As::master(),
        &json!({
            "className": "RelX",
            "fields": { "items": { "type": "Relation", "targetClass": "Other" } }
        }),
    )
    .await;
    assert_eq!(rel.code(), Some(111), "{}", rel.raw);

    // Resubmitting the same target is still an options update, not a conflict.
    let same = put(
        host,
        "/schemas/PtrX",
        &As::master(),
        &json!({
            "className": "PtrX",
            "fields": { "owner": { "type": "Pointer", "targetClass": "_User" } }
        }),
    )
    .await;
    assert_eq!(same.status, 200, "{}", same.raw);
    assert_eq!(
        same.body["fields"]["owner"]["targetClass"],
        json!("_User"),
        "and the target survives: {}",
        same.raw
    );
}

/// Schema metadata is stored in the **envelope** form, which is what parse-server reads.
///
/// A local round-trip cannot see this defect: parse-rust decoding its own storage form returns the
/// right value either way. The assertion has to be against the stored BSON, because the reader that
/// disagrees is the other node. Storing a `Date` default as a BSON date makes parse-server render
/// it as a bare ISO string, and a `Bytes` default as a bare base64 string.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn schema_metadata_keeps_the_type_envelope_in_storage() {
    let server = common::boot().await;
    let host = &server.host;
    let iso = "2020-01-02T03:04:05.678Z";

    let made = post(
        host,
        "/schemas/MetaEnv",
        &As::master(),
        &json!({
            "className": "MetaEnv",
            "fields": {
                "d": { "type": "Date", "defaultValue": { "__type": "Date", "iso": iso } },
                "b": { "type": "Bytes", "defaultValue": { "__type": "Bytes", "base64": "AQID" } }
            }
        }),
    )
    .await;
    assert_eq!(made.status, 200, "{}", made.raw);

    // Read the raw `_SCHEMA` document, which is what a parse-server node sees.
    let client = mongodb::Client::with_uri_str(common::mongo_uri())
        .await
        .expect("mongo");
    let raw: bson::Document = client
        .database(&server.database)
        .collection("_SCHEMA")
        .find_one(bson::doc! { "_id": "MetaEnv" })
        .await
        .expect("find")
        .expect("the schema row");

    let options = raw
        .get_document("_metadata")
        .and_then(|m| m.get_document("fields_options"))
        .expect("fields_options");

    let d = options
        .get_document("d")
        .expect("d")
        .get_document("defaultValue")
        .expect("d default");
    assert_eq!(
        d.get_str("__type").ok(),
        Some("Date"),
        "a Date default is stored as its envelope, not as a BSON date: {d:?}"
    );
    assert_eq!(d.get_str("iso").ok(), Some(iso));

    let b = options
        .get_document("b")
        .expect("b")
        .get_document("defaultValue")
        .expect("b default");
    assert_eq!(
        b.get_str("__type").ok(),
        Some("Bytes"),
        "a Bytes default is stored as its envelope, not as BSON Binary: {b:?}"
    );
    assert_eq!(b.get_str("base64").ok(), Some("AQID"));
}

/// A compound delete-and-retarget applies neither half.
///
/// Upstream deletes first and discovers the mismatch afterwards, so its failed request drops the
/// column. Registered as a deliberate difference: a request parse-rust refuses leaves no durable
/// state.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_refused_compound_schema_update_applies_neither_half() {
    let server = common::boot().await;
    let host = &server.host;

    let made = post(
        host,
        "/schemas/Comp",
        &As::master(),
        &json!({
            "className": "Comp",
            "fields": {
                "old": { "type": "String" },
                "owner": { "type": "Pointer", "targetClass": "_User" }
            }
        }),
    )
    .await;
    assert_eq!(made.status, 200, "{}", made.raw);

    let compound = put(
        host,
        "/schemas/Comp",
        &As::master(),
        &json!({
            "className": "Comp",
            "fields": {
                "old": { "__op": "Delete" },
                "owner": { "type": "Pointer", "targetClass": "Other" }
            }
        }),
    )
    .await;
    assert_eq!(compound.code(), Some(111), "{}", compound.raw);

    let after = get(host, "/schemas/Comp", &As::master()).await;
    assert!(
        after.body["fields"]["old"].is_object(),
        "the deletion must not have committed: {}",
        after.raw
    );
    assert_eq!(
        after.body["fields"]["owner"]["targetClass"],
        json!("_User"),
        "and the target is unchanged: {}",
        after.raw
    );
}

/// A `defaultValue` is stored **exactly as sent**, not as parse-rust would have rendered it.
///
/// The three losses a decode introduces, each measured against the pinned parse-server, which
/// stores all of them verbatim: an ISO instant carrying an offset is re-rendered in UTC, unpadded
/// base64 is re-padded, and a key the envelope does not declare is dropped because a decoded value
/// has nowhere to keep it.
///
/// **None of this is visible to a local round trip**, which is why the first version of this test
/// missed it: parse-rust reads its own storage back the same way it wrote it, so a canonicalized
/// value looks perfect from here. The reader that disagrees is the other node, so the assertion is
/// against the response body a client sees and the raw `_SCHEMA` document underneath it.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_default_value_is_stored_exactly_as_sent() {
    let server = common::boot().await;
    let host = &server.host;
    let offset_iso = "2020-01-02T03:04:05.678+02:00";

    let made = post(
        host,
        "/schemas/Verbatim",
        &As::master(),
        &json!({
            "className": "Verbatim",
            "fields": {
                "d": { "type": "Date",
                       "defaultValue": { "__type": "Date", "iso": offset_iso, "marker": true } },
                "b": { "type": "Bytes",
                       "defaultValue": { "__type": "Bytes", "base64": "AQI", "marker": true } }
            }
        }),
    )
    .await;
    assert_eq!(made.status, 200, "{}", made.raw);

    let read = get(host, "/schemas/Verbatim", &As::master()).await;
    assert_eq!(
        read.body["fields"]["d"]["defaultValue"],
        json!({ "__type": "Date", "iso": offset_iso, "marker": true }),
        "the offset and the extra key survive: {}",
        read.raw
    );
    assert_eq!(
        read.body["fields"]["b"]["defaultValue"],
        json!({ "__type": "Bytes", "base64": "AQI", "marker": true }),
        "the unpadded base64 and the extra key survive: {}",
        read.raw
    );

    // And underneath, so a parse-server node reading the same row sees the same thing.
    let client = mongodb::Client::with_uri_str(common::mongo_uri())
        .await
        .expect("mongo");
    let raw: bson::Document = client
        .database(&server.database)
        .collection("_SCHEMA")
        .find_one(bson::doc! { "_id": "Verbatim" })
        .await
        .expect("find")
        .expect("schema row");
    let stored = raw
        .get_document("_metadata")
        .and_then(|m| m.get_document("fields_options"))
        .and_then(|o| o.get_document("d"))
        .and_then(|d| d.get_document("defaultValue"))
        .expect("stored default");
    assert_eq!(
        stored.get_str("iso").ok(),
        Some(offset_iso),
        "stored verbatim, not canonicalized: {stored:?}"
    );
    assert!(stored.get_bool("marker").unwrap_or(false), "{stored:?}");
}
