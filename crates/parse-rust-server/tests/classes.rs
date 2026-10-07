//! `/classes` CRUD, `/roles`, the class-security gate, and the SDK's `_method` transport.
//!
//! `#[ignore]`d because they need a MongoDB on 27017. `tools/test.sh` runs them.

mod common;

use common::{delete, get, post, put, request, signup, where_query, As};
use serde_json::json;

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn create_read_update_delete() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/classes/Post",
        &As::anonymous(),
        &json!({ "title": "first", "views": 1 }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    // The create response is exactly `{objectId, createdAt}`. Returning the whole object would be
    // more helpful and would not match.
    assert_eq!(
        created.body.as_object().map(|m| m.len()),
        Some(2),
        "{}",
        created.raw
    );
    let object_id = created.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();
    assert_eq!(
        object_id.len(),
        10,
        "objectId is 10 characters: {object_id}"
    );

    let fetched = get(
        host,
        &format!("/classes/Post/{object_id}"),
        &As::anonymous(),
    )
    .await;
    assert_eq!(fetched.status, 200, "{}", fetched.raw);
    assert_eq!(fetched.body["title"], json!("first"));
    assert_eq!(fetched.body["views"], json!(1));
    // Top-level timestamps are bare ISO strings, not `{"__type":"Date"}` envelopes.
    assert!(fetched.body["createdAt"].is_string(), "{}", fetched.raw);
    assert!(fetched.body["updatedAt"].is_string());

    let updated = put(
        host,
        &format!("/classes/Post/{object_id}"),
        &As::anonymous(),
        &json!({ "title": "second", "views": { "__op": "Increment", "amount": 4 } }),
    )
    .await;
    assert_eq!(updated.status, 200, "{}", updated.raw);
    assert!(updated.body["updatedAt"].is_string());
    // The response carries back exactly the keys whose request value was an operation.
    assert_eq!(updated.body["views"], json!(5), "{}", updated.raw);
    assert!(
        updated.body.get("title").is_none(),
        "a plain set is not echoed: {}",
        updated.raw
    );

    let queried = get(
        host,
        &format!("/classes/Post{}", where_query(json!({ "title": "second" }))),
        &As::anonymous(),
    )
    .await;
    assert_eq!(queried.results().len(), 1, "{}", queried.raw);

    let counted = get(host, "/classes/Post?count=1&limit=0", &As::anonymous()).await;
    assert_eq!(counted.body["count"], json!(1), "{}", counted.raw);
    assert!(counted.results().is_empty(), "limit=0 means zero rows");

    let removed = delete(
        host,
        &format!("/classes/Post/{object_id}"),
        &As::anonymous(),
    )
    .await;
    assert_eq!(removed.status, 200, "{}", removed.raw);
    assert_eq!(removed.body, json!({}), "a delete answers {{}}, not 204");

    let gone = get(
        host,
        &format!("/classes/Post/{object_id}"),
        &As::anonymous(),
    )
    .await;
    assert_eq!(gone.code(), Some(101), "{}", gone.raw);
}

/// The JavaScript SDK sends every request as a POST with the real method in `_method`, and the
/// credentials in the body rather than in headers.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_sdk_transport_reaches_every_verb() {
    let server = common::boot().await;
    let host = &server.host;

    // A create with body credentials and no headers at all.
    let created = raw_post(
        host,
        "/classes/Sdk",
        &json!({
            "_ApplicationId": common::APP_ID,
            "_JavaScriptKey": common::JS_KEY,
            "_ClientVersion": "js1.0.0",
            "title": "via sdk",
        }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let object_id = created.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();

    // The credential keys must not have become fields on the saved object.
    let fetched = raw_post(
        host,
        &format!("/classes/Sdk/{object_id}"),
        &json!({
            "_ApplicationId": common::APP_ID,
            "_JavaScriptKey": common::JS_KEY,
            "_method": "GET",
        }),
    )
    .await;
    assert_eq!(fetched.status, 200, "{}", fetched.raw);
    assert_eq!(fetched.body["title"], json!("via sdk"));
    for key in [
        "_ApplicationId",
        "_JavaScriptKey",
        "_ClientVersion",
        "_method",
    ] {
        assert!(
            fetched.body.get(key).is_none(),
            "{key} must never become a field: {}",
            fetched.raw
        );
    }

    let updated = raw_post(
        host,
        &format!("/classes/Sdk/{object_id}"),
        &json!({
            "_ApplicationId": common::APP_ID,
            "_JavaScriptKey": common::JS_KEY,
            "_method": "PUT",
            "title": "changed",
        }),
    )
    .await;
    assert_eq!(updated.status, 200, "{}", updated.raw);

    let removed = raw_post(
        host,
        &format!("/classes/Sdk/{object_id}"),
        &json!({
            "_ApplicationId": common::APP_ID,
            "_JavaScriptKey": common::JS_KEY,
            "_method": "DELETE",
        }),
    )
    .await;
    assert_eq!(removed.status, 200, "{}", removed.raw);
}

/// A POST to an object route with no `_method` is not an update. Falling through to one meant an
/// unrelated request could mutate a row.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_bare_post_to_an_object_route_is_not_an_update() {
    let server = common::boot().await;
    let host = &server.host;
    let created = post(
        host,
        "/classes/Post",
        &As::anonymous(),
        &json!({ "title": "keep" }),
    )
    .await;
    let object_id = created.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();

    let r = post(
        host,
        &format!("/classes/Post/{object_id}"),
        &As::anonymous(),
        &json!({ "title": "clobbered" }),
    )
    .await;
    assert_eq!(r.status, 404, "{}", r.raw);

    let after = get(
        host,
        &format!("/classes/Post/{object_id}"),
        &As::anonymous(),
    )
    .await;
    assert_eq!(after.body["title"], json!("keep"), "{}", after.raw);
}

/// The class-security gate, reproduced from `enforceRoleSecurity`.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_master_only_classes_are_upstreams_list() {
    let server = common::boot().await;
    let host = &server.host;

    // `enforceRoleSecurity` builds these through `createSanitizedError` (`SharedRest.js:17`,
    // `:31`, `:40`), so at the default the client is told it was refused and nothing more. The
    // detailed strings are asserted against the second server below.
    let disclosing = {
        let mut config = parse_rust_server::ServerConfig::new(common::APP_ID, common::MASTER_KEY);
        config.enable_sanitized_error_response = false;
        common::boot_with(&server.database, config).await
    };

    for class in [
        "_JobStatus",
        "_PushStatus",
        "_Hooks",
        "_GlobalConfig",
        "_GraphQLConfig",
        "_JobSchedule",
        "_Audience",
        "_Idempotency",
    ] {
        let r = get(host, &format!("/classes/{class}"), &As::anonymous()).await;
        assert_eq!(r.code(), Some(119), "{class}: {}", r.raw);
        assert_eq!(r.error(), "Permission denied", "{class}: {}", r.raw);

        let detailed = get(&disclosing, &format!("/classes/{class}"), &As::anonymous()).await;
        assert_eq!(detailed.code(), Some(119), "{class}: {}", detailed.raw);
        assert_eq!(
            detailed.error(),
            format!(
                "Clients aren't allowed to perform the find operation on the {class} collection."
            )
        );
    }

    // `_Join:` tables are internal and are reachable only through relation operations.
    let join = get(host, "/classes/_Join:users:_Role", &As::anonymous()).await;
    assert_eq!(join.code(), Some(119), "{}", join.raw);

    // `_Role` and `_Session` are **not** on the list. Both go through ordinary CLP plus ACL, and
    // `_Session` additionally through the owner narrowing. A `_Session` read with no user is the
    // session-token error rather than the class-security one.
    let roles = get(host, "/classes/_Role", &As::anonymous()).await;
    assert_eq!(roles.status, 200, "{}", roles.raw);
    let sessions = get(host, "/classes/_Session", &As::anonymous()).await;
    assert_eq!(sessions.code(), Some(209), "{}", sessions.raw);
}

/// Two deliberate additions to that list, both fail-closed over a write stage that does not exist.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn session_and_user_writes_through_the_class_route_are_refused() {
    let server = common::boot().await;
    let host = &server.host;
    let (_id, token) = signup(host, "cls_user", "pw").await;

    // Forging a session row would be account takeover, not a missing feature.
    let forged = post(
        host,
        "/classes/_Session",
        &As::user(&token),
        &json!({ "sessionToken": "r:00000000000000000000000000000000" }),
    )
    .await;
    assert_eq!(forged.code(), Some(119), "{}", forged.raw);

    let user = post(
        host,
        "/classes/_User",
        &As::anonymous(),
        &json!({ "username": "sneaky", "password": "pw" }),
    )
    .await;
    assert_eq!(user.code(), Some(119), "{}", user.raw);

    // Master is exempt, which is what lets the dashboard write both.
    let as_master = post(
        host,
        "/classes/_User",
        &As::master(),
        &json!({ "username": "by_master", "password": "pw" }),
    )
    .await;
    assert_eq!(as_master.status, 201, "{}", as_master.raw);
    // And the password still went through hashing on that path.
    let login = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "by_master", "password": "pw" }),
    )
    .await;
    assert_eq!(login.status, 200, "{}", login.raw);
}

// -------------------------------------------------------------------------------------------
// Roles
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_five_role_verbs() {
    let server = common::boot().await;
    let host = &server.host;
    let (user_id, _token) = signup(host, "role_crud", "pw").await;

    let created = post(
        host,
        "/roles",
        &As::master(),
        &json!({
            "name": "Editors",
            "ACL": { "*": { "read": true } },
            "users": {
                "__op": "AddRelation",
                "objects": [{ "__type": "Pointer", "className": "_User", "objectId": user_id }],
            },
        }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let role_id = created.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();

    let listed = get(host, "/roles", &As::master()).await;
    assert_eq!(listed.results().len(), 1, "{}", listed.raw);
    assert_eq!(listed.results()[0]["name"], json!("Editors"));

    let fetched = get(host, &format!("/roles/{role_id}"), &As::master()).await;
    assert_eq!(fetched.status, 200, "{}", fetched.raw);
    // A Relation field has no column; it is synthesized from the schema on read.
    assert_eq!(fetched.body["users"]["__type"], json!("Relation"));
    assert_eq!(fetched.body["users"]["className"], json!("_User"));

    let updated = put(
        host,
        &format!("/roles/{role_id}"),
        &As::master(),
        &json!({ "ACL": { "*": { "read": true, "write": true } } }),
    )
    .await;
    assert_eq!(updated.status, 200, "{}", updated.raw);

    let removed = delete(host, &format!("/roles/{role_id}"), &As::master()).await;
    assert_eq!(removed.status, 200, "{}", removed.raw);
    assert!(get(host, "/roles", &As::master())
        .await
        .results()
        .is_empty());
}

/// `_Role` requires `name` and `ACL` on write. A role saved with no ACL is world-writable, so any
/// client could add itself to it.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_role_without_a_name_or_an_acl_is_refused() {
    let server = common::boot().await;
    let host = &server.host;

    for body in [
        json!({ "name": "NoAcl" }),
        json!({ "ACL": { "*": { "read": true } } }),
    ] {
        let r = post(host, "/roles", &As::master(), &body).await;
        assert_ne!(r.status, 201, "{}", r.raw);
        assert!(r.code().is_some(), "{}", r.raw);
    }
}

/// A raw POST with no headers, which is exactly what the JavaScript SDK sends.
async fn raw_post(host: &str, path: &str, body: &serde_json::Value) -> common::Response {
    request(
        host,
        "POST",
        path,
        &As::anonymous_without_keys(),
        Some(body),
    )
    .await
}

/// `allowCustomObjectId` at its default, which is what nearly every deployment runs.
///
/// Both keys are refused and both report `INVALID_KEY_NAME` (`RestWrite.js:59-64`). Honoring a
/// client's objectId at the default lets a caller collide with, or predict, an existing row.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_client_supplied_object_id_is_refused_by_default() {
    let server = common::boot().await;
    let host = &server.host;

    for key in ["objectId", "id"] {
        let created = post(
            host,
            "/classes/Note",
            &As::master(),
            &json!({ key: "chosenByClient", "title": "a" }),
        )
        .await;
        assert_eq!(created.code(), Some(105), "{}", created.raw);
        assert_eq!(created.error(), format!("{key} is an invalid field name."));
    }

    // Signup is a create too, and upstream applies the same check to it.
    let signup = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "objectId": "chosenByClient", "username": "custom", "password": "pw" }),
    )
    .await;
    assert_eq!(signup.code(), Some(105), "{}", signup.raw);
}

/// With the option on, the id is honored and only an empty one is refused, under code 104.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn allowing_custom_object_ids_honors_the_id_and_refuses_an_empty_one() {
    let server = common::boot_fresh_with(|mut config| {
        config.allow_custom_object_id = true;
        config
    })
    .await;
    let host = &server.host;

    let created = post(
        host,
        "/classes/Note",
        &As::master(),
        &json!({ "objectId": "chosenByClient", "title": "a" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    assert_eq!(created.body["objectId"], json!("chosenByClient"));

    let fetched = get(host, "/classes/Note/chosenByClient", &As::master()).await;
    assert_eq!(fetched.body["title"], json!("a"), "{}", fetched.raw);

    let empty = post(
        host,
        "/classes/Note",
        &As::master(),
        &json!({ "objectId": "", "title": "b" }),
    )
    .await;
    assert_eq!(empty.code(), Some(104), "{}", empty.raw);
    assert_eq!(
        empty.error(),
        "objectId must not be empty, null or undefined"
    );

    // **A truthy non-string passes the policy check and is refused by schema validation.**
    // `allowCustomObjectId` tests truthiness and nothing else (`RestWrite.js:51-57`), so the value
    // stays on the body and meets `objectId`'s declared `String` type. Replacing it with a
    // generated id would create the row and report success for a body upstream rejects.
    let numeric = post(
        host,
        "/classes/Note",
        &As::master(),
        &json!({ "objectId": 123, "title": "c" }),
    )
    .await;
    assert_eq!(numeric.code(), Some(111), "{}", numeric.raw);
    assert_eq!(
        numeric.error(),
        "schema mismatch for Note.objectId; expected String but got Number"
    );

    // And nothing landed under a substituted id.
    let all = get(host, "/classes/Note", &As::master()).await;
    assert_eq!(all.results().len(), 1, "{}", all.raw);
    assert_eq!(all.results()[0]["objectId"], json!("chosenByClient"));
}

/// A falsy objectId at the default setting is generated, not used.
///
/// Upstream's generation test is `if (!this.data.objectId)` (`RestWrite.js:489-491`), so an empty
/// string reaches it as falsy and is replaced. It gets that far because
/// `enforce_object_id_policy` refuses only *truthy* client ids when the option is off, which is
/// the same truthiness test one step earlier.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_falsy_object_id_is_replaced_rather_than_stored() {
    let server = common::boot().await;
    let host = &server.host;

    for falsy in [json!(""), json!(null)] {
        let created = post(
            host,
            "/classes/Note",
            &As::master(),
            &json!({ "objectId": falsy, "title": "a" }),
        )
        .await;
        assert_eq!(created.status, 201, "for {falsy}: {}", created.raw);
        let id = created.body["objectId"].as_str().expect("an objectId");
        assert_eq!(
            id.len(),
            10,
            "a generated id, not the falsy one: {}",
            created.raw
        );
    }
}

/// A `_User` whose objectId is `role:X` would be granted that role by every ACL check, and the
/// guard is on `ClassesRouter`, so it covers the class route as well as signup.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_role_prefixed_user_id_is_refused_on_both_create_routes() {
    let server = common::boot_fresh_with(|mut config| {
        // The guard is independent of this option; turning it on is only what lets the id reach
        // the guard rather than being refused as a custom objectId first.
        config.allow_custom_object_id = true;
        config
    })
    .await;
    let host = &server.host;

    let body = json!({ "objectId": "role:Admins", "username": "impostor", "password": "pw" });

    let signup = post(host, "/users", &As::anonymous(), &body).await;
    assert_eq!(signup.code(), Some(119), "{}", signup.raw);

    // The same guard, through the class route, which only master may use at all.
    let class_route = post(host, "/classes/_User", &As::master(), &body).await;
    assert_eq!(class_route.code(), Some(119), "{}", class_route.raw);
}

/// A create refused for its `objectId` still leaves the class behind, and one refused for its
/// class name does not.
///
/// Both are ordering properties of `enforceClassExists`, which runs before every one of
/// `validateObject`'s per-field checks (`SchemaController.js:1288`) and refuses an invalid class
/// name without writing (`:987-1004`). Measured against a running parse-server at the pin, with
/// `allowCustomObjectId: true`: it answers 111 and leaves the row, and answers 107 and writes
/// nothing, respectively.
///
/// Gate D asserts the class-name half differentially. This one carries the objectId half, which
/// needs the option on and therefore a second upstream the gate does not boot.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_refused_create_leaves_the_class_behind_unless_the_class_name_is_the_problem() {
    let server = common::boot_fresh_with(|mut config| {
        config.allow_custom_object_id = true;
        config
    })
    .await;
    let host = &server.host;

    // Refused for the objectId's type. The class is created first, so it survives.
    let numeric = post(
        host,
        "/classes/NumericGhost",
        &As::master(),
        &json!({ "objectId": 123, "title": "x" }),
    )
    .await;
    assert_eq!(numeric.code(), Some(111), "{}", numeric.raw);
    let stored = get(host, "/schemas/NumericGhost", &As::master()).await;
    assert_eq!(
        stored.status, 200,
        "the class survives a create refused for its objectId: {}",
        stored.raw
    );

    // Refused for the class name. Nothing may be written, because the name is what could not be
    // created, and the code is the fixed `INVALID_JSON` rather than the schema route's 103.
    let bad_name = post(host, "/classes/1BadName", &As::master(), &json!({ "x": 1 })).await;
    assert_eq!(bad_name.code(), Some(107), "{}", bad_name.raw);
    assert_eq!(bad_name.error(), "schema class name does not revalidate");

    let all = get(host, "/schemas", &As::master()).await;
    assert!(
        !all.raw.contains("1BadName"),
        "an invalid class name must not reach _SCHEMA: {}",
        all.raw
    );
}

/// One GeoPoint per class, enforced on ordinary writes and not only through the schema API.
///
/// Two layers upstream, with two different messages, and both are wire-visible. Measured against
/// parse-server at the pin:
///
/// - two GeoPoints in one body answer `there can only be one geopoint field in a class`, from
///   `validateObject`'s `geocount` over the incoming object (`SchemaController.js:1287-1302`);
/// - a second GeoPoint added by a later write answers `MongoDB only supports one GeoPoint field in
///   a class.`, from the adapter's field reservation (`MongoSchemaCollection.js:224-237`), because
///   the later body carries only one and `geocount` never exceeds 1.
///
/// Both are code 111. A single check with a single message would match upstream on one case and
/// not the other.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_class_may_hold_only_one_geopoint_field() {
    let server = common::boot().await;
    let host = &server.host;
    let geo =
        |lat: f64, lon: f64| json!({ "__type": "GeoPoint", "latitude": lat, "longitude": lon });

    let two_at_once = post(
        host,
        "/classes/GeoA",
        &As::master(),
        &json!({ "a": geo(1.0, 2.0), "b": geo(3.0, 4.0) }),
    )
    .await;
    assert_eq!(two_at_once.code(), Some(111), "{}", two_at_once.raw);
    assert_eq!(
        two_at_once.error(),
        "there can only be one geopoint field in a class"
    );

    let first = post(
        host,
        "/classes/GeoB",
        &As::master(),
        &json!({ "a": geo(1.0, 2.0) }),
    )
    .await;
    assert_eq!(first.status, 201, "one is fine: {}", first.raw);

    let second = post(
        host,
        "/classes/GeoB",
        &As::master(),
        &json!({ "b": geo(3.0, 4.0) }),
    )
    .await;
    assert_eq!(second.code(), Some(111), "{}", second.raw);
    assert_eq!(
        second.error(),
        "MongoDB only supports one GeoPoint field in a class.",
        "the adapter's message, not validateObject's: {}",
        second.raw
    );

    // The refused field must not be left behind in `_SCHEMA`.
    let schema = get(host, "/schemas/GeoB", &As::master()).await;
    assert_eq!(schema.status, 200, "{}", schema.raw);
    assert!(
        schema.body["fields"].get("b").is_none(),
        "a refused GeoPoint leaves no column: {}",
        schema.raw
    );
}

/// Two concurrent creates of an **absent** class, each adding a *different* GeoPoint field.
///
/// The committed race test covers an existing class, where the `$expr` guard does the work. This
/// covers the other half, and it is the half that was racy: the first version read "does the class
/// exist?" and then upserted, so two writers could both observe absence, the first insert `a`, and
/// the second's plain `{b: {$exists: false}}` filter then add a second GeoPoint happily. The class
/// row is created by an `insert_one` now, which is atomic on `_id`, so the loser gets a
/// duplicate-key error and re-tests the guard.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn concurrent_creates_of_an_absent_class_cannot_both_add_a_geopoint() {
    let server = common::boot().await;
    let host = &server.host;
    let geo =
        |lat: f64, lon: f64| json!({ "__type": "GeoPoint", "latitude": lat, "longitude": lon });

    let master = As::master();
    let body_a = json!({ "a": geo(1.0, 2.0) });
    let body_b = json!({ "b": geo(3.0, 4.0) });
    let (ra, rb) = futures::join!(
        post(host, "/classes/GeoRace", &master, &body_a),
        post(host, "/classes/GeoRace", &master, &body_b),
    );

    let winners = [&ra, &rb].iter().filter(|r| r.status == 201).count();
    assert_eq!(winners, 1, "exactly one may win: {} / {}", ra.raw, rb.raw);
    let loser = if ra.status == 201 { &rb } else { &ra };
    assert_eq!(
        loser.code(),
        Some(111),
        "the loser is refused as a second GeoPoint: {}",
        loser.raw
    );

    // And the stored schema carries exactly one GeoPoint column.
    let schema = get(host, "/schemas/GeoRace", &As::master()).await;
    assert_eq!(schema.status, 200, "{}", schema.raw);
    let geo_fields = schema.body["fields"]
        .as_object()
        .expect("fields")
        .iter()
        .filter(|(_, v)| v["type"] == json!("GeoPoint"))
        .count();
    assert_eq!(
        geo_fields, 1,
        "exactly one GeoPoint survives: {}",
        schema.raw
    );
}

/// `$in` and `$nin` over an Array field whose elements are pointers.
///
/// Which converter an operand goes through is decided by the field, not the operator
/// (`MongoTransform.js:656-662`): an `Array`-typed field and a dotted key hold *interior* values,
/// where a Pointer keeps its `__type` envelope. Using the top-level converter made an ordinary
/// `containedIn` answer 111 with an internal implementation sentence on the wire.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_array_of_pointers_can_be_queried_with_in_and_nin() {
    let server = common::boot().await;
    let host = &server.host;
    let (u1, _) = signup(host, "arr1", "pw").await;
    let (u2, _) = signup(host, "arr2", "pw").await;
    let ptr = |id: &str| json!({ "__type": "Pointer", "className": "_User", "objectId": id });

    let made = post(
        host,
        "/classes/Tagged",
        &As::master(),
        &json!({ "who": [ptr(&u1)], "label": "first" }),
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.raw);
    post(
        host,
        "/classes/Tagged",
        &As::master(),
        &json!({ "who": [ptr(&u2)], "label": "second" }),
    )
    .await;

    let w = common::urlencode(&json!({ "who": { "$in": [ptr(&u1)] } }).to_string());
    let found = get(host, &format!("/classes/Tagged?where={w}"), &As::master()).await;
    assert_eq!(found.status, 200, "{}", found.raw);
    let rows = found.results();
    assert_eq!(
        rows.len(),
        1,
        "$in matches the row holding it: {}",
        found.raw
    );
    assert_eq!(rows[0]["label"], json!("first"));

    let w2 = common::urlencode(&json!({ "who": { "$nin": [ptr(&u1)] } }).to_string());
    let rest = get(host, &format!("/classes/Tagged?where={w2}"), &As::master()).await;
    assert_eq!(rest.status, 200, "{}", rest.raw);
    assert_eq!(
        rest.results().len(),
        1,
        "$nin matches the other: {}",
        rest.raw
    );
    assert_eq!(rest.results()[0]["label"], json!("second"));
}

/// A nested key containing `$` or `.` is refused rather than stored.
///
/// `transformInteriorValue` (`MongoTransform.js:177-187`). MongoDB gives both characters meaning
/// inside a document key, so these are writes parse-server refuses with 121.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_nested_key_with_a_dollar_or_dot_is_refused() {
    let server = common::boot().await;
    let host = &server.host;

    for body in [
        json!({ "tags": [{ "$regex": "x" }] }),
        json!({ "tags": [{ "a.b": 1 }] }),
        json!({ "meta": { "inner": { "$set": 1 } } }),
    ] {
        let r = post(host, "/classes/Nested", &As::master(), &body).await;
        assert_eq!(r.code(), Some(121), "{body}: {}", r.raw);
        assert_eq!(
            r.error(),
            "Nested keys should not contain the '$' or '.' characters"
        );
    }

    // The query path still accepts `$regex`, which is what a constraint looks like.
    post(
        host,
        "/classes/Nested",
        &As::master(),
        &json!({ "name": "abc" }),
    )
    .await;
    let w = common::urlencode(&json!({ "name": { "$regex": "^ab" } }).to_string());
    let found = get(host, &format!("/classes/Nested?where={w}"), &As::master()).await;
    assert_eq!(found.status, 200, "{}", found.raw);
    assert_eq!(found.results().len(), 1, "{}", found.raw);
}

/// A query atom containing a nested Parse value is compared **unchanged**, so it matches nothing.
///
/// `transformInteriorAtom` is shallow: its last arm is `return atom`, so a nested `{"__type":
/// "Date"}` inside a query operand stays three string keys and cannot equal the BSON date the row
/// holds. Recursing instead matched a row upstream does not return, which is the direction that
/// matters: a query answering with more than upstream would is an authorization concern here, not
/// a formatting one. Measured against parse-server at the pin, which answers with no results.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_nested_parse_value_in_a_query_atom_matches_nothing() {
    let server = common::boot().await;
    let host = &server.host;
    let iso = "2020-01-02T03:04:05.678Z";
    let date = json!({ "__type": "Date", "iso": iso });

    let made = post(
        host,
        "/classes/Tg",
        &As::master(),
        &json!({ "tags": [{ "at": date }] }),
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.raw);

    let w = common::urlencode(&json!({ "tags": { "$in": [{ "at": date }] } }).to_string());
    let found = get(host, &format!("/classes/Tg?where={w}"), &As::master()).await;
    assert_eq!(found.status, 200, "{}", found.raw);
    assert!(
        found.results().is_empty(),
        "the operand is not converted, so it cannot match the stored BSON date: {}",
        found.raw
    );
}

/// A non-string `$regex` operand coerces rather than producing a 500.
///
/// `new RegExp(atom.$regex)` (`MongoTransform.js:581`): `new RegExp(7)` is `/7/`.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_non_string_regex_operand_coerces() {
    let server = common::boot().await;
    let host = &server.host;

    let made = post(
        host,
        "/classes/Rx",
        &As::master(),
        &json!({ "tags": ["a7b", "zzz"] }),
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.raw);

    let w = common::urlencode(&json!({ "tags": { "$in": [{ "$regex": 7 }] } }).to_string());
    let found = get(host, &format!("/classes/Rx?where={w}"), &As::master()).await;
    assert_eq!(
        found.status, 200,
        "a numeric pattern coerces rather than 500ing: {}",
        found.raw
    );
    assert_eq!(found.results().len(), 1, "and matches `a7b`: {}", found.raw);
}

/// Array and object `$regex` operands coerce rather than 500.
///
/// `new RegExp(String(v))` is the whole rule (`MongoTransform.js:581`), so `[7]` joins to `7` and
/// `{}` renders as `[object Object]`, and both are then read as patterns. Measured against the pin:
/// all four of `[7]`, `[]`, `{}` and `[1,2]` answer 200 there, and `[7]` matches `a7b`.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_array_or_object_regex_operand_coerces_rather_than_erroring() {
    let server = common::boot().await;
    let host = &server.host;

    let made = post(
        host,
        "/classes/Rx2",
        &As::master(),
        &json!({ "tags": ["a7b", "zzz"] }),
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.raw);

    for operand in [json!([7]), json!([]), json!({}), json!([1, 2])] {
        let w =
            common::urlencode(&json!({ "tags": { "$in": [{ "$regex": operand }] } }).to_string());
        let r = get(host, &format!("/classes/Rx2?where={w}"), &As::master()).await;
        assert_eq!(r.status, 200, "{operand} must not error: {}", r.raw);
    }

    // `[7]` joins to `7`, which matches `a7b`. The others are not asserted on content: `[]` and
    // `{}` produce patterns nothing here is meant to match.
    let w = common::urlencode(&json!({ "tags": { "$in": [{ "$regex": [7] }] } }).to_string());
    let found = get(host, &format!("/classes/Rx2?where={w}"), &As::master()).await;
    assert_eq!(
        found.results().len(),
        1,
        "`[7]` matches `a7b`: {}",
        found.raw
    );
}

/// Four write shapes where a guard matches one spelling and a second is reachable.
///
/// **This test exists because of a pattern, not a bug.** Every recent defect in the `_User` and
/// authorization paths has been a guard written for one spelling of something that has two: an ACL
/// as an object but not as a `Delete`, a username as a string but not as an op, a pointer operand
/// on a Pointer field but not on an Array field. An audit walked the remaining guards of that
/// shape and found these four already correct. They are pinned here so that stays true, since the
/// cost of rediscovering them is another round.
///
/// Every expectation was measured against the pinned parse-server rather than reasoned about.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn op_form_writes_match_upstream_on_the_paths_an_audit_covered() {
    let server = common::boot().await;
    let host = &server.host;

    // 1. An ACL `Delete` on an ordinary class clears both columns rather than removing the ACL.
    //    The distinction matters: an absent ACL is world-readable, empty arrays are nobody.
    //    Upstream stores `_rperm: []`, `_wperm: []` and answers 404 to an anonymous read.
    let made = post(
        host,
        "/classes/Post",
        &As::master(),
        &json!({ "t": 1, "ACL": { "*": { "read": true, "write": true } } }),
    )
    .await;
    let id = made.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();
    let unset = put(
        host,
        &format!("/classes/Post/{id}"),
        &As::master(),
        &json!({ "ACL": { "__op": "Delete" } }),
    )
    .await;
    assert_eq!(unset.status, 200, "{}", unset.raw);
    let after = get(host, &format!("/classes/Post/{id}"), &As::master()).await;
    assert_eq!(
        after.body["ACL"],
        json!({}),
        "the ACL is emptied, not removed: {}",
        after.raw
    );
    let anon = get(host, &format!("/classes/Post/{id}"), &As::anonymous()).await;
    assert_eq!(
        anon.code(),
        Some(101),
        "an emptied ACL is not public: {}",
        anon.raw
    );

    // 2. A non-string `email` is refused by schema validation rather than skipped, which is where
    //    upstream lands too, though it arrives by a different route: it reaches `.match()` on a
    //    number and 500s only when the column does not already type it.
    let (uid, tok) = signup(host, "audit_email", "pw").await;
    let bad_email = put(
        host,
        &format!("/classes/_User/{uid}"),
        &As::user(&tok),
        &json!({ "email": 123 }),
    )
    .await;
    assert_eq!(bad_email.code(), Some(111), "{}", bad_email.raw);

    // 3. `objectId` as an op on a create is refused by name, not substituted.
    let oid = post(
        host,
        "/classes/Oid",
        &As::master(),
        &json!({ "objectId": { "__op": "Delete" }, "x": 1 }),
    )
    .await;
    assert_eq!(oid.code(), Some(105), "{}", oid.raw);
    assert_eq!(oid.error(), "objectId is an invalid field name.");
}

/// A query operand keeps what the client sent, so the predicate executed is the one asked for.
///
/// Four shapes, all measured against the pinned parse-server. The asymmetry between the second and
/// the fourth is the whole point: upstream *reconstructs* a recognized atom from its declared keys,
/// so an unknown key on the atom itself cannot affect the comparison, while a plain object is
/// compared whole.
///
/// Decoding an operand all the way down collapses those two into one and **matches a row upstream
/// does not return**. ACL and CLP still run, so nothing widens what a caller may see, but the query
/// answers with more than it was asked for, which this project treats as the direction that counts.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_query_operand_is_compared_as_sent() {
    let server = common::boot().await;
    let host = &server.host;
    let ptr = json!({ "__type": "Pointer", "className": "_User", "objectId": "abc" });

    let a = post(host, "/classes/T", &As::master(), &json!({ "tags": [ptr] })).await;
    assert_eq!(a.status, 201, "{}", a.raw);
    let b = post(
        host,
        "/classes/T",
        &As::master(),
        &json!({ "nest": [{ "p": ptr }] }),
    )
    .await;
    assert_eq!(b.status, 201, "{}", b.raw);

    let count = |w: serde_json::Value| async move {
        let q = common::urlencode(&w.to_string());
        let r = get(host, &format!("/classes/T?where={q}"), &As::master()).await;
        assert_eq!(r.status, 200, "{}", r.raw);
        r.results().len()
    };

    let mut with_extra = ptr.clone();
    with_extra["extra"] = json!(1);

    assert_eq!(
        count(json!({ "tags": { "$in": [ptr] } })).await,
        1,
        "plain atom matches"
    );
    assert_eq!(
        count(json!({ "tags": { "$in": [with_extra] } })).await,
        1,
        "an unknown key on the atom itself is discarded by the reconstruction, so it still matches"
    );
    assert_eq!(
        count(json!({ "nest": { "$in": [{ "p": ptr }] } })).await,
        1,
        "a nested atom inside a plain object matches when it is identical"
    );
    assert_eq!(
        count(json!({ "nest": { "$in": [{ "p": with_extra }] } })).await,
        0,
        "and must not match once it carries a key the stored value does not: the operand is \
         compared as sent"
    );
}

/// The remaining operand shapes, and the two atom lists that differ.
///
/// `transformInteriorAtom` recognizes **three** envelopes, Pointer, Date and Bytes;
/// `transformTopLevelAtom` recognizes all of them. Which one applies is a property of the field
/// (`MongoTransform.js:655-662`), so the choice belongs to the storage layer.
///
/// **The shorthand rows here originally asserted a 200 and were never measured.** They asserted the
/// shape the `$in` rows below have, on the assumption that the two positions differ only in their
/// tag list. They do not: the top-level position also *refuses* anything that is not an atom, so a
/// pointer nested in a plain object is a 107 rather than a comparison. Every row below is measured
/// against `transformWhere` at the pin.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn operand_atom_recognition_matches_upstreams_two_lists() {
    let server = common::boot().await;
    let host = &server.host;
    let ptr = json!({ "__type": "Pointer", "className": "_User", "objectId": "abc" });
    let geo = json!({ "__type": "GeoPoint", "latitude": 1.0, "longitude": 2.0 });

    post(
        host,
        "/classes/Q",
        &As::master(),
        &json!({ "obj": { "p": ptr } }),
    )
    .await;
    post(host, "/classes/Q", &As::master(), &json!({ "tags": [geo] })).await;

    let query = |w: serde_json::Value| async move {
        let q = common::urlencode(&w.to_string());
        get(host, &format!("/classes/Q?where={q}"), &As::master()).await
    };
    let count = |w: serde_json::Value| async move {
        let r = query(w).await;
        assert_eq!(r.status, 200, "{}", r.raw);
        r.results().len()
    };
    let refused = |w: serde_json::Value, message: &'static str| async move {
        let r = query(w).await;
        assert_eq!(r.status, 400, "{}", r.raw);
        assert_eq!(r.code(), Some(107), "{}", r.raw);
        assert_eq!(r.error(), message, "{}", r.raw);
    };

    let mut geo_extra = geo.clone();
    geo_extra["extra"] = json!(1);

    // Shorthand equality with a plain object is not a comparison at all. `transformTopLevelAtom`
    // cannot transform it and the caller raises 107, rendering the value the way a JS template
    // literal does.
    refused(
        json!({ "obj": { "p": ptr } }),
        "You cannot use [object Object] as a query parameter.",
    )
    .await;
    // The same operand under `$eq` is refused too, and by the other of the two throw sites, so the
    // message is different. A client matching on either one sees the one upstream sends.
    refused(
        json!({ "obj": { "$eq": { "p": ptr } } }),
        r#"bad atom: {"p":{"__type":"Pointer","className":"_User","objectId":"abc"}}"#,
    )
    .await;
    // A bare pointer *is* an atom, and at the top level it collapses to the storage form whatever
    // the field's declared type is.
    assert_eq!(
        count(json!({ "obj": ptr })).await,
        0,
        "the row stores an object, not a pointer, so this matches nothing but is a legal query"
    );

    // The interior position has no such refusal: its last arm returns the atom untouched. This is
    // where the tag lists actually diverge, and a GeoPoint is not on the interior one, so an
    // unknown key on it is compared rather than discarded.
    assert_eq!(
        count(json!({ "tags": { "$in": [geo] } })).await,
        1,
        "the identical operand matches"
    );
    assert_eq!(
        count(json!({ "tags": { "$in": [geo_extra] } })).await,
        0,
        "a GeoPoint is not rebuilt in an interior position, so the unknown key counts"
    );
}

/// A `File` column reads back as its envelope, which only the schema can say.
///
/// **Covered here rather than in the data-fidelity gate because that gate drives the JavaScript
/// SDK, and a `Parse.File` cannot be constructed without uploading one.** The files subsystem is
/// not built, so the gate can reach GeoPoint, Polygon and Bytes and cannot reach this. The stored
/// form is a bare string, indistinguishable from a String column, so a read path that does not
/// consult `_SCHEMA` hands the client `"avatar.png"` where every SDK expects a `File`.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_file_column_reads_back_as_a_file_and_not_as_its_name() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/classes/Avatar",
        &As::master(),
        &json!({ "pic": { "__type": "File", "name": "avatar.png" }, "label": "avatar.png" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let id = created.body["objectId"].as_str().expect("objectId");

    let fetched = get(host, &format!("/classes/Avatar/{id}"), &As::master()).await;
    assert_eq!(fetched.status, 200, "{}", fetched.raw);
    assert_eq!(
        fetched.body["pic"]["__type"],
        json!("File"),
        "a File column must raise to its envelope: {}",
        fetched.raw
    );
    assert_eq!(fetched.body["pic"]["name"], json!("avatar.png"));
    // The control. An identical string in a String column must stay a string, which is what makes
    // the assertion above about the schema rather than about the value.
    assert_eq!(
        fetched.body["label"],
        json!("avatar.png"),
        "{}",
        fetched.raw
    );
    // No `url`. Upstream synthesizes one in `expandFilesInObject` from the files adapter, and there
    // is no files subsystem at 0.2.0. Asserted so the gap is visible here rather than discovered by
    // a client.
    assert!(
        fetched.body["pic"].get("url").is_none(),
        "0.2.0 has no files adapter to build a url from: {}",
        fetched.raw
    );
}

/// A raw `defaultValue` is still validated, tag and payload.
///
/// Decoding a schema body raw so it can be stored as sent removed the check the ordinary decoder
/// used to perform on the way in. `getObjectType` guards every recognized tag on the key carrying
/// its payload and throws `This is not a valid <tag>` for a failed guard or an unknown tag, so
/// without this parse-rust would write schema metadata that parse-server refuses to create into a
/// database they share.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_raw_default_value_is_still_validated() {
    let server = common::boot().await;
    let host = &server.host;

    for (spec, default, tag) in [
        (
            json!({ "type": "Date" }),
            json!({ "__type": "Date" }),
            "Date",
        ),
        (
            json!({ "type": "Object" }),
            json!({ "__type": "NoSuchType" }),
            "NoSuchType",
        ),
        (
            json!({ "type": "Bytes" }),
            json!({ "__type": "Bytes" }),
            "Bytes",
        ),
        // `targetClass` on the *field* is required for a Pointer field and is a different error;
        // what is under test is the **default value** missing its own `className`.
        (
            json!({ "type": "Pointer", "targetClass": "_User" }),
            json!({ "__type": "Pointer", "objectId": "x" }),
            "Pointer",
        ),
    ] {
        let mut field = spec.clone();
        field["defaultValue"] = default.clone();
        let r = post(
            host,
            "/schemas/Invalid",
            &As::master(),
            &json!({ "className": "Invalid", "fields": { "f": field } }),
        )
        .await;
        assert_eq!(r.code(), Some(111), "{default}: {}", r.raw);
        assert_eq!(r.error(), format!("This is not a valid {tag}"));
    }

    // **The guards are JavaScript truthiness, and the two directions of getting that wrong.**
    // Every row measured against a running server at the pin.
    for (name, field, code, message) in [
        // A falsy payload fails `if (obj.iso)`, where a presence test accepts it.
        (
            "empty iso",
            json!({ "type": "Date", "defaultValue": { "__type": "Date", "iso": "" } }),
            Some(111),
            Some("This is not a valid Date"),
        ),
        // A truthy non-string tag matches no `case` and falls to the throw, where a type test lets
        // it through as an ordinary object. The message renders it by concatenation.
        (
            "numeric tag",
            json!({ "type": "Object", "defaultValue": { "__type": 7 } }),
            Some(111),
            Some("This is not a valid 7"),
        ),
        // A falsy tag is not a tag at all, so this is an ordinary object and is accepted.
        (
            "empty tag",
            json!({ "type": "Object", "defaultValue": { "__type": "", "a": 1 } }),
            None,
            None,
        ),
    ] {
        let r = post(
            host,
            &format!("/schemas/Truthy{name}", name = name.replace(' ', "")),
            &As::master(),
            &json!({
                "className": format!("Truthy{}", name.replace(' ', "")),
                "fields": { "f": field }
            }),
        )
        .await;
        assert_eq!(r.code(), code, "{name}: {}", r.raw);
        if let Some(message) = message {
            assert_eq!(r.error(), message, "{name}");
        }
    }

    // **`targetClass` is compared with `!==`, so coercing it before comparing accepts metadata
    // upstream refuses.** A declared `targetClass` of the string `"true"` against a default value
    // whose `className` is the boolean `true` is a mismatch, and upstream says so.
    //
    // The message is the tell and it is not a typo: `typeToString` interpolates, so both sides
    // render as `Pointer<true>` and the error reads `expected Pointer<true> but got Pointer<true>`.
    // Stringifying for the comparison as well makes those two equal, the schema is accepted, and a
    // parse-server node sharing the database then applies the stored default to creates.
    let r = post(
        host,
        "/schemas/StrictTarget",
        &As::master(),
        &json!({
            "className": "StrictTarget",
            "fields": { "p": {
                "type": "Pointer",
                "targetClass": "true",
                "defaultValue": { "__type": "Pointer", "className": true, "objectId": "x" }
            } }
        }),
    )
    .await;
    assert_eq!(r.code(), Some(111), "{}", r.raw);
    assert_eq!(
        r.error(),
        "schema mismatch for StrictTarget.p default value; expected Pointer<true> but got \
         Pointer<true>"
    );

    // The same field with a *string* `className` is the case that must still be accepted, which is
    // what makes the assertion above about the type rather than about the value.
    let ok = post(
        host,
        "/schemas/StrictTargetOk",
        &As::master(),
        &json!({
            "className": "StrictTargetOk",
            "fields": { "p": {
                "type": "Pointer",
                "targetClass": "true",
                "defaultValue": { "__type": "Pointer", "className": "true", "objectId": "x" }
            } }
        }),
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.raw);

    // A well-formed one still works, so the guard is not just refusing everything.
    let ok = post(
        host,
        "/schemas/Valid",
        &As::master(),
        &json!({
            "className": "Valid",
            "fields": { "d": { "type": "Date",
                               "defaultValue": { "__type": "Date", "iso": "2020-01-02T03:04:05.678Z" } } }
        }),
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.raw);
}

/// An SDK read carries its parameters in the body, already JSON, and they are not parsed a second
/// time. A query-string value of the same name wins (`ClassesRouter.js:23`).
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn sdk_body_parameters_keep_their_json_types() {
    let server = common::boot().await;
    let host = &server.host;
    for title in ["a", "b", "c"] {
        let r = post(
            host,
            "/classes/BodyParams",
            &As::master(),
            &json!({ "title": title }),
        )
        .await;
        assert_eq!(r.status, 201, "{}", r.raw);
    }

    // The string "true" is not the boolean upstream's explain validation accepts.
    let explained = raw_post(
        host,
        "/classes/BodyParams",
        &json!({
            "_ApplicationId": common::APP_ID,
            "_MasterKey": common::MASTER_KEY,
            "_method": "GET",
            "explain": "true",
        }),
    )
    .await;
    assert_eq!(explained.code(), Some(102), "{}", explained.raw);
    assert_eq!(explained.error(), "Invalid value for explain");

    let limited = raw_post(
        host,
        "/classes/BodyParams?limit=1",
        &json!({
            "_ApplicationId": common::APP_ID,
            "_JavaScriptKey": common::JS_KEY,
            "_method": "GET",
            "limit": 2,
        }),
    )
    .await;
    assert_eq!(limited.status, 200, "{}", limited.raw);
    assert_eq!(
        limited.body["results"].as_array().map(Vec::len),
        Some(1),
        "the query string's limit wins: {}",
        limited.raw
    );
}
