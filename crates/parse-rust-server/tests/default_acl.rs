//! The CLP-declared default ACL, end to end.
//!
//! 0.2.0 accepted `classLevelPermissions.ACL` through `POST /schemas`, stored it, echoed it back
//! from `GET /schemas` and never applied it. A class configured as private created world-readable
//! rows, because no `ACL` on the body means no `_rperm` column and an absent `_rperm` is public.
//!
//! **Every assertion here is a request rather than a look at the stored columns.** The failure
//! being guarded is that no columns are written at all, and a test that reads `_rperm` and finds
//! it absent has to decide what absent means. A read does not.
//!
//! Both halves are asserted, because the failure to guard is not only "too open": a server that
//! wrote an empty ACL, or stored the literal string `currentUser` as a principal, would shut out
//! user B and pass a naive test while also locking out the object's own creator.
//!
//! `#[ignore]`d because they need a MongoDB on 27017. `tools/test.sh` runs them.

mod common;

use common::*;
use serde_json::{json, Value};

/// The operations, all open to everybody.
///
/// **Spelled out because a present `classLevelPermissions` block is merged over `emptyCLPS`**, so
/// an operation the block does not mention becomes `{}`, which grants nobody. Declaring only an
/// `ACL` key would therefore lock the class down through the CLP gate and every assertion below
/// would pass for the wrong reason: the objects would be unreachable because nobody may create
/// them, not because the default ACL was applied.
fn open_operations() -> Value {
    json!({
        "find": { "*": true },
        "count": { "*": true },
        "get": { "*": true },
        "create": { "*": true },
        "update": { "*": true },
        "delete": { "*": true },
        "addField": { "*": true },
    })
}

fn clp_with_acl(acl: Value) -> Value {
    let mut block = open_operations();
    block["ACL"] = acl;
    block
}

/// Declare a class whose default ACL names `currentUser`.
async fn declare_private_class(host: &str, class: &str) {
    let created = post(
        host,
        "/schemas",
        &As::master(),
        &json!({
            "className": class,
            "fields": { "title": { "type": "String" } },
            "classLevelPermissions":
                clp_with_acl(json!({ "currentUser": { "read": true, "write": true } })),
        }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);
}

async fn create_object(host: &str, class: &str, token: &str) -> String {
    let created = post(
        host,
        &format!("/classes/{class}"),
        &As::user(token),
        &json!({ "title": "x" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    created.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string()
}

/// **The create response carries the ACL this server generated.**
///
/// It is the only way the caller learns what permissions its object got: on a private class it
/// cannot read the row back to find out, and nothing else in the response mentions the ACL.
/// Upstream marks the field as changed by the server and returns it (`RestWrite.js:454`), measured
/// at the pin. Asserted separately from the read-back tests because those pass whether or not the
/// response says anything.
#[tokio::test]
#[ignore = "needs MongoDB on 127.0.0.1:27017"]
async fn the_create_response_carries_the_generated_acl() {
    let server = boot().await;
    let host = &server.host;
    declare_private_class(host, "Echoed").await;

    let (a_id, a) = signup(host, "echo-owner", "pw").await;
    let created = post(
        host,
        "/classes/Echoed",
        &As::user(&a),
        &json!({ "title": "x" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    assert_eq!(
        created.body["ACL"],
        json!({ a_id: { "read": true, "write": true } }),
        "the caller has no other way to learn its object's permissions: {}",
        created.raw
    );

    // The anonymous case answers an empty object rather than omitting the key, which is what
    // upstream does once `currentUser` is deleted with no id to substitute.
    let anon = post(
        host,
        "/classes/Echoed",
        &As::anonymous(),
        &json!({ "title": "y" }),
    )
    .await;
    assert_eq!(anon.status, 201, "{}", anon.raw);
    assert_eq!(anon.body["ACL"], json!({}), "{}", anon.raw);

    // The control: a class with no declared ACL still answers with no ACL key at all, so the
    // assertions above are the setting rather than an unconditional addition to every response.
    let open = post(
        host,
        "/schemas",
        &As::master(),
        &json!({
            "className": "EchoedOpen",
            "fields": { "title": { "type": "String" } },
            "classLevelPermissions": open_operations(),
        }),
    )
    .await;
    assert_eq!(open.status, 200, "{}", open.raw);
    let plain = post(
        host,
        "/classes/EchoedOpen",
        &As::user(&a),
        &json!({ "title": "z" }),
    )
    .await;
    assert_eq!(plain.status, 201, "{}", plain.raw);
    assert!(plain.body.get("ACL").is_none(), "{}", plain.raw);
}

async fn find_all(host: &str, class: &str, who: &As) -> Vec<Value> {
    let response = get(host, &format!("/classes/{class}"), who).await;
    assert_eq!(response.status, 200, "{}", response.raw);
    response.results()
}

/// The headline case. User A creates an object in a class declared private; A can still read and
/// write it, and B can do neither.
#[tokio::test]
#[ignore = "needs MongoDB on 127.0.0.1:27017"]
async fn a_declared_default_acl_isolates_the_creator() {
    let server = boot().await;
    let host = &server.host;
    declare_private_class(host, "Private").await;

    let (a_id, a) = signup(host, "acl-owner", "pw").await;
    let (_, b) = signup(host, "acl-stranger", "pw").await;
    let object_id = create_object(host, "Private", &a).await;

    // The owner is not locked out, which is the half an empty or literal-`currentUser` ACL fails.
    let mine = find_all(host, "Private", &As::user(&a)).await;
    assert_eq!(mine.len(), 1, "the creator must see its own object");
    assert_eq!(mine[0]["objectId"], json!(object_id));

    let updated = put(
        host,
        &format!("/classes/Private/{object_id}"),
        &As::user(&a),
        &json!({ "title": "y" }),
    )
    .await;
    assert_eq!(
        updated.status, 200,
        "_wperm is written separately from _rperm and can be wrong on its own: {}",
        updated.raw
    );

    // And the stranger is shut out of both.
    assert!(
        find_all(host, "Private", &As::user(&b)).await.is_empty(),
        "0.2.0 returned this object to every caller"
    );
    let denied = put(
        host,
        &format!("/classes/Private/{object_id}"),
        &As::user(&b),
        &json!({ "title": "z" }),
    )
    .await;
    assert_eq!(denied.status, 404, "{}", denied.raw);
    assert_eq!(denied.code(), Some(101));

    // The resolved principal is the caller's objectId, not the literal key. Read back through the
    // owner, the only caller who can see it.
    let one = get(
        host,
        &format!("/classes/Private/{object_id}"),
        &As::user(&a),
    )
    .await;
    assert_eq!(one.status, 200, "{}", one.raw);
    assert_eq!(
        one.body["ACL"],
        json!({ a_id.clone(): { "read": true, "write": true } }),
        "currentUser must resolve to the caller and the literal key must be gone"
    );
}

/// The control. Without it the test above passes against a server that lost the ability to read
/// anything at all.
#[tokio::test]
#[ignore = "needs MongoDB on 127.0.0.1:27017"]
async fn a_class_with_no_declared_acl_still_creates_public_rows() {
    let server = boot().await;
    let host = &server.host;
    let created = post(
        host,
        "/schemas",
        &As::master(),
        &json!({
            "className": "Open",
            "fields": { "title": { "type": "String" } },
            "classLevelPermissions": open_operations(),
        }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);

    let (_, a) = signup(host, "open-owner", "pw").await;
    let (_, b) = signup(host, "open-stranger", "pw").await;
    create_object(host, "Open", &a).await;

    assert_eq!(find_all(host, "Open", &As::user(&b)).await.len(), 1);
}

/// The `!this.query` guard. A server that stamps the default on every write passes everything
/// above while silently reverting a permission change a client made on purpose, and nothing in
/// the response shows it: the update succeeds either way.
#[tokio::test]
#[ignore = "needs MongoDB on 127.0.0.1:27017"]
async fn the_default_applies_on_create_and_never_on_update() {
    let server = boot().await;
    let host = &server.host;
    declare_private_class(host, "Shared").await;

    let (a_id, a) = signup(host, "shared-owner", "pw").await;
    let (b_id, b) = signup(host, "shared-reader", "pw").await;

    // A supplies its own ACL, which suppresses the class default and lets B read.
    let created = post(
        host,
        "/classes/Shared",
        &As::user(&a),
        &json!({
            "title": "x",
            "ACL": {
                a_id.clone(): { "read": true, "write": true },
                b_id.clone(): { "read": true },
            },
        }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let object_id = created.body["objectId"].as_str().expect("objectId");
    assert_eq!(
        find_all(host, "Shared", &As::user(&b)).await.len(),
        1,
        "a client-supplied ACL must win over the class default on create"
    );

    let updated = put(
        host,
        &format!("/classes/Shared/{object_id}"),
        &As::user(&a),
        &json!({ "title": "y" }),
    )
    .await;
    assert_eq!(updated.status, 200, "{}", updated.raw);
    assert_eq!(
        find_all(host, "Shared", &As::user(&b)).await.len(),
        1,
        "the explicitly set ACL must survive an unrelated update"
    );
}

/// The public ACL is the one declaration upstream skips, because stamping
/// `{"*": {"read": true, "write": true}}` would only restate what an absent ACL already means.
#[tokio::test]
#[ignore = "needs MongoDB on 127.0.0.1:27017"]
async fn a_declared_public_acl_leaves_rows_public() {
    let server = boot().await;
    let host = &server.host;
    let created = post(
        host,
        "/schemas",
        &As::master(),
        &json!({
            "className": "Public",
            "fields": { "title": { "type": "String" } },
            "classLevelPermissions":
                clp_with_acl(json!({ "*": { "read": true, "write": true } })),
        }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);

    let (_, a) = signup(host, "public-owner", "pw").await;
    let (_, b) = signup(host, "public-stranger", "pw").await;
    let object_id = create_object(host, "Public", &a).await;

    assert_eq!(find_all(host, "Public", &As::user(&b)).await.len(), 1);
    let one = get(host, &format!("/classes/Public/{object_id}"), &As::user(&b)).await;
    assert!(
        one.body.get("ACL").is_none(),
        "no ACL columns are written, so the row has no ACL key at all: {}",
        one.raw
    );
}

/// An anonymous create has no id to substitute, and upstream's `delete` runs anyway, so the entry
/// simply goes. The resulting row has no principals: master can read it and nobody else can. That
/// is the restrictive direction and it is upstream's.
#[tokio::test]
#[ignore = "needs MongoDB on 127.0.0.1:27017"]
async fn an_anonymous_create_produces_a_row_only_master_can_read() {
    let server = boot().await;
    let host = &server.host;
    declare_private_class(host, "Orphan").await;

    let created = post(
        host,
        "/classes/Orphan",
        &As::anonymous(),
        &json!({ "title": "x" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);

    assert!(find_all(host, "Orphan", &As::anonymous()).await.is_empty());
    let (_, b) = signup(host, "orphan-stranger", "pw").await;
    assert!(find_all(host, "Orphan", &As::user(&b)).await.is_empty());
    assert_eq!(find_all(host, "Orphan", &As::master()).await.len(), 1);
}
