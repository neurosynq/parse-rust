//! The `UsersRouter` routes beyond signup and `/users/me`, the login payload, and the write-order
//! checks on `_User` and `_Installation`.
//!
//! `#[ignore]`d because they need a MongoDB. `tools/test.sh` runs them.

mod common;

use common::{delete, get, post, put, request, signup, As};
use serde_json::{json, Value};

const PASSWORD: &str = "pw";

fn sdk(mut body: Value) -> Value {
    body["_ApplicationId"] = json!(common::APP_ID);
    body["_JavaScriptKey"] = json!(common::JS_KEY);
    body
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn login_is_served_over_get_and_reads_the_query_string() {
    let server = common::boot().await;
    let host = &server.host;
    signup(host, "getter", PASSWORD).await;

    let over_get = get(
        host,
        &format!("/login?username=getter&password={PASSWORD}"),
        &As::anonymous(),
    )
    .await;
    assert_eq!(over_get.status, 200, "{}", over_get.raw);
    assert!(
        over_get.body["sessionToken"].is_string(),
        "{}",
        over_get.raw
    );

    // The JavaScript SDK's form: a POST whose body names the method.
    let sdk_get = request(
        host,
        "POST",
        "/login",
        &As::anonymous_without_keys(),
        Some(&sdk(json!({
            "_method": "GET",
            "username": "getter",
            "password": PASSWORD,
        }))),
    )
    .await;
    assert_eq!(sdk_get.status, 200, "{}", sdk_get.raw);
    assert!(sdk_get.body["sessionToken"].is_string(), "{}", sdk_get.raw);

    // A POST whose body has no username takes the query string whole.
    let from_query = post(
        host,
        &format!("/login?username=getter&password={PASSWORD}"),
        &As::anonymous(),
        &json!({}),
    )
    .await;
    assert_eq!(from_query.status, 200, "{}", from_query.raw);

    // Whole, not merged: a password in the body does not survive the switch.
    let not_merged = post(
        host,
        "/login?username=getter",
        &As::anonymous(),
        &json!({ "password": PASSWORD }),
    )
    .await;
    assert_eq!(not_merged.code(), Some(201), "{}", not_merged.raw);
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_stray_key_beside_the_credentials_does_not_fail_a_login() {
    let server = common::boot().await;
    let host = &server.host;
    signup(host, "stray", PASSWORD).await;

    let r = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({
            "username": "stray",
            "password": PASSWORD,
            "junk": { "__op": "NotAnOperation" },
        }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.raw);
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn fetching_your_own_user_row_returns_your_session_token_last() {
    let server = common::boot().await;
    let host = &server.host;
    let (me, token) = signup(host, "self_fetch", PASSWORD).await;
    let (other, other_token) = signup(host, "other_fetch", PASSWORD).await;
    // Users are private by default, so the other row is opened to public read to be fetchable.
    let opened = put(
        host,
        &format!("/users/{other}"),
        &As::user(&other_token),
        &json!({ "ACL": { "*": { "read": true } } }),
    )
    .await;
    assert_eq!(opened.status, 200, "{}", opened.raw);

    for path in [format!("/users/{me}"), format!("/classes/_User/{me}")] {
        let own = get(host, &path, &As::user(&token)).await;
        assert_eq!(own.status, 200, "{}", own.raw);
        let keys: Vec<_> = own
            .body
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            keys.last().map(String::as_str),
            Some("sessionToken"),
            "{}",
            own.raw
        );
        assert_eq!(own.body["sessionToken"], json!(token), "{}", own.raw);
    }

    let theirs = get(host, &format!("/users/{other}"), &As::user(&token)).await;
    assert_eq!(theirs.status, 200, "{}", theirs.raw);
    assert!(theirs.body.get("sessionToken").is_none(), "{}", theirs.raw);

    let as_master = get(host, &format!("/users/{me}"), &As::master()).await;
    assert!(
        as_master.body.get("sessionToken").is_none(),
        "{}",
        as_master.raw
    );
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_users_router_serves_find_get_update_and_delete() {
    let server = common::boot().await;
    let host = &server.host;
    let (me, token) = signup(host, "routed", PASSWORD).await;

    let listed = get(host, "/users", &As::master()).await;
    assert_eq!(listed.status, 200, "{}", listed.raw);
    assert!(
        listed.results().iter().any(|u| u["objectId"] == json!(me)),
        "{}",
        listed.raw
    );

    let updated = put(
        host,
        &format!("/users/{me}"),
        &As::user(&token),
        &json!({ "nickname": "r" }),
    )
    .await;
    assert_eq!(updated.status, 200, "{}", updated.raw);
    assert!(updated.body["updatedAt"].is_string(), "{}", updated.raw);

    let gone = delete(host, &format!("/users/{me}"), &As::master()).await;
    assert_eq!(gone.status, 200, "{}", gone.raw);
    let after = get(host, &format!("/users/{me}"), &As::master()).await;
    assert_eq!(after.code(), Some(101), "{}", after.raw);
}

/// The router's `role:` guard runs before the constructor's objectId policy, and the credential
/// check before the restricted-field check.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn signup_refuses_in_upstreams_order() {
    let server = common::boot().await;
    let host = &server.host;

    let role = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "objectId": "role:admin", "username": "r", "password": PASSWORD }),
    )
    .await;
    assert_eq!(role.code(), Some(119), "{}", role.raw);

    let verified = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "emailVerified": true, "password": PASSWORD }),
    )
    .await;
    assert_eq!(verified.code(), Some(200), "{}", verified.raw);
}

/// A non-owner is refused before anything reads the body as a write.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_non_owner_user_update_is_refused_before_the_body_is_decoded() {
    let server = common::boot().await;
    let host = &server.host;
    let (_, token) = signup(host, "updater", PASSWORD).await;
    let (victim, _) = signup(host, "target", PASSWORD).await;

    let r = put(
        host,
        &format!("/users/{victim}"),
        &As::user(&token),
        &json!({ "x": { "__op": "NotAnOperation" } }),
    )
    .await;
    assert_eq!(r.code(), Some(206), "{}", r.raw);
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_installation_keeps_its_ids_and_device_type() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/classes/_Installation",
        &As::master(),
        &json!({ "installationId": "abc", "deviceType": "ios", "deviceToken": "tok" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let id = created.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();
    let path = format!("/classes/_Installation/{id}");

    for (body, message) in [
        (
            json!({ "installationId": "other" }),
            "installationId may not be changed in this operation",
        ),
        (
            json!({ "deviceType": "android" }),
            "deviceType may not be changed in this operation",
        ),
        (
            json!({ "deviceType": { "__op": "Delete" } }),
            "deviceType may not be changed in this operation",
        ),
    ] {
        let r = put(host, &path, &As::master(), &body).await;
        assert_eq!(r.code(), Some(136), "{body}: {}", r.raw);
        assert_eq!(r.error(), message, "{}", r.raw);
    }

    // The same values, and anything not critical, pass.
    let same = put(
        host,
        &path,
        &As::master(),
        &json!({ "installationId": "ABC", "deviceType": "ios", "badge": 1 }),
    )
    .await;
    assert_eq!(same.status, 200, "{}", same.raw);

    let missing = put(
        host,
        "/classes/_Installation/nosuchrow",
        &As::master(),
        &json!({ "deviceType": "ios" }),
    )
    .await;
    assert_eq!(missing.code(), Some(101), "{}", missing.raw);
    assert_eq!(
        missing.error(),
        "Object not found for update.",
        "{}",
        missing.raw
    );

    // Without an installationId on either side, the device token is fixed too.
    let tokened = post(
        host,
        "/classes/_Installation",
        &As::master(),
        &json!({ "deviceType": "ios", "deviceToken": "first" }),
    )
    .await;
    let tid = tokened.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();
    let r = put(
        host,
        &format!("/classes/_Installation/{tid}"),
        &As::master(),
        &json!({ "deviceToken": "second" }),
    )
    .await;
    assert_eq!(r.code(), Some(136), "{}", r.raw);
    assert_eq!(
        r.error(),
        "deviceToken may not be changed in this operation"
    );
}
