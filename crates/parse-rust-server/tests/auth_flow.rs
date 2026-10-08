//! Signup, login, `/users/me`, logout, and the property that makes persisting sessions worth
//! doing: a token outlives the process that issued it.
//!
//! `#[ignore]`d because they need a MongoDB on 27017. `tools/test.sh` runs them.

mod common;

use common::{delete, get, post, put, signup, As};
use serde_json::json;

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn signup_login_me_logout() {
    let server = common::boot().await;
    let host = &server.host;

    let (object_id, token) = signup(host, "alice", "hunter2").await;
    assert!(
        token.starts_with("r:") && token.len() == 34,
        "a session token is `r:` plus 32 hex characters, and a client can observe it: {token}"
    );
    assert!(
        token[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase hex only, not the objectId alphabet: {token}"
    );

    let me = get(host, "/users/me", &As::user(&token)).await;
    assert_eq!(me.status, 200, "{}", me.raw);
    assert_eq!(me.body["objectId"], json!(object_id));
    assert_eq!(me.body["username"], json!("alice"));
    assert_eq!(
        me.body["sessionToken"],
        json!(token),
        "SDKs expect the token echoed back"
    );
    assert!(
        me.body.get("password").is_none() && me.body.get("_hashed_password").is_none(),
        "no form of the password may reach a response: {}",
        me.raw
    );

    let login = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "alice", "password": "hunter2" }),
    )
    .await;
    assert_eq!(login.status, 200, "{}", login.raw);
    assert_eq!(login.body["objectId"], json!(object_id));
    let login_token = login.body["sessionToken"].as_str().expect("token");
    assert_ne!(login_token, token, "login mints a new session");
    assert!(login.body.get("_hashed_password").is_none());

    let out = post(host, "/logout", &As::user(&token), &json!({})).await;
    assert_eq!(out.status, 200);

    // The revoked token is an error, not a downgrade to anonymity.
    let after = get(host, "/users/me", &As::user(&token)).await;
    assert_eq!(after.code(), Some(209), "{}", after.raw);
    // The other session is untouched: logout revokes one row, not every row for the user.
    let other = get(host, "/users/me", &As::user(login_token)).await;
    assert_eq!(other.status, 200, "{}", other.raw);
}

/// The whole point of `_Session` being rows rather than a `HashMap`.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_session_survives_a_restart() {
    let server = common::boot().await;
    let (object_id, token) = signup(&server.host, "bob", "hunter2").await;

    // A second server, sharing nothing but the database.
    let restarted = common::reboot(&server.database).await;

    let me = get(&restarted, "/users/me", &As::user(&token)).await;
    assert_eq!(
        me.status, 200,
        "a token minted by one process must be accepted by the next: {}",
        me.raw
    );
    assert_eq!(me.body["objectId"], json!(object_id));
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn login_does_not_distinguish_a_missing_user_from_a_wrong_password() {
    let server = common::boot().await;
    let host = &server.host;
    signup(host, "carol", "hunter2").await;

    for body in [
        json!({ "username": "carol", "password": "wrong" }),
        json!({ "username": "nobody", "password": "hunter2" }),
    ] {
        let r = post(host, "/login", &As::anonymous(), &body).await;
        assert_eq!(r.code(), Some(101), "{}", r.raw);
        assert_eq!(r.error(), "Invalid username/password.");
    }
}

/// A collision on each of the two indexes signup depends on, and what the body may say about it.
///
/// The codes are what an SDK branches on, so they are asserted first. The second half is the
/// assertion that matters more: the driver's own `E11000` text names the database and quotes the
/// colliding value, and none of it may reach a client. Which field collided travels beside the
/// error rather than inside its message, which is what makes that possible.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_duplicate_username_or_email_is_reported_without_disclosing_the_row() {
    let server = common::boot().await;
    let host = &server.host;
    let database = &server.database;
    signup(host, "dave", "hunter2").await;
    let with_email = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "erin", "password": "pw", "email": "erin@example.com" }),
    )
    .await;
    assert_eq!(with_email.status, 201, "{}", with_email.raw);

    // 202 rather than a bare 137, which is what the index name is contractual for.
    let same_username = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "dave", "password": "other" }),
    )
    .await;
    assert_eq!(same_username.code(), Some(202), "{}", same_username.raw);
    assert_eq!(
        same_username.error(),
        "Account already exists for this username."
    );

    let same_email = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "frank", "password": "pw", "email": "erin@example.com" }),
    )
    .await;
    assert_eq!(same_email.code(), Some(203), "{}", same_email.raw);
    assert_eq!(
        same_email.error(),
        "Account already exists for this email address."
    );

    for response in [&same_username, &same_email] {
        assert_no_storage_detail(
            &response.raw,
            database,
            &["dave", "erin@example.com", "E11000"],
        );
    }
}

/// No response may quote the database, the collection, or a stored value.
///
/// Asserted over the raw bytes rather than over a parsed field, because a leak that lands in a
/// key nobody thought to read is still a leak.
fn assert_no_storage_detail(raw: &str, database: &str, values: &[&str]) {
    assert!(
        !raw.contains(database),
        "the database name is on the wire: {raw}"
    );
    for value in values {
        assert!(!raw.contains(value), "`{value}` is on the wire: {raw}");
    }
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_unknown_token_is_an_error_rather_than_anonymity() {
    let server = common::boot().await;
    let host = &server.host;

    let r = get(
        host,
        "/classes/Post",
        &As::user("r:0123456789abcdef0123456789abcdef"),
    )
    .await;
    assert_eq!(r.code(), Some(209), "{}", r.raw);
    assert_eq!(r.error(), "Invalid session token");
}

/// `/sessions/me` and `/users/me` answer different strings for the same condition. A client
/// matching on the message would see it.
///
/// They differ twice over, and the second difference is the easy one to miss: `handleMe` builds
/// its refusal through `createSanitizedError` (`UsersRouter.js:193`), so at the default it says
/// `Permission denied`, while `SessionsRouter` does not and keeps its detailed string in both
/// regimes. Both configurations are asserted, because both are what some deployment runs.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_two_me_routes_report_a_missing_token_differently() {
    let server = common::boot().await;
    let host = &server.host;

    let users = get(host, "/users/me", &As::anonymous()).await;
    assert_eq!(users.code(), Some(209));
    assert_eq!(users.error(), "Permission denied");

    let sessions = get(host, "/sessions/me", &As::anonymous()).await;
    assert_eq!(sessions.code(), Some(209));
    assert_eq!(sessions.error(), "Session token required.");

    // With `enableSanitizedErrorResponse` off, `/users/me` names the reason and `/sessions/me`
    // is unchanged, because it never participated.
    let disclosing = {
        let mut config = parse_rust_server::ServerConfig::new(common::APP_ID, common::MASTER_KEY);
        config.enable_sanitized_error_response = false;
        common::boot_with(&server.database, config).await
    };
    let users = get(&disclosing, "/users/me", &As::anonymous()).await;
    assert_eq!(users.code(), Some(209));
    assert_eq!(users.error(), "Invalid session token");

    let sessions = get(&disclosing, "/sessions/me", &As::anonymous()).await;
    assert_eq!(sessions.code(), Some(209));
    assert_eq!(sessions.error(), "Session token required.");
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn sessions_me_returns_the_callers_own_session() {
    let server = common::boot().await;
    let host = &server.host;
    let (user_id, token) = signup(host, "erin", "hunter2").await;

    let me = get(host, "/sessions/me", &As::user(&token)).await;
    assert_eq!(me.status, 200, "{}", me.raw);
    assert_eq!(me.body["sessionToken"], json!(token));
    assert_eq!(me.body["user"]["objectId"], json!(user_id));
    assert_eq!(me.body["user"]["__type"], json!("Pointer"));
    // `expiresAt` comes back as a full Date envelope even at the top level, while `createdAt`
    // comes back as a bare ISO string. That asymmetry is upstream's and is wire-visible.
    assert_eq!(me.body["expiresAt"]["__type"], json!("Date"));
    assert!(me.body["createdAt"].is_string());
}

/// `_Session` rows carry no ACL, so without the query narrowing a non-master read would return
/// every session token on the server. This is the test that would catch that.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_session_read_is_narrowed_to_the_caller() {
    let server = common::boot().await;
    let host = &server.host;
    let (a_id, a_token) = signup(host, "frank", "hunter2").await;
    let (_b_id, b_token) = signup(host, "grace", "hunter2").await;

    // Assert first that A can see its own. A test that only checks A cannot see B's proves
    // nothing if A can see nothing at all.
    let mine = get(host, "/sessions", &As::user(&a_token)).await;
    assert_eq!(mine.status, 200, "{}", mine.raw);
    assert_eq!(mine.results().len(), 1, "{}", mine.raw);
    assert_eq!(mine.results()[0]["user"]["objectId"], json!(a_id));

    let b_session = get(host, "/sessions/me", &As::user(&b_token)).await;
    let b_object_id = b_session.body["objectId"].as_str().expect("objectId");

    let stolen = get(
        host,
        &format!("/sessions/{b_object_id}"),
        &As::user(&a_token),
    )
    .await;
    assert_eq!(
        stolen.code(),
        Some(101),
        "one user must not read another's session row: {}",
        stolen.raw
    );

    // Master sees both.
    let all = get(host, "/sessions", &As::master()).await;
    assert_eq!(all.results().len(), 2, "{}", all.raw);
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_session_can_only_be_deleted_by_its_owner() {
    let server = common::boot().await;
    let host = &server.host;
    let (_a_id, a_token) = signup(host, "heidi", "hunter2").await;
    let (_b_id, b_token) = signup(host, "ivan", "hunter2").await;

    let b_session = get(host, "/sessions/me", &As::user(&b_token)).await;
    let b_object_id = b_session.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();

    let stolen = delete(
        host,
        &format!("/sessions/{b_object_id}"),
        &As::user(&a_token),
    )
    .await;
    assert_eq!(stolen.code(), Some(101), "{}", stolen.raw);
    assert_eq!(stolen.error(), "Object not found for delete.");

    // B's session still works, which is what proves the delete did not happen.
    assert_eq!(
        get(host, "/users/me", &As::user(&b_token)).await.status,
        200
    );

    let own = delete(
        host,
        &format!("/sessions/{b_object_id}"),
        &As::user(&b_token),
    )
    .await;
    assert_eq!(own.status, 200, "{}", own.raw);
    assert_eq!(
        get(host, "/users/me", &As::user(&b_token)).await.code(),
        Some(209)
    );
}

/// The master-only class list has to survive `include` too, for the same reason.
///
/// `enforceRoleSecurity` is called from the `RestQuery` constructor (`RestQuery.js:54`) as well as
/// from the `rest.js` entry points, and the include path builds a `RestQuery`
/// (`RestQuery.js:1250-1258`), so upstream checks the included class. parse-rust had this at the
/// router until 0.2.0.
///
/// Inert today, because none of the classes on that list exist yet. It stops being inert when
/// `_PushStatus` and `_Hooks` land, and `_GlobalConfig`'s objectId is the literal `1`, which
/// removes even the guessing step.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_included_master_only_class_is_refused() {
    let server = common::boot().await;
    let host = &server.host;
    let (_id, token) = signup(host, "peggy", "hunter2").await;

    let created = post(
        host,
        "/classes/Probe",
        &As::user(&token),
        &json!({
            "tag": "probe",
            "cfg": { "__type": "Pointer", "className": "_GlobalConfig", "objectId": "1" }
        }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);

    // Without the include the read is fine: the pointer is just a value.
    let plain = get(
        host,
        &format!(
            "/classes/Probe{}",
            common::where_query(json!({ "tag": "probe" }))
        ),
        &As::user(&token),
    )
    .await;
    assert_eq!(plain.status, 200, "{}", plain.raw);

    // With it, the nested read addresses a master-only class and is refused.
    let expanded = get(
        host,
        &format!(
            "/classes/Probe{}&include=cfg",
            common::where_query(json!({ "tag": "probe" }))
        ),
        &As::user(&token),
    )
    .await;
    // 400, not 403: upstream's status mapping sends nearly every `Parse.Error` out as 400 and the
    // code is what a client reads. The other `OPERATION_FORBIDDEN` assertions in this suite agree.
    assert_eq!(expanded.status, 400, "{}", expanded.raw);
    assert_eq!(expanded.body["code"], json!(119), "{}", expanded.raw);
}

/// `_Installation` is refused for `find` and allowed for `get`, so the include path has to pick
/// the method the way upstream does: `get` for one collected id, `find` for several
/// (`RestQuery.js:1250-1251`).
///
/// Deriving the method from the query shape instead makes every include a `get` and hands a client
/// the whole installation collection a page at a time. The CLP operation is a separate question
/// and stays `get` for both halves of this test (`RestQuery.js:1259`).
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_multi_object_include_of_installations_is_refused_and_a_single_one_is_not() {
    let server = common::boot().await;
    let host = &server.host;
    let (_id, token) = signup(host, "quinn", "hunter2").await;

    let probe = |tag: &str, installation: &str| {
        json!({
            "tag": tag,
            "inst": {
                "__type": "Pointer",
                "className": "_Installation",
                "objectId": installation
            }
        })
    };
    for (tag, installation) in [("one", "iAAAAAAAAA"), ("two", "iBBBBBBBBB")] {
        let created = post(
            host,
            "/classes/Probe",
            &As::user(&token),
            &probe(tag, installation),
        )
        .await;
        assert_eq!(created.status, 201, "{}", created.raw);
    }

    // One row means one collected id, so the nested read is a `get` and survives.
    let single = get(
        host,
        &format!(
            "/classes/Probe{}&include=inst",
            common::where_query(json!({ "tag": "one" }))
        ),
        &As::user(&token),
    )
    .await;
    assert_eq!(single.status, 200, "{}", single.raw);

    // Both rows mean two collected ids, so the nested read is a `find` and is refused.
    let many = get(
        host,
        &format!(
            "/classes/Probe{}&include=inst",
            common::where_query(json!({ "tag": { "$in": ["one", "two"] } }))
        ),
        &As::user(&token),
    )
    .await;
    assert_eq!(many.status, 400, "{}", many.raw);
    assert_eq!(many.body["code"], json!(119), "{}", many.raw);
}

/// The same split at the top level: a `find` request stays a `find` however narrow its `where` is.
///
/// `rest.js:136` names the method literally rather than deriving it, so pinning one objectId in a
/// `where` narrows what the CLP is asked about (`DatabaseController.js:1413-1414`) and changes
/// nothing about `enforceRoleSecurity`.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_pinned_where_does_not_turn_a_find_on_installations_into_a_get() {
    let server = common::boot().await;
    let host = &server.host;
    let (_id, token) = signup(host, "rhea", "hunter2").await;

    let pinned = get(
        host,
        &format!(
            "/classes/_Installation{}",
            common::where_query(json!({ "objectId": "iAAAAAAAAA" }))
        ),
        &As::user(&token),
    )
    .await;
    assert_eq!(pinned.status, 400, "{}", pinned.raw);
    assert_eq!(pinned.body["code"], json!(119), "{}", pinned.raw);

    // The `get` route is the one clients may use, and it is unaffected.
    let by_id = get(host, "/classes/_Installation/iAAAAAAAAA", &As::user(&token)).await;
    assert_eq!(by_id.body["code"], json!(101), "{}", by_id.raw);
}

/// The narrowing has to survive `include`, which is a nested read that never touches the router.
///
/// `_Session` rows carry no ACL, `filterSensitiveData` strips `sessionToken` only on `_User`, and
/// `_session_token` un-prefixes back to `sessionToken` on the way out. So a nested read of another
/// user's session row hands over a live token, and the objectId is the only thing the attacker
/// needs. Upstream narrows in the query constructor (`RestQuery.js:115-134`) and the include path
/// builds a real query (`RestQuery.js:1250-1258`), so it is narrowed there too.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_included_session_is_narrowed_to_the_caller() {
    let server = common::boot().await;
    let host = &server.host;
    let (_a_id, a_token) = signup(host, "mallory", "hunter2").await;
    let (_b_id, b_token) = signup(host, "trent", "hunter2").await;

    let a_session = get(host, "/sessions/me", &As::user(&a_token)).await;
    let a_object_id = a_session.body["objectId"].as_str().expect("objectId");
    let b_session = get(host, "/sessions/me", &As::user(&b_token)).await;
    let b_object_id = b_session.body["objectId"].as_str().expect("objectId");
    let b_session_token = b_session.body["sessionToken"]
        .as_str()
        .expect("sessionToken")
        .to_string();

    let pointer = |object_id: &str| json!({ "__type": "Pointer", "className": "_Session", "objectId": object_id });

    // Assert first that the include resolves at all for this caller. Without this, "the row came
    // back empty" would pass just as well against an include that never runs.
    let own = post(
        host,
        "/classes/Leak",
        &As::user(&a_token),
        &json!({ "tag": "own", "s": pointer(a_object_id) }),
    )
    .await;
    assert_eq!(own.status, 201, "{}", own.raw);
    let mine = get(
        host,
        &format!(
            "/classes/Leak{}&include=s",
            common::where_query(json!({ "tag": "own" }))
        ),
        &As::user(&a_token),
    )
    .await;
    assert_eq!(mine.status, 200, "{}", mine.raw);
    assert_eq!(
        mine.results()[0]["s"]["objectId"],
        json!(a_object_id),
        "the caller's own session must resolve, or the negative case below proves nothing: {}",
        mine.raw
    );

    let stolen = post(
        host,
        "/classes/Leak",
        &As::user(&a_token),
        &json!({ "tag": "stolen", "s": pointer(b_object_id) }),
    )
    .await;
    assert_eq!(stolen.status, 201, "{}", stolen.raw);
    let leaked = get(
        host,
        &format!(
            "/classes/Leak{}&include=s",
            common::where_query(json!({ "tag": "stolen" }))
        ),
        &As::user(&a_token),
    )
    .await;
    assert_eq!(leaked.status, 200, "{}", leaked.raw);
    assert!(
        !leaked.raw.contains(&b_session_token),
        "an included `_Session` handed over another user's session token: {}",
        leaked.raw
    );
    assert!(
        leaked.results()[0].get("s").is_none(),
        "an unresolved include leaves the key absent: {}",
        leaked.raw
    );

    // The token really is live, so the assertion above is about a usable credential rather than a
    // string that happens not to appear.
    assert_eq!(
        get(host, "/users/me", &As::user(&b_session_token))
            .await
            .status,
        200
    );
}

/// The out-of-scope session routes are absent rather than answering 501.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_excluded_session_routes_are_404() {
    let server = common::boot().await;
    let host = &server.host;
    let (_id, token) = signup(host, "judy", "hunter2").await;

    for (method, path) in [
        ("POST", "/sessions"),
        ("PUT", "/sessions/abc123"),
        ("POST", "/upgradeToRevocableSession"),
    ] {
        let r = match method {
            "POST" => post(host, path, &As::user(&token), &json!({})).await,
            _ => put(host, path, &As::user(&token), &json!({})).await,
        };
        assert!(
            r.status == 404 || r.status == 405,
            "{method} {path} must not be served, got {}: {}",
            r.status,
            r.raw
        );
    }
}

/// An expired or otherwise dead session token attached to `/login` is ignored, not validated.
///
/// Upstream deletes `info.sessionToken` for `/login` before any `Auth` is built
/// (`middlewares.js:267-268`). Without that, the generic resolver refuses the request on the stale
/// token before it ever reads the credentials in the body, so the client's only route back to a
/// working session is the one route that is failing. SDKs keep sending the stored token until a
/// login succeeds, which makes it stick rather than resolve.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_dead_session_token_does_not_block_a_login() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "relogin", "password": "pw" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let token = created.body["sessionToken"]
        .as_str()
        .expect("token")
        .to_string();

    // Kill the session the way an expiry would: the row is gone, the client still holds the string.
    let out = post(host, "/logout", &As::user(&token), &json!({})).await;
    assert_eq!(out.status, 200, "{}", out.raw);

    // Confirm the token really is dead, so the test below is not passing for a trivial reason.
    let me = get(host, "/users/me", &As::user(&token)).await;
    assert_eq!(me.code(), Some(209), "the token must be dead: {}", me.raw);

    let again = post(
        host,
        "/login",
        &As::user(&token),
        &json!({ "username": "relogin", "password": "pw" }),
    )
    .await;
    assert_eq!(
        again.status, 200,
        "a dead token attached to /login must be discarded, not validated: {}",
        again.raw
    );
    assert!(again.body["sessionToken"].is_string(), "{}", again.raw);
    assert_ne!(
        again.body["sessionToken"].as_str().expect("token"),
        token,
        "a fresh session, not the dead one"
    );
}

/// The status an unserved method produces: Express's 404, on every path.
///
/// Every route takes any method and dispatches on the effective one, the `_method` override
/// included, so a method a path does not serve finds no arm and is a 404, as an Express router
/// answers it. It used to be 405 for a method axum had no arm for.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_unserved_method_is_404() {
    let server = common::boot().await;
    let host = &server.host;

    for path in ["/sessions", "/users/me"] {
        let r = post(host, path, &As::master(), &json!({})).await;
        assert_eq!(r.status, 404, "POST {path}: {}", r.raw);
    }
    for path in ["/sessions", "/login", "/serverInfo"] {
        let r = put(host, path, &As::master(), &json!({})).await;
        assert_eq!(r.status, 404, "PUT {path}: {}", r.raw);
    }
    // An unknown path is 404 whatever the method.
    let r = get(host, "/nonesuch", &As::master()).await;
    assert_eq!(r.status, 404, "{}", r.raw);
}

/// `user.save()` on an existing user, which is what every SDK compiles an ordinary profile edit to.
///
/// The SDK sends `PUT /classes/_User/:objectId`, not `/users/:objectId`. That was refused for every
/// non-master caller, so a logged-in user could not change their own display name, let alone their
/// password. The refusal was fail-closed over `transformUser`, but the stages an *update* needs do
/// exist: the password is hashed, reserved keys are refused, username and email uniqueness is
/// checked case-insensitively under upstream's collation, and
/// the row's ACL already restricts it to its owner.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_user_can_save_their_own_row() {
    let server = common::boot().await;
    let host = &server.host;

    let (object_id, token) = signup(host, "saver", "pw").await;

    let saved = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "nickname": "Sav" }),
    )
    .await;
    assert_eq!(
        saved.status, 200,
        "a user may save their own row: {}",
        saved.raw
    );

    let me = get(host, "/users/me", &As::user(&token)).await;
    assert_eq!(me.body["nickname"], json!("Sav"), "{}", me.raw);

    // Another user's row is still refused, by the ACL rather than by the class guard, and reported
    // as a missing session the way `handleSessionMissingError` reports it (`rest.js:320-331`):
    // 206, not the 101 the write itself produced.
    let (other_id, _) = signup(host, "other", "pw").await;
    let intruder = put(
        host,
        &format!("/classes/_User/{other_id}"),
        &As::user(&token),
        &json!({ "nickname": "hacked" }),
    )
    .await;
    assert_eq!(
        intruder.code(),
        Some(206),
        "one user may not save another's row: {}",
        intruder.raw
    );
}

/// A password change through `user.save()` revokes every session and issues a replacement.
///
/// `RestWrite.js:1284-1303`. Both halves matter: revoking is what makes changing a password mean
/// anything, and the new token is what stops the caller logging themselves out by changing their
/// own password.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn changing_a_password_revokes_sessions_and_issues_a_new_token() {
    let server = common::boot().await;
    let host = &server.host;

    let (object_id, first) = signup(host, "changer", "old-pw").await;
    // A second session, so "every session" has something to prove.
    let second = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "changer", "password": "old-pw" }),
    )
    .await;
    let second_token = second.body["sessionToken"]
        .as_str()
        .expect("token")
        .to_string();

    let changed = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&first),
        &json!({ "password": "new-pw" }),
    )
    .await;
    assert_eq!(changed.status, 200, "{}", changed.raw);
    let replacement = changed.body["sessionToken"]
        .as_str()
        .expect("a replacement token is issued")
        .to_string();
    assert_ne!(replacement, first, "a new session, not the old one");

    // Both old tokens are dead.
    for dead in [&first, &second_token] {
        let r = get(host, "/users/me", &As::user(dead)).await;
        assert_eq!(
            r.code(),
            Some(209),
            "an old token must be revoked: {}",
            r.raw
        );
    }
    // The replacement works.
    let alive = get(host, "/users/me", &As::user(&replacement)).await;
    assert_eq!(alive.status, 200, "{}", alive.raw);

    // The new password is the one that logs in, and the hash never reaches a response.
    let old = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "changer", "password": "old-pw" }),
    )
    .await;
    assert_eq!(old.code(), Some(101), "{}", old.raw);
    let new = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "changer", "password": "new-pw" }),
    )
    .await;
    assert_eq!(new.status, 200, "{}", new.raw);
    assert!(changed.raw.find("_hashed_password").is_none());
}

/// A username collision through `user.save()` reports 202, not a raw duplicate-key error.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn saving_a_taken_username_reports_the_parse_code() {
    let server = common::boot().await;
    let host = &server.host;

    signup(host, "taken", "pw").await;
    let (object_id, token) = signup(host, "mover", "pw").await;

    let clash = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "username": "taken" }),
    )
    .await;
    assert_eq!(clash.code(), Some(202), "{}", clash.raw);
    assert_eq!(clash.error(), "Account already exists for this username.");
    assert!(
        !clash.raw.contains("E11000") && !clash.raw.contains(&server.database),
        "no driver detail on the wire: {}",
        clash.raw
    );
}

/// Create and delete through `/classes/_User` stay refused for a non-master caller.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn creating_or_deleting_a_user_through_classes_is_still_refused() {
    let server = common::boot().await;
    let host = &server.host;
    let (object_id, token) = signup(host, "fixed", "pw").await;

    let created = post(
        host,
        "/classes/_User",
        &As::user(&token),
        &json!({ "username": "sneaky", "password": "pw" }),
    )
    .await;
    assert_eq!(created.code(), Some(119), "{}", created.raw);

    let deleted = delete(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
    )
    .await;
    assert_eq!(deleted.code(), Some(119), "{}", deleted.raw);
}

/// The takeover this route opened, and the guard that closes it.
///
/// `enforce_class_security` asks whether a class is writable, not whether the caller is anybody.
/// A `_User` row whose ACL grants public write was therefore updatable by an anonymous request,
/// and because a password change mints a replacement session, an anonymous caller could take the
/// account. Upstream refuses an unauthenticated `_User` update before the ACL is consulted
/// (`RestWrite.js:1711-1715`).
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_unauthenticated_user_update_is_refused_even_with_a_public_write_acl() {
    let server = common::boot().await;
    let host = &server.host;
    let (object_id, _) = signup(host, "victim", "pw").await;

    let opened = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::master(),
        &json!({ "ACL": { "*": { "read": true, "write": true } } }),
    )
    .await;
    assert_eq!(opened.status, 200, "{}", opened.raw);

    let taken = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::anonymous(),
        &json!({ "password": "hacked" }),
    )
    .await;
    assert_eq!(taken.code(), Some(206), "{}", taken.raw);
    assert!(
        taken.body.get("sessionToken").is_none(),
        "no session may be issued to an anonymous caller: {}",
        taken.raw
    );

    // The old password still works, so nothing was changed on the way to being refused.
    let still = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "victim", "password": "pw" }),
    )
    .await;
    assert_eq!(still.status, 200, "{}", still.raw);
}

/// Server-controlled `_User` columns are not ordinary fields.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn server_controlled_user_fields_are_refused() {
    let server = common::boot().await;
    let host = &server.host;
    let (object_id, token) = signup(host, "controlled", "pw").await;

    for body in [
        json!({ "emailVerified": true }),
        json!({ "authData": { "custom": { "id": "1" } } }),
    ] {
        let r = put(
            host,
            &format!("/classes/_User/{object_id}"),
            &As::user(&token),
            &body,
        )
        .await;
        assert_eq!(r.code(), Some(119), "{body} must be refused: {}", r.raw);
    }

    // A submitted ACL keeps the owner's entry, so a user cannot lock itself out of its own row.
    let acl = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "ACL": { "*": { "read": true } } }),
    )
    .await;
    assert_eq!(acl.status, 200, "{}", acl.raw);
    let me = get(host, "/users/me", &As::user(&token)).await;
    assert_eq!(
        me.body["ACL"][&object_id],
        json!({ "read": true, "write": true }),
        "the owner entry is forced back in: {}",
        me.raw
    );
}

/// Username and email uniqueness is case-insensitive, and an email must look like one.
///
/// The `username_1` and `email_1` indexes compare case-sensitively, so `CaseOnly` and `caseonly`
/// are two different keys to MongoDB and both would be stored. Upstream refuses the second with
/// 202, through a case-insensitive query rather than through the index.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn user_identity_is_validated_case_insensitively() {
    let server = common::boot().await;
    let host = &server.host;
    signup(host, "CaseOnly", "pw").await;
    let (object_id, token) = signup(host, "mover2", "pw").await;

    let case = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "username": "caseonly" }),
    )
    .await;
    assert_eq!(case.code(), Some(202), "{}", case.raw);

    let bad_email = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "email": "not-an-email" }),
    )
    .await;
    assert_eq!(bad_email.code(), Some(125), "{}", bad_email.raw);
    assert_eq!(bad_email.error(), "Email address format is invalid.");

    // Saving a row with its own username unchanged must not collide with itself.
    let self_save = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "username": "mover2", "email": "m@example.com" }),
    )
    .await;
    assert_eq!(self_save.status, 200, "{}", self_save.raw);
}

/// `password: null` reported a change it did not make.
///
/// It read as "no password" to the hasher and as "a password change" to the followup, so it
/// revoked every session and issued a replacement while leaving the old password working. A false
/// report of a security-relevant change is worse than either outcome alone.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_non_string_password_is_refused_and_changes_nothing() {
    let server = common::boot().await;
    let host = &server.host;
    let (object_id, token) = signup(host, "nuller", "pw").await;

    // 201 `password is required` for every present non-string and for the empty string, as of
    // 9.10.3 (`RestWrite.js:528-538`). Before it, upstream crashed into a 500 on these and parse-rust
    // answered 111.
    for bad in [
        json!(null),
        json!(7),
        json!(true),
        json!({"a": 1}),
        json!(""),
    ] {
        let r = put(
            host,
            &format!("/classes/_User/{object_id}"),
            &As::user(&token),
            &json!({ "password": bad }),
        )
        .await;
        assert_eq!(r.code(), Some(201), "{bad}: {}", r.raw);
        assert_eq!(r.error(), "password is required", "{bad}");
        assert!(r.body.get("sessionToken").is_none(), "{}", r.raw);
    }

    // The session survived and the old password still works.
    let me = get(host, "/users/me", &As::user(&token)).await;
    assert_eq!(me.status, 200, "no session was revoked: {}", me.raw);
    let login = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "nuller", "password": "pw" }),
    )
    .await;
    assert_eq!(login.status, 200, "{}", login.raw);
}

/// The replacement session carries no `createdWith`, and the relabelling is `_User` only.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_replacement_session_has_no_created_with() {
    let server = common::boot().await;
    let host = &server.host;
    let (object_id, token) = signup(host, "meta", "pw").await;

    let changed = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "password": "new-pw" }),
    )
    .await;
    assert_eq!(changed.status, 200, "{}", changed.raw);
    let replacement = changed.body["sessionToken"].as_str().expect("token");

    let me = get(host, "/sessions/me", &As::user(replacement)).await;
    assert_eq!(me.status, 200, "{}", me.raw);
    assert!(
        me.body.get("createdWith").is_none(),
        "a password-update session describes no action: {}",
        me.raw
    );
}

/// A duplicate-key collision on an ordinary class is not relabelled as a user error.
///
/// The first version of this test proved nothing: the schema API creates non-unique indexes, so
/// the second insert simply succeeded, and asserting "not 202" passes for a successful write. The
/// index has to actually be unique, and the request has to be an **update**, because `update_core`
/// is where the relabelling lives.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_non_user_duplicate_is_not_relabelled_as_a_username_error() {
    let server = common::boot().await;
    let host = &server.host;

    let first = post(
        host,
        "/classes/Member",
        &As::master(),
        &json!({ "username": "one" }),
    )
    .await;
    assert_eq!(first.status, 201, "{}", first.raw);
    let second = post(
        host,
        "/classes/Member",
        &As::master(),
        &json!({ "username": "two" }),
    )
    .await;
    assert_eq!(second.status, 201, "{}", second.raw);
    let second_id = second.body["objectId"].as_str().expect("objectId");

    // A unique index on an ordinary class whose auto-generated name is `username_1`, which is
    // exactly the name the `duplicated_field` regex reads. Created directly, because the schema
    // API's `indexes` block builds non-unique indexes.
    common::create_unique_index(&server.database, "Member", "username").await;

    // Now collide, through the route that carries the relabelling.
    let clash = put(
        host,
        &format!("/classes/Member/{second_id}"),
        &As::master(),
        &json!({ "username": "one" }),
    )
    .await;
    assert_eq!(
        clash.code(),
        Some(137),
        "an ordinary class's collision stays DUPLICATE_VALUE: {}",
        clash.raw
    );
    assert_ne!(
        clash.error(),
        "Account already exists for this username.",
        "and is never reported as a user error: {}",
        clash.raw
    );

    // The same collision on `_User` is relabelled, which is what makes the gating meaningful.
    signup(host, "taken_u", "pw").await;
    let (mover, token) = signup(host, "mover_u", "pw").await;
    let user_clash = put(
        host,
        &format!("/classes/_User/{mover}"),
        &As::user(&token),
        &json!({ "username": "taken_u" }),
    )
    .await;
    assert_eq!(user_clash.code(), Some(202), "{}", user_clash.raw);
}

/// Signup runs the same identity validation an update does.
///
/// `transformUser` is one function and does not branch on create versus update for these checks
/// (`RestWrite.js:895-899`). Validating on the update path alone left signup admitting exactly the
/// identities the update path refuses.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn signup_validates_identity_the_same_way_an_update_does() {
    let server = common::boot().await;
    let host = &server.host;
    signup(host, "SignupCase", "pw").await;

    let case_dupe = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "signupcase", "password": "pw" }),
    )
    .await;
    assert_eq!(
        case_dupe.code(),
        Some(202),
        "a case-only duplicate must not sign up: {}",
        case_dupe.raw
    );

    let bad_email = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "fresh", "password": "pw", "email": "not-an-email" }),
    )
    .await;
    assert_eq!(bad_email.code(), Some(125), "{}", bad_email.raw);
}

/// Master replaces an ACL exactly; only a client gets the owner entry forced back.
///
/// Forcing it unconditionally means an operator cannot revoke a user's access to their own row,
/// which is a legitimate administrative action.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn master_can_replace_a_user_acl_without_the_owner_being_re_added() {
    let server = common::boot().await;
    let host = &server.host;
    let (object_id, token) = signup(host, "revokable", "pw").await;

    let replaced = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::master(),
        &json!({ "ACL": { "*": { "read": true } } }),
    )
    .await;
    assert_eq!(replaced.status, 200, "{}", replaced.raw);

    let seen = get(host, &format!("/classes/_User/{object_id}"), &As::master()).await;
    assert!(
        seen.body["ACL"].get(&object_id).is_none(),
        "a master ACL is stored exactly as written: {}",
        seen.raw
    );

    // And the same write from the owner still keeps their entry.
    let (other_id, other_token) = signup(host, "keeper", "pw").await;
    let by_owner = put(
        host,
        &format!("/classes/_User/{other_id}"),
        &As::user(&other_token),
        &json!({ "ACL": { "*": { "read": true } } }),
    )
    .await;
    assert_eq!(by_owner.status, 200, "{}", by_owner.raw);
    let owned = get(host, &format!("/classes/_User/{other_id}"), &As::master()).await;
    assert_eq!(
        owned.body["ACL"][&other_id],
        json!({ "read": true, "write": true }),
        "a client's ACL keeps the owner entry: {}",
        owned.raw
    );
    let _ = token;
}

/// Email validation matches upstream's laxness, and username is checked first.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn email_validation_matches_upstreams_regex_and_ordering() {
    let server = common::boot().await;
    let host = &server.host;
    let (object_id, token) = signup(host, "emails", "pw").await;

    // `""` is falsy upstream, so it is skipped rather than rejected. `"@a@b"` matches `/^.+@.+$/`
    // through its *last* `@`, so it is accepted too. Both answer 200 upstream.
    for accepted in [json!(""), json!("@a@b")] {
        let r = put(
            host,
            &format!("/classes/_User/{object_id}"),
            &As::user(&token),
            &json!({ "email": accepted }),
        )
        .await;
        assert_eq!(r.status, 200, "{accepted} is accepted upstream: {}", r.raw);
    }

    for rejected in [json!("not-an-email"), json!("a@"), json!("@a")] {
        let r = put(
            host,
            &format!("/classes/_User/{object_id}"),
            &As::user(&token),
            &json!({ "email": rejected }),
        )
        .await;
        assert_eq!(r.code(), Some(125), "{rejected}: {}", r.raw);
    }

    // Username is validated before email, so a body with both problems reports the username.
    signup(host, "OrderCase", "pw").await;
    let both = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "username": "ordercase", "email": "not-an-email" }),
    )
    .await;
    assert_eq!(
        both.code(),
        Some(202),
        "username is checked first: {}",
        both.raw
    );
}

/// The detailed messages are upstream's, which is contract when sanitizing is off.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn user_update_refusals_carry_upstreams_detailed_messages() {
    let server = common::boot_fresh_with(|mut c| {
        c.enable_sanitized_error_response = false;
        c
    })
    .await;
    let host = &server.host;
    let (object_id, token) = signup(host, "messages", "pw").await;

    put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::master(),
        &json!({ "ACL": { "*": { "read": true, "write": true } } }),
    )
    .await;

    let anon = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::anonymous(),
        &json!({ "nickname": "x" }),
    )
    .await;
    assert_eq!(anon.code(), Some(206), "{}", anon.raw);
    assert_eq!(anon.error(), format!("Cannot modify user {object_id}."));

    let verified = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "emailVerified": true }),
    )
    .await;
    assert_eq!(verified.code(), Some(119), "{}", verified.raw);
    assert_eq!(
        verified.error(),
        "Clients aren't allowed to manually update email verification.",
        "the noun is upstream's, not the column name"
    );
}

/// The Unicode case a case-folding regex admits and a collation does not.
///
/// Stored `Café` (precomposed) against submitted `Cafe` plus a combining acute (decomposed). A
/// collation at strength 2 normalizes, so they are one key; a regex compares code points, so they
/// are two. The regex version of this check therefore admitted identities upstream treats as
/// duplicates, which is the wrong direction for a uniqueness check.
///
/// Both spellings carry the same accent. Strength 2 keeps diacritics significant, so this is a
/// normalization test and not a claim that `Café` and `Cafe` collide.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn uniqueness_folds_unicode_normalization_not_just_case() {
    let server = common::boot().await;
    let host = &server.host;

    let precomposed = "Caf\u{e9}";
    let decomposed = "Cafe\u{301}";
    assert_ne!(precomposed, decomposed, "the two spellings differ by bytes");

    signup(host, precomposed, "pw").await;
    let clash = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": decomposed, "password": "pw" }),
    )
    .await;
    assert_eq!(
        clash.code(),
        Some(202),
        "a decomposed spelling is the same identity: {}",
        clash.raw
    );
}

/// `checkRestrictedFields` covers create as well as update upstream (`RestWrite.js:119`), and
/// applying it only to the update path left signup able to set both fields on its own new row.
///
/// `emailVerified` is upstream's restriction verbatim. `authData` is parse-rust's addition, because
/// upstream validates a provider block against the configured auth adapter rather than refusing it,
/// and there is no adapter host here to validate against; storing it unvalidated would let a client
/// write a third-party identity a later login could match on.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn signup_cannot_set_email_verification_or_auth_data() {
    let server = common::boot().await;
    let host = &server.host;

    for (field, value) in [
        ("emailVerified", json!(true)),
        ("authData", json!({"custom": {"id": "someone-elses"}})),
    ] {
        let response = post(
            host,
            "/users",
            &As::anonymous(),
            &json!({ "username": format!("u_{field}"), "password": "pw", field: value }),
        )
        .await;
        assert_eq!(
            response.code(),
            Some(119),
            "signup must refuse a client-set {field}: {}",
            response.raw
        );
    }

    // The control: the same signup without either field still works, so the refusal above is the
    // field and not the request shape.
    let ok = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "u_control", "password": "pw" }),
    )
    .await;
    assert_eq!(ok.status, 201, "{}", ok.raw);
}

/// Logging in with an email address, which is what `Parse.User.logIn(email, password)` sends in
/// every SDK. Upstream matches an identifier against `username` **or** `email`
/// (`UsersRouter.js:99-107`); matching `username` alone answered `Invalid username/password.` for a
/// correct email and password, and an `email` key was not read at all.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn login_accepts_an_email_address_as_the_identifier() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "ada", "password": "pw", "email": "ada@example.com" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);

    // The identifier in the `username` slot, which is what the SDK does.
    let by_email = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "ada@example.com", "password": "pw" }),
    )
    .await;
    assert_eq!(by_email.status, 200, "{}", by_email.raw);
    assert_eq!(by_email.body["username"], "ada");

    // The identifier in its own `email` key, which a REST client may send.
    let email_key = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "email": "ada@example.com", "password": "pw" }),
    )
    .await;
    assert_eq!(email_key.status, 200, "{}", email_key.raw);

    // The control: the username still works, and a wrong password still fails whichever
    // identifier was used.
    let by_username = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "ada", "password": "pw" }),
    )
    .await;
    assert_eq!(by_username.status, 200, "{}", by_username.raw);

    let wrong = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "ada@example.com", "password": "nope" }),
    )
    .await;
    assert_eq!(wrong.code(), Some(101), "{}", wrong.raw);

    // A mismatched pair is an AND upstream, so it is not a login.
    let mismatched = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "ada", "email": "someone@else.example", "password": "pw" }),
    )
    .await;
    assert_eq!(mismatched.code(), Some(101), "{}", mismatched.raw);
}

/// The three login refusals, each with its own code (`UsersRouter.js:84-96`). They had been
/// collapsed into `USERNAME_MISSING`, so a client that omitted its password and one that sent a
/// non-string password both got told the username was missing.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn login_reports_which_credential_was_wrong() {
    let server = common::boot().await;
    let host = &server.host;
    signup(host, "grace", "pw").await;

    for (body, code, label) in [
        (json!({ "password": "pw" }), 200, "no identifier"),
        (
            json!({ "username": "", "password": "pw" }),
            200,
            "empty identifier",
        ),
        (json!({ "username": "grace" }), 201, "no password"),
        (
            json!({ "username": "grace", "password": "" }),
            201,
            "empty password",
        ),
        (
            json!({ "username": "grace", "password": 7 }),
            101,
            "non-string password",
        ),
        (
            json!({ "username": 7, "password": "pw" }),
            101,
            "non-string identifier",
        ),
    ] {
        let response = post(host, "/login", &As::anonymous(), &body).await;
        assert_eq!(response.code(), Some(code), "{label}: {}", response.raw);
    }
}

/// An explicitly empty ACL disables the account for login.
///
/// `UsersRouter.js:151-153`. A master setting `ACL: {}` is the documented way to lock a user out.
/// Without the check the password still works and the account still receives a session, so the
/// lock does nothing until the user's existing sessions are separately destroyed.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_empty_acl_disables_login() {
    let server = common::boot().await;
    let host = &server.host;
    let (object_id, _) = signup(host, "disabled", "pw").await;

    // Sanity: the account logs in before it is disabled.
    let before = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "disabled", "password": "pw" }),
    )
    .await;
    assert_eq!(before.status, 200, "{}", before.raw);

    let locked = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::master(),
        &json!({ "ACL": {} }),
    )
    .await;
    assert_eq!(locked.status, 200, "{}", locked.raw);

    let after = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "disabled", "password": "pw" }),
    )
    .await;
    assert_eq!(
        after.code(),
        Some(101),
        "a disabled account must not log in: {}",
        after.raw
    );
    assert!(
        after.body.get("sessionToken").is_none(),
        "and must not receive a session: {}",
        after.raw
    );
}

/// An email that equals another user's username resolves to the username match.
///
/// Upstream queries without a limit and prefers the exact username (`UsersRouter.js:108-124`).
/// Capping at one row makes the winner whichever row the database returns first, which can reject
/// a valid login or authenticate the wrong account when the passwords coincide.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_username_wins_over_another_users_matching_email() {
    let server = common::boot().await;
    let host = &server.host;

    // **The colliding row is created first, and the order is the test.** With the
    // username-owning row inserted first, a `limit: 1` query can return it by accident and the
    // test passes against the implementation it is supposed to catch. Inserting the email-owning
    // row first means the naive query returns the wrong account, so only the exact-username
    // preference can satisfy the assertion below.
    let other = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "other_user", "password": "wrong-pw", "email": "collide@example.com" }),
    )
    .await;
    assert_eq!(other.status, 201, "{}", other.raw);
    let other_id = other.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();
    let (target_id, _) = signup(host, "collide@example.com", "right-pw").await;
    assert_ne!(target_id, other_id);

    let logged_in = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "collide@example.com", "password": "right-pw" }),
    )
    .await;
    assert_eq!(logged_in.status, 200, "{}", logged_in.raw);
    assert_eq!(
        logged_in.body["objectId"],
        json!(target_id),
        "the exact username match wins, not whichever row the database returned first: {}",
        logged_in.raw
    );
}

/// A non-master read of an absent class is refused when clients may not create classes.
///
/// `RestQuery.js:485-500`. Answering an empty result instead tells a client that cannot create
/// classes that the class merely has no rows.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_read_of_an_absent_class_is_refused_when_client_class_creation_is_off() {
    // The harness baseline turns the option on so ordinary tests can create classes. This one is
    // about the shipped default, so it turns it back off.
    let server = common::boot_fresh_with(|mut c| {
        c.allow_client_class_creation = false;
        c
    })
    .await;
    let host = &server.host;
    let (_id, token) = signup(host, "reader", "pw").await;

    let read = get(host, "/classes/NoSuchClass", &As::user(&token)).await;
    assert_eq!(read.code(), Some(119), "{}", read.raw);

    // Master still reads it as empty, and a system class is always allowed.
    let as_master = get(host, "/classes/NoSuchClass", &As::master()).await;
    assert_eq!(as_master.status, 200, "{}", as_master.raw);
    assert_eq!(as_master.body["results"], json!([]));

    // **Maintenance is not master here.** The write path exempts both
    // (`RestWrite.js:206-208`); the read path exempts master alone (`RestQuery.js:486-489`). The
    // two share one predicate in parse-rust, and `AclScope::Unrestricted` covers both keys, so
    // maintenance silently inherited the write path's exemption until this case was written. The
    // earlier version of this test checked a user and master and omitted maintenance, which is
    // exactly the gap.
    let as_maintenance = get(host, "/classes/NoSuchClass", &As::maintenance()).await;
    assert_eq!(
        as_maintenance.code(),
        Some(119),
        "maintenance is subject to the read-path check: {}",
        as_maintenance.raw
    );

    // And it *is* exempt on the write path, which is the half that must not change.
    let written = post(
        host,
        "/classes/NoSuchClass",
        &As::maintenance(),
        &json!({ "x": 1 }),
    )
    .await;
    assert_eq!(
        written.status, 201,
        "maintenance may still create a class: {}",
        written.raw
    );
}

/// A failed login pays the bcrypt cost whether or not the account exists.
///
/// The shared `Invalid username/password.` message hides *which* of the two failed, but only if the
/// two take comparable time. Without the dummy compare a missing account returns in microseconds
/// and a real one in milliseconds, which answers the same question the message refuses to, and does
/// it over the network.
///
/// Asserted as a ratio rather than an absolute, and loosely, because this runs on shared CI. The
/// defect it catches is three orders of magnitude, so a factor of five is a wide margin that still
/// fails if the dummy compare is removed.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_login_for_a_missing_user_costs_what_a_real_one_does() {
    use std::time::Instant;

    let server = common::boot().await;
    let host = &server.host;
    signup(host, "real_user", "correct-horse").await;

    // Warm the connection and the runtime so the first request's cost is not measured.
    for _ in 0..2 {
        post(
            host,
            "/login",
            &As::anonymous(),
            &json!({ "username": "real_user", "password": "wrong" }),
        )
        .await;
    }

    let time = |body: serde_json::Value| async move {
        let started = Instant::now();
        let r = post(host, "/login", &As::anonymous(), &body).await;
        assert_eq!(r.code(), Some(101), "both must fail: {}", r.raw);
        started.elapsed()
    };

    let existing = time(json!({ "username": "real_user", "password": "wrong" })).await;
    let missing = time(json!({ "username": "no_such_user", "password": "wrong" })).await;

    assert!(
        missing * 5 >= existing,
        "a missing account answered in {missing:?} against {existing:?} for a real one, which \
         leaks account existence through timing regardless of the shared error message"
    );
}

/// A signup the CLP will refuse costs the same whether the account exists or not.
///
/// `validate_user_identity` queries `_User` and the password is then hashed, so checking the
/// `create` permission after them answers 202 in milliseconds for a name that exists and 119 after
/// a bcrypt-length pause for one that does not. Upstream checks the permission first: since 9.10.3
/// `validateWritePermission` runs ahead of `validateSchema` and `transformUser` (`RestWrite.js:134`,
/// defined at `:793-804`).
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_refused_signup_does_not_disclose_whether_the_account_exists() {
    use std::time::Instant;

    let server = common::boot().await;
    let host = &server.host;
    signup(host, "already_here", "pw").await;

    // Close `create` on `_User`.
    let clp = put(
        host,
        "/schemas/_User",
        &As::master(),
        &json!({
            "className": "_User",
            "classLevelPermissions": { "find": {"*": true}, "get": {"*": true}, "create": {} }
        }),
    )
    .await;
    assert_eq!(clp.status, 200, "{}", clp.raw);

    let attempt = |name: &'static str| async move {
        let started = Instant::now();
        let r = post(
            host,
            "/users",
            &As::anonymous(),
            &json!({ "username": name, "password": "pw" }),
        )
        .await;
        (r, started.elapsed())
    };

    // The CLP write invalidates the schema cache, so the first request after it pays for the
    // reload. Take that hit on a third name, then compare the fastest of alternating attempts, so
    // neither side is measured cold.
    attempt("warms_the_cache").await;
    let (mut existing, mut t_existing) = attempt("already_here").await;
    let (mut fresh, mut t_fresh) = attempt("brand_new_name").await;
    for _ in 0..4 {
        let (r, t) = attempt("already_here").await;
        if t < t_existing {
            (existing, t_existing) = (r, t);
        }
        let (r, t) = attempt("brand_new_name").await;
        if t < t_fresh {
            (fresh, t_fresh) = (r, t);
        }
    }

    // Both must be the permission refusal, not one of them a uniqueness error.
    assert_eq!(existing.code(), Some(119), "{}", existing.raw);
    assert_eq!(fresh.code(), Some(119), "{}", fresh.raw);
    assert!(
        t_existing * 5 >= t_fresh && t_fresh * 5 >= t_existing,
        "a refused signup must not disclose account existence through timing: \
         existing {t_existing:?} against fresh {t_fresh:?}"
    );
}

/// A master create through `/classes/_User` gets the same identity validation a signup does.
///
/// `transformUser` is not gated on the caller, and the dashboard creates users through this route.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_master_user_create_validates_identity() {
    let server = common::boot().await;
    let host = &server.host;
    signup(host, "MasterCase", "pw").await;

    let case_dupe = post(
        host,
        "/classes/_User",
        &As::master(),
        &json!({ "username": "mastercase", "password": "pw" }),
    )
    .await;
    assert_eq!(case_dupe.code(), Some(202), "{}", case_dupe.raw);

    let bad_email = post(
        host,
        "/classes/_User",
        &As::master(),
        &json!({ "username": "fresh_master", "password": "pw", "email": "not-an-email" }),
    )
    .await;
    assert_eq!(bad_email.code(), Some(125), "{}", bad_email.raw);

    // An exact duplicate is 202, not a bare 137 from the index.
    let exact = post(
        host,
        "/classes/_User",
        &As::master(),
        &json!({ "username": "MasterCase", "password": "pw" }),
    )
    .await;
    assert_eq!(exact.code(), Some(202), "{}", exact.raw);
}

/// A created `_User` must carry a username and a password, master included.
///
/// Upstream's guard is `!this.query && !hasAuthData` (`RestWrite.js:528`) and is not gated on
/// the caller, so the dashboard's own route is subject to it. Without it that route admitted a row
/// with no username, and a passwordless row that no login can ever match.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn creating_a_user_requires_a_username_and_a_password() {
    let server = common::boot().await;
    let host = &server.host;

    for route in ["/users", "/classes/_User"] {
        let who = if route == "/users" {
            As::anonymous()
        } else {
            As::master()
        };

        let no_username = post(host, route, &who, &json!({ "password": "pw" })).await;
        assert_eq!(
            no_username.code(),
            Some(200),
            "{route} without a username: {}",
            no_username.raw
        );
        assert_eq!(no_username.error(), "bad or missing username");

        let no_password = post(host, route, &who, &json!({ "username": "nopw_x" })).await;
        assert_eq!(
            no_password.code(),
            Some(201),
            "{route} without a password: {}",
            no_password.raw
        );
        // Upstream's string carries no trailing period.
        assert_eq!(no_password.error(), "password is required");

        // An empty string is not a credential either.
        let empty = post(
            host,
            route,
            &who,
            &json!({ "username": "", "password": "pw" }),
        )
        .await;
        assert_eq!(
            empty.code(),
            Some(200),
            "{route} empty username: {}",
            empty.raw
        );
    }
}

/// A regex operand inside an Array-field `$in` is a query, not a write.
///
/// The two interior converters differ by the nested-key guard, which belongs to writes alone: a
/// `{"$regex": ...}` operand is what the SDK's `containsAllStartingWith` sends, and refusing it
/// with `INVALID_NESTED_KEY` turns a legitimate query into a 121.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_regex_operand_in_an_array_in_is_a_query_not_a_write() {
    let server = common::boot().await;
    let host = &server.host;

    let made = post(
        host,
        "/classes/Tagger",
        &As::master(),
        &json!({ "tags": ["xylophone", "banjo"] }),
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.raw);

    let w = common::urlencode(&json!({ "tags": { "$in": [{ "$regex": "^xy" }] } }).to_string());
    let found = get(host, &format!("/classes/Tagger?where={w}"), &As::master()).await;
    assert_eq!(
        found.status, 200,
        "a regex operand must not be refused as a nested write key: {}",
        found.raw
    );
    assert_eq!(found.results().len(), 1, "{}", found.raw);

    // The write path still refuses the same shape, which is the half that must not regress.
    let written = post(
        host,
        "/classes/Tagger",
        &As::master(),
        &json!({ "tags": [{ "$regex": "^xy" }] }),
    )
    .await;
    assert_eq!(written.code(), Some(121), "{}", written.raw);
}

/// The `Delete` form of an ACL write keeps the owner, the same as the object form.
///
/// `user.unset("ACL").save()` sends `{"ACL": {"__op": "Delete"}}`, which is the other way to
/// replace an ACL and was not covered: the guard matched only the object form, so the delete
/// reached the lowering and cleared both permission columns. An empty ACL on `_User` is a row its
/// owner can no longer read or write, and it reads as a disabled account at login. Measured at the
/// pin: upstream answers 200 and the row comes back holding the owner entry alone.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn deleting_an_acl_keeps_the_owner_and_leaves_the_account_usable() {
    let server = common::boot().await;
    let host = &server.host;
    let (object_id, token) = signup(host, "acl_unset", "pw").await;

    let unset = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "ACL": { "__op": "Delete" } }),
    )
    .await;
    assert_eq!(unset.status, 200, "{}", unset.raw);

    // The stored ACL is the owner alone, not empty.
    let stored = get(host, &format!("/classes/_User/{object_id}"), &As::master()).await;
    assert_eq!(
        stored.body["ACL"],
        json!({ &object_id: { "read": true, "write": true } }),
        "the owner entry survives an unset: {}",
        stored.raw
    );

    // The consequence that makes it matter: the owner can still write, and can still log in.
    let after = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "nickname": "still here" }),
    )
    .await;
    assert_eq!(
        after.status, 200,
        "an unset ACL must not lock the owner out: {}",
        after.raw
    );
    let login = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "acl_unset", "password": "pw" }),
    )
    .await;
    assert_eq!(
        login.status, 200,
        "and must not read as a disabled account: {}",
        login.raw
    );
}

/// A `Delete` on `username` is refused; a `Delete` on `email` is allowed.
///
/// The asymmetry is upstream's: `_validateEmail` returns early on a `Delete`
/// (`RestWrite.js:978`), while a present `username` must be a non-empty string
/// (`RestWrite.js:531-535`). Matching only the string form let `user.unset("username").save()`
/// remove the username with no validation.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn deleting_a_username_is_refused_and_deleting_an_email_is_not() {
    let server = common::boot().await;
    let host = &server.host;
    let created = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "unset_me", "password": "pw", "email": "unset@example.com" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let object_id = created.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();
    let token = created.body["sessionToken"]
        .as_str()
        .expect("token")
        .to_string();

    let refused = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "username": { "__op": "Delete" } }),
    )
    .await;
    // 200 `bad or missing username` as of 9.10.3 (`RestWrite.js:531-535`), which superseded the 107
    // that came from the uniqueness query being built with the op object.
    assert_eq!(refused.code(), Some(200), "{}", refused.raw);
    assert_eq!(refused.error(), "bad or missing username");

    let emptied = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "username": "" }),
    )
    .await;
    assert_eq!(emptied.code(), Some(200), "{}", emptied.raw);

    // And the username is still there.
    let me = get(host, "/users/me", &As::user(&token)).await;
    assert_eq!(me.body["username"], json!("unset_me"), "{}", me.raw);

    // An email unset is upstream's allowed case.
    let allowed = put(
        host,
        &format!("/classes/_User/{object_id}"),
        &As::user(&token),
        &json!({ "email": { "__op": "Delete" } }),
    )
    .await;
    assert_eq!(
        allowed.status, 200,
        "an email unset is explicitly permitted upstream: {}",
        allowed.raw
    );
}

/// An owner's credential checks answer before the class-level `update` gate.
///
/// Upstream's `authorizeUserUpdate` returns early for the owner, and the gate runs later in
/// `validateWritePermission` (`RestWrite.js:113-134`). So with `update` closed, an empty username
/// is still 200 `bad or missing username`, and a valid change is 119.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_owner_update_checks_credentials_before_the_class_gate() {
    let server = common::boot().await;
    let host = &server.host;
    let (object_id, token) = signup(host, "gate_order", "pw").await;

    let clp = put(
        host,
        "/schemas/_User",
        &As::master(),
        &json!({
            "className": "_User",
            "classLevelPermissions": {
                "find": {"*": true}, "get": {"*": true}, "create": {"*": true}, "update": {}
            }
        }),
    )
    .await;
    assert_eq!(clp.status, 200, "{}", clp.raw);

    let path = format!("/classes/_User/{object_id}");
    let empty = put(host, &path, &As::user(&token), &json!({ "username": "" })).await;
    assert_eq!(empty.code(), Some(200), "{}", empty.raw);
    assert_eq!(empty.error(), "bad or missing username");

    let renamed = put(
        host,
        &path,
        &As::user(&token),
        &json!({ "username": "renamed" }),
    )
    .await;
    assert_eq!(renamed.code(), Some(119), "{}", renamed.raw);
}
