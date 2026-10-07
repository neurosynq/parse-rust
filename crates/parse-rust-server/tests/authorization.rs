//! The 0.2.0 claim, over HTTP: roles resolve, CLP is evaluated, pointer permissions narrow a
//! query, protected fields are stripped and cannot be probed.
//!
//! Every isolation test here asserts first that the caller can see its **own** data. A test that
//! only checks "A cannot see B's" passes just as well when A can see nothing at all, which is how
//! a cross-user isolation test once proved nothing while looking decisive.
//!
//! `#[ignore]`d because they need a MongoDB on 27017. `tools/test.sh` runs them.

mod common;

use common::{delete, get, post, put, signup, where_query, As};
use serde_json::{json, Value};

/// Create a class with a CLP, using the master-key schema API.
async fn set_clp(host: &str, class_name: &str, clp: Value) {
    let existing = get(host, &format!("/schemas/{class_name}"), &As::master()).await;
    let response = if existing.status == 200 {
        put(
            host,
            &format!("/schemas/{class_name}"),
            &As::master(),
            &json!({ "classLevelPermissions": clp }),
        )
        .await
    } else {
        post(
            host,
            &format!("/schemas/{class_name}"),
            &As::master(),
            &json!({ "classLevelPermissions": clp }),
        )
        .await
    };
    assert_eq!(
        response.status, 200,
        "setting the CLP failed: {}",
        response.raw
    );
}

/// A second server on the same database with `enableSanitizedErrorResponse` off.
///
/// The option's default is `true` (`Options/Definitions.js:259-264`), so the messages a stock
/// deployment emits are the generic ones and the detailed ones only exist under this
/// configuration. Both are wire contract, and a test that asserts one regime says nothing about
/// the other.
async fn detailed_server(database: &str) -> String {
    let mut config = parse_rust_server::ServerConfig::new(common::APP_ID, common::MASTER_KEY);
    config.enable_sanitized_error_response = false;
    common::boot_with(database, config).await
}

async fn create_role(host: &str, name: &str, members: &[&str]) -> String {
    let role = post(
        host,
        "/roles",
        &As::master(),
        &json!({
            "name": name,
            "ACL": { "*": { "read": true } },
            "users": {
                "__op": "AddRelation",
                "objects": members.iter().map(|id| json!({
                    "__type": "Pointer", "className": "_User", "objectId": id
                })).collect::<Vec<_>>(),
            },
        }),
    )
    .await;
    assert_eq!(role.status, 201, "role create failed: {}", role.raw);
    role.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string()
}

// -------------------------------------------------------------------------------------------
// ACL
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn one_user_cannot_read_or_write_anothers_object() {
    let server = common::boot().await;
    let host = &server.host;
    let (a_id, a_token) = signup(host, "acl_a", "pw").await;
    let (_b_id, b_token) = signup(host, "acl_b", "pw").await;

    let created = post(
        host,
        "/classes/Note",
        &As::user(&a_token),
        &json!({
            "title": "private",
            "ACL": { a_id.clone(): { "read": true, "write": true } },
        }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let object_id = created.body["objectId"].as_str().expect("objectId");

    // A sees its own. Without this the two assertions below prove nothing.
    let own = get(
        host,
        &format!("/classes/Note/{object_id}"),
        &As::user(&a_token),
    )
    .await;
    assert_eq!(
        own.status, 200,
        "the owner must see its own row: {}",
        own.raw
    );
    assert_eq!(own.body["title"], json!("private"));
    let own_list = get(host, "/classes/Note", &As::user(&a_token)).await;
    assert_eq!(own_list.results().len(), 1, "{}", own_list.raw);

    // B sees nothing, on both shapes of read.
    let stolen = get(
        host,
        &format!("/classes/Note/{object_id}"),
        &As::user(&b_token),
    )
    .await;
    assert_eq!(stolen.code(), Some(101), "{}", stolen.raw);
    let listed = get(host, "/classes/Note", &As::user(&b_token)).await;
    assert!(listed.results().is_empty(), "{}", listed.raw);

    // And cannot write it. Upstream conflates "does not exist" with "you cannot see it", because
    // distinguishing them would tell an unauthorized caller that the object exists.
    let overwritten = put(
        host,
        &format!("/classes/Note/{object_id}"),
        &As::user(&b_token),
        &json!({ "title": "taken" }),
    )
    .await;
    assert_eq!(overwritten.code(), Some(101), "{}", overwritten.raw);
    let removed = delete(
        host,
        &format!("/classes/Note/{object_id}"),
        &As::user(&b_token),
    )
    .await;
    assert_eq!(removed.code(), Some(101), "{}", removed.raw);

    // The row is intact, which is what proves the write did not land.
    let after = get(
        host,
        &format!("/classes/Note/{object_id}"),
        &As::user(&a_token),
    )
    .await;
    assert_eq!(after.body["title"], json!("private"), "{}", after.raw);
}

// -------------------------------------------------------------------------------------------
// Roles
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_role_member_reads_a_role_acled_object_and_a_non_member_does_not() {
    let server = common::boot().await;
    let host = &server.host;
    let (member_id, member_token) = signup(host, "role_member", "pw").await;
    let (_outsider_id, outsider_token) = signup(host, "role_outsider", "pw").await;

    create_role(host, "Readers", &[&member_id]).await;

    let created = post(
        host,
        "/classes/Doc",
        &As::master(),
        &json!({
            "title": "restricted",
            "ACL": { "role:Readers": { "read": true } },
        }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let object_id = created.body["objectId"].as_str().expect("objectId");

    let member = get(
        host,
        &format!("/classes/Doc/{object_id}"),
        &As::user(&member_token),
    )
    .await;
    assert_eq!(
        member.status, 200,
        "a `role:` entry must match a member, which is what 0.1.0 could not do: {}",
        member.raw
    );

    let outsider = get(
        host,
        &format!("/classes/Doc/{object_id}"),
        &As::user(&outsider_token),
    )
    .await;
    assert_eq!(outsider.code(), Some(101), "{}", outsider.raw);

    let anonymous = get(host, &format!("/classes/Doc/{object_id}"), &As::anonymous()).await;
    assert_eq!(anonymous.code(), Some(101), "{}", anonymous.raw);
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_nested_role_member_inherits_the_parent_role() {
    let server = common::boot().await;
    let host = &server.host;
    let (member_id, member_token) = signup(host, "nested_member", "pw").await;

    // The user is in Juniors; Seniors contains Juniors; so the user holds Seniors too.
    let junior_id = create_role(host, "Juniors", &[&member_id]).await;
    let seniors = post(
        host,
        "/roles",
        &As::master(),
        &json!({
            "name": "Seniors",
            "ACL": { "*": { "read": true } },
            "roles": {
                "__op": "AddRelation",
                "objects": [{ "__type": "Pointer", "className": "_Role", "objectId": junior_id }],
            },
        }),
    )
    .await;
    assert_eq!(seniors.status, 201, "{}", seniors.raw);

    let created = post(
        host,
        "/classes/Doc",
        &As::master(),
        &json!({ "title": "senior only", "ACL": { "role:Seniors": { "read": true } } }),
    )
    .await;
    let object_id = created.body["objectId"].as_str().expect("objectId");

    let member = get(
        host,
        &format!("/classes/Doc/{object_id}"),
        &As::user(&member_token),
    )
    .await;
    assert_eq!(
        member.status, 200,
        "role expansion must be transitive: {}",
        member.raw
    );
}

/// `A -> B -> A` terminates with both names and no error. A cycle check that raised would be a
/// behavior change; no cycle check at all is a hang.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_role_cycle_terminates() {
    let server = common::boot().await;
    let host = &server.host;
    let (member_id, member_token) = signup(host, "cycle_member", "pw").await;

    let a = create_role(host, "CycleA", &[&member_id]).await;
    let b = create_role(host, "CycleB", &[]).await;
    // A contains B, and B contains A.
    for (owner, child) in [(&a, &b), (&b, &a)] {
        let r = put(
            host,
            &format!("/roles/{owner}"),
            &As::master(),
            &json!({
                "roles": {
                    "__op": "AddRelation",
                    "objects": [{ "__type": "Pointer", "className": "_Role", "objectId": child }],
                },
            }),
        )
        .await;
        assert_eq!(r.status, 200, "{}", r.raw);
    }

    let created = post(
        host,
        "/classes/Doc",
        &As::master(),
        &json!({ "title": "cyclic", "ACL": { "role:CycleB": { "read": true } } }),
    )
    .await;
    let object_id = created.body["objectId"].as_str().expect("objectId");

    // The request completing at all is the assertion. A member of CycleA holds CycleB through the
    // cycle, so the read succeeds rather than hanging or erroring.
    let member = get(
        host,
        &format!("/classes/Doc/{object_id}"),
        &As::user(&member_token),
    )
    .await;
    assert_eq!(member.status, 200, "{}", member.raw);
}

// -------------------------------------------------------------------------------------------
// CLP
// -------------------------------------------------------------------------------------------

/// **The code is 101, not 119.** It is deliberate existence hiding and it is wire contract.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn requires_authentication_denies_anonymously_with_code_101() {
    let server = common::boot().await;
    let host = &server.host;
    let (_id, token) = signup(host, "clp_user", "pw").await;

    set_clp(
        host,
        "Guarded",
        json!({
            "find": { "requiresAuthentication": true },
            "get": { "requiresAuthentication": true },
            "create": { "*": true },
        }),
    )
    .await;
    post(host, "/classes/Guarded", &As::master(), &json!({ "n": 1 })).await;

    // At the default the client is told it was refused and nothing else. The code still hides
    // the class's existence, which is the part `enableSanitizedErrorResponse` does not change.
    let anonymous = get(host, "/classes/Guarded", &As::anonymous()).await;
    assert_eq!(anonymous.code(), Some(101), "{}", anonymous.raw);
    assert_eq!(anonymous.error(), "Permission denied");

    // With the option off, the detailed message is back. Both strings are contract, so both are
    // asserted: testing only one leaves the other free to drift.
    let disclosing = detailed_server(&server.database).await;
    let detailed = get(&disclosing, "/classes/Guarded", &As::anonymous()).await;
    assert_eq!(detailed.code(), Some(101), "{}", detailed.raw);
    assert_eq!(
        detailed.error(),
        "Permission denied, user needs to be authenticated."
    );

    let authenticated = get(host, "/classes/Guarded", &As::user(&token)).await;
    assert_eq!(authenticated.status, 200, "{}", authenticated.raw);
    assert_eq!(authenticated.results().len(), 1, "{}", authenticated.raw);
}

/// A class with no CLP block is unrestricted. Inverting this fails closed, which looks safe, and
/// locks every existing database out on upgrade.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_class_with_no_clp_block_is_open() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(host, "/classes/Open", &As::anonymous(), &json!({ "n": 1 })).await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let listed = get(host, "/classes/Open", &As::anonymous()).await;
    assert_eq!(listed.results().len(), 1, "{}", listed.raw);
}

/// Stage one is a gate; passing it is not authorization to read anything. Stage two is the filter.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn pointer_permissions_narrow_a_query_to_the_callers_own_rows() {
    let server = common::boot().await;
    let host = &server.host;
    let (a_id, a_token) = signup(host, "pp_a", "pw").await;
    let (b_id, b_token) = signup(host, "pp_b", "pw").await;

    for owner in [&a_id, &b_id] {
        let r = post(
            host,
            "/classes/Owned",
            &As::master(),
            &json!({
                "owner": { "__type": "Pointer", "className": "_User", "objectId": owner },
                "title": "mine",
            }),
        )
        .await;
        assert_eq!(r.status, 201, "{}", r.raw);
    }

    set_clp(
        host,
        "Owned",
        json!({
            "find": { "pointerFields": ["owner"] },
            "get": { "pointerFields": ["owner"] },
            "count": { "pointerFields": ["owner"] },
            "update": { "pointerFields": ["owner"] },
            "delete": { "pointerFields": ["owner"] },
        }),
    )
    .await;

    // Each user sees exactly their own row. Assert this before the anonymous sweep.
    for (token, owner) in [(&a_token, &a_id), (&b_token, &b_id)] {
        let mine = get(host, "/classes/Owned", &As::user(token)).await;
        assert_eq!(mine.results().len(), 1, "{}", mine.raw);
        assert_eq!(mine.results()[0]["owner"]["objectId"], json!(owner));
    }

    // The mitigation test for `PointerPermOutcome::DenyAll` reaching a caller as "no constraint":
    // an anonymous caller gets nothing on **every** verb, not just on find.
    let anonymous = get(host, "/classes/Owned", &As::anonymous()).await;
    assert!(anonymous.results().is_empty(), "find: {}", anonymous.raw);

    let counted = get(host, "/classes/Owned?count=1&limit=0", &As::anonymous()).await;
    assert_eq!(counted.body["count"], json!(0), "count: {}", counted.raw);

    let a_row = get(host, "/classes/Owned", &As::user(&a_token)).await;
    let object_id = a_row.results()[0]["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();

    let fetched = get(
        host,
        &format!("/classes/Owned/{object_id}"),
        &As::anonymous(),
    )
    .await;
    assert_eq!(fetched.code(), Some(101), "get: {}", fetched.raw);

    let updated = put(
        host,
        &format!("/classes/Owned/{object_id}"),
        &As::anonymous(),
        &json!({ "title": "taken" }),
    )
    .await;
    assert_eq!(updated.code(), Some(101), "update: {}", updated.raw);

    let removed = delete(
        host,
        &format!("/classes/Owned/{object_id}"),
        &As::anonymous(),
    )
    .await;
    assert_eq!(removed.code(), Some(101), "delete: {}", removed.raw);

    // Nothing was mutated by any of the above.
    let after = get(
        host,
        &format!("/classes/Owned/{object_id}"),
        &As::user(&a_token),
    )
    .await;
    assert_eq!(after.body["title"], json!("mine"), "{}", after.raw);
}

// -------------------------------------------------------------------------------------------
// Protected fields
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_protected_field_is_absent_from_a_read_and_cannot_be_probed() {
    let server = common::boot().await;
    let host = &server.host;
    let (_id, token) = signup(host, "pf_user", "pw").await;

    let created = post(
        host,
        "/classes/Profile",
        &As::master(),
        &json!({ "nickname": "visible", "secret": "hidden" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);

    // Master sees everything, which establishes the field exists before it is protected.
    let as_master = get(host, "/classes/Profile", &As::master()).await;
    assert_eq!(as_master.results()[0]["secret"], json!("hidden"));

    // `find` and `get` have to be spelled out. A stored CLP block is merged over `emptyCLPS`,
    // whose unspecified operations are `{}`, so a block carrying only `protectedFields` closes the
    // class outright. That is the asymmetry with an *absent* block, which reads back as
    // `defaultCLPS` and is fully public.
    set_clp(
        host,
        "Profile",
        json!({
            "find": { "*": true },
            "get": { "*": true },
            "protectedFields": { "*": ["secret"] },
        }),
    )
    .await;

    let read = get(host, "/classes/Profile", &As::user(&token)).await;
    assert_eq!(
        read.results().len(),
        1,
        "the row is still readable: {}",
        read.raw
    );
    assert_eq!(read.results()[0]["nickname"], json!("visible"));
    assert!(
        read.results()[0].get("secret").is_none(),
        "the protected field must be absent: {}",
        read.raw
    );

    // Without `denyProtectedFields` a client binary-searches the value through `where` and
    // `order`, so both are `OPERATION_FORBIDDEN` rather than a filtered result.
    let queried = get(
        host,
        &format!(
            "/classes/Profile{}",
            where_query(json!({ "secret": "hidden" }))
        ),
        &As::user(&token),
    )
    .await;
    assert_eq!(queried.code(), Some(119), "{}", queried.raw);
    assert_eq!(queried.error(), "Permission denied");

    let sorted = get(host, "/classes/Profile?order=secret", &As::user(&token)).await;
    assert_eq!(sorted.code(), Some(119), "{}", sorted.raw);
    assert_eq!(sorted.error(), "Permission denied");

    // The other regime. The detailed strings name the field, which is exactly why upstream
    // withholds them by default: `Permission denied` does not confirm that `secret` exists.
    let disclosing = detailed_server(&server.database).await;
    let queried = get(
        &disclosing,
        &format!(
            "/classes/Profile{}",
            where_query(json!({ "secret": "hidden" }))
        ),
        &As::user(&token),
    )
    .await;
    assert_eq!(queried.code(), Some(119), "{}", queried.raw);
    assert_eq!(
        queried.error(),
        "This user is not allowed to query secret on class Profile"
    );
    let sorted = get(
        &disclosing,
        "/classes/Profile?order=secret",
        &As::user(&token),
    )
    .await;
    assert_eq!(sorted.code(), Some(119), "{}", sorted.raw);
    assert_eq!(
        sorted.error(),
        "This user is not allowed to sort by secret on class Profile"
    );

    // Master is never protected.
    let master_query = get(
        host,
        &format!(
            "/classes/Profile{}",
            where_query(json!({ "secret": "hidden" }))
        ),
        &As::master(),
    )
    .await;
    assert_eq!(master_query.results().len(), 1, "{}", master_query.raw);
}

/// The server-level default, `{_User: {'*': ['email']}}`, and the owner exemption that comes with
/// it. Both are defaults rather than configuration, so getting either wrong is a security default.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_default_protected_fields_hide_another_users_email_but_not_your_own() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "pf_owner", "password": "pw", "email": "owner@example.com" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let token = created.body["sessionToken"].as_str().expect("token");
    let owner_id = created.body["objectId"].as_str().expect("objectId");

    // `protectedFieldsOwnerExempt` defaults to true, so the owner sees their own email.
    let me = get(host, "/users/me", &As::user(token)).await;
    assert_eq!(me.body["email"], json!("owner@example.com"), "{}", me.raw);

    // A different user does not, even with the row made readable.
    let (_other_id, other_token) = signup(host, "pf_other", "pw").await;
    put(
        host,
        &format!("/classes/_User/{owner_id}"),
        &As::master(),
        &json!({ "ACL": { "*": { "read": true }, owner_id: { "read": true, "write": true } } }),
    )
    .await;

    let seen = get(
        host,
        &format!("/classes/_User/{owner_id}"),
        &As::user(&other_token),
    )
    .await;
    assert_eq!(seen.status, 200, "the row is readable: {}", seen.raw);
    assert_eq!(seen.body["username"], json!("pf_owner"));
    assert!(
        seen.body.get("email").is_none(),
        "`email` is protected on `_User` by default: {}",
        seen.raw
    );
}

/// `protectedFieldsSaveResponseExempt`, which decides whether a write response carries a protected
/// field the write touched. It defaults to `true`, the pass-through case.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_save_response_exemption_controls_the_operation_echo() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/classes/Counter",
        &As::master(),
        &json!({ "hits": 0 }),
    )
    .await;
    let object_id = created.body["objectId"]
        .as_str()
        .expect("objectId")
        .to_string();
    set_clp(
        host,
        "Counter",
        json!({
            "find": { "*": true },
            "get": { "*": true },
            "update": { "*": true },
            "protectedFields": { "*": ["hits"] },
        }),
    )
    .await;

    let increment = json!({ "hits": { "__op": "Increment", "amount": 1 } });

    // Default: the echo carries the post-write value even though a read would not.
    let exempt = put(
        host,
        &format!("/classes/Counter/{object_id}"),
        &As::anonymous(),
        &increment,
    )
    .await;
    assert_eq!(exempt.body["hits"], json!(1), "{}", exempt.raw);
    let read = get(
        host,
        &format!("/classes/Counter/{object_id}"),
        &As::anonymous(),
    )
    .await;
    assert!(
        read.body.get("hits").is_none(),
        "a read still strips it: {}",
        read.raw
    );

    // Set to false, the echo is stripped the same way a query result is.
    let strict = {
        let mut config = parse_rust_server::ServerConfig::new(common::APP_ID, common::MASTER_KEY);
        config.protected_fields_save_response_exempt = false;
        common::boot_with(&server.database, config).await
    };
    let stripped = put(
        &strict,
        &format!("/classes/Counter/{object_id}"),
        &As::anonymous(),
        &increment,
    )
    .await;
    assert_eq!(stripped.status, 200, "{}", stripped.raw);
    assert!(
        stripped.body.get("hits").is_none(),
        "the protected field must not survive the echo: {}",
        stripped.raw
    );
    // The write itself still happened.
    let after = get(
        &strict,
        &format!("/classes/Counter/{object_id}"),
        &As::master(),
    )
    .await;
    assert_eq!(after.body["hits"], json!(2), "{}", after.raw);
}

// -------------------------------------------------------------------------------------------
// Role name uniqueness
// -------------------------------------------------------------------------------------------

/// Two `_Role` rows may not share a name.
///
/// Upstream creates a unique index on `_Role.name` at startup unless `createIndexRoleName` is
/// explicitly `false` (`DatabaseController.js:2045-2050`). It is a privilege-escalation guard
/// rather than data hygiene: an ACL entry names a role by string, so a second role called
/// `Admins` would grant every member of both to anything ACLed `role:Admins`.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_second_role_with_the_same_name_is_refused() {
    let server = common::boot().await;
    let host = &server.host;
    let (member, _token) = signup(host, "rolename_member", "pw").await;
    let (outsider, outsider_token) = signup(host, "rolename_outsider", "pw").await;

    create_role(host, "Admins", &[&member]).await;

    // The escalation this prevents, attempted directly.
    let duplicate = post(
        host,
        "/roles",
        &As::master(),
        &json!({
            "name": "Admins",
            "ACL": { "*": { "read": true } },
            "users": {
                "__op": "AddRelation",
                "objects": [{ "__type": "Pointer", "className": "_User", "objectId": outsider }],
            },
        }),
    )
    .await;
    assert_eq!(
        duplicate.code(),
        Some(137),
        "a duplicate role name must be a DUPLICATE_VALUE: {}",
        duplicate.raw
    );
    // The message is upstream's fixed one, and the driver's `E11000` text that it replaced named
    // the database and quoted the colliding role name.
    assert_eq!(
        duplicate.error(),
        "A duplicate value for a field with unique values was provided"
    );
    for secret in [server.database.as_str(), "Admins", "E11000", "name_1"] {
        assert!(
            !duplicate.raw.contains(secret),
            "`{secret}` is on the wire: {}",
            duplicate.raw
        );
    }

    // And the outsider still holds nothing, which is the consequence the code is standing in for.
    let doc = post(
        host,
        "/classes/RoleNameDoc",
        &As::master(),
        &json!({ "title": "admin only", "ACL": { "role:Admins": { "read": true } } }),
    )
    .await;
    assert_eq!(doc.status, 201, "{}", doc.raw);
    let object_id = doc.body["objectId"].as_str().expect("objectId");
    let seen = get(
        host,
        &format!("/classes/RoleNameDoc/{object_id}"),
        &As::user(&outsider_token),
    )
    .await;
    assert_eq!(seen.code(), Some(101), "{}", seen.raw);
}

// -------------------------------------------------------------------------------------------
// The internal-error envelope
// -------------------------------------------------------------------------------------------

/// A CLP whose `pointerFields` names a field the schema no longer has.
///
/// The schema API refuses that combination when it is written in one request, which is why this
/// reaches it by drift: a valid CLP first, then the field deleted out from under it. A body with
/// no `classLevelPermissions` leaves the stored block alone (`SchemaController.js:1097-1099`), so
/// the class ends up in the state upstream's own comment calls "should not happen". Mixed fleets
/// and hand-edited schemas produce it in the field.
///
/// Two things are asserted. The refusal is a 500 rather than an unconstrained query, because
/// failing open here would hand the whole class to the caller. And the body is the generic one:
/// upstream throws a plain `Error` here (`DatabaseController.js:1804-1806`), which
/// `handleParseErrors` renders as `{"code":1,"message":"Internal server error."}` with the key
/// `message` and none of the detail (`middlewares.js:636-644`).
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_misconfigured_pointer_permission_is_a_generic_five_hundred() {
    let server = common::boot().await;
    let host = &server.host;
    let (_id, token) = signup(host, "drift_user", "pw").await;

    let created = post(
        host,
        "/schemas/DriftedClass",
        &As::master(),
        &json!({
            "fields": { "ownerRef": { "type": "Pointer", "targetClass": "_User" } },
            "classLevelPermissions": { "find": { "pointerFields": ["ownerRef"] } },
        }),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.raw);

    let dropped = put(
        host,
        "/schemas/DriftedClass",
        &As::master(),
        &json!({ "fields": { "ownerRef": { "__op": "Delete" } } }),
    )
    .await;
    assert_eq!(dropped.status, 200, "{}", dropped.raw);

    let found = get(host, "/classes/DriftedClass", &As::user(&token)).await;
    assert_eq!(found.status, 500, "{}", found.raw);
    assert_eq!(found.code(), Some(1), "{}", found.raw);
    assert_eq!(
        found.body["message"],
        json!("Internal server error."),
        "the key is `message`, not `error`: {}",
        found.raw
    );
    assert!(
        found.body.get("error").is_none(),
        "an SDK reading `error` must find nothing here: {}",
        found.raw
    );
    // The detail names the class and the field. Neither may reach a client.
    for secret in ["DriftedClass", "ownerRef", "pointer permissions"] {
        assert!(
            !found.raw.contains(secret),
            "`{secret}` is on the wire: {}",
            found.raw
        );
    }
}

/// `createIndexRoleName: false` skips the index, which is what makes the option real rather than
/// a field nothing reads.
///
/// A fresh database, because a config that skips index creation cannot remove an index an
/// earlier boot already made.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_role_name_index_can_be_turned_off() {
    let server = common::boot_fresh_with(|mut config| {
        config.create_index_role_name = false;
        config
    })
    .await;
    let host = &server.host;

    for _ in 0..2 {
        let created = post(
            host,
            "/roles",
            &As::master(),
            &json!({ "name": "Dupes", "ACL": { "*": { "read": true } } }),
        )
        .await;
        assert_eq!(
            created.status, 201,
            "with the index off both writes land: {}",
            created.raw
        );
    }
}

/// `POST /login` answers with the user's own view of their row, not the raw stored row.
///
/// The login path reads `_User` directly through the adapter, because the password check needs the
/// hash the read pipeline strips. That read answers to no CLP, no ACL and no `protectedFields`, so
/// returning it puts every protected field on the wire at every login while the response looks
/// entirely ordinary. Upstream re-fetches under the caller's own auth for exactly this reason
/// (`UsersRouter.js:360-398`).
///
/// **`protectedFieldsOwnerExempt` is turned off here, and the test is worthless without it.** At
/// login the caller is always the owner of the row being returned, so at the default of `true` the
/// owner exemption applies and `protectedFields` never strips anything. A version of this test
/// that asserted `email` was *present* passed identically before and after the re-fetch existed,
/// which is to say it tested nothing about protected fields at all.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_login_response_is_filtered_by_protected_fields() {
    let server = common::boot_fresh_with(|mut c| {
        c.protected_fields_owner_exempt = false;
        c
    })
    .await;
    let host = &server.host;

    let created = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "login_pf", "password": "pw", "email": "login@example.com" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);

    let logged_in = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "login_pf", "password": "pw" }),
    )
    .await;
    assert_eq!(logged_in.status, 200, "{}", logged_in.raw);
    assert!(
        logged_in.body["sessionToken"].is_string(),
        "login still succeeds: {}",
        logged_in.raw
    );
    assert_eq!(logged_in.body["username"], json!("login_pf"));
    assert!(
        logged_in.body.get("_hashed_password").is_none(),
        "no hash on a login response: {}",
        logged_in.raw
    );
    // The assertion that only holds because the response came from the re-fetch. `email` is a
    // default protected field, and with the owner exemption off it applies to the owner too.
    assert!(
        logged_in.body.get("email").is_none(),
        "`email` is protected and must not survive the login response: {}",
        logged_in.raw
    );
}

/// A `_User` `get` CLP that denies the caller means the login response carries the identity and
/// the token, and nothing else.
///
/// Authentication and authorization are separate questions. Passing the password check does not
/// entitle the caller to read the row, and the raw row is the worst possible fallback precisely
/// because it is reached when access control said no.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_login_denied_the_row_returns_only_the_identity() {
    let server = common::boot().await;
    let host = &server.host;

    let created = post(
        host,
        "/users",
        &As::anonymous(),
        &json!({ "username": "login_clp", "password": "pw", "email": "clp@example.com" }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.raw);
    let user_id = created.body["objectId"].as_str().expect("objectId");

    // Close `get` on `_User`. `find` stays open so this is specifically the re-fetch being denied.
    let clp = put(
        host,
        "/schemas/_User",
        &As::master(),
        &json!({
            "className": "_User",
            "classLevelPermissions": {
                "find": { "*": true },
                "get": {},
                "create": { "*": true },
                "update": { "*": true },
                "delete": { "*": true },
                "addField": { "*": true }
            }
        }),
    )
    .await;
    assert_eq!(clp.status, 200, "{}", clp.raw);

    let logged_in = post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": "login_clp", "password": "pw" }),
    )
    .await;
    assert_eq!(
        logged_in.status, 200,
        "login still succeeds: {}",
        logged_in.raw
    );
    assert!(
        logged_in.body["sessionToken"].is_string(),
        "the token is still issued: {}",
        logged_in.raw
    );
    assert_eq!(logged_in.body["objectId"], json!(user_id));
    assert!(
        logged_in.body.get("email").is_none(),
        "a denied re-fetch must not fall back to the raw row: {}",
        logged_in.raw
    );
    assert!(
        logged_in.body.get("username").is_none(),
        "identity only means objectId and the token: {}",
        logged_in.raw
    );
}

/// A malformed `classLevelPermissions` must not create a class with no permissions at all.
///
/// The parse collapsed "absent" and "present but not an object" into the same `None`, and `None`
/// means the request said nothing about permissions, so a typo produced a default-open class and
/// answered 200. Upstream refuses the body (`SchemaController.js:272-281`).
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_malformed_clp_is_refused_and_creates_nothing() {
    let server = common::boot().await;
    let host = &server.host;

    for bad in [json!("typo"), json!([]), json!(7), json!(true)] {
        let created = post(
            host,
            "/schemas/ClpTypo",
            &As::master(),
            &json!({ "className": "ClpTypo", "classLevelPermissions": bad }),
        )
        .await;
        assert_eq!(
            created.code(),
            Some(107),
            "a non-object CLP is refused, not read as absent: {} for {bad}",
            created.raw
        );

        let fetched = get(host, "/schemas/ClpTypo", &As::master()).await;
        assert_eq!(
            fetched.code(),
            Some(103),
            "and the class must not exist afterwards: {}",
            fetched.raw
        );
    }
}
