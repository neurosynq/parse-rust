//! `accountLockout`, end to end against MongoDB.
//!
//! The cases follow `spec/AccountLockoutPolicy.spec.js`: the lock trips on the attempt after the
//! threshold, holds against the right password, lifts once its expiry passes, and holds its
//! threshold under concurrent attempts. Two more are particular to this implementation: a
//! successful login resets the count, and the two `_User` columns are stored in the shape a
//! parse-server node reading the same database expects, because that is the reason the lockout is
//! implemented at all.
//!
//! The expiry is moved into the past directly in MongoDB rather than waited out. Upstream's spec
//! sleeps three seconds; the column is the contract, so setting it is the same test without the
//! wall-clock dependency.
//!
//! `#[ignore]`d because they need a MongoDB. `tools/test.sh` runs them.

mod common;

use common::*;
use parse_rust_server::lockout::AccountLockout;
use serde_json::json;

const INVALID: &str = "Invalid username/password.";

fn locked_message(duration: &str) -> String {
    format!(
        "Your account is locked due to multiple failed login attempts. Please try again after \
         {duration} minute(s)"
    )
}

async fn boot_locking(duration: f64, threshold: u32) -> Server {
    boot_fresh_with(|mut config| {
        config.account_lockout = Some(AccountLockout {
            duration,
            threshold,
            unlock_on_password_reset: false,
        });
        config
    })
    .await
}

async fn login(host: &str, username: &str, password: &str) -> Response {
    post(
        host,
        "/login",
        &As::anonymous(),
        &json!({ "username": username, "password": password }),
    )
    .await
}

/// The stored `_User` document, read straight from MongoDB.
async fn stored_user(database: &str, username: &str) -> bson::Document {
    let client = mongodb::Client::with_uri_str(mongo_uri())
        .await
        .expect("mongo client");
    client
        .database(database)
        .collection::<bson::Document>("_User")
        .find_one(bson::doc! { "username": username })
        .await
        .expect("find _User")
        .expect("the user row exists")
}

async fn set_user(database: &str, username: &str, set: bson::Document) {
    let client = mongodb::Client::with_uri_str(mongo_uri())
        .await
        .expect("mongo client");
    client
        .database(database)
        .collection::<bson::Document>("_User")
        .update_one(
            bson::doc! { "username": username },
            bson::doc! { "$set": set },
        )
        .await
        .expect("update _User");
}

fn failed_count(user: &bson::Document) -> Option<f64> {
    match user.get("_failed_login_count") {
        Some(bson::Bson::Int32(n)) => Some(f64::from(*n)),
        Some(bson::Bson::Int64(n)) => Some(*n as f64),
        Some(bson::Bson::Double(n)) => Some(*n),
        _ => None,
    }
}

/// `lock account if failed login attempts are above threshold`. Threshold 2: the first two wrong
/// passwords are ordinary failures, the second sets the lock, the third is refused as locked.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_attempt_after_the_threshold_is_refused_as_locked() {
    let server = boot_locking(1.0, 2).await;
    signup(&server.host, "lockme", "right").await;

    for attempt in 1..=2 {
        let r = login(&server.host, "lockme", "wrong").await;
        assert_eq!(r.code(), Some(101), "attempt {attempt}: {}", r.raw);
        assert_eq!(r.error(), INVALID, "attempt {attempt}");
    }
    let r = login(&server.host, "lockme", "wrong").await;
    assert_eq!(r.code(), Some(101), "{}", r.raw);
    assert_eq!(r.error(), locked_message("1"));

    // A locked account is refused with the right password too (`_notLocked` runs first).
    let r = login(&server.host, "lockme", "right").await;
    assert_eq!(r.code(), Some(101), "{}", r.raw);
    assert_eq!(r.error(), locked_message("1"));
}

/// The two columns are the mixed-fleet contract: a number for the count and a BSON date for the
/// expiry, set roughly `duration` minutes ahead, which is what parse-server's `_notLocked` query
/// compares against.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_lock_is_stored_in_the_columns_parse_server_reads() {
    let server = boot_locking(5.0, 2).await;
    signup(&server.host, "columns", "right").await;

    login(&server.host, "columns", "wrong").await;
    let user = stored_user(&server.database, "columns").await;
    assert_eq!(failed_count(&user), Some(1.0), "{user:?}");
    assert!(
        user.get("_account_lockout_expires_at").is_none(),
        "no lock below the threshold: {user:?}"
    );

    let before = bson::DateTime::now().timestamp_millis();
    login(&server.host, "columns", "wrong").await;
    let user = stored_user(&server.database, "columns").await;
    assert_eq!(failed_count(&user), Some(2.0), "{user:?}");
    let Some(bson::Bson::DateTime(expires)) = user.get("_account_lockout_expires_at") else {
        panic!("the expiry must be a BSON date: {user:?}");
    };
    let ahead = expires.timestamp_millis() - before;
    assert!(
        (5 * 60 * 1000 - 5_000..=5 * 60 * 1000 + 5_000).contains(&ahead),
        "expiry should be about five minutes out, was {ahead} ms"
    );
}

/// `allow login for locked account after accountPolicy.duration minutes`, with the expiry moved
/// into the past rather than slept through. The fractional duration also checks the message prints
/// it as JavaScript does.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_lock_lifts_once_its_expiry_has_passed() {
    let server = boot_locking(0.05, 2).await;
    signup(&server.host, "expires", "right").await;

    for _ in 0..2 {
        login(&server.host, "expires", "wrong").await;
    }
    let r = login(&server.host, "expires", "right").await;
    assert_eq!(r.error(), locked_message("0.05"), "{}", r.raw);

    let past = bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 1_000);
    set_user(
        &server.database,
        "expires",
        bson::doc! { "_account_lockout_expires_at": past },
    )
    .await;

    let r = login(&server.host, "expires", "right").await;
    assert_eq!(r.status, 200, "login after the expiry: {}", r.raw);
    assert!(r.body.get("sessionToken").is_some(), "{}", r.raw);
    let user = stored_user(&server.database, "expires").await;
    assert_eq!(
        failed_count(&user),
        Some(0.0),
        "a successful login resets the count: {user:?}"
    );
}

/// A successful login resets the count to zero (`_setFailedLoginCount(0)`), so failures either
/// side of it do not add up to a lock.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_successful_login_resets_the_count() {
    let server = boot_locking(1.0, 2).await;
    signup(&server.host, "resets", "right").await;

    login(&server.host, "resets", "wrong").await;
    let r = login(&server.host, "resets", "right").await;
    assert_eq!(r.status, 200, "{}", r.raw);
    assert_eq!(
        failed_count(&stored_user(&server.database, "resets").await),
        Some(0.0)
    );

    // Two more failures reach the threshold, which is still an ordinary failure, not a lock.
    for attempt in 1..=2 {
        let r = login(&server.host, "resets", "wrong").await;
        assert_eq!(r.error(), INVALID, "attempt {attempt}: {}", r.raw);
    }
}

/// Without a policy nothing counts and nothing locks
/// (`account should not be locked even after failed login attempts if account lockout policy is
/// not set`).
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn without_a_policy_failures_never_lock() {
    let server = boot().await;
    signup(&server.host, "free", "right").await;

    for _ in 0..5 {
        let r = login(&server.host, "free", "wrong").await;
        assert_eq!(r.error(), INVALID, "{}", r.raw);
    }
    let r = login(&server.host, "free", "right").await;
    assert_eq!(r.status, 200, "{}", r.raw);
    let user = stored_user(&server.database, "free").await;
    assert!(
        user.get("_failed_login_count").is_none()
            && user.get("_account_lockout_expires_at").is_none(),
        "no lockout columns without a policy: {user:?}"
    );
}

/// `should enforce lockout threshold under concurrent failed login attempts`. The increment is
/// atomic and its post-image decides, so no more than `threshold` concurrent attempts can be
/// answered as ordinary failures, and at least one is answered as locked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_threshold_holds_under_concurrent_attempts() {
    let threshold = 3;
    let server = boot_locking(5.0, threshold).await;
    signup(&server.host, "race", "right").await;

    let attempts = (0..30).map(|_| login(&server.host, "race", "wrong"));
    let responses = futures::future::join_all(attempts).await;

    let locked = locked_message("5");
    let mut invalid = 0;
    let mut refused = 0;
    for r in &responses {
        match r.error() {
            e if e == INVALID => invalid += 1,
            e if e == locked => refused += 1,
            other => panic!("unexpected answer {other:?}: {}", r.raw),
        }
    }
    assert!(refused > 0, "at least one attempt is refused as locked");
    assert!(
        invalid <= threshold,
        "at most {threshold} ordinary failures, saw {invalid}"
    );
}

/// A login takes the account's gate before it compares the password, so attempts on one account
/// run one after another; see `lockout::serialize_attempts`. Asserted on the wiring rather than on
/// a race: while the test holds the gate, a login cannot finish, and once it lets go the login does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_login_waits_for_the_accounts_gate() {
    let server = boot_locking(5.0, 3).await;
    signup(&server.host, "gated", "right").await;

    let held = parse_rust_server::lockout::serialize_attempts("gated").await;
    let host = server.host.clone();
    let mut pending = tokio::spawn(async move { login(&host, "gated", "right").await });
    let early = tokio::time::timeout(std::time::Duration::from_millis(500), &mut pending).await;
    assert!(early.is_err(), "the login finished while the gate was held");

    drop(held);
    let r = pending.await.expect("login task");
    assert_eq!(r.status, 200, "{}", r.raw);
}
