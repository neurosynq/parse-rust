//! `masterKeyIps` and `maintenanceKeyIps`, over a real socket.
//!
//! **What this file proves and what it does not.** The peer address these tests speak from is
//! always `127.0.0.1`, because binding a client to a second loopback alias needs `ifconfig lo0
//! alias` on macOS and is therefore not portable. So the shipped defect's own precondition, a
//! master key accepted from a remote peer *at the default configuration*, is not reproduced here.
//! It is Gate E's job, and Gate E speaks from a genuinely non-allowlisted address.
//!
//! What is proved here is the wiring: that the address consulted is the connection's and not a
//! header's, that a configured list is enforced end to end rather than only in the unit tests,
//! and that the refusal is upstream's bare 403 rather than a demotion to a client request. The
//! allowlist is configured to exclude loopback so that the refusal is reachable from one machine.
//!
//! Every refusal is paired with a request that succeeds, so a broken server cannot pass by
//! refusing everything.
//!
//! `#[ignore]`d because they need a MongoDB on 27017. `tools/test.sh` runs them.

mod common;

use common::*;
use parse_rust_server::{IpAllowlist, ServerConfig};
use serde_json::json;

/// An address that is not the caller. RFC 5737 documentation space, so it is not routable and
/// cannot accidentally be the machine running the tests.
const ELSEWHERE: &str = "203.0.113.9";

fn excluding_loopback(mut config: ServerConfig) -> ServerConfig {
    config.master_key_ips = IpAllowlist::parse([ELSEWHERE]).expect("entries");
    config.maintenance_key_ips = IpAllowlist::parse([ELSEWHERE]).expect("entries");
    config
}

/// Upstream answers a rejected key with HTTP 403 and `{"error":"unauthorized"}`, with **no `code`
/// field**. A `code` here would tell a client something upstream does not.
///
/// **Not the same code path as the other 403 carrying this envelope**, which is worth stating
/// because the two are easy to conflate and only one of them is `invalidRequest`. An appId or
/// client-key rejection calls `invalidRequest` directly (`middlewares.js:845-848`). This one is a
/// plain `Error` carrying `status` and `message` thrown out of `resolveKeyAuth`
/// (`middlewares.js:453-462`); express 5 forwards the rejected promise, and `handleParseErrors`
/// renders it from its `err.status && err.message` branch (`middlewares.js:629-631`). Same status
/// and same body, different function, and the `Parse.Error` branch above it is what would have
/// added a `code`.
fn assert_unauthorized(response: &Response) {
    assert_eq!(response.status, 403, "{}", response.raw);
    assert_eq!(response.error(), "unauthorized");
    assert_eq!(response.code(), None, "upstream sends no code on this one");
}

#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_master_key_from_a_non_allowlisted_address_is_refused() {
    let server = boot_fresh_with(excluding_loopback).await;

    // The control first: the server is alive and the class is reachable without the master key.
    let ordinary = post(
        &server.host,
        "/classes/Post",
        &As::anonymous(),
        &json!({"title": "x"}),
    )
    .await;
    assert_eq!(ordinary.status, 201, "{}", ordinary.raw);

    assert_unauthorized(&get(&server.host, "/classes/Post", &As::master()).await);
    assert_unauthorized(&get(&server.host, "/schemas", &As::master()).await);
}

/// The control for the filter itself. The identical request against a server whose allowlist names
/// the caller succeeds, so the refusal above is the allowlist rather than a broken master key.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_same_request_succeeds_when_the_address_is_allowed() {
    let server = boot_fresh_with(|mut config: ServerConfig| {
        config.master_key_ips = IpAllowlist::parse([ELSEWHERE, "127.0.0.1"]).expect("entries");
        config
    })
    .await;
    let response = get(&server.host, "/schemas", &As::master()).await;
    assert_eq!(response.status, 200, "{}", response.raw);
}

/// The control for the shipped default. Every other test in this crate depends on it, but nothing
/// asserted it: a default of "deny everything" would leave those tests failing for a reason nobody
/// would attribute to this option.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_shipped_default_admits_loopback() {
    let server = boot().await;
    let response = get(&server.host, "/schemas", &As::master()).await;
    assert_eq!(response.status, 200, "{}", response.raw);
}

/// **The forgery case.** A caller who can spell an address must not be able to write itself into
/// the allowlist, in either direction.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_forwarded_header_cannot_move_a_caller_in_or_out() {
    let refusing = boot_fresh_with(excluding_loopback).await;
    for header in ["X-Forwarded-For", "Forwarded", "X-Real-IP"] {
        assert_unauthorized(
            &get(
                &refusing.host,
                "/schemas",
                &As::master().with_header(header, ELSEWHERE),
            )
            .await,
        );
    }

    // And the converse, so the header is inert rather than inverted: naming a refused address on a
    // request from an allowed one changes nothing.
    let allowing = boot().await;
    let response = get(
        &allowing.host,
        "/schemas",
        &As::master().with_header("X-Forwarded-For", ELSEWHERE),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.raw);
}

/// A refused master key must not fall through to client-key validation and be served as an
/// ordinary request. Upstream throws; a fall-through would answer 200 where upstream answers 403,
/// and would let a caller skip a check it would otherwise have to satisfy.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn a_refused_master_key_is_not_demoted_to_a_client_request() {
    let server = boot_fresh_with(excluding_loopback).await;
    // `/schemas` is master-only, so a demotion would show as 403 with a Parse code rather than as
    // the bare envelope. A route any client may reach shows it more plainly: a demoted request
    // would succeed outright.
    assert_unauthorized(
        &post(
            &server.host,
            "/classes/Post",
            &As::master(),
            &json!({"title": "x"}),
        )
        .await,
    );
}

/// The empty array means the key cannot be used at all, including from the machine the server runs
/// on. It is not "unset, therefore allow".
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn an_empty_allowlist_refuses_the_master_key_from_the_server_itself() {
    let server = boot_fresh_with(|mut config: ServerConfig| {
        config.master_key_ips = IpAllowlist::deny_all();
        config
    })
    .await;
    assert_unauthorized(&get(&server.host, "/schemas", &As::master()).await);
}

/// The maintenance key is filtered by its own option, with the same default.
#[tokio::test]
#[ignore = "needs MongoDB (PARSE_RUST_TEST_MONGO, default 127.0.0.1:27017)"]
async fn the_maintenance_key_carries_the_same_filter() {
    let refusing = boot_fresh_with(excluding_loopback).await;
    assert_unauthorized(
        &post(
            &refusing.host,
            "/classes/Post",
            &As::maintenance(),
            &json!({"title": "x"}),
        )
        .await,
    );

    let allowing = boot().await;
    let response = post(
        &allowing.host,
        "/classes/Post",
        &As::maintenance(),
        &json!({"title": "x"}),
    )
    .await;
    assert_eq!(response.status, 201, "{}", response.raw);
}
