//! bcrypt interop with parse-server, in both directions.
//!
//! The requirement: a `_User` row written by parse-rust must be loginable by parse-server, and a
//! row written by parse-server must be loginable by parse-rust, against the same database. That
//! is a mixed-fleet property and it is invisible until a second server exists, which is exactly
//! why it is checked now rather than at the end of the auth work.
//!
//! `#[ignore]` because it shells out to node and requires the upstream checkout's `node_modules`
//! for the same bcrypt implementation parse-server uses. Run via `tools/test.sh`.

use std::process::Command;

/// Where the upstream checkout lives.
///
/// Defaults to a sibling of this repository so the two-repos-side-by-side layout works for
/// anyone; override with `PARSE_SERVER_ROOT`. A home-directory path here worked only on one
/// machine, which is a poor property for a test that exists to prove interoperability.
fn ps_root() -> String {
    // **Resolved against the workspace root, including the override.** A relative
    // `PARSE_SERVER_ROOT` such as `../parse-server-pinned` is relative to the repository, not to
    // this crate, and using it raw looked for it beside `crates/parse-rust-auth/`. That path is
    // how a pinned worktree is selected, so it has to work.
    let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    match std::env::var("PARSE_SERVER_ROOT") {
        Ok(p) if std::path::Path::new(&p).is_absolute() => p,
        Ok(p) => format!("{root}/{p}"),
        Err(_) => format!("{root}/../parse-server"),
    }
}

fn node(script: &str) -> String {
    let out = Command::new("node")
        // See the note in the other differentials: an editor's NODE_OPTIONS debug bootloader
        // makes every node process hang waiting for a debugger.
        .env_remove("NODE_OPTIONS")
        .arg("-e")
        .arg(script)
        .output()
        .expect("node must be on PATH; this test is #[ignore]d by default");
    assert!(
        out.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The two modules parse-server can load, with the prefix each writes.
///
/// `password.js` requires `bcryptjs`, then replaces it with `@node-rs/bcrypt` when that is
/// installed (`password.js:3-14`), which it is in an ordinary install. So a stock parse-server
/// writes `$2y$` hashes and one without the native module writes `$2b$`, and a fleet can hold both.
const MODULES: [(&str, &str); 2] = [("bcryptjs", "$2b$10$"), ("@node-rs/bcrypt", "$2y$10$")];

/// A script prelude defining `hash(p)` and `verify(p, h)` over one module, synchronously.
fn module(name: &str) -> String {
    let path = format!("{}/node_modules/{name}", ps_root());
    if name == "bcryptjs" {
        format!(
            "const m = require({path:?}); \
             const hash = p => m.hashSync(p, 10); const verify = (p, h) => m.compareSync(p, h);"
        )
    } else {
        format!(
            "const m = require({path:?}); \
             const hash = p => m.hashSync(p, 10); const verify = (p, h) => m.verifySync(p, h);"
        )
    }
}

fn node_hash(name: &str, password: &str) -> String {
    node(&format!(
        "{} console.log(hash({}));",
        module(name),
        js(password)
    ))
}

fn node_verify(name: &str, password: &str, hash: &str) -> bool {
    node(&format!(
        "{} console.log(verify({}, {hash:?}));",
        module(name),
        js(password)
    )) == "true"
}

/// A JavaScript string literal. JSON's escaping is valid JavaScript, a NUL included.
fn js(s: &str) -> String {
    serde_json::to_string(s).expect("a string serializes")
}

async fn rust_hash(password: &str) -> String {
    parse_rust_auth::password::hash(password.into())
        .await
        .expect("hash")
}

async fn rust_verify(password: &str, hash: &str) -> bool {
    parse_rust_auth::password::verify(password.into(), hash.into()).await
}

#[tokio::test]
#[ignore = "requires node and the upstream checkout; run via tools/test.sh"]
async fn rust_hash_verifies_in_parse_servers_bcrypt() {
    let h = rust_hash("hunter2").await;
    for (name, _) in MODULES {
        assert!(node_verify(name, "hunter2", &h), "{name} rejected {h}");
        assert!(
            !node_verify(name, "wrong", &h),
            "{name} accepted a wrong password"
        );
    }
}

#[tokio::test]
#[ignore = "requires node and the upstream checkout; run via tools/test.sh"]
async fn parse_servers_hash_verifies_in_rust() {
    for (name, _) in MODULES {
        let h = node_hash(name, "hunter2");
        assert!(
            rust_verify("hunter2", &h).await,
            "{name}'s hash rejected: {h}"
        );
        assert!(
            !rust_verify("wrong", &h).await,
            "{name}'s hash accepted a wrong password"
        );
    }
}

#[tokio::test]
#[ignore = "requires node and the upstream checkout; run via tools/test.sh"]
async fn the_prefix_question_is_answered_rather_than_assumed() {
    // Exact, not `$2`: a dependency bump that changes what either side writes is what this exists
    // to catch, and `$2b$` against `$2y$` is the difference between the two modules upstream uses.
    let rust = rust_hash("x").await;
    assert!(
        rust.starts_with("$2b$10$"),
        "unexpected rust format: {rust}"
    );
    for (name, prefix) in MODULES {
        let h = node_hash(name, "x");
        assert!(h.starts_with(prefix), "unexpected {name} format: {h}");
    }
}

/// Passwords bcrypt treats specially: over 72 bytes, where it truncates, and with a NUL, where a
/// C-string implementation stops reading. Whatever each side does, both must do the same, or a
/// password set on one server fails to log in on the other, or a different one succeeds.
#[tokio::test]
#[ignore = "requires node and the upstream checkout; run via tools/test.sh"]
async fn edge_passwords_agree_in_both_directions() {
    let long = "p".repeat(80);
    let long_tail = format!("{}{}", &long[..72], "different tail");
    let cases = [
        (long.as_str(), long_tail.as_str()),
        ("a\0b", "a\0c"),
        ("a\0b", "a"),
    ];
    for (name, _) in MODULES {
        for (password, probe) in cases {
            let from_rust = rust_hash(password).await;
            let from_node = node_hash(name, password);
            assert!(
                node_verify(name, password, &from_rust),
                "{name}: {password:?}"
            );
            assert!(
                rust_verify(password, &from_node).await,
                "{name}: {password:?}"
            );
            // The probe matches or not as each side decides, but the sides must agree.
            assert_eq!(
                node_verify(name, probe, &from_rust),
                rust_verify(probe, &from_rust).await,
                "{name}: {probe:?} against a rust hash of {password:?}"
            );
            assert_eq!(
                node_verify(name, probe, &from_node),
                rust_verify(probe, &from_node).await,
                "{name}: {probe:?} against its own hash of {password:?}"
            );
        }
    }
}
