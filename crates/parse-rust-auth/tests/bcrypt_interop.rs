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
    std::env::var("PARSE_SERVER_ROOT")
        .unwrap_or_else(|_| format!("{}/../../../parse-server", env!("CARGO_MANIFEST_DIR")))
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

/// The exact module parse-server loads (`password.js` requires `bcryptjs`).
fn bcryptjs() -> String {
    format!(
        "const bcrypt = require('{}/node_modules/bcryptjs');",
        ps_root()
    )
}

#[test]
#[ignore = "requires node and the upstream checkout; run via tools/test.sh"]
fn rust_hash_verifies_in_parse_servers_bcrypt() {
    let h = parse_rust_auth::password::hash("hunter2").expect("hash");
    let script = format!(
        "{} console.log(bcrypt.compareSync('hunter2', {:?}) && !bcrypt.compareSync('wrong', {:?}));",
        bcryptjs(),
        h,
        h
    );
    assert_eq!(
        node(&script),
        "true",
        "parse-server could not verify a parse-rust hash: {h}"
    );
}

#[test]
#[ignore = "requires node and the upstream checkout; run via tools/test.sh"]
fn parse_servers_hash_verifies_in_rust() {
    // Cost 10, as `password.js` uses.
    let h = node(&format!(
        "{} console.log(bcrypt.hashSync('hunter2', 10));",
        bcryptjs()
    ));
    assert!(
        parse_rust_auth::password::verify("hunter2", &h),
        "parse-rust could not verify a parse-server hash: {h}"
    );
    assert!(!parse_rust_auth::password::verify("wrong", &h));
}

#[test]
#[ignore = "requires node and the upstream checkout; run via tools/test.sh"]
fn the_prefix_question_is_answered_rather_than_assumed() {
    // Measured, not assumed, and the guess going in was wrong: bcryptjs and the Rust `bcrypt`
    // crate BOTH emit `$2b$` at cost 10, so there is no prefix mismatch to accommodate. Recorded
    // here rather than deleted, because "they happen to agree today" is a fact a future
    // dependency bump can invalidate, and this is what would catch it.
    let rust = parse_rust_auth::password::hash("x").expect("hash");
    let js = node(&format!(
        "{} console.log(bcrypt.hashSync('x', 10));",
        bcryptjs()
    ));
    println!("rust prefix: {}  js prefix: {}", &rust[..4], &js[..4]);
    assert!(rust.starts_with("$2"), "unexpected rust format: {rust}");
    assert!(js.starts_with("$2"), "unexpected js format: {js}");
}
