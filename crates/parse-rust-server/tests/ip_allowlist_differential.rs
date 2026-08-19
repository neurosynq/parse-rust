//! `IpAllowlist` against upstream's `checkIp`, at the pin.
//!
//! **The unit test in `ip_allowlist.rs` asserts a committed table; this asserts the table is
//! upstream's.** Those are different claims, and the first one on its own is what let a wrong
//! table stand: it was derived from `net.BlockList` rather than from `checkIp`, which skips the
//! five allow-all literals entirely, and it blessed two answers broader than upstream. A table
//! nothing re-derives is a table that agrees with whatever produced it.
//!
//! `#[ignore]` because it needs node and the upstream checkout. Run via `tools/test.sh`.

use std::collections::BTreeSet;
use std::process::Command;

use parse_rust_server::IpAllowlist;

#[test]
#[ignore = "requires node and the upstream checkout; run via tools/test.sh"]
fn every_rule_and_peer_matches_upstreams_check_ip() {
    let oracle = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/ip-allowlist-oracle.js"
    );
    let out = Command::new("node")
        // Editors inject a debug bootloader through NODE_OPTIONS, which makes every node process
        // wait for a debugger and hang. A test must not inherit that.
        .env_remove("NODE_OPTIONS")
        .arg(oracle)
        .output()
        .expect("node must be on PATH; this test is #[ignore]d by default");
    assert!(
        out.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let payload = stdout
        .lines()
        .find_map(|l| l.strip_prefix("IP_ORACLE "))
        .unwrap_or_else(|| panic!("oracle emitted no IP_ORACLE line:\n{stdout}"));
    let emitted: serde_json::Value = serde_json::from_str(payload).expect("oracle emitted JSON");
    let rows = emitted["rows"].as_array().expect("rows").clone();

    // **The exact inventory, not a row count.** A count is satisfied by dropping one rule and
    // duplicating another, and a floor is satisfied by dropping one outright: with 11 rules and 7
    // peers, `>= 70` still passes having lost a whole rule. That is the same hole this release had
    // to fix in Gate E's assertion floor, so it is not repeated here.
    //
    // The axes are declared on both sides. The oracle emits the lists it iterated, and this test
    // asserts they are the lists it expects and that every pair appears exactly once, so a rule
    // that disappears from the script fails here rather than shrinking the matrix quietly.
    const RULES: [&str; 11] = [
        "::/0",
        "::",
        "::0",
        "0.0.0.0/0",
        "0.0.0.0",
        "127.0.0.1",
        "::1",
        "::/64",
        "10.0.0.0/8",
        "2000::/3",
        "::ffff:0.0.0.0/96",
    ];
    const PEERS: [&str; 7] = [
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "127.0.0.2",
        "10.1.2.3",
        "::ffff:10.1.2.3",
        "2001:db8::1",
    ];

    let axis = |key: &str| -> Vec<String> {
        emitted[key]
            .as_array()
            .unwrap_or_else(|| panic!("oracle emitted no {key}"))
            .iter()
            .map(|v| v.as_str().expect("string").to_string())
            .collect()
    };
    assert_eq!(axis("rules"), RULES, "the oracle's rule list changed");
    assert_eq!(axis("peers"), PEERS, "the oracle's peer list changed");

    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for row in &rows {
        let pair = (
            row["rule"].as_str().expect("rule").to_string(),
            row["peer"].as_str().expect("peer").to_string(),
        );
        assert!(seen.insert(pair.clone()), "duplicate row for {pair:?}");
    }
    let expected: BTreeSet<(String, String)> = RULES
        .iter()
        .flat_map(|r| PEERS.iter().map(move |p| (r.to_string(), p.to_string())))
        .collect();
    assert_eq!(
        seen, expected,
        "the oracle did not cover every rule against every peer exactly once"
    );

    let mut disagreements = Vec::new();
    for row in &rows {
        let rule = row["rule"].as_str().expect("rule");
        let peer = row["peer"].as_str().expect("peer");
        let upstream = row["allowed"].as_bool().expect("allowed");
        let ours = IpAllowlist::parse([rule])
            .expect("every oracle rule must parse")
            .allows(peer.parse().expect("every oracle peer must parse"));
        if ours != upstream {
            disagreements.push(format!(
                "[{rule}] against {peer}: upstream {upstream}, parse-rust {ours}"
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} of {} rows disagree with upstream:\n  {}",
        disagreements.len(),
        rows.len(),
        disagreements.join("\n  ")
    );
}
