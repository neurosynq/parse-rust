//! Differential test: every number parse-rust-core emits must match what Node emits.
//!
//! The unit tests in `js_number` assert against expectations pasted from Node. This asserts
//! against Node itself, across a corpus large enough that the four known divergence rules could
//! not all have been guessed correctly by accident.
//!
//! Marked `#[ignore]` because it shells out to `node`, and a unit test suite that silently
//! requires an external runtime is a unit test suite that breaks on someone else's machine.
//! Run it explicitly, or via `tools/test.sh`, which is what CI uses:
//!
//! ```text
//! cargo test -p parse-rust-core -- --ignored
//! ```

use std::io::Write;
use std::process::{Command, Stdio};

use parse_rust_core::js_number::to_ecma_string;

/// Values chosen because they sit on a rule boundary, not because they look interesting.
fn edge_cases() -> Vec<f64> {
    let mut v = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.1,
        0.5,
        1.5,
        -1.5,
        // The upper switch to exponential, either side of 1e21.
        1e20,
        9.999_999_999_999_999e20,
        1e21,
        1.000_000_000_000_000_1e21,
        1e22,
        // The lower switch, either side of 1e-7.
        1e-5,
        1e-6,
        9.999e-7,
        1e-7,
        1e-8,
        // Integer widths up to the 21-digit ceiling.
        1e15,
        1e16,
        1e17,
        1e18,
        1e19,
        123_456_789_012_345_678_901.0,
        // Precision limits.
        9_007_199_254_740_992.0, // 2^53
        9_007_199_254_740_994.0, // 2^53 + 2
        f64::MAX,
        f64::MIN_POSITIVE,
        5e-324, // smallest subnormal
        f64::EPSILON,
        // Non-finite. The oracle compares these via String(), not JSON.stringify.
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];
    // Powers of ten across the whole range, both signs.
    for e in -323i32..=308 {
        let p = format!("1e{e}").parse::<f64>().unwrap_or(0.0);
        if p != 0.0 {
            v.push(p);
            v.push(-p);
        }
    }
    // Small integers and simple decimals, where the "no trailing .0" rule bites hardest.
    for i in 0..1000 {
        v.push(i as f64);
        v.push(-(i as f64));
        v.push(i as f64 / 8.0);
        v.push(i as f64 * 1e6);
    }
    v
}

/// Deterministic pseudo-random bit patterns. A fixed seed so a failure is reproducible from the
/// log line alone; a randomized corpus that fails once and never again trains people to re-run.
fn random_bit_patterns(count: usize) -> Vec<f64> {
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        // xorshift64*
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let bits = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        out.push(f64::from_bits(bits));
    }
    out
}

#[test]
#[ignore = "requires node; run with --ignored or via tools/test.sh"]
fn every_formatted_number_matches_node() {
    let mut corpus = edge_cases();
    corpus.extend(random_bit_patterns(200_000));

    let mut tsv = String::with_capacity(corpus.len() * 32);
    for v in &corpus {
        tsv.push_str(&v.to_bits().to_string());
        tsv.push('\t');
        tsv.push_str(&to_ecma_string(*v));
        tsv.push('\n');
    }

    let oracle = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/js-number-oracle.js"
    );
    let mut child = Command::new("node")
        // Editors inject a debug bootloader through NODE_OPTIONS, which makes every node process
        // wait for a debugger and hang. A test must not inherit that.
        .env_remove("NODE_OPTIONS")
        .arg(oracle)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node must be on PATH for this test; it is #[ignore]d by default");

    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(tsv.as_bytes())
        .expect("failed writing corpus to node");

    let out = child
        .wait_with_output()
        .expect("node did not run to completion");

    assert!(
        out.status.success(),
        "js_number diverges from Node.\n{}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    println!("{}", String::from_utf8_lossy(&out.stdout).trim());
}
