#!/usr/bin/env node
/*
 * Differential oracle for parse-rust-core's `js_number` formatter.
 *
 * Reads TSV on stdin: <f64 bit pattern as unsigned decimal>\t<what Rust produced>
 * For each row, reconstructs the double from its bits, formats it the way Parse Server would
 * (JSON.stringify, i.e. ECMAScript Number::toString), and compares.
 *
 * Comparing by bit pattern rather than by decimal text is deliberate: it removes any question
 * of whether the two sides parsed the same literal, which is exactly the kind of ambiguity that
 * would make a passing run meaningless.
 *
 * Exits non-zero on the first divergence class found, printing a bounded sample.
 */
'use strict';

const MAX_REPORTED = 20;

function main() {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', d => { input += d; });
  process.stdin.on('end', () => {
    const buf = new ArrayBuffer(8);
    const asF64 = new Float64Array(buf);
    const asU64 = new BigUint64Array(buf);

    let checked = 0;
    const mismatches = [];

    for (const line of input.split('\n')) {
      if (!line) { continue; }
      const tab = line.indexOf('\t');
      if (tab < 0) {
        console.error(`malformed row: ${JSON.stringify(line)}`);
        process.exit(2);
      }
      const bits = BigInt(line.slice(0, tab));
      const ours = line.slice(tab + 1);

      asU64[0] = bits;
      const value = asF64[0];

      // JSON.stringify renders non-finite as null; the Rust side is asked for the
      // Number::toString form, so those are compared via String() instead.
      const expected = Number.isFinite(value) ? JSON.stringify(value) : String(value);

      checked++;
      if (expected !== ours) {
        if (mismatches.length < MAX_REPORTED) {
          mismatches.push({ bits: bits.toString(), value, expected, ours });
        }
      }
    }

    if (mismatches.length) {
      console.error(`FAIL: ${mismatches.length}+ mismatches out of ${checked} values\n`);
      for (const m of mismatches) {
        console.error(`  bits=${m.bits}`);
        console.error(`    node: ${m.expected}`);
        console.error(`    rust: ${m.ours}`);
      }
      process.exit(1);
    }

    console.log(`OK: ${checked} values match Node exactly`);
  });
}

main();
