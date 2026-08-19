#!/usr/bin/env node
/*
 * Oracle for `masterKeyIps` and `maintenanceKeyIps` matching.
 *
 * **Drives `checkIp`, which is the function the server calls, and not `net.BlockList`.** The
 * distinction is the whole reason this file exists. `checkIp` is a wrapper with real semantics in
 * it: `getBlockList` intercepts five allow-all literals by string comparison, sets an
 * `allowAllIpv4` or `allowAllIpv6` flag and adds nothing to the block list, and `checkIp` then
 * consults those flags against the peer's own address family (`middlewares.js:27-64`).
 *
 * A first version of the parse-rust implementation was measured against `BlockList` directly. That
 * layer knows nothing about the five literals, so it answered `true` where the server answers
 * `false` in both directions: an IPv4 peer under `::/0`, and an IPv4-mapped peer under
 * `0.0.0.0/0`. Both widen a configured authorization boundary, and the measurement blessed them.
 *
 * Prints one `IP_ORACLE <json>` line: an array of `{rule, peer, allowed}`. The Rust side compares
 * against the table committed in `crates/parse-rust-server/src/ip_allowlist.rs`.
 */
'use strict';

// Resolve the parse-server checkout relative to this repository rather than to a home directory,
// so the default works for anyone with the two repos side by side. Override with
// PARSE_SERVER_ROOT when it lives elsewhere, resolved absolutely so a relative override is read
// against the repository and not against `tools/`.
const PS_ROOT = require('path').resolve(
  __dirname, '..', process.env.PARSE_SERVER_ROOT || '../parse-server',
);

const { checkIp } = require(`${PS_ROOT}/lib/middlewares.js`);

// Every rule the Rust table covers, and every peer worth asking about each: the two loopback
// forms, the IPv4-mapped form of each, a non-allowlisted IPv4, and a genuine global IPv6.
const RULES = [
  '::/0', '::', '::0',
  '0.0.0.0/0', '0.0.0.0',
  '127.0.0.1', '::1',
  '::/64', '10.0.0.0/8', '2000::/3', '::ffff:0.0.0.0/96',
];
const PEERS = [
  '127.0.0.1', '::1', '::ffff:127.0.0.1',
  '127.0.0.2', '10.1.2.3', '::ffff:10.1.2.3', '2001:db8::1',
];

const rows = [];
for (const rule of RULES) {
  for (const peer of PEERS) {
    // A fresh store per call. The store memoizes both the block list and previously-admitted
    // addresses, so reusing one across rules would answer for the first rule seen.
    rows.push({ rule, peer, allowed: checkIp(peer, [rule], new Map()) });
  }
}

// The axes travel with the rows so the Rust side can assert the **exact** inventory rather than a
// row count. A count alone is satisfied by dropping one rule and duplicating another, which is the
// same shape of hole this release already had to fix in Gate E's floor.
console.log(`IP_ORACLE ${JSON.stringify({ rules: RULES, peers: PEERS, rows })}`);
