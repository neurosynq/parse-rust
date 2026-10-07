//! The address allowlist behind `masterKeyIps` and `maintenanceKeyIps`.
//!
//! Upstream builds a `net.BlockList` from the configured entries and asks it about the request's
//! peer address (`middlewares.js:50-64`). The default for both options is the two literal
//! addresses `127.0.0.1` and `::1` (`Options/Definitions.js:391-394`, `:396-399`), which is why an
//! unimplemented option is an open control rather than a missing feature: a stock parse-server
//! honours the master key only from the machine it runs on.
//!
//! # Two mechanisms, and measuring only one of them gets both wrong
//!
//! Upstream's check is `checkIp`, not `BlockList.check`, and the wrapper is not a thin one. It
//! implements **five allow-all literals that never reach the block list at all**: `getBlockList`
//! compares each configured entry against `'::/0'`, `'::'`, `'::0'`, `'0.0.0.0/0'` and `'0.0.0.0'`
//! by string, sets `allowAllIpv6` or `allowAllIpv4`, and `return`s without adding anything
//! (`middlewares.js:27-48`). `checkIp` then consults those flags **against the peer's own address
//! family**, where `isIPv4` is false for an IPv4-mapped IPv6 address (`middlewares.js:50-64`).
//!
//! Everything else does go to the block list, which works in one 128-bit space where an IPv4
//! address is its IPv4-mapped form. So there are two rules, not one:
//!
//! - **The five literals are family-scoped.** `::/0` admits every IPv6 peer, mapped ones included,
//!   and **no** IPv4 peer. `0.0.0.0/0` admits every IPv4 peer and **no** IPv6 peer, mapped ones
//!   included. Bare `::`, `::0` and `0.0.0.0` mean the same as their `/0` spellings rather than
//!   naming one address.
//! - **Every other entry is matched in IPv6 space**, so an IPv4 rule `a.b.c.d/n` becomes
//!   `::ffff:a.b.c.d/(96+n)`, `127.0.0.1` matches a peer of `::ffff:127.0.0.1`, and `::/64` matches
//!   an IPv4 peer because the mapped form's top 64 bits are zero.
//!
//! Measured through `checkIp` on the Node that builds the pinned parse-server, and the table is
//! asserted below rather than described:
//!
//! | rule | `127.0.0.1` | `::1` | `::ffff:127.0.0.1` |
//! |---|---|---|---|
//! | `::/0`, `::`, `::0` | no | yes | yes |
//! | `0.0.0.0/0`, `0.0.0.0` | yes | no | no |
//! | `127.0.0.1` | yes | no | yes |
//! | `::1` | no | yes | no |
//! | `::/64` | yes | yes | yes |
//!
//! **An earlier version of this module drove `BlockList` directly and produced the wrong answer in
//! both directions**, admitting an IPv4 peer under `::/0` and a mapped peer under `0.0.0.0/0`,
//! because neither special case exists at that layer. The test below therefore measures the same
//! layer the server uses. Nothing here is derived from the option's help text, which says the two
//! families "are not compared against each other" and is true only of the block-list half.

use std::net::IpAddr;

/// One entry: a single address, or a CIDR range, held in IPv6 space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rule {
    /// Masked to `prefix` bits at parse time, as `BlockList.addSubnet` does: a base that is not
    /// the network address of its own prefix is accepted and canonicalized rather than refused.
    network: u128,
    prefix: u8,
}

impl Rule {
    fn contains(&self, probe: u128) -> bool {
        if self.prefix == 0 {
            return true;
        }
        (probe ^ self.network) >> (128 - self.prefix) == 0
    }
}

/// Why an entry could not be read.
///
/// **Upstream validates too, and this is mostly the same refusal rather than an extra one.**
/// `Config.validateIps` runs at boot and rejects any entry whose address portion is not an IP,
/// naming it (`Config.js:632-641`).
///
/// Where it is stricter is the **mask**, which upstream strips before checking and then reads
/// loosely. Three entries upstream accepts are refused here, all measured through `checkIp` at the
/// pin: `127.0.0.1/999` boots there and throws out of `BlockList.addSubnet` on the first master-key
/// request; `127.0.0.1/` has an empty mask, which `!mask` reads as absent, so it becomes a bare
/// address; and `127.0.0.1/32/ignored` is destructured to its first two parts with the rest
/// discarded. Note that the differential does not cover any of them: it drives `checkIp` with
/// well-formed rules and says nothing about parsing, so these were measured by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidIpEntry(pub String);

impl std::fmt::Display for InvalidIpEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not an IP address or CIDR range: {}", self.0)
    }
}

impl std::error::Error for InvalidIpEntry {}

/// The addresses a privileged key may be presented from.
///
/// **There is no "unset" state.** An empty allowlist means the key cannot be used at all, which is
/// upstream's documented behavior for an empty array, and a `ServerConfig` that never sets the
/// field gets [`IpAllowlist::default`], which is upstream's default rather than "allow anything".
/// The type deliberately offers no way to spell "no filter" except by writing the range out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAllowlist {
    rules: Vec<Rule>,
    /// `'0.0.0.0/0'` or `'0.0.0.0'` was configured: every IPv4 peer is admitted, and no IPv6 peer,
    /// **including an IPv4-mapped one**.
    allow_all_v4: bool,
    /// `'::/0'`, `'::'` or `'::0'` was configured: every IPv6 peer is admitted, mapped ones
    /// included, and no IPv4 peer.
    allow_all_v6: bool,
    /// The entries as configured, for reporting what the server runs with. Never consulted for a
    /// decision.
    source: Vec<String>,
}

/// The five entries `getBlockList` intercepts before the block list sees them
/// (`middlewares.js:30-38`). Matched as strings, exactly as upstream matches them, so a spelling
/// that is numerically equivalent but textually different (`0000::/0`, `0.0.0.0/32`) is an
/// ordinary rule under both servers.
const ALLOW_ALL_V6: [&str; 3] = ["::/0", "::", "::0"];
const ALLOW_ALL_V4: [&str; 2] = ["0.0.0.0/0", "0.0.0.0"];

impl Default for IpAllowlist {
    /// `['127.0.0.1', '::1']`: only the machine the server runs on.
    fn default() -> Self {
        Self {
            rules: vec![
                rule_of(IpAddr::from([127, 0, 0, 1]), None),
                rule_of(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]), None),
            ],
            allow_all_v4: false,
            allow_all_v6: false,
            source: vec!["127.0.0.1".into(), "::1".into()],
        }
    }
}

impl IpAllowlist {
    /// The entries this allowlist was built from, as written.
    pub fn entries(&self) -> &[String] {
        &self.source
    }

    /// Read a list of entries, each a bare address, an `address/prefix`, or one of the five
    /// allow-all literals.
    pub fn parse<I, S>(entries: I) -> Result<Self, InvalidIpEntry>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Self::deny_all();
        for entry in entries {
            let entry = entry.as_ref();
            out.source.push(entry.to_string());
            if ALLOW_ALL_V6.contains(&entry) {
                out.allow_all_v6 = true;
            } else if ALLOW_ALL_V4.contains(&entry) {
                out.allow_all_v4 = true;
            } else {
                out.rules.push(parse_entry(entry)?);
            }
        }
        Ok(out)
    }

    /// The comma-separated spelling an environment variable carries
    /// (`PARSE_SERVER_MASTER_KEY_IPS`).
    ///
    /// **Neither trimmed nor tolerant of an empty value**, because upstream is neither.
    /// `arrayParser` is `opt.split(',')` and nothing else (`Options/parsers.js:42-50`), and
    /// `Config.validateIps` then rejects any entry whose address portion is not an IP
    /// (`Config.js:632-641`). So `"127.0.0.1, ::1"` yields `" ::1"` and refuses to boot upstream,
    /// and so does an empty value, and both refuse to boot here with the offending entry named.
    ///
    /// Trimming looked like a harmless courtesy and it is a divergence in what a configuration
    /// means: a deployment whose variable boots one server and not the other is worse off than one
    /// that is told about the space.
    pub fn parse_env(value: &str) -> Result<Self, InvalidIpEntry> {
        Self::parse(value.split(','))
    }

    /// The empty array: the key cannot be used from anywhere, including the server itself.
    ///
    /// Reachable only from Rust, which is upstream's situation too: there is no way to pass an
    /// empty array through an environment variable, and the option's help text says so.
    pub fn deny_all() -> Self {
        Self {
            rules: Vec::new(),
            allow_all_v4: false,
            allow_all_v6: false,
            source: Vec::new(),
        }
    }

    /// Is this peer allowed to present the key?
    ///
    /// The family test is `isIPv4`, which is **false for an IPv4-mapped IPv6 address**. That is
    /// what makes `0.0.0.0/0` refuse a peer of `::ffff:127.0.0.1` upstream, so the mapped form is
    /// deliberately not unwrapped here even though the block-list half below treats it as the
    /// same address.
    pub fn allows(&self, peer: IpAddr) -> bool {
        let peer_is_v4 = matches!(peer, IpAddr::V4(_));
        if peer_is_v4 && self.allow_all_v4 {
            return true;
        }
        if !peer_is_v4 && self.allow_all_v6 {
            return true;
        }
        let probe = to_v6(peer);
        self.rules.iter().any(|r| r.contains(probe))
    }

    /// True when no address at all is permitted.
    pub fn is_deny_all(&self) -> bool {
        self.rules.is_empty() && !self.allow_all_v4 && !self.allow_all_v6
    }
}

fn parse_entry(entry: &str) -> Result<Rule, InvalidIpEntry> {
    let invalid = || InvalidIpEntry(entry.to_string());
    let (address, mask) = match entry.split_once('/') {
        Some((a, m)) => (a, Some(m.parse::<u8>().map_err(|_| invalid())?)),
        None => (entry, None),
    };
    let address: IpAddr = address.parse().map_err(|_| invalid())?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    if mask.is_some_and(|m| m > width) {
        return Err(invalid());
    }
    Ok(rule_of(address, mask))
}

/// Lift an address and an optional family-relative mask into the shared IPv6 space.
fn rule_of(address: IpAddr, mask: Option<u8>) -> Rule {
    let prefix = match address {
        // An IPv4 rule occupies the `::ffff:0:0/96` block, so its prefix is offset by 96. That
        // offset is what keeps a genuine IPv6 peer outside every IPv4 rule, including `0.0.0.0/0`.
        IpAddr::V4(_) => 96 + mask.unwrap_or(32),
        IpAddr::V6(_) => mask.unwrap_or(128),
    };
    let network = to_v6(address);
    Rule {
        network: mask_to(network, prefix),
        prefix,
    }
}

fn mask_to(value: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        value & (u128::MAX << (128 - prefix))
    }
}

/// The 128-bit form: an IPv4 address becomes `::ffff:a.b.c.d`, which is the same address written
/// the other way and is how upstream's block list sees it.
fn to_v6(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    fn list(entries: &[&str]) -> IpAllowlist {
        IpAllowlist::parse(entries).expect("test entries")
    }

    /// The shipped default, and the defect this release closes. 0.2.0 honoured the master key from
    /// every one of the refused addresses below.
    #[test]
    fn the_default_is_loopback_only() {
        let allow = IpAllowlist::default();
        for peer in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert!(allow.allows(ip(peer)), "{peer} must be allowed");
        }
        for peer in [
            "127.0.0.2",
            "::ffff:127.0.0.2",
            "10.0.0.1",
            "192.168.1.10",
            "::2",
            "2001:db8::1",
        ] {
            assert!(!allow.allows(ip(peer)), "{peer} must be refused");
        }
    }

    /// The oracle table, in the order `tools/ip-allowlist-oracle.js` prints it.
    ///
    /// **Measured through `checkIp`, not through `BlockList`.** The first version of this table
    /// drove the block list directly, which skips the five allow-all literals entirely, and it
    /// blessed two answers that were broader than upstream: an IPv4 peer admitted by `::/0` and a
    /// mapped peer admitted by `0.0.0.0/0`. A differential that measures the wrong layer is worth
    /// less than no differential, because it reads as confirmation.
    ///
    /// `cargo test -p parse-rust-server --ignored ip_allowlist` re-derives it from the pinned
    /// checkout, so this cannot drift silently.
    const ORACLE: &[(&str, &[(&str, bool)])] = &[
        (
            "::/0",
            &[
                ("127.0.0.1", false),
                ("::1", true),
                ("::ffff:127.0.0.1", true),
                ("127.0.0.2", false),
                ("10.1.2.3", false),
                ("::ffff:10.1.2.3", true),
                ("2001:db8::1", true),
            ],
        ),
        (
            "::",
            &[
                ("127.0.0.1", false),
                ("::1", true),
                ("::ffff:127.0.0.1", true),
                ("2001:db8::1", true),
            ],
        ),
        (
            "::0",
            &[
                ("127.0.0.1", false),
                ("::1", true),
                ("::ffff:127.0.0.1", true),
                ("2001:db8::1", true),
            ],
        ),
        (
            "0.0.0.0/0",
            &[
                ("127.0.0.1", true),
                ("::1", false),
                ("::ffff:127.0.0.1", false),
                ("127.0.0.2", true),
                ("10.1.2.3", true),
                ("::ffff:10.1.2.3", false),
                ("2001:db8::1", false),
            ],
        ),
        (
            "0.0.0.0",
            &[
                ("127.0.0.1", true),
                ("::1", false),
                ("::ffff:127.0.0.1", false),
                ("10.1.2.3", true),
            ],
        ),
        (
            "127.0.0.1",
            &[
                ("127.0.0.1", true),
                ("::1", false),
                ("::ffff:127.0.0.1", true),
                ("127.0.0.2", false),
                ("10.1.2.3", false),
            ],
        ),
        (
            "::1",
            &[
                ("127.0.0.1", false),
                ("::1", true),
                ("::ffff:127.0.0.1", false),
            ],
        ),
        (
            "::/64",
            &[
                ("127.0.0.1", true),
                ("::1", true),
                ("::ffff:127.0.0.1", true),
                ("10.1.2.3", true),
                ("2001:db8::1", false),
            ],
        ),
        (
            "10.0.0.0/8",
            &[
                ("127.0.0.1", false),
                ("::ffff:127.0.0.1", false),
                ("10.1.2.3", true),
                ("::ffff:10.1.2.3", true),
                ("2001:db8::1", false),
            ],
        ),
        (
            "2000::/3",
            &[
                ("127.0.0.1", false),
                ("::ffff:127.0.0.1", false),
                ("2001:db8::1", true),
            ],
        ),
        (
            "::ffff:0.0.0.0/96",
            &[
                ("127.0.0.1", true),
                ("::1", false),
                ("::ffff:127.0.0.1", true),
                ("10.1.2.3", true),
            ],
        ),
    ];

    #[test]
    fn every_oracle_row_matches() {
        for (rule, peers) in ORACLE {
            let allow = list(&[rule]);
            for (peer, expected) in *peers {
                assert_eq!(allow.allows(ip(peer)), *expected, "[{rule}] against {peer}");
            }
        }
    }

    /// The two rows the block-list-only reading got backwards, called out on their own because
    /// they are the ones that widen a configured boundary rather than narrow it.
    #[test]
    fn the_allow_all_literals_are_scoped_to_one_family() {
        assert!(
            !list(&["::/0"]).allows(ip("127.0.0.1")),
            "::/0 is allowAllIpv6 and an IPv4 peer is not IPv6"
        );
        assert!(
            !list(&["0.0.0.0/0"]).allows(ip("::ffff:127.0.0.1")),
            "isIPv4 is false for a mapped address, so allowAllIpv4 does not apply to it"
        );
        // Both together is upstream's documented way to disable the filter entirely.
        let both = list(&["0.0.0.0/0", "::0"]);
        for peer in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "2001:db8::1"] {
            assert!(both.allows(ip(peer)), "{peer}");
        }
    }

    /// The bare spellings mean "all of this family", not "this one address". `::` as an ordinary
    /// rule would match only the unspecified address, and `0.0.0.0` only itself.
    #[test]
    fn the_bare_spellings_are_allow_all_rather_than_one_address() {
        assert!(list(&["::"]).allows(ip("2001:db8::1")));
        assert!(list(&["0.0.0.0"]).allows(ip("203.0.113.9")));
    }

    /// Matched as strings, exactly as upstream matches them, so an equivalent-but-different
    /// spelling stays an ordinary rule on both sides.
    #[test]
    fn a_numerically_equivalent_spelling_is_not_a_special_case() {
        // `0.0.0.0/32` is an ordinary /32, so it matches only the unspecified address.
        assert!(!list(&["0.0.0.0/32"]).allows(ip("127.0.0.1")));
    }

    /// A genuine IPv6 peer is not let in by an IPv4 range and the converse.
    #[test]
    fn the_two_families_stay_separate_for_genuine_addresses() {
        assert!(!list(&["0.0.0.0/0"]).allows(ip("2001:db8::1")));
        assert!(!list(&["2000::/3"]).allows(ip("32.0.0.1")));
    }

    #[test]
    fn cidr_ranges_match_by_prefix() {
        let allow = list(&["10.0.1.0/24", "2001:db8::/32"]);
        assert!(allow.allows(ip("10.0.1.0")));
        assert!(allow.allows(ip("10.0.1.255")));
        assert!(!allow.allows(ip("10.0.2.0")));
        assert!(allow.allows(ip("2001:db8:1234::9")));
        assert!(!allow.allows(ip("2001:db9::1")));
    }

    /// `BlockList.addSubnet` accepts a base that is not its own network address and canonicalizes
    /// it. Refusing it instead would reject a configuration upstream runs.
    #[test]
    fn a_non_canonical_base_is_masked_rather_than_refused() {
        let allow = list(&["10.0.1.5/24"]);
        assert!(allow.allows(ip("10.0.1.7")));
        assert!(allow.allows(ip("10.0.1.5")));
        assert!(!allow.allows(ip("10.0.2.7")));
    }

    /// The empty array is not "unset, therefore allow". It is upstream's documented way to say the
    /// key cannot be used at all.
    #[test]
    fn an_empty_allowlist_denies_everything_including_loopback() {
        let allow = IpAllowlist::deny_all();
        assert!(allow.is_deny_all());
        for peer in ["127.0.0.1", "::1", "10.0.0.1"] {
            assert!(!allow.allows(ip(peer)));
        }
        assert_eq!(
            IpAllowlist::parse::<[&str; 0], &str>([]).expect("empty"),
            allow
        );
    }

    #[test]
    fn the_env_spelling_is_comma_separated() {
        let allow = IpAllowlist::parse_env("127.0.0.1,10.0.1.0/24,::1").expect("parse");
        assert!(allow.allows(ip("127.0.0.1")));
        assert!(allow.allows(ip("10.0.1.9")));
        assert!(allow.allows(ip("::1")));
        assert!(!allow.allows(ip("10.0.2.9")));
    }

    /// **Not trimmed, and an empty value is not deny-all**, because upstream is neither.
    /// `arrayParser` splits and nothing else, and `Config.validateIps` then refuses `" ::1"` and
    /// `""` by name. A variable that boots one server and not the other is the divergence worth
    /// avoiding; being told about the space is not.
    #[test]
    fn the_env_spelling_matches_upstreams_strictness() {
        assert_eq!(
            IpAllowlist::parse_env("127.0.0.1, ::1").expect_err("space"),
            InvalidIpEntry(" ::1".to_string())
        );
        assert_eq!(
            IpAllowlist::parse_env("").expect_err("empty"),
            InvalidIpEntry(String::new())
        );
        assert_eq!(
            IpAllowlist::parse_env("  ").expect_err("blank"),
            InvalidIpEntry("  ".to_string())
        );
    }

    /// The one place this is deliberately stricter than upstream: an out-of-range prefix.
    /// `Config.validateIps` strips the mask before checking (`Config.js:634-636`), so
    /// `127.0.0.1/999` boots, and `BlockList.addSubnet` then throws on the **first master-key
    /// request**, which upstream answers as a 500. Refusing at boot names the entry instead.
    #[test]
    fn an_out_of_range_prefix_is_refused_at_boot_rather_than_on_the_first_request() {
        assert_eq!(
            IpAllowlist::parse(["127.0.0.1/999"]).expect_err("mask"),
            InvalidIpEntry("127.0.0.1/999".to_string())
        );
    }

    #[test]
    fn a_malformed_entry_is_refused_by_name() {
        for entry in [
            "",
            "localhost",
            "127.0.0.1/33",
            "::1/129",
            "127.0.0.1/x",
            "1.2.3",
        ] {
            let e = IpAllowlist::parse([entry]).expect_err("must refuse");
            assert_eq!(e, InvalidIpEntry(entry.to_string()));
        }
        // A zone index is not supported upstream either, and Rust's parser refuses it for us.
        assert!(IpAllowlist::parse(["fe80::1%lo0"]).is_err());
    }
}
