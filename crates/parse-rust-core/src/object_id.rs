//! `objectId` generation.
//!
//! The alphabet and length are part of the contract: clients make assumptions about both, and
//! `allowCustomObjectId: false` makes the server validate incoming ids against
//! `/^[a-zA-Z0-9]{1,}$/` (`SchemaController.js`).
//!
//! Upstream: `src/cryptoUtils.js`, `randomString` and `newObjectId`. The alphabet is uppercase,
//! then lowercase, then digits, 62 characters, and the default size is 10.
//!
//! **Divergence, Tier 2, deliberate.** Upstream indexes the alphabet with `byte % 62`, which is
//! biased because 256 is not a multiple of 62: the first 8 characters (`A` through `H`) come up
//! about 25% more often than the rest. Upstream's own comment acknowledges this. The bias is not
//! wire-visible (a client cannot tell a biased 10-char alphanumeric id from an unbiased one), and
//! reproducing a weak RNG on purpose is worse than fixing it, so this uses rejection sampling.
//! This is a deliberate, recorded difference from upstream rather than an oversight.

use rand::Rng;

/// Uppercase, then lowercase, then digits. Order matters only for matching upstream's source;
/// the set is what the client-visible contract depends on.
const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Upstream's `newObjectId` default (`cryptoUtils.js`).
pub const DEFAULT_OBJECT_ID_SIZE: usize = 10;

/// A random alphanumeric string of `size` characters, uniformly distributed over the 62-char
/// alphabet.
///
/// Uses rejection sampling rather than upstream's `byte % 62`. The largest multiple of 62 at or
/// below 256 is 248, so bytes 248..=255 are rejected and redrawn. Expected redraws are about
/// 3.2%, which is not worth a smarter scheme.
pub fn random_string(size: usize) -> String {
    let mut rng = rand::rng();
    let mut out = String::with_capacity(size);
    let mut buf = [0u8; 64];
    let mut have = 0usize;
    let mut pos = 0usize;

    while out.len() < size {
        if pos == have {
            rng.fill_bytes(&mut buf);
            have = buf.len();
            pos = 0;
        }
        let b = buf[pos];
        pos += 1;
        // 248 == 62 * 4. Anything at or above it would bias the low residues.
        if b < 248 {
            out.push(ALPHABET[(b % 62) as usize] as char);
        }
    }
    out
}

/// A new `objectId`. Ten characters unless a size is given.
pub fn new_object_id() -> String {
    random_string(DEFAULT_OBJECT_ID_SIZE)
}

/// Does this string satisfy upstream's default `objectId` shape?
///
/// Mirrors `SchemaController`'s `autoIdRegEx`, `/^[a-zA-Z0-9]{1,}$/`. Note it has no upper
/// bound: upstream accepts any length, so this must not impose one. With
/// `allowCustomObjectId: true` the applicable pattern is `/^.{1,}$/` instead, which is a
/// different check and belongs with the schema controller, not here.
pub fn is_valid_auto_object_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn default_shape() {
        let id = new_object_id();
        assert_eq!(id.len(), 10);
        assert!(
            is_valid_auto_object_id(&id),
            "{id} failed the upstream regex shape"
        );
    }

    #[test]
    fn alphabet_is_exactly_the_upstream_62() {
        let set: HashSet<u8> = ALPHABET.iter().copied().collect();
        assert_eq!(set.len(), 62, "alphabet has a duplicate");
        for b in b'A'..=b'Z' {
            assert!(set.contains(&b));
        }
        for b in b'a'..=b'z' {
            assert!(set.contains(&b));
        }
        for b in b'0'..=b'9' {
            assert!(set.contains(&b));
        }
    }

    #[test]
    fn validator_matches_the_regex_semantics() {
        assert!(is_valid_auto_object_id("aA0"));
        assert!(is_valid_auto_object_id("a"));
        // No upper bound upstream, so none here.
        assert!(is_valid_auto_object_id(&"a".repeat(500)));
        assert!(!is_valid_auto_object_id(""));
        assert!(!is_valid_auto_object_id("has-dash"));
        assert!(!is_valid_auto_object_id("has space"));
        assert!(!is_valid_auto_object_id("ünïcode"));
    }

    /// Not a randomness test, just a guard that rejection sampling did not silently truncate
    /// the alphabet, which is the plausible failure mode of the bounds check.
    #[test]
    fn covers_the_whole_alphabet() {
        let mut seen: HashSet<char> = HashSet::new();
        for _ in 0..2000 {
            seen.extend(random_string(32).chars());
        }
        assert_eq!(
            seen.len(),
            62,
            "some alphabet characters were never produced"
        );
    }

    #[test]
    fn ids_are_not_repeating() {
        let ids: HashSet<String> = (0..1000).map(|_| new_object_id()).collect();
        assert_eq!(ids.len(), 1000, "collision in 1000 draws of a 62^10 space");
    }
}
