//! Password hashing.
//!
//! Upstream is `src/password.js`: `bcrypt.hash(password, 10)`, using `bcryptjs` by default and
//! `@node-rs/bcrypt` when it can be required.
//!
//! **The cost factor and the output format are interop contract, not implementation detail.** A
//! `_User` row written by parse-rust must be loginable by parse-server and the reverse, on the
//! same database. That is a mixed-fleet requirement, and it is the kind of thing that looks fine
//! until a second server exists. `tests/bcrypt_interop.rs` checks both directions against Node.

use parse_rust_core::{ErrorCode, ParseError};

/// Upstream's cost factor (`password.js`, `bcrypt.hash(password, 10)`).
///
/// Not raised. A higher cost would be better practice and would produce hashes parse-server can
/// still verify, but it would change login latency in a way an operator did not ask for, and the
/// benchmark story would then be comparing different work. Revisit deliberately, not silently.
pub const BCRYPT_COST: u32 = 10;

/// Hash a password for storage in `_User._hashed_password`.
pub fn hash(password: &str) -> Result<String, ParseError> {
    bcrypt::hash(password, BCRYPT_COST).map_err(|e| {
        // Never include the password or the error's inner detail in a client-visible message.
        ParseError::new(
            ErrorCode::InternalServerError,
            format!("password hashing failed: {}", kind_of(&e)),
        )
    })
}

/// Verify a password against a stored hash.
///
/// Returns `false` rather than an error for a malformed or empty hash, matching upstream:
/// `compare` resolves `false` when either side is falsy rather than throwing
/// (`password.js:24-29`). A stored hash that cannot be parsed is a failed login, not a 500.
pub fn verify(password: &str, hashed: &str) -> bool {
    if password.is_empty() || hashed.is_empty() {
        return false;
    }
    bcrypt::verify(password, hashed).unwrap_or(false)
}

fn kind_of(e: &bcrypt::BcryptError) -> &'static str {
    match e {
        bcrypt::BcryptError::CostNotAllowed(_) => "cost not allowed",
        bcrypt::BcryptError::InvalidHash(_) => "invalid hash",
        _ => "internal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let h = hash("hunter2").expect("hash");
        assert!(verify("hunter2", &h));
        assert!(!verify("hunter3", &h));
    }

    #[test]
    fn uses_upstreams_cost_factor() {
        let h = hash("x").expect("hash");
        // bcrypt encodes the cost in the third field: $2b$10$...
        let cost = h.split('$').nth(2).expect("cost field");
        assert_eq!(
            cost, "10",
            "cost must match upstream's bcrypt.hash(password, 10)"
        );
    }

    #[test]
    fn empty_inputs_are_a_failed_login_not_an_error() {
        let h = hash("x").expect("hash");
        assert!(!verify("", &h));
        assert!(!verify("x", ""));
    }

    #[test]
    fn a_corrupt_stored_hash_fails_login_rather_than_panicking() {
        // A row written by something else, or truncated in transit. Must not take down a worker.
        assert!(!verify("x", "not-a-bcrypt-hash"));
        assert!(!verify("x", "$2b$10$tooshort"));
    }
}
