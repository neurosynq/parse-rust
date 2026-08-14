//! Session tokens.
//!
//! **In-memory, and that is a 0.1.0 limitation with consequences worth stating rather than
//! discovering.** Upstream stores sessions in the `_Session` class, so they survive a restart and
//! are visible to every node. This store does neither: restarting the server logs everyone out,
//! and two parse-rust processes do not share sessions.
//!
//! That is acceptable for a proof of concept and unacceptable beyond it. It is recorded in
//! the release notes rather than left implicit, because "sessions work" and "sessions
//! work on one process until it restarts" look identical in a demo.
//!
//! The token *format* is not a shortcut: `r:` plus a 32-character random string is what upstream
//! generates, and clients treat the prefix as meaningful.

use std::collections::HashMap;
use std::sync::RwLock;

use parse_rust_core::object_id::random_string;

/// Upstream's revocable-session prefix. A token without it is a legacy session.
const REVOCABLE_PREFIX: &str = "r:";

#[derive(Default)]
pub struct SessionStore {
    // token -> user objectId
    by_token: RwLock<HashMap<String, String>>,
}

impl SessionStore {
    /// Mint a session token for a user.
    pub fn create(&self, user_object_id: &str) -> String {
        let token = format!("{REVOCABLE_PREFIX}{}", random_string(32));
        if let Ok(mut map) = self.by_token.write() {
            map.insert(token.clone(), user_object_id.to_string());
        }
        token
    }

    /// Which user does this token belong to?
    pub fn user_for(&self, token: &str) -> Option<String> {
        self.by_token.read().ok()?.get(token).cloned()
    }

    /// Revoke one token. Returns whether it existed.
    pub fn revoke(&self, token: &str) -> bool {
        self.by_token
            .write()
            .map(|mut m| m.remove(token).is_some())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_carry_the_revocable_prefix() {
        let s = SessionStore::default();
        let t = s.create("u1");
        assert!(
            t.starts_with("r:"),
            "clients treat the r: prefix as meaningful: {t}"
        );
        assert_eq!(t.len(), 2 + 32);
    }

    #[test]
    fn a_token_resolves_to_its_user_and_only_its_user() {
        let s = SessionStore::default();
        let a = s.create("alice");
        let b = s.create("bob");
        assert_eq!(s.user_for(&a).as_deref(), Some("alice"));
        assert_eq!(s.user_for(&b).as_deref(), Some("bob"));
        assert_ne!(a, b);
    }

    #[test]
    fn an_unknown_token_resolves_to_nobody() {
        let s = SessionStore::default();
        assert_eq!(s.user_for("r:nonsense"), None);
        assert_eq!(s.user_for(""), None);
    }

    #[test]
    fn revoking_removes_the_token() {
        let s = SessionStore::default();
        let t = s.create("u1");
        assert!(s.revoke(&t));
        assert_eq!(
            s.user_for(&t),
            None,
            "a revoked token must resolve to nobody"
        );
        assert!(!s.revoke(&t), "revoking twice reports the second as a miss");
    }
}
