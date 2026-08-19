//! Sessions, roles and password hashing.
//!
//! What is here:
//!
//! - [`password`]: bcrypt hashing and verification, at upstream's cost factor and output format.
//! - [`sessions`]: `_Session` rows. Token minting, resolution, duplicate destruction, revocation.
//! - [`roles`]: the role graph, expanded from `_Role` and its two join collections.
//!
//! What is not here, and is not hidden behind a partial implementation: auth adapters and
//! `authData` linking, MFA, password policy, account lockout, password reset, email verification,
//! and the role cache. The crate name describes a subsystem; this list describes the crate.
//!
//! **Both [`sessions`] and [`roles`] read and write storage with no ACL and no CLP constraint.**
//! That is not a shortcut, it is upstream's own design: `Auth.js` resolves a session token under
//! `master(config)` (`Auth.js:168`) and expands roles under `master(this.config)`
//! (`Auth.js:283`, `:383`). The reason is structural rather than a matter of convenience. A
//! session lookup that respected the caller's ACL could not run at all, because until the lookup
//! completes there is no caller to evaluate an ACL against. The same holds for the role graph:
//! the role names are an *input* to every later access-control decision, so they cannot
//! themselves be gated by one.
//!
//! The safety of that rests on the boundary being narrow. Nothing in this crate takes a
//! client-supplied query. Every query it issues is built here from a session token, a user
//! objectId or a set of role objectIds, and every row it returns is either consumed internally or
//! reduced to a token, an id or a role name.
//!
//! Citations of the form `File.js:LINE` refer to parse-server at the pin recorded in `PIN` at the
//! repository root.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod password;
pub mod roles;
pub mod sessions;

#[cfg(test)]
mod testing;

pub use roles::{expand_roles, RoleName, RolePrincipal};
pub use sessions::{
    create_session, ensure_session_schema, new_session_token, resolve_session, revoke,
    revoke_all_for_user, CreatedSession, CreatedWith, NewSession, ResolvedSession, SessionAction,
    SessionConfig, SESSION_TOKEN_PREFIX,
};
