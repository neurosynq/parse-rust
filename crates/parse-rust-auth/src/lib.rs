//! Parse Server compatible bcrypt password hashing.
//!
//! **That is the whole of this crate today.** It is named for the subsystem it will grow into,
//! sessions, users, roles, auth adapters and MFA, but none of that is here yet: sessions
//! currently live in `parse-rust-server`, and roles do not exist. Do not read the name as an
//! inventory.
//!
//! Password hashing landed first, ahead of the rest of the milestone, because bcrypt interop with
//! parse-server is a fact that could invalidate a dependency choice, and finding that out during
//! the auth step would be finding it out late.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod password;
