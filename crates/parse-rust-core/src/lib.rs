//! Parse type system, JSON encoding and error codes. No I/O.
//!
//! This crate is the bottom of the workspace: it depends on no other parse-rust crate and
//! performs no I/O, so everything in it is directly testable without a server or a database.
//!
//! The contract for the whole project is **wire compatibility**: an unmodified Parse SDK
//! pointed at parse-rust must see the same bytes it sees from parse-server. That is why this
//! crate carries an ECMAScript number formatter, an order-preserving map, and a hand-written
//! equality predicate rather than the obvious Rust defaults for each. See
//! the modules below, each of which states the upstream behavior it reproduces.
//!
//! Citations of the form `File.js:LINE` refer to parse-server at pin `ca75b1fe`, recorded in
//! `PIN` at the repository root. Read them with `git -C ../parse-server show ca75b1fe:<path>`.

#![forbid(unsafe_code)]
// "No `unwrap()` or `panic!()` in request paths": a malformed request from an untrusted client
// must never take down a worker. Scoped to non-test builds on purpose. A test that cannot
// assert with `unwrap` is a test written to satisfy a lint rather than to catch a bug, and the
// invariant being protected is about serving traffic, not about test code.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod acl;
pub mod date;
pub mod decode;
pub mod error;
pub mod js_number;
pub mod object_id;
pub mod op;
pub mod value;

pub use acl::{Acl, Permissions, Principal};
pub use date::ParseDate;
pub use decode::classify;
pub use error::{ErrorCode, ParseError};
pub use object_id::new_object_id;
pub use op::Op;
pub use value::{deep_strict_eq, ParseMap, ParseValue};
