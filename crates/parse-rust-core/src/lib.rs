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
//! Citations of the form `File.js:LINE` refer to parse-server at the commit recorded in `PIN` at
//! the repository root, which is not restated here so it cannot go stale. Read them with
//! `git -C ../parse-server show $(awk '/^parse-server /{print $3}' PIN):<path>`.

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
pub mod clp;
pub mod date;
pub mod decode;
pub mod error;
pub mod js_number;
pub mod object_id;
pub mod op;
pub mod value;

pub use acl::{Acl, Permissions, Principal};
pub use clp::{
    is_js_truthy, ClassLevelPermissions, OpEntity, OpPerm, Operation, PfEntity, UserFieldsKey,
};
pub use date::ParseDate;
pub use decode::{classify, classify_raw, recognize_atom, AtomPosition};
pub use error::{
    ErrorCode, ErrorDetail, ErrorOrigin, ParseError, ParseErrorInfo, DUPLICATE_VALUE_MESSAGE,
    PERMISSION_DENIED,
};
pub use object_id::new_object_id;
pub use op::{classify_field, FieldWrite, Op};
pub use value::{
    base64_decode, base64_encode, deep_strict_eq, is_base64_value, ParseMap, ParseValue,
};
