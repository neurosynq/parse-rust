//! Field types, inference, validation, and the `_SCHEMA` storage format.
//!
//! Parse's schema is *implicit*: the first write that mentions a field decides its type, and every
//! later write is checked against that decision. This crate owns that machinery. It performs no
//! I/O; loading and persisting a schema belongs to the storage adapter.
//!
//! `storage_format` is the highest-risk module in the crate, because `_SCHEMA` is shared with any
//! parse-server reading the same database and both of its failure modes are silent.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod controller;
pub mod infer;
pub mod storage_format;

pub use controller::{apply, default_schema, validate_write, SchemaDelta};
pub use infer::{class_name_is_valid, field_name_is_valid, infer_type};
pub use parse_rust_storage::{ClassSchema, FieldType};
