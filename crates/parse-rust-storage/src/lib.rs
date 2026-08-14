//! `StorageAdapter` trait and the query/update AST adapters lower.
//!
//! **The trait must be shaped by two consumers, not one.** Building against Mongo alone bakes
//! Mongo-isms (BSON semantics, `$` operators, implicit schema) into the interface, and the
//! Postgres port then fights it, which is roughly what happened upstream and produced the 55
//! catalogued divergences. The rule: if a method can only be implemented sensibly for one
//! backend, the trait is wrong.
//!
//! Only the pieces the 0.1.0 proof of concept needs exist so far: schemas, a small constraint
//! vocabulary, and the CRUD verbs. Aggregation, relations and transactions are absent.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod adapter;
pub mod query;
pub mod schema;

pub use adapter::{Row, StorageAdapter, WriteResult};
pub use query::{Comparison, Constraint, QueryOptions, SortDirection};
pub use schema::{ClassSchema, FieldType};
