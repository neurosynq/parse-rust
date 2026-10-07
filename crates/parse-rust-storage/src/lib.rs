//! `StorageAdapter` trait and the query/update AST adapters lower.
//!
//! **The trait must be shaped by two consumers, not one.** Building against Mongo alone bakes
//! Mongo-isms (BSON semantics, `$` operators, implicit schema) into the interface, and the
//! Postgres port then fights it, which is roughly what happened upstream and produced the 55
//! catalogued divergences. The rule: if a method can only be implemented sensibly for one
//! backend, the trait is wrong.
//!
//! 0.2.0 added the query tree (`$or`/`$and`/`$nor`), the update op AST, atomic field reservation,
//! join-table primitives and schema mutation. Aggregation, distinct and transactions are still
//! absent, and a batch that asks for a transaction is refused rather than silently run without
//! one.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod adapter;
pub mod query;
pub mod schema;

pub use adapter::{AddFieldOutcome, Row, SchemaIndex, StorageAdapter, WriteResult};
pub use query::{
    Clause, Comparison, Constraint, CountOptions, ExplainVerbosity, Hint, Query, QueryOptions,
    SortDirection, Update, UpdateValue, DEFAULT_LIMIT, GEO_OPERATORS,
};
pub use schema::{join_schema, join_table_name, ClassSchema, FieldType};
