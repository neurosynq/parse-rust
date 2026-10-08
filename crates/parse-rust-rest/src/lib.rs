//! The read and write pipelines. The behavioral heart.
//!
//! Never references JS types, `serde_json::Value`-as-JS-value conventions, or JS async semantics.
//! Everything JavaScript lives behind the sidecar socket, and keeping this crate clean of it is
//! what makes that boundary real rather than aspirational. The one `serde_json` use is
//! `query_parse` and `write`, which read client-supplied documents, and those are JSON on the
//! wire rather than JS values.
//!
//! The authorization model lives in [`clp`] and [`acl`], and its structure is the point: stage
//! one is a gate that throws, stage two is a filter that narrows the query, and passing the gate
//! is not authorization to read anything.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod acl;
pub mod class_security;
pub mod clp;
pub mod guard;
pub mod include;
pub mod pipeline;
pub mod query_parse;
pub mod relations;
pub mod snapshot;
pub mod write;

#[cfg(test)]
pub mod testing;

pub use acl::AclScope;
pub use class_security::enforce_class_security;
pub use clp::{
    validate_permission, PermissionOptions, PointerPermOutcome, ProtectedFieldPlan, WriteAction,
};
pub use guard::{
    into_response_body, reject_reserved_keys, reject_reserved_keys_in, strip_internal_keys,
    to_response_body,
};
pub use pipeline::{
    authorize_update, count, create, create_checked, delete, explain, find, get, update,
    update_checked, update_gate, BeforeInsert, CreateResponse, Ctx, FindOptions, UpdateResponse,
};
pub use query_parse::{
    parse_client_where, parse_include, parse_where, DeferredWhere, ParsedClause, ParsedWhere,
};
pub use relations::RelatedToOutcome;
pub use snapshot::SchemaSnapshot;
pub use write::{decode_write_body, enforce_object_id_policy, WriteBody};
