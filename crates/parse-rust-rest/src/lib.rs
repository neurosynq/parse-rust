//! The read and write pipelines. The behavioral heart.
//!
//! Never references JS types, `serde_json::Value`-as-JS-value conventions, or JS async semantics.
//! Everything JavaScript lives behind the sidecar socket, and keeping this crate clean of it is
//! what makes that boundary real rather than aspirational. The one `serde_json` use is
//! `query_parse`, which reads a client-supplied `where` document, and that is JSON on the wire
//! rather than a JS value.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod acl;
pub mod guard;
pub mod pipeline;
pub mod query_parse;

pub use acl::AclScope;
pub use guard::{reject_reserved_keys, strip_internal_keys, to_response_body};
pub use pipeline::{count, create, delete, find, get, update, CreateResponse, UpdateResponse};
pub use query_parse::parse_where;
