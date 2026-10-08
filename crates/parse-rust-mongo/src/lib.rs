//! MongoDB storage adapter and the Parse/BSON transform.
//!
//! `transform` is the part full of load-bearing special cases, and
//! it is also pure, which makes it the one piece of this crate that can be differentially tested
//! against upstream directly rather than through a running server. That is why it landed first.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod adapter;
#[cfg(feature = "bench-instrumentation")]
pub mod bench;
mod js_regex;
pub mod transform;

pub use adapter::MongoAdapter;
/// The `bson` this crate is built with. The transform functions take and return its `Document` and
/// `Bson`, so a caller should name bson through this re-export rather than depend on a version that
/// might not match.
pub use bson;
