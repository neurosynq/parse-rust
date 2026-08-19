//! HTTP routes. One module per upstream router, so a change upstream maps to an obvious place.
//!
//! The axum handlers live in [`http`] and do exactly three things: build a [`crate::params::Params`] from the
//! query string, resolve the request context, and hand a [`dispatch::Route`] to
//! [`dispatch::dispatch`]. Every behavior is in the cores below, because `/batch` reaches the same
//! cores and two copies of a handler are two copies that drift.

pub mod batch;
pub mod classes;
pub mod dispatch;
pub mod features;
pub mod health;
pub mod http;
pub mod schemas;
pub mod sessions;
pub mod users;
