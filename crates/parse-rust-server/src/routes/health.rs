//! `GET /health`. Credential-free upstream, and the endpoint every bring-up script polls.
//!
//! It reports liveness only, and that is a known gap rather than a pending one: storage has
//! landed, so this must learn to distinguish "process up" from "database reachable". A health
//! endpoint that returns ok before its dependencies are connected turns every startup race into a
//! mystery test failure, because the harness stops polling exactly when the server is least ready.
//!
//! Until it does, the one property it has to keep is that it answers **without** resolving a
//! request context. A health check that loaded schemas would fail exactly when a caller most
//! wants to tell "process up, database down" from "process down".

use serde_json::{json, Value as Json};

pub fn body() -> Json {
    json!({ "status": "ok" })
}
