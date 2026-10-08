//! The benchmark build's per-request database time, as response headers. Compiled only with the
//! `bench-instrumentation` feature; see `parse_rust_mongo::bench` for what is measured.
//!
//! `X-Bench-Db-Micros` and `X-Bench-Db-Ops` carry the totals and `X-Bench-Db-Shape` the normalized
//! command shapes as a JSON array, which is what the harness's query-shape fixtures pin. parse-server
//! under the harness emits the same three headers, so the driver reads one format from both.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::HeaderValue;

pub async fn instrument(request: Request, next: Next) -> Response {
    let (mut response, db) = parse_rust_mongo::bench::scope(next.run(request)).await;
    let headers = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&db.micros.to_string()) {
        headers.insert("x-bench-db-micros", v);
    }
    if let Ok(v) = HeaderValue::from_str(&db.ops.to_string()) {
        headers.insert("x-bench-db-ops", v);
    }
    let shapes = serde_json::to_string(&db.shapes).unwrap_or_default();
    if let Ok(v) = HeaderValue::from_str(&shapes) {
        headers.insert("x-bench-db-shape", v);
    }
    response
}
