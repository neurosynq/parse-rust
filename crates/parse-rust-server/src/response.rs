//! Error response envelopes.
//!
//! Parse has **two different error bodies**, and they are not interchangeable. Getting this
//! wrong is invisible in a browser and breaks SDKs, because clients branch on the presence of
//! `code`.
//!
//! | Source | Status | Body |
//! |---|---|---|
//! | A `Parse.Error` | 400, or 404 for `OBJECT_NOT_FOUND`, or 500 for `INTERNAL_SERVER_ERROR` | `{"code":N,"error":"..."}` |
//! | An HTTP-level rejection | as given, e.g. 403 | `{"error":"..."}` with **no `code`** |
//!
//! Upstream: `handleParseErrors` (`middlewares.js:596-645`). The `code`-less shape comes from
//! the `err.status && err.message` branch at `:629-631`.

use axum::response::{IntoResponse, Response};
use http::StatusCode;
use parse_rust_core::{ErrorCode, ParseError};

/// An HTTP-level rejection: a status and a message, with no Parse error code.
///
/// Kept as a distinct type from `ParseError` rather than a variant of it, so that a route
/// cannot accidentally emit one envelope where the other is required.
#[derive(Debug, Clone)]
pub struct HttpError {
    pub status: StatusCode,
    pub message: String,
}

impl HttpError {
    /// The master-key gate's rejection.
    ///
    /// `promiseEnforceMasterKeyAccess` builds this through `createSanitizedHttpError`
    /// (`Error.js:32-43`), which logs the detailed reason server-side and sends a generic one to
    /// the client when `enableSanitizedErrorResponse` is true, which is the default.
    ///
    /// The detailed message is `unauthorized: master key is required`; the client sees
    /// `Permission denied`. Both strings are asserted by `spec/features.spec.js`, the first via
    /// a logger spy and the second in the response body.
    pub fn master_key_required(sanitized: bool) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: if sanitized {
                "Permission denied".to_string()
            } else {
                "unauthorized: master key is required".to_string()
            },
        }
    }

    /// The header layer's rejection. Upstream's `invalidRequest` (`middlewares.js:829-832`).
    ///
    /// Note it is **not** sanitization-dependent and the message is lowercase `unauthorized`,
    /// unlike the master-key gate above. Two similar-looking 403s with different bodies.
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: "unauthorized".to_string(),
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let body = format!("{{\"error\":{}}}", json_string(&self.message));
        (
            self.status,
            [(
                http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )],
            body,
        )
            .into_response()
    }
}

/// A `Parse.Error`, with upstream's status mapping.
pub struct ParseErrorResponse(pub ParseError);

impl IntoResponse for ParseErrorResponse {
    fn into_response(self) -> Response {
        // `handleParseErrors` maps exactly two codes and defaults everything else to 400.
        // The upstream comment on that switch is a literal "TODO: fill out this mapping", so
        // the sparseness is the contract rather than an oversight to improve on.
        let status = match self.0.code {
            ErrorCode::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::ObjectNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::BAD_REQUEST,
        };
        let body = format!(
            "{{\"code\":{},\"error\":{}}}",
            self.0.code.as_i32(),
            json_string(&self.0.message)
        );
        (
            status,
            [(
                http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )],
            body,
        )
            .into_response()
    }
}

/// Minimal JSON string escaping for error messages, which are server-authored and short.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_envelopes_are_distinguishable() {
        // An HTTP rejection has no `code` key at all. A client branching on it must not find one.
        let http = HttpError::master_key_required(true);
        assert_eq!(http.message, "Permission denied");
        assert_eq!(http.status, StatusCode::FORBIDDEN);

        // The header layer's is a different string.
        assert_eq!(HttpError::unauthorized().message, "unauthorized");
    }

    #[test]
    fn sanitization_toggles_only_the_master_key_message() {
        assert_eq!(
            HttpError::master_key_required(false).message,
            "unauthorized: master key is required"
        );
        // The header rejection does not participate in sanitization.
        assert_eq!(HttpError::unauthorized().message, "unauthorized");
    }

    #[test]
    fn escaping_is_applied_to_messages() {
        assert_eq!(json_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(json_string("a\nb"), r#""a\nb""#);
    }
}
