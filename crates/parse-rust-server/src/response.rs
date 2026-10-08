//! Error response envelopes.
//!
//! Parse has **three different error bodies**, and they are not interchangeable. Getting this
//! wrong is invisible in a browser and breaks SDKs, because clients branch on the presence of
//! `code` and read `error` rather than `message`.
//!
//! | Source | Status | Body |
//! |---|---|---|
//! | A `Parse.Error` | 400, or 404 for `OBJECT_NOT_FOUND`, or 500 for `INTERNAL_SERVER_ERROR` | `{"code":N,"error":"..."}` |
//! | An HTTP-level rejection | as given, e.g. 403 | `{"error":"..."}` with **no `code`** |
//! | Anything else thrown | 500 | `{"code":1,"message":"Internal server error."}`, key `message` |
//!
//! Upstream: `handleParseErrors` (`middlewares.js:596-646`), which branches on the type of the
//! thrown value in that order. The `code`-less shape comes from the `err.status && err.message`
//! branch at `:629-631`; the third from the `else` at `:635-644`.
//!
//! The third row is the reason [`parse_rust_core::ErrorOrigin`] exists. It is not "code 1": a
//! `Parse.Error` deliberately carrying `INTERNAL_SERVER_ERROR` is row one and keeps its message,
//! and there are several of those upstream. Branching on the code instead of on the origin would
//! blank out those messages, which is a worse defect than the disclosure it would be fixing.

use axum::response::{IntoResponse, Response};
use http::StatusCode;
use parse_rust_core::{ErrorCode, ErrorDetail, ErrorOrigin, ParseError, PERMISSION_DENIED};

/// The whole of the generic 500 body's message (`middlewares.js:640`). Note the trailing period.
pub const INTERNAL_SERVER_ERROR_MESSAGE: &str = "Internal server error.";

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
    pub fn master_key_required(detail: ErrorDetail) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: match detail {
                ErrorDetail::Withheld => PERMISSION_DENIED.to_string(),
                ErrorDetail::Disclosed => "unauthorized: master key is required".to_string(),
            },
        }
    }

    /// The header layer's rejection. Upstream's `invalidRequest` (`middlewares.js:845-848`).
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

/// A failure raised by a route, rendered as whichever of the two `code`-carrying bodies it is.
pub struct ParseErrorResponse(pub ParseError);

impl IntoResponse for ParseErrorResponse {
    fn into_response(self) -> Response {
        let (status, body) = match self.0.origin {
            // Anything that was not a `Parse.Error` upstream. The detail was logged where it was
            // built; here it is dropped, because this is the byte stream a client reads.
            ErrorOrigin::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "{{\"code\":{},\"message\":{}}}",
                    ErrorCode::InternalServerError.as_i32(),
                    json_string(INTERNAL_SERVER_ERROR_MESSAGE)
                ),
            ),
            // `handleParseErrors` maps exactly two codes and defaults everything else to 400.
            // The upstream comment on that switch is a literal "TODO: fill out this mapping", so
            // the sparseness is the contract rather than an oversight to improve on.
            ErrorOrigin::Parse => {
                let status = match self.0.code {
                    ErrorCode::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::ObjectNotFound => StatusCode::NOT_FOUND,
                    _ => StatusCode::BAD_REQUEST,
                };
                (
                    status,
                    format!(
                        "{{\"code\":{},\"error\":{}}}",
                        self.0.code.as_i32(),
                        json_string(&self.0.message)
                    ),
                )
            }
        };
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
        let http = HttpError::master_key_required(ErrorDetail::Withheld);
        assert_eq!(http.message, "Permission denied");
        assert_eq!(http.status, StatusCode::FORBIDDEN);

        // The header layer's is a different string.
        assert_eq!(HttpError::unauthorized().message, "unauthorized");
    }

    #[test]
    fn sanitization_toggles_only_the_master_key_message() {
        assert_eq!(
            HttpError::master_key_required(ErrorDetail::Disclosed).message,
            "unauthorized: master key is required"
        );
        // The header rejection does not participate in sanitization.
        assert_eq!(HttpError::unauthorized().message, "unauthorized");
    }

    /// Read the body back off a rendered response.
    async fn rendered(e: ParseError) -> (StatusCode, String) {
        let response = ParseErrorResponse(e).into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8(bytes.to_vec()).expect("utf-8"))
    }

    /// The third branch: key `message`, fixed text, nothing of the detail.
    #[tokio::test]
    async fn a_non_parse_error_renders_the_generic_five_hundred() {
        let (status, body) = rendered(ParseError::internal(
            "pointer permissions: Invoice ownerRef",
        ))
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, r#"{"code":1,"message":"Internal server error."}"#);
        assert!(!body.contains("Invoice"));
        assert!(!body.contains("ownerRef"));
        // The key is `message`, and `error` must not appear. An SDK reading `error` is meant to
        // find nothing here.
        assert!(!body.contains("\"error\""));
    }

    /// The trap: a `Parse.Error` that carries code 1 keeps its own message and its own key.
    /// Blanking these out would be a worse bug than the disclosure the branch above prevents.
    #[tokio::test]
    async fn a_parse_error_carrying_code_one_keeps_its_message() {
        let (status, body) = rendered(ParseError::new(
            ErrorCode::InternalServerError,
            "Invalid object ID.",
        ))
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, r#"{"code":1,"error":"Invalid object ID."}"#);
    }

    #[tokio::test]
    async fn an_ordinary_parse_error_is_unchanged() {
        let (status, body) = rendered(ParseError::new(
            ErrorCode::ObjectNotFound,
            "Object not found.",
        ))
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, r#"{"code":101,"error":"Object not found."}"#);
    }

    #[test]
    fn escaping_is_applied_to_messages() {
        assert_eq!(json_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(json_string("a\nb"), r#""a\nb""#);
    }
}
