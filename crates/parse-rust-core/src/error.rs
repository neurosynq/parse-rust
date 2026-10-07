//! Parse error codes.
//!
//! **Error codes are API.** Every variant carries the upstream numeric code from
//! `src/Error.js`, and `spec/` asserts on these numbers directly. Never invent a code and
//! never change one to a better-fitting one.
//!
//! Codes extracted from the `parse` npm SDK bundled with parse-server 9.10.1-alpha.6, which is
//! the same table `src/Error.js` re-exports.

use std::fmt;

/// The upstream error code table. The discriminant *is* the wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
#[non_exhaustive]
pub enum ErrorCode {
    OtherCause = -1,
    InternalServerError = 1,
    ConnectionFailed = 100,
    ObjectNotFound = 101,
    InvalidQuery = 102,
    InvalidClassName = 103,
    MissingObjectId = 104,
    InvalidKeyName = 105,
    InvalidPointer = 106,
    InvalidJson = 107,
    CommandUnavailable = 108,
    NotInitialized = 109,
    IncorrectType = 111,
    InvalidChannelName = 112,
    PushMisconfigured = 115,
    ObjectTooLarge = 116,
    OperationForbidden = 119,
    CacheMiss = 120,
    InvalidNestedKey = 121,
    InvalidFileName = 122,
    InvalidAcl = 123,
    Timeout = 124,
    InvalidEmailAddress = 125,
    MissingContentType = 126,
    MissingContentLength = 127,
    InvalidContentLength = 128,
    FileTooLarge = 129,
    FileSaveError = 130,
    /// 135 and 136 have **no name in the `parse` SDK's error table**. Upstream throws them as
    /// bare numbers: `new Parse.Error(135, ...)` at `SchemaController.js:508` and
    /// `SchemasRouter.js:90`, `new Parse.Error(136, ...)` at `SchemaController.js:1242` and
    /// three places in `RestWrite.js`. The names here are ours, chosen from the messages, and
    /// `spec/Schema.spec.js` asserts on the numbers rather than on any constant. Do not
    /// "correct" either to a named neighbour: the number is what a client sees.
    MissingClassName = 135,
    UnchangeableField = 136,
    DuplicateValue = 137,
    InvalidRoleName = 139,
    ExceededQuota = 140,
    ScriptFailed = 141,
    ValidationError = 142,
    InvalidImageData = 143,
    UnsavedFileError = 151,
    InvalidPushTimeError = 152,
    FileDeleteError = 153,
    RequestLimitExceeded = 155,
    DuplicateRequest = 159,
    InvalidEventName = 160,
    FileDeleteUnnamedError = 161,
    InvalidValue = 162,
    UsernameMissing = 200,
    PasswordMissing = 201,
    UsernameTaken = 202,
    EmailTaken = 203,
    EmailMissing = 204,
    EmailNotFound = 205,
    SessionMissing = 206,
    MustCreateUserThroughSignup = 207,
    AccountAlreadyLinked = 208,
    InvalidSessionToken = 209,
    MfaError = 210,
    MfaTokenRequired = 211,
    LinkedIdMissing = 250,
    InvalidLinkedSession = 251,
    UnsupportedService = 252,
    InvalidSchemaOperation = 255,
    AggregateError = 600,
    FileReadError = 601,
    XDomainRequest = 602,
}

impl ErrorCode {
    /// The wire value. This is what goes in the `code` field of an error body.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_i32())
    }
}

/// Which upstream throw an error corresponds to, and therefore which body a client sees.
///
/// `handleParseErrors` branches on the **type** of the thrown value rather than on its code
/// (`middlewares.js:596-646`). A `Parse.Error` renders its own message; anything else renders a
/// fixed one and the detail goes only to the log. So the same detail is a disclosure or not
/// depending on which of the two it travelled in, and the code alone cannot tell them apart:
/// upstream throws `Parse.Error(INTERNAL_SERVER_ERROR, ...)` deliberately in several places
/// (`Auth.js:195`, `DatabaseController.js:1591-1596`) and those keep their messages.
///
/// **No `Default` impl, deliberately.** A forgotten field would select the disclosing variant,
/// which is the failure this enum exists to prevent. Every value is chosen by a constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorOrigin {
    /// A `Parse.Error`. The message is wire-visible.
    Parse,
    /// A bare `Error` upstream. The message is server-side detail and never reaches a client.
    Internal,
}

/// Out-of-band data an error carries for the server's own use.
///
/// **Nothing here is ever serialized into a response body.** Upstream's equivalent is
/// `err.userInfo`, which the error middleware never renders: it writes `code` and `message` and
/// nothing else (`middlewares.js:617`).
///
/// The point of the type is that the alternative is worse. Recovering which unique index collided
/// by leaving the driver's text in `message` and parsing it downstream puts the database name and
/// the colliding value on the wire, which is the disclosure this replaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseErrorInfo {
    /// `err.userInfo.duplicated_field` (`MongoStorageAdapter.js:584`). The field whose unique
    /// index a write collided on.
    pub duplicated_field: Option<String>,
}

/// A Parse error: a code plus a message, plus how much of it may be seen.
///
/// No `source` chaining and no automatic `From` conversions from I/O or driver errors. That is
/// deliberate: mapping a storage failure onto a Parse code is a decision each adapter must make
/// explicitly, because picking the wrong code is a wire-compatibility bug that no type system
/// will catch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct ParseError {
    pub code: ErrorCode,
    pub message: String,
    /// Which envelope this becomes. See [`ErrorOrigin`].
    pub origin: ErrorOrigin,
    /// Data for the server, never for the client. See [`ParseErrorInfo`].
    pub info: ParseErrorInfo,
}

impl ParseError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            origin: ErrorOrigin::Parse,
            info: ParseErrorInfo::default(),
        }
    }

    /// A failure upstream throws as a bare `Error`, so its detail never reaches a client.
    ///
    /// The client sees `{"code":1,"message":"Internal server error."}` whatever `detail` says
    /// (`middlewares.js:636-644`); `detail` is logged and is the only record of what happened.
    /// Write it for an operator reading a log, not for an SDK.
    ///
    /// Use this wherever upstream throws a plain `Error`, and `new(ErrorCode::InternalServerError,
    /// ..)` where upstream throws a `Parse.Error` carrying that code. The two are different bodies.
    #[must_use]
    pub fn internal(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        log_detail(ErrorCode::InternalServerError, &detail);
        Self {
            code: ErrorCode::InternalServerError,
            message: detail,
            origin: ErrorOrigin::Internal,
            info: ParseErrorInfo::default(),
        }
    }

    /// Record which field's unique index collided, out of band.
    #[must_use]
    pub fn with_duplicated_field(mut self, field: impl Into<String>) -> Self {
        self.info.duplicated_field = Some(field.into());
        self
    }

    /// The field whose unique index collided, if the adapter could recover it.
    pub fn duplicated_field(&self) -> Option<&str> {
        self.info.duplicated_field.as_deref()
    }
}

/// Whether a denial tells the client *why* it was denied.
///
/// `enableSanitizedErrorResponse` (`Options/Definitions.js:259-264`). Upstream's default is
/// `true`, and its check is `config?.enableSanitizedErrorResponse !== false` (`Error.js:21`), so
/// an absent config withholds too. [`ErrorDetail::Withheld`] is therefore what a stock deployment
/// runs, and it is the message every unmodified SDK sees.
///
/// **No `Default` impl, deliberately.** The disclosing regime is a configuration decision, and a
/// type that hands one out lets a call site acquire it by forgetting rather than by choosing.
/// Every value of this type is derived from a config field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorDetail {
    /// The client sees the generic message. The detail stays server-side.
    Withheld,
    /// The client sees the detailed message. `enableSanitizedErrorResponse: false`.
    Disclosed,
}

impl ErrorDetail {
    /// From the config flag, so the mapping lives in one place rather than at each call site.
    pub fn from_sanitized(enable_sanitized_error_response: bool) -> Self {
        if enable_sanitized_error_response {
            ErrorDetail::Withheld
        } else {
            ErrorDetail::Disclosed
        }
    }
}

/// Log the detail that may be about to be withheld.
///
/// Upstream logs it on every call through the logger controller, in both regimes
/// (`Error.js:15-19`), so the reason for a denial is always recoverable from the server log.
/// parse-rust has no logger controller yet, so this follows the pattern the server crate already
/// uses: stderr behind `PARSE_RUST_TRACE`. Structured logging through `tracing` is a later
/// milestone, and until it lands the detail is available on demand rather than by default.
fn log_detail(code: ErrorCode, detailed: &str) {
    static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *TRACE.get_or_init(|| std::env::var("PARSE_RUST_TRACE").is_ok()) {
        eprintln!("[trace] sanitized error: {code}: {detailed}");
    }
}

/// Denials whose detail is logged and, by default, withheld.
impl ParseError {
    /// `createSanitizedError` (`Error.js:13-21`): the single constructor for a denial whose
    /// detailed message upstream replaces with a generic one.
    ///
    /// The set of call sites is contract in both directions. Upstream routes a specific list of
    /// errors through this function and leaves the rest alone, so an error parse-rust sanitizes
    /// that upstream does not is as much a wire divergence as one it fails to sanitize. Adding a
    /// call here means finding the matching `createSanitizedError` at the pin first.
    ///
    /// `generic` is upstream's `sanitizedMessage` parameter, which defaults to `Permission
    /// denied` and is overridden at exactly one call site (`DatabaseController.js:1591-1596`).
    /// It is required here rather than defaulted, because the two upstream spellings are
    /// different strings on the wire and picking the wrong one silently is the failure this
    /// argument exists to prevent.
    #[must_use]
    pub fn sanitized(
        code: ErrorCode,
        detailed: impl Into<String>,
        generic: &str,
        detail: ErrorDetail,
    ) -> Self {
        let detailed = detailed.into();
        log_detail(code, &detailed);
        match detail {
            ErrorDetail::Withheld => Self::new(code, generic),
            ErrorDetail::Disclosed => Self::new(code, detailed),
        }
    }

    /// The common case: upstream's default `sanitizedMessage`.
    #[must_use]
    pub fn permission_denied(
        code: ErrorCode,
        detailed: impl Into<String>,
        detail: ErrorDetail,
    ) -> Self {
        Self::sanitized(code, detailed, PERMISSION_DENIED, detail)
    }
}

/// `createSanitizedError`'s default `sanitizedMessage` (`Error.js:13`), and the whole of
/// `createSanitizedHttpError`'s (`Error.js:41`).
pub const PERMISSION_DENIED: &str = "Permission denied";

/// The one message a duplicate-key collision ever carries (`MongoStorageAdapter.js:576-579`).
///
/// Fixed, and the same string in both upstream adapters. Which field collided travels in
/// [`ParseErrorInfo::duplicated_field`] instead, because the driver's own text names the database
/// and the value that collided.
pub const DUPLICATE_VALUE_MESSAGE: &str =
    "A duplicate value for a field with unique values was provided";

/// Convenience constructors for the codes used most often in the core.
impl ParseError {
    pub fn invalid_json(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidJson, message)
    }
    pub fn incorrect_type(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::IncorrectType, message)
    }
    pub fn invalid_key_name(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidKeyName, message)
    }
    pub fn invalid_acl(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidAcl, message)
    }
    pub fn invalid_query(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidQuery, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_match_upstream() {
        // Spot-check the ones the rest of this workspace leans on, plus the two that
        // are easy to transpose.
        assert_eq!(ErrorCode::OtherCause.as_i32(), -1);
        assert_eq!(ErrorCode::InternalServerError.as_i32(), 1);
        assert_eq!(ErrorCode::ObjectNotFound.as_i32(), 101);
        assert_eq!(ErrorCode::InvalidQuery.as_i32(), 102);
        assert_eq!(ErrorCode::IncorrectType.as_i32(), 111);
        assert_eq!(ErrorCode::OperationForbidden.as_i32(), 119);
        assert_eq!(ErrorCode::DuplicateValue.as_i32(), 137);
        assert_eq!(ErrorCode::ScriptFailed.as_i32(), 141);
        assert_eq!(ErrorCode::DuplicateRequest.as_i32(), 159);
        assert_eq!(ErrorCode::InvalidSessionToken.as_i32(), 209);
        assert_eq!(ErrorCode::InvalidSchemaOperation.as_i32(), 255);
        // 110 and 113 do not exist upstream; there is no variant to assert, and adding one
        // would be inventing a code.
    }

    #[test]
    fn display_is_the_number() {
        assert_eq!(ErrorCode::ObjectNotFound.to_string(), "101");
    }

    /// The default regime is the withholding one, because upstream's default is `true`.
    #[test]
    fn the_two_regimes_produce_the_two_upstream_messages() {
        let detailed = "Permission denied for action find on class Post.";
        assert_eq!(
            ParseError::permission_denied(
                ErrorCode::OperationForbidden,
                detailed,
                ErrorDetail::from_sanitized(true)
            )
            .message,
            "Permission denied"
        );
        assert_eq!(
            ParseError::permission_denied(
                ErrorCode::OperationForbidden,
                detailed,
                ErrorDetail::from_sanitized(false)
            )
            .message,
            detailed
        );
    }

    /// The code never moves. Only the message does.
    #[test]
    fn sanitizing_does_not_change_the_code() {
        for detail in [ErrorDetail::Withheld, ErrorDetail::Disclosed] {
            let e = ParseError::permission_denied(ErrorCode::ObjectNotFound, "why", detail);
            assert_eq!(e.code, ErrorCode::ObjectNotFound);
        }
    }

    /// The two ways to reach code 1 are different bodies, so they must be different values.
    #[test]
    fn an_internal_error_is_distinguishable_from_a_parse_error_carrying_code_one() {
        let internal = ParseError::internal("pointer permissions: Post owner");
        assert_eq!(internal.code, ErrorCode::InternalServerError);
        assert_eq!(internal.origin, ErrorOrigin::Internal);

        // `Auth.js:195` throws this one as a real `Parse.Error`, and its message is wire-visible.
        let parse = ParseError::new(ErrorCode::InternalServerError, "Invalid object ID.");
        assert_eq!(parse.origin, ErrorOrigin::Parse);
    }

    /// Everything built through the ordinary constructors keeps its message.
    #[test]
    fn the_ordinary_constructors_produce_parse_origin() {
        for e in [
            ParseError::new(ErrorCode::ObjectNotFound, "Object not found."),
            ParseError::invalid_json("bad"),
            ParseError::permission_denied(
                ErrorCode::OperationForbidden,
                "why",
                ErrorDetail::Withheld,
            ),
        ] {
            assert_eq!(e.origin, ErrorOrigin::Parse);
        }
    }

    /// The duplicate-key field rides beside the message rather than inside it.
    #[test]
    fn the_duplicated_field_is_out_of_band() {
        let e = ParseError::new(ErrorCode::DuplicateValue, DUPLICATE_VALUE_MESSAGE)
            .with_duplicated_field("username");
        assert_eq!(e.duplicated_field(), Some("username"));
        // The name of the field is not in the message, and neither is anything else.
        assert_eq!(e.message, DUPLICATE_VALUE_MESSAGE);
        assert!(!e.message.contains("username"));
        assert_eq!(ParseError::invalid_json("x").duplicated_field(), None);
    }

    /// The one call site upstream overrides the generic message at.
    #[test]
    fn the_generic_message_is_per_call_site() {
        let e = ParseError::sanitized(
            ErrorCode::InternalServerError,
            "a driver said something specific",
            "An internal server error occurred",
            ErrorDetail::Withheld,
        );
        assert_eq!(e.message, "An internal server error occurred");
    }
}
