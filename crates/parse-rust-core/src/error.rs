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

/// A Parse error: a code plus a message, both wire-visible.
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
}

impl ParseError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

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
        // Spot-check the ones this repository's design documents lean on, plus the two that
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
}
