//! `GET /sessions/me`.
//!
//! Upstream: `src/Routers/SessionsRouter.js`. The other three session routes are `ClassesRouter`
//! handlers with `className()` pinned to `_Session` and live in [`crate::routes::classes`];
//! `handleMe` is the one that is genuinely its own thing.
//!
//! `POST /sessions`, `PUT /sessions/:objectId` and `POST /upgradeToRevocableSession` are out of
//! scope for 0.2.0 and are **absent** rather than answering 501. They exist to let a client mint
//! or migrate a session directly, which is a legacy path and a set of `OPERATION_FORBIDDEN`
//! special cases (`RestWrite.js:1313-1386`) with no bearing on the milestone claim.

use parse_rust_auth::resolve_session;
use parse_rust_core::{ErrorCode, ParseError, ParseValue};
use parse_rust_rest::{FindOptions, ParsedClause, ParsedWhere};
use parse_rust_storage::Constraint;
use serde_json::Value as Json;

use crate::request::RequestContext;
use crate::state::AppState;

/// `GET /sessions/me` (`SessionsRouter.js:12-61`).
///
/// Three messages, and none of them is `/users/me`'s. A missing token is `Session token
/// required.`; a token that resolves to nothing at either step is `Session token not found.`
/// `GET /users/me` answers `Invalid session token` for both, and a client matching on the string
/// would see the difference.
///
/// The two-step shape is upstream's and is not redundant: the row is located with master so the
/// token can be validated at all, then **re-fetched by objectId with the caller's own auth** so
/// that protected fields and CLP apply to what comes back.
pub async fn me_core(state: &AppState, rc: &RequestContext) -> Result<Json, ParseError> {
    let Some(token) = rc.session_token.as_deref() else {
        return Err(ParseError::new(
            ErrorCode::InvalidSessionToken,
            "Session token required.",
        ));
    };
    let not_found = || ParseError::new(ErrorCode::InvalidSessionToken, "Session token not found.");

    // Step one, under master. `resolve_session` reports its own three failures in upstream's
    // order; every one of them means the token did not locate a usable session here.
    let session = resolve_session(state.storage(), token)
        .await
        .map_err(|_| not_found())?;

    // Step two, with the caller's own auth. For a master caller that is unrestricted, which is
    // what upstream's `req.auth.isMaster ? req.auth : ...` produces.
    //
    // The `user` half of this is deliberately absent: the read pipeline narrows every non-master
    // `_Session` read to the caller's own sessions, and adding a second equality on the same field
    // is `INVALID_QUERY` rather than a redundant conjunct, because the Mongo transform refuses to
    // let one equality silently overwrite another.
    let mut where_ = ParsedWhere::default();
    where_.push(ParsedClause::Field(Constraint::equal(
        "objectId",
        ParseValue::String(session.object_id.clone()),
    )));

    let ctx = rc.ctx(state.storage());
    let rows = parse_rust_rest::find(
        &ctx,
        crate::routes::classes::SESSION_CLASS,
        where_,
        FindOptions {
            limit: Some(1),
            ..Default::default()
        },
    )
    .await
    .map_err(|_| not_found())?;

    let Some(row) = rows.into_iter().next() else {
        return Err(not_found());
    };
    Ok(crate::routes::classes::body_of(&row))
}
