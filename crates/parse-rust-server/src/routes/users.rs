//! Signup, login, `/users/me`, logout.
//!
//! Upstream: `src/Routers/UsersRouter.js`. Two facts shape this module and both are easy to lose:
//!
//! - **`POST /users` is not `POST /classes/_User`.** Only the signup route returns a session
//!   token. Non-master class writes are refused, while an allowed master write still has to pass
//!   through the same password and ACL preparation as signup.
//! - **The password hash must never reach a response.** Upstream reattaches the hash onto the
//!   object as `password` and strips it in exactly one place, so every response path depends on
//!   that one step running. Here the hash is never placed on a response object at all, so there is
//!   nothing to strip and no path that can forget to.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use parse_rust_core::{ErrorCode, ParseError, ParseMap, ParseValue};
use parse_rust_rest::AclScope;
use serde_json::{json, Value as Json_};

use crate::auth::Authority;
use crate::response::ParseErrorResponse;
use crate::state::AppState;

const USER_CLASS: &str = "_User";
/// The column upstream stores the bcrypt hash in. Never a response key.
const HASHED_PASSWORD: &str = "_hashed_password";

fn err(e: ParseError) -> Response {
    ParseErrorResponse(e).into_response()
}

/// Remove everything a client must never see from a `_User` row.
///
/// A denylist is the wrong shape in general, but here the set is closed and short, and the
/// stronger property is upstream: the hash is stored under an `_`-prefixed key, and the Mongo
/// untransform already refuses to raise unknown `_` keys. This is the second line.
fn strip_sensitive(mut row: ParseMap) -> ParseMap {
    for key in [
        HASHED_PASSWORD,
        "password",
        "_perishable_token",
        "_email_verify_token",
    ] {
        row.shift_remove(key);
    }
    row
}

/// As in the classes router: strip every internal key before serializing.
fn body_of(row: &ParseMap) -> Json_ {
    let row = parse_rust_rest::to_response_body(row);
    serde_json::from_str(&ParseValue::Object(row).to_json()).unwrap_or(Json_::Null)
}

fn take_string(body: &ParseMap, key: &str) -> Option<String> {
    match body.get(key) {
        Some(ParseValue::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Replace a user-facing password with the bcrypt column that is safe to persist.
///
/// This is shared by signup and master-key writes through `/classes/_User`. Authorization decides
/// whether the class route is allowed; it must not decide whether a password is hashed.
pub(crate) fn hash_user_password(body: &mut ParseMap) -> Result<(), ParseError> {
    let password = match body.get("password") {
        Some(ParseValue::String(password)) => password.clone(),
        // Schema validation reports the wire-compatible error for a non-string value. An absent
        // password is also valid for updates that change another field.
        _ => return Ok(()),
    };
    let hash = parse_rust_auth::password::hash(&password)?;
    body.shift_remove("password");
    body.insert(HASHED_PASSWORD.to_string(), ParseValue::String(hash));
    Ok(())
}

/// Give a newly created user an id and ensure its ACL always contains its own principal.
///
/// Upstream preserves any ACL supplied by a master caller, then adds the owner entry. Leaving an
/// invalid ACL untouched lets the schema/ACL validator return the correct Parse error.
///
/// The result is a user readable and writable by itself and nobody else, which is what
/// `enforcePrivateUsers` produces at its default of **true** (`Options/Definitions.js:263-268`).
/// With that option set to `false` upstream additionally grants `{"*": {"read": true}}`. The
/// option is not modeled, so the private form is the only one produced here: the safe direction,
/// and the one matching the default.
pub(crate) fn ensure_user_identity_and_acl(body: &mut ParseMap) -> String {
    let object_id = match body.get("objectId") {
        Some(ParseValue::String(id)) => id.clone(),
        _ => {
            let id = parse_rust_core::new_object_id();
            body.insert("objectId".to_string(), ParseValue::String(id.clone()));
            id
        }
    };

    let mut permissions = ParseMap::new();
    permissions.insert("read".to_string(), ParseValue::Bool(true));
    permissions.insert("write".to_string(), ParseValue::Bool(true));

    match body.get_mut("ACL") {
        Some(ParseValue::Object(acl)) => {
            acl.insert(object_id.clone(), ParseValue::Object(permissions));
        }
        Some(_) => {}
        None => {
            let mut acl = ParseMap::new();
            acl.insert(object_id.clone(), ParseValue::Object(permissions));
            body.insert("ACL".to_string(), ParseValue::Object(acl));
        }
    }
    object_id
}

/// `POST /users`. Signup.
pub async fn signup(
    State(state): State<AppState>,
    _authority: Authority,
    Json(body): Json<Json_>,
) -> Response {
    let mut body = match parse_rust_core::classify(body) {
        Ok(ParseValue::Object(m)) => m,
        Ok(_) => return err(ParseError::invalid_json("body must be an object")),
        Err(e) => return err(e),
    };
    // Before anything else: a signup body must not carry `_hashed_password` of the caller's
    // choosing.
    if let Err(e) = parse_rust_rest::reject_reserved_keys(&body) {
        return err(e);
    }

    let Some(username) = take_string(&body, "username") else {
        return err(ParseError::new(
            ErrorCode::UsernameMissing,
            "bad or missing username",
        ));
    };
    let Some(password) = take_string(&body, "password") else {
        return err(ParseError::new(
            ErrorCode::PasswordMissing,
            "password is required.",
        ));
    };
    if username.is_empty() {
        return err(ParseError::new(
            ErrorCode::UsernameMissing,
            "bad or missing username",
        ));
    }
    if password.is_empty() {
        return err(ParseError::new(
            ErrorCode::PasswordMissing,
            "password is required.",
        ));
    }

    if let Err(e) = hash_user_password(&mut body) {
        return err(e);
    }

    // `enforcePrivateUsers` defaults to **true** at the pin (`Options/Definitions.js:263-268`),
    // so a new user is readable and writable only by itself.
    //
    // This used to be a comment with no code behind it, which meant every user was world
    // readable. The ACL cannot be built until the objectId exists, and the objectId is generated
    // inside `create`, so signup generates it here and passes it in. That is also what keeps the
    // row from existing unprotected for even one write.
    ensure_user_identity_and_acl(&mut body);

    let created = match parse_rust_rest::create(
        state.storage(),
        USER_CLASS,
        body.clone(),
        &AclScope::Unrestricted,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return err(map_duplicate(e)),
    };

    let token = state.sessions().create(&created.object_id);
    (
        axum::http::StatusCode::CREATED,
        Json(json!({
            "objectId": created.object_id,
            "createdAt": created.created_at.to_iso(),
            "sessionToken": token,
        })),
    )
        .into_response()
}

/// Turn a duplicate-key error into the code the SDK expects.
///
/// A `username_1` collision must be 202 `USERNAME_TAKEN`, not a bare 137. Upstream recovers which
/// field collided by regex over the index name, which is why the index names are contractual.
fn map_duplicate(e: ParseError) -> ParseError {
    if e.code != ErrorCode::DuplicateValue {
        return e;
    }
    if e.message.contains("username_1") {
        return ParseError::new(
            ErrorCode::UsernameTaken,
            "Account already exists for this username.",
        );
    }
    if e.message.contains("email_1") {
        return ParseError::new(
            ErrorCode::EmailTaken,
            "Account already exists for this email address.",
        );
    }
    e
}

/// `POST /login`.
pub async fn login(
    State(state): State<AppState>,
    _authority: Authority,
    Json(body): Json<Json_>,
) -> Response {
    let body = match parse_rust_core::classify(body) {
        Ok(ParseValue::Object(m)) => m,
        Ok(_) => return err(ParseError::invalid_json("body must be an object")),
        Err(e) => return err(e),
    };

    let (Some(username), Some(password)) = (
        take_string(&body, "username"),
        take_string(&body, "password"),
    ) else {
        return err(ParseError::new(
            ErrorCode::UsernameMissing,
            "username/email is required.",
        ));
    };

    let rows = match parse_rust_rest::find(
        state.storage(),
        USER_CLASS,
        vec![parse_rust_storage::Constraint::equal(
            "username",
            ParseValue::String(username),
        )],
        parse_rust_storage::QueryOptions {
            limit: Some(1),
            ..Default::default()
        },
        &AclScope::Unrestricted,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };

    // One error for "no such user" and for "wrong password", so login cannot be used to
    // enumerate accounts. Upstream does the same.
    let invalid = || ParseError::new(ErrorCode::ObjectNotFound, "Invalid username/password.");

    let Some(row) = rows.into_iter().next() else {
        return err(invalid());
    };
    let Some(ParseValue::String(hash)) = row.get(HASHED_PASSWORD) else {
        return err(invalid());
    };
    if !parse_rust_auth::password::verify(&password, hash) {
        return err(invalid());
    }

    let Some(ParseValue::String(object_id)) = row.get("objectId") else {
        return err(ParseError::new(
            ErrorCode::InternalServerError,
            "stored user has no objectId",
        ));
    };

    let token = state.sessions().create(object_id);
    let mut out = strip_sensitive(row.clone());
    out.insert("sessionToken".to_string(), ParseValue::String(token));
    Json(body_of(&out)).into_response()
}

/// `GET /users/me`.
pub async fn me(State(state): State<AppState>, authority: Authority) -> Response {
    let Authority::Client {
        session_token: Some(token),
    } = &authority
    else {
        return err(ParseError::new(
            ErrorCode::InvalidSessionToken,
            "Invalid session token",
        ));
    };
    let Some(object_id) = state.sessions().user_for(token) else {
        return err(ParseError::new(
            ErrorCode::InvalidSessionToken,
            "Invalid session token",
        ));
    };

    match parse_rust_rest::get(
        state.storage(),
        USER_CLASS,
        &object_id,
        &AclScope::Unrestricted,
    )
    .await
    {
        Ok(row) => {
            let mut out = strip_sensitive(row);
            out.insert(
                "sessionToken".to_string(),
                ParseValue::String(token.clone()),
            );
            Json(body_of(&out)).into_response()
        }
        Err(e) => err(e),
    }
}

/// `POST /logout`.
pub async fn logout(State(state): State<AppState>, authority: Authority) -> Response {
    if let Authority::Client {
        session_token: Some(token),
    } = &authority
    {
        state.sessions().revoke(token);
    }
    Json(json!({})).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_user_transform_removes_plaintext_and_writes_a_bcrypt_hash() {
        let mut body = ParseMap::new();
        body.insert(
            "password".to_string(),
            ParseValue::String("hunter2".to_string()),
        );

        hash_user_password(&mut body).expect("password hashes");

        assert!(!body.contains_key("password"));
        let Some(ParseValue::String(hash)) = body.get(HASHED_PASSWORD) else {
            panic!("hash missing");
        };
        assert!(parse_rust_auth::password::verify("hunter2", hash));
    }

    #[test]
    fn user_owner_acl_is_added_without_discarding_a_master_supplied_acl() {
        let mut public = ParseMap::new();
        public.insert("read".to_string(), ParseValue::Bool(true));
        let mut acl = ParseMap::new();
        acl.insert("*".to_string(), ParseValue::Object(public));

        let mut body = ParseMap::new();
        body.insert(
            "objectId".to_string(),
            ParseValue::String("user123456".to_string()),
        );
        body.insert("ACL".to_string(), ParseValue::Object(acl));

        let object_id = ensure_user_identity_and_acl(&mut body);

        assert_eq!(object_id, "user123456");
        let Some(ParseValue::Object(acl)) = body.get("ACL") else {
            panic!("ACL missing");
        };
        assert!(acl.contains_key("*"));
        let Some(ParseValue::Object(owner)) = acl.get("user123456") else {
            panic!("owner ACL missing");
        };
        assert!(matches!(owner.get("read"), Some(ParseValue::Bool(true))));
        assert!(matches!(owner.get("write"), Some(ParseValue::Bool(true))));
    }
}
