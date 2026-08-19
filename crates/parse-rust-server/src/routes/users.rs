//! Signup, login, `/users/me`, logout.
//!
//! Upstream: `src/Routers/UsersRouter.js`. Three facts shape this module.
//!
//! - **`POST /users` is not `POST /classes/_User`.** Only the signup route returns a session
//!   token. A non-master **create or delete** through the class route is refused; an **update** is
//!   allowed, because that is what `user.save()` sends. See `classes::enforce_class_security`.
//! - **The password hash must never reach a response.** Upstream reattaches the hash onto the
//!   object as `password` and strips it in exactly one place, so every response path depends on
//!   that one step running. Here the hash is never placed on a response object at all, so there
//!   is nothing to strip and no path that can forget to.
//! - **Login reads below the pipeline.** `filterSensitiveData` removes every `_`-prefixed key,
//!   including the hash the password check needs, so a login that went through the read pipeline
//!   could never verify anything. Upstream has the same problem and solves it by reading under
//!   `Auth.maintenance` (`UsersRouter.js:108-110`), whose bypass parse-rust does not model; the
//!   equivalent here is one direct adapter read, built from a username and nothing client-shaped.

use parse_rust_auth::{create_session, CreatedWith, NewSession};
use parse_rust_core::{ErrorCode, FieldWrite, ParseError, ParseMap, ParseValue};
use parse_rust_rest::{FindOptions, WriteBody};
use parse_rust_storage::{Constraint, Query, QueryOptions, StorageAdapter};
use serde_json::{json, Value as Json};

use crate::auth::Authority;
use crate::request::RequestContext;
use crate::state::AppState;

pub const USER_CLASS: &str = "_User";
/// The column upstream stores the bcrypt hash in. Never a response key.
const HASHED_PASSWORD: &str = "_hashed_password";

/// Remove everything a client must never see from a raw `_User` row.
///
/// Only the direct-adapter login path needs this, because every other read goes through
/// `filterSensitiveData`. A denylist is the wrong shape in general; here the set is closed and the
/// stronger property is that `to_response_body` strips every `_`-prefixed key afterwards anyway.
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

/// Whether a key is present with a JS-truthy value, whatever its type.
///
/// `!password` is upstream's test, and it fires on an absent key, `null`, `false`, `0` and `""`
/// alike, but **not** on a non-string that happens to be truthy. That one falls to the type check
/// below it, which is a different code.
fn body_has_truthy(body: &WriteBody, key: &str) -> bool {
    match body.get(key) {
        Some(FieldWrite::Value(v)) => parse_rust_core::is_js_truthy(v),
        // An op envelope is an object on the JS side, so it is truthy.
        Some(FieldWrite::Op(_)) => true,
        None => false,
    }
}

fn take_string(body: &WriteBody, key: &str) -> Option<String> {
    match body.get(key) {
        Some(FieldWrite::Value(ParseValue::String(s))) => Some(s.clone()),
        _ => None,
    }
}

/// Replace a user-facing password with the bcrypt column that is safe to persist, and, on a
/// create, give the row an id and an owner ACL.
///
/// Shared by signup and master-key writes through `/classes/_User`. Authorization decides whether
/// the class route is allowed; it must not decide whether a password is hashed.
pub(crate) async fn prepare_user_write(
    body: &mut WriteBody,
    is_create: bool,
) -> Result<(), ParseError> {
    hash_user_password(body).await?;
    if is_create {
        ensure_user_identity_and_acl(body);
    }
    Ok(())
}

async fn hash_user_password(body: &mut WriteBody) -> Result<(), ParseError> {
    let Some(password) = take_string(body, "password") else {
        // Schema validation reports the wire-compatible error for a non-string value. An absent
        // password is also valid for updates that change another field.
        return Ok(());
    };
    let hash = parse_rust_auth::password::hash(password).await?;
    body.shift_remove("password");
    body.insert(
        HASHED_PASSWORD.to_string(),
        FieldWrite::Value(ParseValue::String(hash)),
    );
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
pub(crate) fn ensure_user_identity_and_acl(body: &mut WriteBody) -> String {
    let object_id = match take_string(body, "objectId") {
        Some(id) => id,
        None => {
            let id = parse_rust_core::new_object_id();
            body.insert(
                "objectId".to_string(),
                FieldWrite::Value(ParseValue::String(id.clone())),
            );
            id
        }
    };

    let mut permissions = ParseMap::new();
    permissions.insert("read".to_string(), ParseValue::Bool(true));
    permissions.insert("write".to_string(), ParseValue::Bool(true));

    match body.get_mut("ACL") {
        Some(FieldWrite::Value(ParseValue::Object(acl))) => {
            acl.insert(object_id.clone(), ParseValue::Object(permissions));
        }
        // A non-object ACL is left alone so the ACL validator reports it.
        Some(_) => {}
        None => {
            let mut acl = ParseMap::new();
            acl.insert(object_id.clone(), ParseValue::Object(permissions));
            body.insert(
                "ACL".to_string(),
                FieldWrite::Value(ParseValue::Object(acl)),
            );
        }
    }
    object_id
}

/// `handleCreate`'s `role:`-prefixed objectId refusal (`ClassesRouter.js:105-112`).
///
/// A user whose objectId is `role:Admins` is granted that role by every ACL check, because an ACL
/// names a role by string and the caller's ACL group carries its own objectId.
///
/// **On `ClassesRouter`, not on `UsersRouter`**, which is the detail that matters for where this
/// is called from. `UsersRouter extends ClassesRouter` and does not override `handleCreate`
/// (`UsersRouter.js:23`, `:824-826`), so one guard covers `POST /users` and `POST /classes/_User`
/// alike. parse-rust had it on the signup route only, which left the class route uncovered for
/// the master key.
pub(crate) fn reject_role_prefixed_object_id(
    body: &WriteBody,
    rc: &RequestContext,
) -> Result<(), ParseError> {
    let Some(FieldWrite::Value(ParseValue::String(id))) = body.get("objectId") else {
        // `typeof req.body?.objectId === 'string'` guards it upstream, so a non-string is not
        // refused here. It is refused by schema validation instead.
        return Ok(());
    };
    if !id.starts_with("role:") {
        return Ok(());
    }
    // `createSanitizedError` (`ClassesRouter.js:111`). Note this is the sanitized twin of
    // `Auth.js`'s identically worded refusal, which is a plain `Parse.Error` and stays detailed;
    // the two are different call sites with the same string.
    Err(ParseError::permission_denied(
        ErrorCode::OperationForbidden,
        "Invalid object ID.",
        rc.options.error_detail,
    ))
}

/// A created `_User` must carry a non-empty username and a non-empty password
/// (`RestWrite.js:468-473`).
///
/// **Not gated on the caller.** Upstream's guard is `!this.query && !hasAuthData`, which asks
/// whether this is a create and whether an auth adapter is supplying the identity instead. Master
/// is not exempt, so `POST /classes/_User` with the master key is subject to it too. Without that,
/// the dashboard's own route admitted a user with no username, or a passwordless row that no
/// login can ever match and that `verify_dummy` exists to make indistinguishable.
///
/// Runs **before** identity validation and hashing, which is upstream's order: `validateAuthData`
/// is stage 5 of the chain and `transformUser` is stage 12 (`RestWrite.js:122-141`). Checking a
/// uniqueness query and paying a bcrypt cost for a body that was never well-formed is work done on
/// behalf of a request that cannot succeed.
///
/// The `authData` branch is not modelled: parse-rust refuses `authData` outright, so the only
/// reachable case is the one that requires both fields. When auth adapters land, this guard grows
/// the second condition rather than moving.
pub(crate) fn require_create_credentials(body: &WriteBody) -> Result<(), ParseError> {
    if take_string(body, "username")
        .filter(|u| !u.is_empty())
        .is_none()
    {
        return Err(ParseError::new(
            ErrorCode::UsernameMissing,
            "bad or missing username",
        ));
    }
    if take_string(body, "password")
        .filter(|p| !p.is_empty())
        .is_none()
    {
        // No trailing period. Upstream's string is `password is required`, and the message is
        // contract in the disclosing regime.
        return Err(ParseError::new(
            ErrorCode::PasswordMissing,
            "password is required",
        ));
    }
    Ok(())
}

/// `POST /users`. Signup.
pub async fn signup_core(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    body: &Json,
) -> Result<Json, ParseError> {
    let mut body = parse_rust_rest::decode_write_body(body, parse_rust_core::op::OpPath::Create)?;
    // Before anything else: a signup body must not carry a `_hashed_password` of the caller's
    // choosing.
    parse_rust_rest::reject_reserved_keys_in(body.keys().map(String::as_str))?;
    // Signup is a create like any other, so the objectId policy applies to it
    // (`RestWrite.js:50-65`). It has to run here rather than inside the pipeline, because
    // `ensure_user_identity_and_acl` below puts a server-generated objectId into the body.
    parse_rust_rest::enforce_object_id_policy(&body, state.config().allow_custom_object_id)?;

    reject_role_prefixed_object_id(&body, rc)?;
    // Upstream runs this on create as well as update (`RestWrite.js:116`), and running it only on
    // the update path left signup able to set `emailVerified` and `authData` on its own new row.
    reject_client_restricted_user_fields(&body, rc, authority)?;

    require_create_credentials(&body)?;

    // **The `create` permission is checked before any identity work** (`RestWrite.js:730-746`,
    // whose own comment names this exact hazard). `validate_user_identity` queries `_User` by
    // username and email, and the password is then hashed, so a signup that the CLP will refuse
    // otherwise answers 202 in milliseconds for a name that exists and 119 after a bcrypt-length
    // pause for one that does not. Measured on a closed `_User.create`: ~4 ms against ~196 ms.
    //
    // That is account enumeration against a class whose whole point is that outsiders may not read
    // it, and no response body discloses it: the difference is entirely in which check runs first.
    // Master and maintenance skip the gate, as upstream's `isMaster || isMaintenance` does.
    if !authority.is_privileged() {
        parse_rust_rest::validate_permission(
            rc.snapshot.clp(USER_CLASS),
            USER_CLASS,
            &rc.scope.acl_group(),
            parse_rust_core::Operation::Create,
            None,
            rc.options.error_detail,
        )?;
    }

    // **Signup runs the same identity validation an update does**, because `transformUser` is one
    // function and does not branch on create versus update for these two checks
    // (`RestWrite.js:803-807`). Validating on the update path alone left signup admitting exactly
    // the identities the update path refuses: a case-only duplicate username, and an email that is
    // not one.
    //
    // The objectId is not known yet, so the `$ne` exclusion is given a value no row can hold. On a
    // create there is no self to exclude, which is the same thing upstream's `this.objectId()`
    // returning undefined achieves.
    validate_user_identity(state, rc, &body, "").await?;

    prepare_user_write(&mut body, true).await?;

    let ctx = rc.ctx(state.storage());
    let created = parse_rust_rest::create(&ctx, USER_CLASS, body)
        .await
        .map_err(map_duplicate)?;

    let session = create_session(
        state.storage(),
        &state.config().session,
        NewSession {
            user_object_id: &created.object_id,
            created_with: Some(CreatedWith::signup(None)),
            installation_id: rc.installation_id.as_deref(),
        },
    )
    .await?;

    Ok(json!({
        "objectId": created.object_id,
        "createdAt": created.created_at.to_iso(),
        "sessionToken": session.session_token,
    }))
}

/// Turn a duplicate-key error into the code the SDK expects (`RestWrite.js:1697-1716`).
///
/// A `username_1` collision must be 202 `USERNAME_TAKEN`, not a bare 137. Which field collided is
/// read from the adapter's out-of-band [`ParseError::duplicated_field`], which the adapter fills
/// in by recognising the auto-generated index name. That is why index names are contractual, and
/// it is why nothing here reads `message`: the message is the fixed
/// `A duplicate value for a field with unique values was provided` in every case, and the driver
/// text it replaced named the database and the colliding value.
///
/// **Not modelled: upstream's fallback.** When it cannot recover the field, upstream re-queries
/// `_User` by username and then by email before settling for 137 (`RestWrite.js:1718-1755`). The
/// only index Parse creates that reaches that path is a case-insensitive one, which parse-rust
/// does not create, so a collision it cannot attribute stays 137 here.
pub(crate) fn map_duplicate(e: ParseError) -> ParseError {
    if e.code != ErrorCode::DuplicateValue {
        return e;
    }
    match e.duplicated_field() {
        Some("username") => ParseError::new(
            ErrorCode::UsernameTaken,
            "Account already exists for this username.",
        ),
        Some("email") => ParseError::new(
            ErrorCode::EmailTaken,
            "Account already exists for this email address.",
        ),
        _ => e,
    }
}

/// `POST /login`.
pub async fn login_core(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    body: &Json,
) -> Result<Json, ParseError> {
    let body = parse_rust_rest::decode_write_body(body, parse_rust_core::op::OpPath::Create)?;

    // **Three refusals in upstream's order, each with its own code** (`UsersRouter.js:84-96`).
    // Collapsing them into one `USERNAME_MISSING`, which is what this did, is wire-visible twice
    // over: a client with no password got the username error, and a client with a non-string
    // password got it too where upstream answers `OBJECT_NOT_FOUND`.
    //
    // **Each guard tests JavaScript truthiness of the raw value, not "is it a non-empty string".**
    // The distinction decides which of the three fires: `{"username": 7}` is truthy, so it passes
    // the first guard and is refused by the third as a type error, where testing for a string here
    // would report a missing username instead.
    let has_username = body_has_truthy(&body, "username");
    let has_email = body_has_truthy(&body, "email");
    if !has_username && !has_email {
        return Err(ParseError::new(
            ErrorCode::UsernameMissing,
            "username/email is required.",
        ));
    }
    if !body_has_truthy(&body, "password") {
        return Err(ParseError::new(
            ErrorCode::PasswordMissing,
            "password is required.",
        ));
    }
    // A truthy non-string password, username or email is the third refusal, and it deliberately
    // answers the same thing a wrong password does rather than naming the type: telling a caller
    // its password was the wrong *type* is one bit more than upstream gives away here.
    let invalid_credentials =
        || ParseError::new(ErrorCode::ObjectNotFound, "Invalid username/password.");
    let username = take_string(&body, "username");
    let email = take_string(&body, "email");
    let Some(password) = take_string(&body, "password") else {
        return Err(invalid_credentials());
    };
    if (has_username && username.is_none()) || (has_email && email.is_none()) {
        return Err(invalid_credentials());
    }

    // Straight to the adapter. See the module note: the read pipeline strips the hash this has to
    // check, and the query is built here from the identifier rather than from anything the client
    // shaped, so nothing client-supplied reaches storage unfiltered.
    //
    // **The `$or` is what makes logging in with an email address work** (`UsersRouter.js:99-107`).
    // Given only an identifier, upstream matches it against `username` *or* `email`, which is what
    // every SDK's `Parse.User.logIn(emailAddress, password)` relies on. Matching `username` alone,
    // which is what this did, answered `Invalid username/password.` for a correct email and
    // password, and an `email` key was not read at all.
    let schema = rc.snapshot.get_or_default(USER_CLASS);
    let identifier = username.filter(|_| has_username);
    // Kept for the multi-row preference below, which compares against the submitted username.
    let username_for_preference = identifier.clone();
    let email = email.filter(|_| has_email);
    let query = match (identifier, email) {
        // Both given: an AND, so a mismatched pair is not a login.
        (Some(username), Some(email)) => Query::from_constraints(vec![
            Constraint::equal("email", ParseValue::String(email)),
            Constraint::equal("username", ParseValue::String(username)),
        ]),
        (None, Some(email)) => {
            Query::from_constraints(vec![Constraint::equal("email", ParseValue::String(email))])
        }
        // The identifier arrived as `username` and may be either.
        (Some(identifier), None) => Query::any_of(vec![
            Query::from_constraints(vec![Constraint::equal(
                "username",
                ParseValue::String(identifier.clone()),
            )]),
            Query::from_constraints(vec![Constraint::equal(
                "email",
                ParseValue::String(identifier),
            )]),
        ]),
        // Unreachable: the first guard refused the case where neither is truthy, and the third
        // refused the case where a truthy one is not a string.
        (None, None) => return Err(invalid_credentials()),
    };

    // **No limit.** Upstream passes an empty options object (`UsersRouter.js:108-110`), and the
    // reason surfaces one line down: an account whose email equals another account's username
    // matches both rows, and upstream resolves that by preferring the exact username match. Capping
    // the query at one row makes the winner whichever row MongoDB returns first, which can reject a
    // valid login or, if the two passwords happen to match, authenticate the wrong account.
    let rows = state
        .storage()
        .find(&schema, &query, &QueryOptions::default())
        .await?;

    // One error for "no such user" and for "wrong password", so login cannot be used to
    // enumerate accounts. Upstream does the same.
    let invalid = || ParseError::new(ErrorCode::ObjectNotFound, "Invalid username/password.");

    // `results.filter(user => user.username === username)[0]` (`UsersRouter.js:121-124`). Upstream
    // logs a warning here; there is no logger yet, so the preference is applied silently. Falling
    // back to the first row covers the case upstream would crash on, where more than one row
    // matched but the identifier arrived as an `email` key and no row's username can equal it.
    let row = select_login_row(rows, username_for_preference.as_deref());

    // **Both failure paths below pay the bcrypt cost.** Returning early makes a missing account
    // answer in microseconds where a real one answers in milliseconds, and that difference is
    // measurable across a network, so the shared error message stops hiding which accounts exist.
    // Upstream runs the same dummy compare in both branches (`UsersRouter.js:112-118`, `:132-136`).
    let Some(row) = row else {
        parse_rust_auth::password::verify_dummy(password).await;
        return Err(invalid());
    };
    let hash = match row.get(HASHED_PASSWORD) {
        Some(ParseValue::String(hash)) if !hash.is_empty() => hash.clone(),
        // A passwordless account, which an auth-adapter signup produces upstream. Never a valid
        // password login, and it must not be a fast one either.
        _ => {
            parse_rust_auth::password::verify_dummy(password).await;
            return Err(invalid());
        }
    };
    if !parse_rust_auth::password::verify(password, hash).await {
        return Err(invalid());
    }

    // **An explicitly empty ACL is a disabled account** (`UsersRouter.js:151-153`). A master caller
    // setting `ACL: {}` is the documented way to lock a user out, and without this the account
    // still logs in and receives a working session, so the lock does nothing until its existing
    // sessions are separately destroyed.
    //
    // `authority.is_master()` rather than `rc.is_master()`: upstream's guard is `!req.auth.isMaster`
    // alone, so **maintenance is subject to the check**, and `rc.is_master()` answers for the ACL
    // scope, which treats master and maintenance alike.
    if !authority.is_master() && acl_is_explicitly_empty(&row) {
        return Err(invalid());
    }

    let Some(ParseValue::String(object_id)) = row.get("objectId") else {
        // Nothing upstream throws here, because a row without an objectId cannot exist through
        // any write path. If one does, the shape of the stored row is not the client's business.
        return Err(ParseError::internal("stored user has no objectId"));
    };

    let session = create_session(
        state.storage(),
        &state.config().session,
        NewSession {
            user_object_id: object_id,
            created_with: Some(CreatedWith::login(None)),
            installation_id: rc.installation_id.as_deref(),
        },
    )
    .await?;

    // **Re-fetch under the caller's own auth before answering** (`UsersRouter.js:349-387`).
    //
    // The row above came from a direct adapter read, deliberately below the pipeline, because the
    // password check needs the hash that `filterSensitiveData` strips. That read answers to
    // nothing: not `_User` `get` CLP, not `protectedFields`, not the object's ACL. Returning it is
    // how a deployment that protects `email` still puts `email` on the wire at every login, and
    // the response looks completely ordinary while it happens.
    //
    // `strip_sensitive` is a denylist over the columns login itself must not echo. It is not an
    // authorization filter and cannot become one, because the fields at issue are configured per
    // deployment and are ordinary columns.
    let object_id = object_id.to_string();
    let mut out = refetch_for_response(state, rc, &object_id, row).await?;
    out.insert(
        "sessionToken".to_string(),
        ParseValue::String(session.session_token),
    );
    Ok(crate::routes::classes::body_of(&out))
}

/// Choose the account a login refers to when the identifier matched more than one row.
///
/// `results.filter(user => user.username === username)[0]` (`UsersRouter.js:121-124`). One user's
/// email can equal another's username, and the `$or` matches both; upstream prefers the exact
/// username and logs a warning. There is no logger yet, so the preference is applied silently.
///
/// **A pure function so it can be tested against the adverse order.** The integration test cannot
/// force which row MongoDB returns first from an `$or`, so it passes against a `limit: 1`
/// implementation whenever the database happens to return the right one, which is most of the
/// time: a test that reports success for the bug it was written to catch. Deciding here, over a
/// list the caller supplies, is what makes the failing case reachable on demand.
///
/// Falling back to the first row covers what upstream crashes on: more than one match when the
/// identifier arrived as an `email` key, so no row's username can equal it and
/// `results.filter(...)[0]` is `undefined`.
fn select_login_row(rows: Vec<ParseMap>, submitted_username: Option<&str>) -> Option<ParseMap> {
    if rows.len() <= 1 {
        return rows.into_iter().next();
    }
    let mut rows = rows;
    let exact = submitted_username.and_then(|name| {
        rows.iter()
            .position(|r| matches!(r.get("username"), Some(ParseValue::String(u)) if u == name))
    });
    match exact {
        Some(i) => Some(rows.swap_remove(i)),
        None => rows.into_iter().next(),
    }
}

/// The authenticated user's own view of their row, for a login response.
///
/// Master and maintenance keep the raw row: they bypass CLP and `protectedFields` everywhere else,
/// so re-reading would only narrow a view they are entitled to, and an empty result for them is a
/// genuine not-found rather than a denial (`UsersRouter.js:378-387`).
///
/// **A denied or empty re-fetch falls back to the identity alone, never to the raw row.** That is
/// upstream's explicit choice at `:376` and it is the whole point: the fallback is reached exactly
/// when access control refused the record, which is the case where returning the raw row would
/// disclose the most. Login still succeeds, because authentication and authorization are separate
/// questions and passing the first does not entitle the caller to read the row.
async fn refetch_for_response(
    state: &AppState,
    rc: &RequestContext,
    object_id: &str,
    row: ParseMap,
) -> Result<ParseMap, ParseError> {
    if rc.is_master() {
        return Ok(parse_rust_rest::acl::raise_acl(strip_sensitive(row)));
    }

    let identity_only = || {
        let mut map = ParseMap::new();
        map.insert(
            "objectId".to_string(),
            ParseValue::String(object_id.to_string()),
        );
        map
    };

    // The caller is whoever just authenticated, not whoever the request arrived as. A login
    // carrying somebody else's token still answers about the account whose password was verified.
    let roles = parse_rust_auth::expand_roles(
        state.storage(),
        parse_rust_auth::RolePrincipal::User(object_id),
    )
    .await?;
    let scope = parse_rust_rest::AclScope::user(
        object_id.to_string(),
        roles.iter().map(|r| r.as_str().to_string()).collect(),
    )?;

    let ctx = parse_rust_rest::Ctx::new(state.storage(), &rc.snapshot, &scope, &rc.options);
    match parse_rust_rest::get(&ctx, USER_CLASS, object_id, FindOptions::default()).await {
        Ok(row) => Ok(row),
        // Any refusal, not just `ObjectNotFound`: a CLP of `get: {}` answers
        // `OPERATION_FORBIDDEN`, and both mean access control withheld the row.
        Err(_) => Ok(identity_only()),
    }
}

/// Is the row's ACL present and empty, which upstream treats as a disabled account?
///
/// Upstream tests `user.ACL && Object.keys(user.ACL).length == 0` on the rehydrated object
/// (`UsersRouter.js:151`). The stored form is `_rperm`/`_wperm`, so this raises them the same way a
/// read would and asks whether the result is an ACL with no entries. A row with neither column has
/// no ACL at all and is not disabled, which is the `user.ACL &&` half of upstream's test.
fn acl_is_explicitly_empty(row: &ParseMap) -> bool {
    matches!(
        parse_rust_rest::acl::raise_acl(row.clone()).get("ACL"),
        Some(ParseValue::Object(acl)) if acl.is_empty()
    )
}

/// `GET /users/me`.
///
/// The token is validated first, then the user is re-fetched **with the caller's own auth**
/// (`UsersRouter.js:214-223`) so protected fields and CLP apply. Both failures answer
/// `Invalid session token`, which is a different string from `/sessions/me`'s.
pub async fn me_core(state: &AppState, rc: &RequestContext) -> Result<Json, ParseError> {
    // `createSanitizedError` at all three of `handleMe`'s refusals (`UsersRouter.js:193`, `:211`,
    // `:225`). `GET /sessions/me` is a different router with different strings and is not
    // sanitized upstream, so it stays detailed.
    let invalid = || {
        ParseError::permission_denied(
            ErrorCode::InvalidSessionToken,
            "Invalid session token",
            rc.options.error_detail,
        )
    };
    let (Some(token), Some(user_id)) = (rc.session_token.as_deref(), rc.user_id.as_deref()) else {
        return Err(invalid());
    };

    let ctx = rc.ctx(state.storage());
    let row = parse_rust_rest::get(&ctx, USER_CLASS, user_id, FindOptions::default())
        .await
        .map_err(|e| {
            if e.code == ErrorCode::ObjectNotFound {
                invalid()
            } else {
                e
            }
        })?;

    let mut out = row;
    // Send the token back on the response, because SDKs expect that (`UsersRouter.js:228-229`).
    out.insert(
        "sessionToken".to_string(),
        ParseValue::String(token.to_string()),
    );
    Ok(crate::routes::classes::body_of(&out))
}

/// `POST /logout`.
///
/// Deletes the `_Session` row (`UsersRouter.js:509-538`). A request with no token, or with one
/// that no longer resolves, still answers `{}`.
pub async fn logout_core(state: &AppState, rc: &RequestContext) -> Result<Json, ParseError> {
    if let Some(token) = rc.session_token.as_deref() {
        parse_rust_auth::revoke(state.storage(), token).await?;
    }
    Ok(json!({}))
}

// ---------------------------------------------------------------------------------------------
// `_User` update policy
//
// `PUT /classes/_User/:objectId` is the route `user.save()` compiles to, and opening it to
// non-master callers means running the stages `RestWrite.transformUser` runs. Reserving the
// password and the ACL, which is all this module did before, is not enough: it leaves the row's
// server-controlled columns writable and its identity columns unvalidated.
// ---------------------------------------------------------------------------------------------

/// `_User` columns a client may never write, whatever the ACL says.
///
/// `emailVerified` is the one that matters: it is the output of a verification flow, so a client
/// that can set it has verified its own email. Upstream refuses it with `OPERATION_FORBIDDEN`
/// (`RestWrite.js:1543-1556`).
///
/// `authData` is refused rather than validated, which is a deliberate fail-closed gap: upstream
/// hands it to an auth adapter that decides whether the credential is real, and parse-rust has no
/// adapter host. Accepting it unvalidated would let a client write a third-party identity that a
/// later login could match on.
const CLIENT_FORBIDDEN_USER_FIELDS: [&str; 2] = ["emailVerified", "authData"];

/// The noun upstream uses in the refusal, which is not the column name.
///
/// `emailVerified` is reported as `email verification` (`RestWrite.js:724`). The message is
/// contract in the disclosing regime, and a client matching on it would see the difference.
fn forbidden_label(field: &str) -> &str {
    match field {
        "emailVerified" => "email verification",
        other => other,
    }
}

/// Refuse the `_User` columns a client may not set on itself.
///
/// **Create and update alike, which is the half signup was missing.** Upstream's
/// `checkRestrictedFields` sits in the chain `RestWrite.execute` runs for both
/// (`RestWrite.js:116`, defined at `:716-728`), so `POST /users` is covered there. parse-rust
/// applied it only on the update path, which left signup able to set both fields on the row it was
/// creating.
///
/// The two fields are here for different reasons and only the first is upstream's:
///
/// - `emailVerified` is upstream's own restriction, with upstream's message. A client that can set
///   it at signup marks its own address verified without ever receiving mail.
/// - `authData` is **not** in upstream's list, because upstream validates it instead: every
///   provider block goes to the configured auth adapter, which decides whether the credential is
///   real (`RestWrite.js:409-460`). parse-rust has no adapter host, so there is nothing to validate
///   against, and storing the block unvalidated would let a client write a third-party identity
///   that a later login could match on. Refusing is the fail-closed stand-in until adapters exist,
///   and it is recorded as a deliberate difference rather than left implicit.
fn reject_client_restricted_user_fields(
    body: &WriteBody,
    rc: &RequestContext,
    authority: &Authority,
) -> Result<(), ParseError> {
    if authority.is_privileged() {
        return Ok(());
    }
    for field in CLIENT_FORBIDDEN_USER_FIELDS {
        if body.get(field).is_some() {
            return Err(ParseError::permission_denied(
                ErrorCode::OperationForbidden,
                format!(
                    "Clients aren't allowed to manually update {}.",
                    forbidden_label(field)
                ),
                rc.options.error_detail,
            ));
        }
    }
    Ok(())
}

/// The checks that need no database read, run before the write.
///
/// **The first is the one that was missing and it is the serious one.** `enforce_class_security`
/// asks whether a *class* is writable, not whether the caller is anybody. A `_User` row whose ACL
/// grants public write was therefore updatable by an anonymous request, and because a password
/// change mints a replacement session, that is account takeover against any user with a permissive
/// ACL. Upstream refuses an unauthenticated `_User` update outright, before the ACL is consulted
/// (`RestWrite.js:1572-1576`), and so does this.
pub(crate) fn enforce_user_update_policy(
    body: &WriteBody,
    rc: &RequestContext,
    authority: &Authority,
    object_id: &str,
) -> Result<(), ParseError> {
    if !authority.is_privileged() && rc.user_id.is_none() {
        return Err(ParseError::permission_denied(
            ErrorCode::SessionMissing,
            format!("Cannot modify user {object_id}."),
            rc.options.error_detail,
        ));
    }

    reject_client_restricted_user_fields(body, rc, authority)?;

    // A non-string password reaches bcrypt upstream and throws out of the hashing library, which
    // answers a bare 500 (`RestWrite.js:636`, `password.js:17`). Measured: `{"password": null}`
    // answers `{"code":1,"message":"Internal server error."}`.
    //
    // Refused cleanly here instead. Reproducing a 500 has no client value, and the specific shape
    // matters: `password: null` previously read as "no password" to the hasher and as "a password
    // change" to the followup, so it revoked every session and issued a replacement while leaving
    // the old password working. A false report of a security-relevant change is worse than either
    // behaviour.
    match body.get("password") {
        None | Some(FieldWrite::Value(ParseValue::String(_))) => {}
        Some(_) => {
            return Err(ParseError::incorrect_type(
                "password must be a string".to_string(),
            ))
        }
    }
    Ok(())
}

/// Force the row's own principal back into a submitted ACL.
///
/// Upstream re-adds it after the client's ACL is applied, so a `_User` cannot be made unreadable
/// or unwritable by its owner. Measured against parse-server 9.10.1-alpha.6: saving
/// `{"ACL": {"*": {"read": true, "write": true}}}` reads back with the owner entry still present.
/// Without this a client can lock itself out of its own row, and can do it to another user
/// wherever an ACL permits the write.
pub(crate) fn force_owner_into_acl(body: &mut WriteBody, object_id: &str, privileged: bool) {
    // **Master and maintenance are exempt.** Upstream applies the owner entry only for a
    // non-privileged caller, so an administrator replacing a user's ACL with one that excludes
    // them gets exactly that. Forcing it back in unconditionally means an operator cannot revoke a
    // user's access to their own row, which is a legitimate administrative action and one a
    // dashboard offers.
    if privileged {
        return;
    }
    let mut permissions = ParseMap::new();
    permissions.insert("read".to_string(), ParseValue::Bool(true));
    permissions.insert("write".to_string(), ParseValue::Bool(true));
    let owner_entry = ParseValue::Object(permissions);

    match body.get_mut("ACL") {
        Some(FieldWrite::Value(ParseValue::Object(acl))) => {
            acl.insert(object_id.to_string(), owner_entry);
        }
        // **`{"ACL": {"__op": "Delete"}}` is the other way to replace an ACL, and it was not
        // covered.** `user.unset("ACL").save()` sends exactly this. Matching only the object form
        // let it through to the lowering, which cleared both permission columns, and an empty ACL
        // on `_User` is a row its owner can no longer read or write: their next save answered 101
        // and the account read as disabled at login. Upstream answers 200 and the row comes back
        // holding the owner entry alone.
        //
        // Rewritten to that value rather than dropped, so the delete still happens: every other
        // principal goes, the owner stays.
        Some(entry @ FieldWrite::Op(parse_rust_core::Op::Delete)) => {
            let mut acl = ParseMap::new();
            acl.insert(object_id.to_string(), owner_entry);
            *entry = FieldWrite::Value(ParseValue::Object(acl));
        }
        _ => {}
    }
}

/// `_validateUserName` and `_validateEmail` (`RestWrite.js:811-884`), for the update path.
///
/// **Case-insensitive, and that is the whole point of doing it here rather than leaving it to the
/// unique indexes.** The indexes parse-rust creates are the plain `username_1` and `email_1`, which
/// compare case-sensitively, so `CaseOnly` and `caseonly` are two different keys to MongoDB and
/// both are stored. Upstream refuses the second with 202. The changelog claimed the indexes held
/// uniqueness; they hold only exact-match uniqueness, and this is the half that was missing.
///
/// The comparison runs under upstream's collation, through `QueryOptions::case_insensitive`, which
/// is upstream's own `{caseInsensitive: true}` find rather than an approximation of it.
///
/// The `objectId: {$ne: <self>}` term is load-bearing: without it, saving a row with its own
/// username unchanged collides with itself.
pub(crate) async fn validate_user_identity(
    state: &AppState,
    rc: &RequestContext,
    body: &WriteBody,
    object_id: &str,
) -> Result<(), ParseError> {
    // **Username first, then email**, which is `transformUser`'s chain order
    // (`RestWrite.js:803-807`). A body carrying both a colliding username and a malformed email
    // reports the username, and checking email first reported the email instead.
    // **A `Delete` on `username` is refused, and on `email` it is allowed.** The asymmetry is
    // upstream's and is visible on the wire. `_validateEmail` opens with
    // `if (!this.data.email || this.data.email.__op === 'Delete') return` (`RestWrite.js:886`);
    // `_validateUserName` has no such branch, so the op object is truthy, reaches the uniqueness
    // query as a value, and answers `107 You cannot use [object Object] as a query parameter.`
    //
    // Matching only the string form let `user.unset("username").save()` through, removing the
    // username with no validation at all. The message is upstream's rendering of a query built
    // from an op object, which is an accident of how it fails rather than a designed error, but it
    // is the string a client sees.
    if matches!(body.get("username"), Some(FieldWrite::Op(_))) {
        return Err(ParseError::invalid_json(
            "You cannot use [object Object] as a query parameter.",
        ));
    }
    if let Some(FieldWrite::Value(ParseValue::String(username))) = body.get("username") {
        if taken(state, rc, "username", username, object_id).await? {
            return Err(ParseError::new(
                ErrorCode::UsernameTaken,
                "Account already exists for this username.",
            ));
        }
    }

    let Some(FieldWrite::Value(ParseValue::String(email))) = body.get("email") else {
        return Ok(());
    };
    // `if (!this.data.email ...) return` (`RestWrite.js:886`). An empty string is falsy, so it is
    // skipped rather than rejected, and upstream answers 200 for `{"email": ""}`.
    if email.is_empty() {
        return Ok(());
    }
    if !is_valid_email(email) {
        return Err(ParseError::new(
            ErrorCode::InvalidEmailAddress,
            "Email address format is invalid.",
        ));
    }
    if taken(state, rc, "email", email, object_id).await? {
        return Err(ParseError::new(
            ErrorCode::EmailTaken,
            "Account already exists for this email address.",
        ));
    }
    Ok(())
}

/// `/^.+@.+$/` as JavaScript evaluates it (`RestWrite.js:890`).
///
/// Deliberately not an address grammar. Matching upstream's laxness matters more than being right
/// about RFC 5322, and `a b@c d` is a valid address to this check on both servers.
///
/// **Two things about that regex are easy to get wrong, and a naive `find('@')` gets both wrong.**
///
/// `.` does not match a line terminator, and JavaScript counts four: `\n`, `\r`, U+2028 and
/// U+2029. Since `^` and `$` with no `m` flag anchor to the whole string, and `.+@.+` has to span
/// it, a line terminator *anywhere* means no match. The two Unicode ones are the trap: they are
/// invisible in most editors and are not what `char::is_whitespace` or a `\n` check would catch.
/// Ordinary spaces and tabs are not line terminators and are accepted.
///
/// And the `@` may be neither the first nor the last character, but need not be the only one:
/// `.` matches `@` too, so `@a@b` and `a@b@` both match through an interior `@`. Looking at only
/// the first or only the last `@` therefore answers wrongly for one of those two.
///
/// Verified against Node itself for each case in the test below.
fn is_valid_email(email: &str) -> bool {
    const LINE_TERMINATORS: [char; 4] = ['\n', '\r', '\u{2028}', '\u{2029}'];
    if email.chars().any(|c| LINE_TERMINATORS.contains(&c)) {
        return false;
    }
    // At least one `@` strictly inside, which is what `.+@.+` requires.
    let chars: Vec<char> = email.chars().collect();
    chars.len() >= 3 && chars[1..chars.len() - 1].contains(&'@')
}

/// Does another `_User` already hold this value, compared case-insensitively?
///
/// An exact-equality constraint run under upstream's collation, which is upstream's own mechanism
/// (`RestWrite.js:818-826` passing `{caseInsensitive: true}`). An anchored `/i` regex was the
/// first shape of this and it was wrong in a way worth recording: a collation at strength 2
/// normalizes, so a precomposed `Café` and a decomposed `Cafe` plus a combining acute are one key
/// to it and two distinct byte strings to any regex. The regex therefore admitted identities
/// upstream treats as duplicates, which is the direction that matters for a uniqueness check.
///
/// Note what strength 2 does *not* do: it is case-insensitive but diacritic-**sensitive**, so
/// `Café` and `Cafe` remain different identities. Secondary strength ignores case and normalizes
/// equivalent Unicode forms; it does not fold accents away.
///
/// The `objectId: {$ne: <self>}` term is load-bearing: without it, saving a row with its own
/// username unchanged collides with itself.
async fn taken(
    state: &AppState,
    rc: &RequestContext,
    field: &str,
    value: &str,
    object_id: &str,
) -> Result<bool, ParseError> {
    let query = Query::from_constraints(vec![
        Constraint::equal(field, ParseValue::String(value.to_string())),
        Constraint {
            field: "objectId".to_string(),
            comparison: parse_rust_storage::Comparison::NotEqual(ParseValue::String(
                object_id.to_string(),
            )),
        },
    ]);
    // The request's own snapshot, not a second read. One request evaluates one schema.
    let schema = rc.snapshot.get_or_default(USER_CLASS);
    let rows = state
        .storage()
        .find(
            &schema,
            &query,
            &QueryOptions {
                limit: Some(1),
                case_insensitive: true,
                ..QueryOptions::default()
            },
        )
        .await?;
    Ok(!rows.is_empty())
}

#[cfg(test)]
mod tests {

    fn row(username: &str, id: &str) -> ParseMap {
        let mut m = ParseMap::new();
        m.insert("objectId".into(), ParseValue::String(id.into()));
        m.insert("username".into(), ParseValue::String(username.into()));
        m
    }

    /// The exact username wins **regardless of the order the database returned the rows in**.
    ///
    /// This is the assertion the integration test cannot make. An `$or` over two indexes has no
    /// defined result order, so end to end the naive `limit: 1` implementation passes whenever
    /// MongoDB happens to hand back the right row, which it usually does. Here the adverse order is
    /// simply the input.
    #[test]
    fn the_exact_username_wins_over_a_matching_email_in_either_order() {
        let target = row("collide@example.com", "TARGET");
        let other = row("other_user", "OTHER");

        for rows in [
            vec![other.clone(), target.clone()],
            vec![target.clone(), other.clone()],
        ] {
            let picked = select_login_row(rows, Some("collide@example.com")).expect("a row");
            assert!(
                matches!(picked.get("objectId"), Some(ParseValue::String(id)) if id == "TARGET"),
                "the username owner is chosen whichever row came first"
            );
        }
    }

    /// More than one match with no submitted username, which is what upstream crashes on.
    #[test]
    fn a_multi_match_without_a_username_falls_back_to_the_first_row() {
        let rows = vec![row("a", "FIRST"), row("b", "SECOND")];
        let picked = select_login_row(rows, None).expect("a row");
        assert!(matches!(picked.get("objectId"), Some(ParseValue::String(id)) if id == "FIRST"));
    }

    /// Every case measured against Node's own evaluation of `/^.+@.+$/`, which is the only
    /// authority for what that regex accepts.
    #[test]
    fn email_validity_matches_javascripts_regex() {
        for (email, expected) in [
            ("a@b", true),
            ("ab@cd", true),
            // `.` matches `@`, so an interior one is enough and there may be more than one.
            ("@a@b", true),
            ("a@b@", true),
            // Spaces and tabs are ordinary characters to `.`.
            ("a b@c d", true),
            ("a\t@b", true),
            ("not-an-email", false),
            ("a@", false),
            ("@a", false),
            ("@", false),
            ("", false),
            // The four JavaScript line terminators, which `.` never matches. The last two are
            // invisible in most editors and are the reason this is not a `\n` check.
            ("a\n@b", false),
            ("a@\nb", false),
            ("a\r@b", false),
            ("a@\rb", false),
            ("a\u{2028}@b", false),
            ("a@\u{2029}b", false),
        ] {
            assert_eq!(
                is_valid_email(email),
                expected,
                "{email:?} ({:?})",
                email.chars().map(|c| c as u32).collect::<Vec<_>>()
            );
        }
    }
    use super::*;

    fn body(json: &str) -> WriteBody {
        parse_rust_rest::decode_write_body(
            &serde_json::from_str(json).expect("test literal"),
            parse_rust_core::op::OpPath::Create,
        )
        .expect("decode")
    }

    #[tokio::test]
    async fn shared_user_transform_removes_plaintext_and_writes_a_bcrypt_hash() {
        let mut b = body(r#"{"password":"hunter2"}"#);
        prepare_user_write(&mut b, false)
            .await
            .expect("password hashes");

        assert!(!b.contains_key("password"));
        let Some(FieldWrite::Value(ParseValue::String(hash))) = b.get(HASHED_PASSWORD) else {
            panic!("hash missing");
        };
        assert!(parse_rust_auth::password::verify("hunter2".into(), hash.clone()).await);
    }

    #[test]
    fn user_owner_acl_is_added_without_discarding_a_master_supplied_acl() {
        let mut b = body(r#"{"objectId":"user123456","ACL":{"*":{"read":true}}}"#);
        let object_id = ensure_user_identity_and_acl(&mut b);

        assert_eq!(object_id, "user123456");
        let Some(FieldWrite::Value(ParseValue::Object(acl))) = b.get("ACL") else {
            panic!("ACL missing");
        };
        assert!(acl.contains_key("*"));
        let Some(ParseValue::Object(owner)) = acl.get("user123456") else {
            panic!("owner ACL missing");
        };
        assert!(matches!(owner.get("read"), Some(ParseValue::Bool(true))));
        assert!(matches!(owner.get("write"), Some(ParseValue::Bool(true))));
    }

    /// An update must not acquire an ACL or an objectId it did not ask for.
    #[tokio::test]
    async fn an_update_is_only_hashed() {
        let mut b = body(r#"{"password":"x","nickname":"n"}"#);
        prepare_user_write(&mut b, false).await.expect("hash");
        assert!(!b.contains_key("ACL"));
        assert!(!b.contains_key("objectId"));
    }
}
