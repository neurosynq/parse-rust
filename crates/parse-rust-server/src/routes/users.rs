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
use parse_rust_core::{ErrorCode, FieldWrite, Op, ParseError, ParseMap, ParseValue};
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
fn raw_truthy(body: &serde_json::Map<String, Json>, key: &str) -> bool {
    match body.get(key) {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Json::String(s)) => !s.is_empty(),
        Some(Json::Array(_) | Json::Object(_)) => true,
    }
}

fn raw_string(body: &serde_json::Map<String, Json>, key: &str) -> Option<String> {
    match body.get(key) {
        Some(Json::String(s)) => Some(s.clone()),
        _ => None,
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
        ensure_user_identity_and_acl(body)?;
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
/// `enforcePrivateUsers` produces at its default of **true** (`Options/Definitions.js:269-274`).
/// With that option set to `false` upstream additionally grants `{"*": {"read": true}}`. The
/// option is not modeled, so the private form is the only one produced here: the safe direction,
/// and the one matching the default.
///
/// **Upstream's two tests are `!ACL` and then a property assignment onto a JavaScript object**
/// (`RestWrite.js:1815-1825`, literally `var ACL = this.data.ACL; if (!ACL) { ACL = {}; ... }`
/// followed by `ACL[objectId] = ...`). Reading either of them as `ParseValue::Object` produced a
/// **publicly readable `_User`**, and 0.2.0 shipped both mistakes:
///
/// - `null`, `false`, `0` and `""` are falsy, so upstream replaces them. Left in place here they
///   reached `lower_acl`, which drops a falsy ACL without writing `_rperm` or `_wperm`.
/// - An op envelope, an array and a tagged value are all **objects** in JavaScript, so upstream
///   assigns the owner into them. Skipped here, `{"__op":"Delete"}` was then removed from the body
///   by `flatten_for_create`, leaving no permission columns at all.
///
/// Both measured against a parse-server at the pin: each of those seven values answered 201 on
/// both servers. **Five of them produced a public row and two did not.** The four falsy values and
/// `{"__op":"Delete"}` left no permission columns at all, so an anonymous read answered 200 here
/// and 404 upstream. The array and the tagged value left two *empty* columns, which is master-only,
/// so both servers answered 404 and the defect there was the missing owner rather than a
/// disclosure. A non-`Delete` operation behaved like the array.
///
/// A truthy **scalar**, where upstream's status depends on whether an email was sent, is refused
/// with 400 in every case. See the comments in the body.
pub(crate) fn ensure_user_identity_and_acl(body: &mut WriteBody) -> Result<String, ParseError> {
    // **A truthy non-string `objectId` is refused, not replaced.** Upstream's substitution test is
    // `if (!this.data.objectId)` (`RestWrite.js:489-491`), so it replaces an absent or falsy id and
    // leaves a truthy one in place, where `enforceFieldExists` then compares it against the
    // `String` type of the default column and answers `INCORRECT_TYPE`.
    //
    // Reading "not a string" as "absent" instead is what generated an id and carried on. Measured
    // at the pin with `allowCustomObjectId` enabled and a body of `{"objectId": 123, ...}`, through
    // both `POST /users` and `POST /classes/_User`: upstream answers 400 code 111 and writes no
    // row, and parse-rust answered 201 with an id the client never asked for, persisted the user
    // and issued a session for it.
    //
    // **That agreement holds for every shape with an inferable type and not for `{"__op":"Delete"}`.**
    // Upstream infers no type for a `Delete`, skips the field check, and answers 201 having stored
    // the row under a Mongo-generated `_id` while echoing the operation object back as the
    // `objectId`. parse-rust refuses it with 107 below. That difference is deliberate, recorded,
    // and scoped for 0.3.0; it is not the 111 case.
    //
    // The pipeline already makes exactly this check for every other class. It could never fire for
    // `_User`, because this function had rewritten the key before the pipeline saw the body, so
    // the class with the strongest reason to have it was the one class that did not.
    if let Some(write) = body.get("objectId") {
        let truthy_non_string = match write {
            FieldWrite::Value(ParseValue::String(_)) => false,
            FieldWrite::Value(v) => parse_rust_core::is_js_truthy(v),
            // An op envelope is a truthy object, so it is never a substitutable absent id.
            FieldWrite::Op(_) => true,
        };
        if truthy_non_string {
            let got = match write {
                FieldWrite::Value(v) => parse_rust_schema::infer_type(v),
                FieldWrite::Op(op) => parse_rust_schema::infer_op_type(op)?,
            };
            return Err(match got {
                Some(got) => parse_rust_schema::infer::schema_mismatch(
                    USER_CLASS,
                    "objectId",
                    &parse_rust_storage::FieldType::String,
                    &got,
                ),
                None => ParseError::invalid_json("objectId is an invalid field name."),
            });
        }
    }

    // Whatever is left is absent, falsy, or a non-empty string, because the truthy non-string
    // cases returned above. **The empty string belongs with `null`, not with a usable id**:
    // `take_string` answered `Some("")` for it, so a body carrying `{"objectId": ""}` created a
    // `_User` whose objectId was the empty string, and every ACL entry naming it named nothing.
    // Upstream's `!this.data.objectId` is falsiness, so it generates one, and the pipeline already
    // agrees for every other class.
    let existing = match body.get("objectId") {
        Some(FieldWrite::Value(ParseValue::String(s))) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let object_id = match existing {
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

    // **Which shape the submitted `ACL` is, in JavaScript's terms rather than in ours.** Upstream
    // does `ACL[objectId] = {read, write}` on whatever `this.data.ACL` holds, and then, on every
    // signup, hands the result to the JavaScript SDK's `Parse.ACL` through `buildParseObjects`
    // (`RestWrite.js:1149`, or `:1013` when the body carries an email). Both steps refuse shapes,
    // and which shapes is the whole of this function's ACL half.
    //
    // The trap this encodes: **an op envelope, an array and a tagged value are all objects in
    // JavaScript and none of them is `ParseValue::Object` here.** Matching only on `Object` looks
    // like "the client sent an ACL" and is not. Measured at the pin, one of them was a public
    // `_User`: `{"ACL":{"__op":"Delete"}}` on signup answered 201 on both servers, and an
    // anonymous read of that user then answered 200 here and 404 upstream.
    //
    // **Every refusal here happens before the insert, and that is the one deliberate difference.**
    // Without an email on the body, upstream's SDK step runs after the row is written, so it
    // answers the error below having already created the user and spent the username, with no
    // session. parse-rust answers the same error and writes nothing. `CHANGELOG.md` lists it under
    // the deliberate differences.
    // **Where the SDK step runs decides whether it sees the owner's entry.** With an email it runs
    // in `_validateEmail` (`RestWrite.js:1013`), before the owner is assigned at `:1824`, so it
    // judges whatever the caller put under the new user's id. Without one it runs after the insert
    // (`:1149`), by which time `ACL[objectId] = {read, write}` has replaced that entry, so an entry
    // under the caller's own custom id is never judged. The same holds when non-anonymous
    // `authData` skips the email step's SDK call.
    let sdk_sees_owner_entry = email_branch_builds_parse_objects(body);
    let judge = |value: &ParseValue| -> Result<(), ParseError> {
        if sdk_sees_owner_entry {
            return sdk_acl_entries_accepted(value);
        }
        let mut map = match value {
            ParseValue::Object(map) => map.clone(),
            ParseValue::Array(items) => parse_rust_rest::acl::array_acl_as_object(items),
            other => return sdk_acl_entries_accepted(other),
        };
        map.shift_remove(&object_id);
        sdk_acl_entries_accepted(&ParseValue::Object(map))
    };
    match body.get("ACL") {
        // Absent, or falsy, which upstream's `if (!ACL)` treats identically. A fresh object
        // holding the owner and nothing else.
        None => replace_with_owner(body, &object_id),
        Some(FieldWrite::Value(v)) if !parse_rust_core::is_js_truthy(v) => {
            replace_with_owner(body, &object_id)
        }
        // A principal map. The owner joins whatever the caller sent, once the SDK would accept it.
        Some(FieldWrite::Value(ParseValue::Object(map))) => {
            judge(&ParseValue::Object(map.clone()))?;
            add_owner(body, &object_id);
        }
        // **An array's indices are principals once the owner is assigned onto it**, so
        // `[{"read":true}]` grants `"0"` beside the owner. Held as the object JavaScript sees.
        Some(FieldWrite::Value(ParseValue::Array(items))) => {
            let value = ParseValue::Array(items.clone());
            judge(&value)?;
            let map = parse_rust_rest::acl::array_acl_as_object(items);
            body.insert(
                "ACL".to_string(),
                FieldWrite::Value(ParseValue::Object(map)),
            );
            add_owner(body, &object_id);
        }
        // A truthy scalar. Upstream throws a `TypeError` assigning the owner onto a primitive and
        // answers 500 without an email, or 400 `ACL must be a Parse ACL.` with one, from the SDK
        // step that runs first in that branch (parse-community/parse-server#10638). **Chosen for
        // 0.3.0: the 400, always.** A status that depends on an unrelated field is not a contract
        // anyone can rely on, and 0.2.1's 201 created an account its owner could not read.
        Some(FieldWrite::Value(
            ParseValue::Bool(_) | ParseValue::Number(_) | ParseValue::String(_),
        )) => return Err(not_a_parse_acl()),
        // `Delete` decodes to an unset in the SDK, so nothing reaches `Parse.ACL` and the lowering
        // finds only the owner. Every other operation reaches the SDK's `validate` as a value that
        // is not a `Parse.ACL`. A `Batch` is refused earlier upstream with a bare 500.
        Some(FieldWrite::Op(Op::Delete)) => replace_with_owner(body, &object_id),
        Some(FieldWrite::Op(Op::Batch(_))) => {
            return Err(ParseError::internal(
                "a Batch operation as the ACL of a signup",
            ))
        }
        Some(FieldWrite::Op(_)) => return Err(not_a_parse_acl()),
        // A tagged value. The SDK decodes it before building the ACL: a Date and a GeoPoint carry
        // nothing `Parse.ACL` enumerates, and a `_User` pointer decodes to a user, which
        // `Parse.ACL` accepts as "this user". Everything else enumerates a string or an array
        // member and throws. The lowering then finds only the owner. Measured at the pin for all
        // eight tagged types.
        Some(FieldWrite::Value(v)) => {
            let accepted = match v {
                ParseValue::Date(_) | ParseValue::GeoPoint { .. } => true,
                ParseValue::Pointer { class_name, .. } => class_name == USER_CLASS,
                _ => false,
            };
            if !accepted {
                return Err(ParseError::internal(
                    "a tagged ACL value that Parse.ACL cannot be built from",
                ));
            }
            replace_with_owner(body, &object_id);
        }
    }
    Ok(object_id)
}

/// Whether `_validateEmail` reaches `buildParseObjects` (`RestWrite.js:977-1013`): a truthy email
/// that is not a `Delete`, and `authData` absent, empty, or anonymous alone. A malformed or taken
/// email is refused before that point either way.
fn email_branch_builds_parse_objects(body: &WriteBody) -> bool {
    let email = match body.get("email") {
        Some(FieldWrite::Value(v)) => parse_rust_core::is_js_truthy(v),
        _ => false,
    };
    let auth_data_allows = match body.get("authData") {
        None => true,
        Some(FieldWrite::Value(ParseValue::Object(map))) => {
            map.is_empty() || (map.len() == 1 && map.contains_key("anonymous"))
        }
        Some(FieldWrite::Value(v)) => !parse_rust_core::is_js_truthy(v),
        Some(FieldWrite::Op(_)) => false,
    };
    email && auth_data_allows
}

fn owner_permissions() -> ParseValue {
    let mut permissions = ParseMap::new();
    permissions.insert("read".to_string(), ParseValue::Bool(true));
    permissions.insert("write".to_string(), ParseValue::Bool(true));
    ParseValue::Object(permissions)
}

fn replace_with_owner(body: &mut WriteBody, object_id: &str) {
    let mut acl = ParseMap::new();
    acl.insert(object_id.to_string(), owner_permissions());
    body.insert(
        "ACL".to_string(),
        FieldWrite::Value(ParseValue::Object(acl)),
    );
}

fn add_owner(body: &mut WriteBody, object_id: &str) {
    if let Some(FieldWrite::Value(ParseValue::Object(acl))) = body.get_mut("ACL") {
        acl.insert(object_id.to_string(), owner_permissions());
    }
}

/// The SDK's `validate`: an `ACL` attribute that is not a `Parse.ACL`.
fn not_a_parse_acl() -> ParseError {
    ParseError::new(ErrorCode::OtherCause, "ACL must be a Parse ACL.")
}

/// Would the SDK's `Parse.ACL` constructor accept these entries?
///
/// It walks `for (userId in acl) for (permission in acl[userId])` and throws a `TypeError` on any
/// permission key other than `read` or `write` and on any value that is not a boolean
/// (`ParseACL.js`, in the SDK parse-server bundles). So an entry is accepted only if enumerating it
/// yields nothing, or yields `read`/`write` with booleans. A non-empty string or array enumerates
/// its indices, which are not permission names. A tagged entry is decoded first, and of those only
/// a Date enumerates nothing. Measured at the pin, entry by entry; each refusal is a bare 500.
///
/// A `null` entry passes here, as it does in the SDK, and is refused by the lowering instead.
fn sdk_acl_entries_accepted(acl: &ParseValue) -> Result<(), ParseError> {
    for (principal, entry) in parse_rust_rest::acl::js_own_entries(acl) {
        let accepted = match entry {
            ParseValue::Null | ParseValue::Bool(_) | ParseValue::Number(_) => true,
            ParseValue::Date(_) => true,
            ParseValue::String(s) => s.is_empty(),
            ParseValue::Array(items) => items.is_empty(),
            ParseValue::Object(permissions) => permissions.iter().all(|(name, allowed)| {
                matches!(name.as_str(), "read" | "write") && matches!(allowed, ParseValue::Bool(_))
            }),
            _ => false,
        };
        if !accepted {
            return Err(ParseError::internal(format!(
                "ACL entry {principal:?} cannot be built into a Parse.ACL"
            )));
        }
    }
    Ok(())
}

/// `handleCreate`'s `role:`-prefixed objectId refusal (`ClassesRouter.js:111-118`).
///
/// A user whose objectId is `role:Admins` is granted that role by every ACL check, because an ACL
/// names a role by string and the caller's ACL group carries its own objectId.
///
/// **On `ClassesRouter`, not on `UsersRouter`**, which is the detail that matters for where this
/// is called from. `UsersRouter extends ClassesRouter` and does not override `handleCreate`
/// (`UsersRouter.js:23`, `:835-837`), so one guard covers `POST /users` and `POST /classes/_User`
/// alike. parse-rust had it on the signup route only, which left the class route uncovered for
/// the master key.
pub(crate) fn reject_role_prefixed_object_id(
    body: &Json,
    rc: &RequestContext,
) -> Result<(), ParseError> {
    // The raw body, because the router reads it before any decoding (`ClassesRouter.js:111-118`).
    let Some(Json::String(id)) = body.get("objectId") else {
        // `typeof req.body?.objectId === 'string'` guards it upstream, so a non-string is not
        // refused here. It is refused by schema validation instead.
        return Ok(());
    };
    if !id.starts_with("role:") {
        return Ok(());
    }
    // `createSanitizedError` (`ClassesRouter.js:117`). Note this is the sanitized twin of
    // `Auth.js`'s identically worded refusal, which is a plain `Parse.Error` and stays detailed;
    // the two are different call sites with the same string.
    Err(ParseError::permission_denied(
        ErrorCode::OperationForbidden,
        "Invalid object ID.",
        rc.options.error_detail,
    ))
}

/// A created `_User` must carry a non-empty username and a non-empty password
/// (`RestWrite.js:528-538`).
///
/// **Not gated on the caller.** Upstream's guard is `!this.query && !hasAuthData`, which asks
/// whether this is a create and whether an auth adapter is supplying the identity instead. Master
/// is not exempt, so `POST /classes/_User` with the master key is subject to it too. Without that,
/// the dashboard's own route admitted a user with no username, or a passwordless row that no
/// login can ever match and that `verify_dummy` exists to make indistinguishable.
///
/// Runs **before** identity validation and hashing, which is upstream's order: `validateAuthData`
/// runs at `RestWrite.js:116` and `transformUser` at `:144`. Checking a
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

/// `validateAuthData`'s credential half on an update (`RestWrite.js:528-538`), from 9.10.3.
///
/// A `username` or `password` that is present must be a non-empty string: 200 `bad or missing
/// username` and 201 `password is required`. Present means present, so `null` and an operation
/// both fail, and `user.unset("username")` is refused here rather than reaching the uniqueness
/// query. **Master is not exempt**, as upstream's test is not. Before 9.10.3 upstream accepted an
/// empty string for either (parse-community/parse-server#10752), and so did parse-rust.
pub(crate) fn require_update_credentials(body: &WriteBody) -> Result<(), ParseError> {
    let missing = |key: &str| match body.get(key) {
        None => false,
        Some(FieldWrite::Value(ParseValue::String(v))) => v.is_empty(),
        Some(_) => true,
    };
    if missing("username") {
        return Err(ParseError::new(
            ErrorCode::UsernameMissing,
            "bad or missing username",
        ));
    }
    if missing("password") {
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
    // `handleCreate`'s guard runs in the router, ahead of the `RestWrite` constructor and its
    // objectId policy (`ClassesRouter.js:111-118`, `RestWrite.js:50-65`).
    reject_role_prefixed_object_id(body, rc)?;
    let body = parse_rust_rest::decode_write_body(body, parse_rust_core::op::OpPath::Create)?;
    // A signup body must not carry a `_hashed_password` of the caller's choosing.
    parse_rust_rest::reject_reserved_keys_in(body.keys().map(String::as_str))?;
    // Signup is a create like any other, so the objectId policy applies to it
    // (`RestWrite.js:50-65`). It has to run here rather than inside the pipeline, because
    // `ensure_user_identity_and_acl` below puts a server-generated objectId into the body.
    parse_rust_rest::enforce_object_id_policy(&body, state.config().allow_custom_object_id)?;

    // `validateAuthData` (`RestWrite.js:116`) before `checkRestrictedFields` (`:119`). The
    // credential half is skipped upstream when `authData` is present, because the adapter supplies
    // the identity; parse-rust refuses a client's `authData` at that same position instead, so a
    // body carrying it is still refused for it rather than for a missing username.
    if !authority.is_privileged() && body.get("authData").is_some() {
        reject_client_restricted_user_fields(&body, rc, authority)?;
    }
    require_create_credentials(&body)?;
    // Upstream runs this on create as well as update (`RestWrite.js:119`), and running it only on
    // the update path left signup able to set `emailVerified` and `authData` on its own new row.
    reject_client_restricted_user_fields(&body, rc, authority)?;

    // **The `create` permission is checked before any identity work**, as upstream's
    // `validateWritePermission` is (`RestWrite.js:793-804`, run at `:134`, ahead of
    // `transformUser` at `:144`). `validate_user_identity` queries `_User` by
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
    // (`RestWrite.js:895-899`). Validating on the update path alone left signup admitting exactly
    // the identities the update path refuses: a case-only duplicate username, and an email that is
    // not one.
    //
    // The objectId is not known yet, so the `$ne` exclusion is given a value no row can hold. On a
    // create there is no self to exclude, which is the same thing upstream's `this.objectId()`
    // returning undefined achieves.
    //
    // Run by the pipeline once the schema's defaults and required fields are applied, as
    // `transformUser` follows `setRequiredFieldsIfNeeded`, so a defaulted email is validated too,
    // and the password is hashed and the owner's ACL added only then. See `identity_check`.
    let ctx = rc.ctx(state.storage());
    let created =
        parse_rust_rest::create_checked(&ctx, USER_CLASS, body, Some(identity_check(state, rc)))
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

    // Server-set fields, defaults among them, join the response before the token, as upstream's
    // `_updateResponseWithData` runs in `runDatabaseOperation` and the token is added after.
    let mut out = json!({
        "objectId": created.object_id,
        "createdAt": created.created_at.to_iso(),
    });
    crate::routes::classes::merge_echo(&mut out, created.echoed, rc, USER_CLASS);
    if let Json::Object(map) = &mut out {
        map.insert("sessionToken".into(), Json::String(session.session_token));
    }
    Ok(out)
}

/// `transformUser` for a create, as a [`parse_rust_rest::BeforeInsert`]: the identity checks, then
/// the password hash and the owner's ACL, on the body as the schema's defaults left it.
pub(crate) fn identity_check<'a>(
    state: &'a AppState,
    rc: &'a RequestContext,
) -> parse_rust_rest::BeforeInsert<'a> {
    Box::new(move |mut body| {
        Box::pin(async move {
            validate_user_identity(state, rc, &body, "").await?;
            prepare_user_write(&mut body, true).await?;
            Ok(body)
        })
    })
}

/// Turn a duplicate-key error into the code the SDK expects (`RestWrite.js:1836-1855`).
///
/// A `username_1` collision must be 202 `USERNAME_TAKEN`, not a bare 137. Which field collided is
/// read from the adapter's out-of-band [`ParseError::duplicated_field`], which the adapter fills
/// in by recognising the auto-generated index name. That is why index names are contractual, and
/// it is why nothing here reads `message`: the message is the fixed
/// `A duplicate value for a field with unique values was provided` in every case, and the driver
/// text it replaced named the database and the colliding value.
///
/// **Not modelled: upstream's fallback.** When it cannot recover the field, upstream re-queries
/// `_User` by username and then by email before settling for 137 (`RestWrite.js:1857-1894`). The
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
    // **Read raw, never decoded as a write.** Upstream destructures `username`, `email` and
    // `password` straight off the payload (`UsersRouter.js:81`) and looks at nothing else, so a
    // stray `{"x":{"__op":"Bogus"}}` beside the credentials is ignored. Decoding the body as a
    // write refused that login over a key the login never reads.
    let empty = serde_json::Map::new();
    let body = match body {
        Json::Object(map) => map,
        _ => &empty,
    };

    // **Three refusals in upstream's order, each with its own code** (`UsersRouter.js:84-96`).
    // Collapsing them into one `USERNAME_MISSING`, which is what this did, is wire-visible twice
    // over: a client with no password got the username error, and a client with a non-string
    // password got it too where upstream answers `OBJECT_NOT_FOUND`.
    //
    // **Each guard tests JavaScript truthiness of the raw value, not "is it a non-empty string".**
    // The distinction decides which of the three fires: `{"username": 7}` is truthy, so it passes
    // the first guard and is refused by the third as a type error, where testing for a string here
    // would report a missing username instead.
    let has_username = raw_truthy(body, "username");
    let has_email = raw_truthy(body, "email");
    if !has_username && !has_email {
        return Err(ParseError::new(
            ErrorCode::UsernameMissing,
            "username/email is required.",
        ));
    }
    if !raw_truthy(body, "password") {
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
    let username = raw_string(body, "username");
    let email = raw_string(body, "email");
    let Some(password) = raw_string(body, "password") else {
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
    // What the client named, for the lockout gate on a login that finds no account. A NUL cannot
    // be part of a stored username, so this cannot share a gate with a real account's.
    let submitted = format!(
        "\0{}\0{}",
        identifier.as_deref().unwrap_or_default(),
        email.as_deref().unwrap_or_default()
    );
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
    //
    // **And both queue.** With `accountLockout` on, attempts on one account are serialized (see
    // `serialize_attempts`). A login that finds no account takes the same kind of gate, keyed on
    // what was submitted, so concurrent attempts on a made-up name queue as attempts on a real one
    // do. The queues are close, not identical: an attempt on a real account also holds the gate
    // for its lockout bookkeeping. Taking the gate only for a real account made the difference
    // the whole compare.
    let Some(row) = row else {
        let _attempt = match &state.config().account_lockout {
            Some(_) => Some(crate::lockout::serialize_attempts(&submitted).await),
            None => None,
        };
        parse_rust_auth::password::verify_dummy(password).await;
        return Err(invalid());
    };
    // Held across the compare and the lockout bookkeeping below; see `serialize_attempts`.
    let attempt = match (&state.config().account_lockout, row.get("username")) {
        (Some(_), Some(ParseValue::String(username))) => {
            Some(crate::lockout::serialize_attempts(username).await)
        }
        _ => None,
    };
    let valid = match row.get(HASHED_PASSWORD) {
        Some(ParseValue::String(hash)) if !hash.is_empty() => {
            parse_rust_auth::password::verify(password, hash.clone()).await
        }
        // A passwordless account, which an auth-adapter signup produces upstream. Never a valid
        // password login, and it must not be a fast one either.
        _ => {
            parse_rust_auth::password::verify_dummy(password).await;
            false
        }
    };

    // The lockout runs on every attempt against an account that exists, after the compare and
    // whichever way it went (`UsersRouter.js:138-142`): a locked account is refused even with the
    // right password, and keyed by the row's own username, not the identifier the client sent.
    if let (Some(policy), Some(ParseValue::String(username))) =
        (&state.config().account_lockout, row.get("username"))
    {
        crate::lockout::handle_login_attempt(state.storage(), &schema, policy, username, valid)
            .await?;
    }
    drop(attempt);
    if !valid {
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

    // **Re-fetch under the caller's own auth before answering** (`UsersRouter.js:360-398`).
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
/// genuine not-found rather than a denial (`UsersRouter.js:389-398`).
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
    let Some(token) = rc.session_token.as_deref() else {
        return Err(invalid());
    };
    // A master or maintenance request never resolves its token into a user, but `handleMe` looks
    // the token up itself, with the master key, whoever is asking (`UsersRouter.js:195-213`), so
    // `/users/me` with the master key and a token answers that token's user.
    let resolved;
    let user_id = match rc.user_id.as_deref() {
        Some(id) => id,
        None => {
            resolved = parse_rust_auth::sessions::session_user(state.storage(), token)
                .await?
                .ok_or_else(invalid)?;
            resolved.as_str()
        }
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
/// Deletes the `_Session` row (`UsersRouter.js:520-549`). A request with no token, or with one
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

/// Authorize a `_User` update before anything reads the target account.
///
/// Upstream's `authorizeUserUpdate` (`RestWrite.js:806-838`, run at `:113`), added in 9.10.3 for
/// GHSA-p49q-9w65-f9p7: the caller's right to write the account is settled before
/// [`validate_user_identity`] reads anything else.
///
/// Order, as upstream's: no session refuses outright; a body `objectId` naming another row is not
/// found; the owner returns here; anybody else must be able to write the target, judged by the
/// same query the update itself would run.
///
/// **The owner's class-level `update` gate is not here.** Upstream's `authorizeUserUpdate`
/// returns early for the owner, so `validateAuthData` and `checkRestrictedFields` run before the
/// gate does, in `validateWritePermission` (`RestWrite.js:113-134`). [`owner_update_gate`] runs it
/// at that position. Running it here answered 119 to an owner sending `{"username":""}` under a
/// CLP that denies `update`, where upstream answers 200 `bad or missing username`.
pub(crate) async fn authorize_user_update(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    object_id: &str,
    body: &Json,
) -> Result<(), ParseError> {
    if authority.is_privileged() {
        return Ok(());
    }
    let Some(caller) = rc.user_id.as_deref() else {
        return Err(ParseError::permission_denied(
            ErrorCode::SessionMissing,
            format!("Cannot modify user {object_id}."),
            rc.options.error_detail,
        ));
    };
    // `this.data.objectId !== undefined && this.data.objectId !== this.query.objectId`: anything
    // present that is not the same string retargets, an op envelope included.
    match body.get("objectId") {
        None => {}
        Some(Json::String(id)) if id == object_id => {}
        Some(_) => {
            return Err(ParseError::new(
                ErrorCode::ObjectNotFound,
                "Object not found.",
            ))
        }
    }
    if caller == object_id {
        return Ok(());
    }
    parse_rust_rest::authorize_update(&rc.ctx(state.storage()), USER_CLASS, object_id).await
}

/// The class-level `update` gate for a caller updating their own row, at `validateWritePermission`'s
/// position (`RestWrite.js:134`): after the credential and restricted-field checks, and before
/// `transformUser` (`:144`), so it still precedes [`validate_user_identity`]'s reads of other rows.
/// Every other caller already passed it inside [`authorize_user_update`].
pub(crate) fn owner_update_gate(
    state: &AppState,
    rc: &RequestContext,
    authority: &Authority,
    object_id: &str,
) -> Result<(), ParseError> {
    if authority.is_privileged() || rc.user_id.as_deref() != Some(object_id) {
        return Ok(());
    }
    parse_rust_rest::update_gate(&rc.ctx(state.storage()), USER_CLASS)
}

/// `handleSessionMissingError` (`rest.js:320-331`): on `_User`, a non-privileged update or delete
/// that comes back not-found is reported as a missing session instead, 206 `Insufficient auth.`,
/// sanitized to `Permission denied` at the default. That covers a nonexistent id, a row the caller
/// cannot write, and a retargeting `objectId` alike, so none of them distinguishes from the others.
/// parse-rust answered 101 for all three until 0.3.0.
pub(crate) fn as_session_missing(
    e: ParseError,
    rc: &RequestContext,
    authority: &Authority,
) -> ParseError {
    if e.code == ErrorCode::ObjectNotFound && !authority.is_privileged() {
        return ParseError::permission_denied(
            ErrorCode::SessionMissing,
            "Insufficient auth.",
            rc.options.error_detail,
        );
    }
    e
}

/// `_User` columns a client may never write, whatever the ACL says.
///
/// `emailVerified` is the one that matters: it is the output of a verification flow, so a client
/// that can set it has verified its own email. Upstream refuses it with `OPERATION_FORBIDDEN`
/// (`RestWrite.js:779-791`).
///
/// `authData` is refused rather than validated, which is a deliberate fail-closed gap: upstream
/// hands it to an auth adapter that decides whether the credential is real, and parse-rust has no
/// adapter host. Accepting it unvalidated would let a client write a third-party identity that a
/// later login could match on.
const CLIENT_FORBIDDEN_USER_FIELDS: [&str; 2] = ["emailVerified", "authData"];

/// The noun upstream uses in the refusal, which is not the column name.
///
/// `emailVerified` is reported as `email verification` (`RestWrite.js:787`). The message is
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
/// (`RestWrite.js:119`, defined at `:779-791`), so `POST /users` is covered there. parse-rust
/// applied it only on the update path, which left signup able to set both fields on the row it was
/// creating.
///
/// The two fields are here for different reasons and only the first is upstream's:
///
/// - `emailVerified` is upstream's own restriction, with upstream's message. A client that can set
///   it at signup marks its own address verified without ever receiving mail.
/// - `authData` is **not** in upstream's list, because upstream validates it instead: every
///   provider block goes to the configured auth adapter, which decides whether the credential is
///   real (`RestWrite.js:513-567`). parse-rust has no adapter host, so there is nothing to validate
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
/// (`RestWrite.js:1711-1715`), and so does this.
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

    // A non-string or empty password never reaches here: `require_update_credentials` refuses it
    // first with upstream's 201, which replaced the 111 this answered before 9.10.3.
    Ok(())
}

/// Force the row's own principal back into a submitted ACL.
///
/// Upstream re-adds it after the client's ACL is applied, so a `_User` cannot be made unreadable
/// or unwritable by its owner. Measured against parse-server at the pin: saving
/// `{"ACL": {"*": {"read": true, "write": true}}}` reads back with the owner entry still present.
/// Without this a client can lock itself out of its own row, and can do it to another user
/// wherever an ACL permits the write.
pub(crate) fn force_owner_into_acl(
    body: &mut WriteBody,
    object_id: &str,
    privileged: bool,
) -> Result<(), ParseError> {
    // **Master and maintenance are exempt.** Upstream applies the owner entry only for a
    // non-privileged caller, so an administrator replacing a user's ACL with one that excludes
    // them gets exactly that. Forcing it back in unconditionally means an operator cannot revoke a
    // user's access to their own row, which is a legitimate administrative action and one a
    // dashboard offers.
    if privileged {
        return Ok(());
    }
    let owner_entry = owner_permissions();

    // **Upstream's test is `this.data.ACL &&` followed by a property assignment**
    // (`RestWrite.js:1729-1738`), which is the same pair the create path applies and has the same
    // trap: an op envelope, an array and a tagged value are all truthy objects in JavaScript and
    // none of them is `ParseValue::Object` here.
    //
    // **Getting this wrong disables accounts.** Measured at the pin with
    // `{"ACL":{"__op":"Increment","amount":1}}` on `PUT /classes/_User/:id`: both servers answer
    // 200, upstream keeps the owner entry and the caller's session still resolves, and parse-rust
    // stored `{}` and the same session then answered 209 `INVALID_SESSION_TOKEN`. Any principal
    // permitted to write a `_User` could therefore lock that user out, which is the exact failure
    // this function exists to prevent and it covered only two of the shapes that reach it.
    //
    // A **falsy** ACL is the one case that must not be touched, and it is upstream's `&&` doing
    // the work: the assignment is skipped, and the falsy value is then dropped by the lowering,
    // which leaves the stored columns exactly as they were. Forcing an owner in here would replace
    // a deliberate ACL with an owner-only one on any request that happened to send `ACL: null`.
    let shape = match body.get("ACL") {
        None => None,
        Some(FieldWrite::Value(v)) if !parse_rust_core::is_js_truthy(v) => None,
        Some(FieldWrite::Value(ParseValue::Object(_))) => Some(OwnerInto::ExistingMap),
        // An array keeps its indices as principals, with the owner assigned beside them, which is
        // what `ACL[objectId] = ...` on a JavaScript array produces. Measured at the pin:
        // `[{"read":true}]` stores `_rperm` of `["0", <owner>]`.
        Some(FieldWrite::Value(ParseValue::Array(items))) => {
            let map = parse_rust_rest::acl::array_acl_as_object(items);
            body.insert(
                "ACL".to_string(),
                FieldWrite::Value(ParseValue::Object(map)),
            );
            Some(OwnerInto::ExistingMap)
        }
        // A truthy **scalar**. Upstream throws a `TypeError` out of the assignment and answers a
        // bare 500, writing nothing. parse-rust refuses it with the 400 it gives the same value on
        // signup, so one malformed value has one answer. Before 0.3.0 this rewrote it to the
        // owner-only ACL and answered 200.
        Some(FieldWrite::Value(
            ParseValue::Bool(_) | ParseValue::Number(_) | ParseValue::String(_),
        )) => return Err(not_a_parse_acl()),
        // Left for the pipeline, which answers upstream's 500.
        Some(FieldWrite::Op(Op::Batch(_))) => None,
        // An op envelope or a tagged value: an object to JavaScript whose own keys carry no
        // permission, so the owner is the only entry the lowering finds.
        Some(_) => Some(OwnerInto::FreshMap),
    };

    match shape {
        None => {}
        Some(OwnerInto::ExistingMap) => {
            if let Some(FieldWrite::Value(ParseValue::Object(acl))) = body.get_mut("ACL") {
                acl.insert(object_id.to_string(), owner_entry);
            }
        }
        // Rewritten rather than dropped, so a `{"__op":"Delete"}` still deletes: every other
        // principal goes and the owner stays, which is what upstream's assignment onto the op
        // object produces once the lowering walks it. `user.unset("ACL").save()` sends exactly
        // that op.
        Some(OwnerInto::FreshMap) => {
            let mut acl = ParseMap::new();
            acl.insert(object_id.to_string(), owner_entry);
            body.insert(
                "ACL".to_string(),
                FieldWrite::Value(ParseValue::Object(acl)),
            );
        }
    }
    Ok(())
}

/// Where the owner entry goes when a `_User` update carries an `ACL`.
enum OwnerInto {
    /// The client sent a principal map; the owner joins it.
    ExistingMap,
    /// The client sent something that is an object to JavaScript but not a principal map, so the
    /// only entry that survives upstream's lowering is the owner. Replaced wholesale.
    FreshMap,
}

/// `_validateUserName` and `_validateEmail` (`RestWrite.js:903-976`), for the update path.
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
    // (`RestWrite.js:895-899`). A body carrying both a colliding username and a malformed email
    // reports the username, and checking email first reported the email instead.
    // An operation on `username` never reaches here. On a create `require_create_credentials`
    // refuses anything that is not a non-empty string, and on an update
    // `require_update_credentials` does, both with upstream's 200. Before 9.10.3 an update reached
    // the uniqueness query with the op object and answered 107 `You cannot use [object Object] as
    // a query parameter.`; a `Delete` on `email` is still allowed, by `_validateEmail`'s own guard
    // (`RestWrite.js:978`).
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
    // `if (!this.data.email ...) return` (`RestWrite.js:978`). An empty string is falsy, so it is
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

/// `/^.+@.+$/` as JavaScript evaluates it (`RestWrite.js:982`).
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
/// (`RestWrite.js:919-929` passing `{caseInsensitive: true}`). An anchored `/i` regex was the
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
        let object_id = ensure_user_identity_and_acl(&mut b).expect("string id");

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

    /// **A falsy `ACL` is not "leave it alone", it is "there is no ACL"**, which is upstream's
    /// `if (!ACL)`. 0.2.0 left all four in place, they were dropped by `lower_acl` without writing
    /// permission columns, and an absent `_rperm` is public: signing up with `{"ACL": null}`
    /// produced a `_User` row any anonymous caller could read. Measured against a parse-server at
    /// the pin, which answers 404 to that read.
    ///
    /// The values are looped rather than sampled, because checking one is exactly how the other
    /// three survived the last review of this function.
    #[test]
    fn a_falsy_acl_on_signup_becomes_the_owner_acl_rather_than_a_public_row() {
        for literal in [
            r#"{"objectId":"user123456","ACL":null}"#,
            r#"{"objectId":"user123456","ACL":false}"#,
            r#"{"objectId":"user123456","ACL":0}"#,
            r#"{"objectId":"user123456","ACL":""}"#,
        ] {
            let mut b = body(literal);
            ensure_user_identity_and_acl(&mut b).expect("string id");
            let Some(FieldWrite::Value(ParseValue::Object(acl))) = b.get("ACL") else {
                panic!("ACL missing or not an object for {literal}");
            };
            assert_eq!(acl.len(), 1, "{literal} produced {acl:?}");
            let Some(ParseValue::Object(owner)) = acl.get("user123456") else {
                panic!("owner entry missing for {literal}");
            };
            assert!(matches!(owner.get("read"), Some(ParseValue::Bool(true))));
            assert!(matches!(owner.get("write"), Some(ParseValue::Bool(true))));
        }
    }

    /// **An op envelope and a tagged value are objects in JavaScript**, and neither is
    /// `ParseValue::Object` here. Matching only on `Object` looks like "the client sent an ACL" and
    /// is not: `{"ACL":{"__op":"Delete"}}` produced a **publicly readable `_User`**, because
    /// `flatten_for_create` then removed the key and no permission columns were written.
    ///
    /// Each shape below is measured at the pin answering 201 with the owner-only ACL.
    #[test]
    fn a_js_object_acl_that_is_not_a_principal_map_still_gets_the_owner() {
        for literal in [
            r#"{"objectId":"user123456","ACL":{"__op":"Delete"}}"#,
            r#"{"objectId":"user123456","ACL":{"__type":"Date","iso":"2020-01-01T00:00:00.000Z"}}"#,
            r#"{"objectId":"user123456","ACL":{"__type":"GeoPoint","latitude":1,"longitude":2}}"#,
            r#"{"objectId":"user123456","ACL":{"__type":"Pointer","className":"_User","objectId":"a"}}"#,
        ] {
            let mut b = body(literal);
            ensure_user_identity_and_acl(&mut b).expect(literal);
            let Some(FieldWrite::Value(ParseValue::Object(acl))) = b.get("ACL") else {
                panic!("ACL missing or not an object for {literal}");
            };
            assert_eq!(acl.len(), 1, "{literal} produced {acl:?}");
            assert!(acl.contains_key("user123456"), "{literal}");
        }
    }

    /// An array's indices stay as principals beside the owner, which is what upstream's
    /// `ACL[objectId] = ...` onto a JavaScript array produces and what the lowering then walks.
    #[test]
    fn an_array_acl_on_signup_keeps_its_indices_beside_the_owner() {
        for (literal, keys) in [
            (r#"{"objectId":"user123456","ACL":[]}"#, vec!["user123456"]),
            (
                r#"{"objectId":"user123456","ACL":[1,2]}"#,
                vec!["0", "1", "user123456"],
            ),
            (
                r#"{"objectId":"user123456","ACL":[{"read":true}]}"#,
                vec!["0", "user123456"],
            ),
        ] {
            let mut b = body(literal);
            ensure_user_identity_and_acl(&mut b).expect(literal);
            let Some(FieldWrite::Value(ParseValue::Object(acl))) = b.get("ACL") else {
                panic!("ACL missing or not an object for {literal}");
            };
            assert_eq!(acl.keys().collect::<Vec<_>>(), keys, "{literal}");
        }
    }

    /// **Chosen for 0.3.0, and the choice is the 400.** Upstream answers 400 `ACL must be a Parse
    /// ACL.` with an email on the body and a bare 500 without one (#10638). One answer whatever the
    /// unrelated field says, and nothing written.
    #[test]
    fn a_truthy_scalar_or_a_non_delete_op_acl_on_signup_is_refused_with_400() {
        for literal in [
            r#"{"objectId":"user123456","ACL":"nonsense"}"#,
            r#"{"objectId":"user123456","ACL":123}"#,
            r#"{"objectId":"user123456","ACL":true}"#,
            r#"{"objectId":"user123456","ACL":{"__op":"Increment","amount":1}}"#,
            r#"{"objectId":"user123456","ACL":{"__op":"Add","objects":[1]}}"#,
        ] {
            let mut b = body(literal);
            let e = ensure_user_identity_and_acl(&mut b).expect_err(literal);
            assert_eq!(e.code, ErrorCode::OtherCause, "{literal}");
            assert_eq!(e.message, "ACL must be a Parse ACL.", "{literal}");
        }
    }

    /// The SDK's `Parse.ACL` constructor throws on these, which upstream answers as a bare 500.
    /// Measured at the pin, each one.
    #[test]
    fn acl_shapes_the_sdk_cannot_build_are_internal_errors() {
        for literal in [
            r#"{"objectId":"user123456","ACL":{"*":{"read":1}}}"#,
            r#"{"objectId":"user123456","ACL":{"*":{"read":true,"x":true}}}"#,
            r#"{"objectId":"user123456","ACL":{"*":"yes"}}"#,
            r#"{"objectId":"user123456","ACL":["ab"]}"#,
            r#"{"objectId":"user123456","ACL":{"*":{"__type":"GeoPoint","latitude":1,"longitude":2}}}"#,
            r#"{"objectId":"user123456","ACL":{"__type":"Pointer","className":"X","objectId":"a"}}"#,
            r#"{"objectId":"user123456","ACL":{"__type":"File","name":"f","url":"http://x/f"}}"#,
            r#"{"objectId":"user123456","ACL":{"__op":"Batch","ops":[]}}"#,
        ] {
            let mut b = body(literal);
            let e = ensure_user_identity_and_acl(&mut b).expect_err(literal);
            assert_eq!(e.code, ErrorCode::InternalServerError, "{literal}");
        }
        for literal in [
            r#"{"objectId":"user123456","ACL":{"*":{"read":true,"write":false}}}"#,
            r#"{"objectId":"user123456","ACL":{"*":5,"a":true,"b":"","c":[],"d":{}}}"#,
            r#"{"objectId":"user123456","ACL":{"*":{"__type":"Date","iso":"2020-01-01T00:00:00.000Z"}}}"#,
        ] {
            let mut b = body(literal);
            ensure_user_identity_and_acl(&mut b).expect(literal);
        }
    }

    /// **The update path has the same JavaScript-object trap as the create path, and getting it
    /// wrong disables accounts rather than exposing them.** `force_owner_into_acl` handled a
    /// principal map and `{"__op":"Delete"}` and nothing else, so every other truthy shape reached
    /// the lowering and cleared both permission columns. On `_User` that is a row its owner can no
    /// longer read, write or log in with.
    ///
    /// Measured at the pin with `{"__op":"Increment","amount":1}` on `PUT /classes/_User/:id`:
    /// both servers answer 200, upstream keeps the owner entry and the caller's session still
    /// resolves, and parse-rust stored `{}` and the same session then answered 209.
    #[test]
    fn every_truthy_acl_shape_on_an_update_keeps_the_owner() {
        for literal in [
            r#"{"ACL":{"__op":"Increment","amount":1}}"#,
            r#"{"ACL":{"__op":"Delete"}}"#,
            r#"{"ACL":{"__op":"Add","objects":[1]}}"#,
            r#"{"ACL":[]}"#,
            r#"{"ACL":[1,2]}"#,
            r#"{"ACL":{"__type":"Date","iso":"2020-01-01T00:00:00.000Z"}}"#,
        ] {
            let mut b = body(literal);
            force_owner_into_acl(&mut b, "user123456", false).expect(literal);
            let Some(FieldWrite::Value(ParseValue::Object(acl))) = b.get("ACL") else {
                panic!("ACL missing or not an object for {literal}");
            };
            let Some(ParseValue::Object(owner)) = acl.get("user123456") else {
                panic!("owner entry missing for {literal}");
            };
            assert!(matches!(owner.get("read"), Some(ParseValue::Bool(true))));
            assert!(matches!(owner.get("write"), Some(ParseValue::Bool(true))));
        }
    }

    /// The half that must **not** change, and the reason the rule is not "always force an owner
    /// in". Upstream's test is `this.data.ACL &&`, so a falsy value skips the assignment and is
    /// then dropped by the lowering, which leaves the stored columns exactly as they were. Forcing
    /// an owner here would replace a deliberate ACL on any request that sent `ACL: null`.
    #[test]
    fn a_falsy_acl_on_an_update_is_left_for_the_lowering_to_drop() {
        for literal in [
            r#"{"ACL":null}"#,
            r#"{"ACL":false}"#,
            r#"{"ACL":0}"#,
            r#"{"ACL":""}"#,
        ] {
            let mut b = body(literal);
            force_owner_into_acl(&mut b, "user123456", false).expect(literal);
            assert!(
                !matches!(b.get("ACL"), Some(FieldWrite::Value(ParseValue::Object(_)))),
                "{literal} must be left alone"
            );
        }
    }

    /// Master and maintenance are exempt, which is upstream's `isMaster !== true` guard. An
    /// operator revoking a user's access to their own row is a legitimate administrative action.
    #[test]
    fn a_privileged_caller_can_still_remove_the_owner() {
        let mut b = body(r#"{"ACL":{"__op":"Delete"}}"#);
        force_owner_into_acl(&mut b, "user123456", true).expect("privileged");
        assert!(matches!(b.get("ACL"), Some(FieldWrite::Op(_))));
    }

    /// A truthy scalar on an update is refused with the 400 signup gives it. Upstream answers a
    /// bare 500 and writes nothing; 0.2.1 rewrote it to the owner-only ACL and answered 200.
    #[test]
    fn a_truthy_scalar_acl_on_an_update_is_refused() {
        for literal in [r#"{"ACL":"nonsense"}"#, r#"{"ACL":123}"#, r#"{"ACL":true}"#] {
            let mut b = body(literal);
            let e = force_owner_into_acl(&mut b, "user123456", false).expect_err(literal);
            assert_eq!(e.code, ErrorCode::OtherCause, "{literal}");
            assert_eq!(e.message, "ACL must be a Parse ACL.");
        }
    }

    /// An array keeps its index principals beside the owner, in JavaScript enumeration order.
    #[test]
    fn an_array_acl_on_an_update_keeps_its_indices() {
        let mut b = body(r#"{"ACL":[{"read":true}]}"#);
        force_owner_into_acl(&mut b, "user123456", false).expect("array");
        let Some(FieldWrite::Value(ParseValue::Object(acl))) = b.get("ACL") else {
            panic!("ACL should be an object");
        };
        assert_eq!(acl.keys().collect::<Vec<_>>(), vec!["0", "user123456"]);
    }

    /// **A truthy non-string `objectId` is refused rather than replaced.** Upstream's substitution
    /// test is `if (!this.data.objectId)`, so a truthy one survives to the type check and answers
    /// `INCORRECT_TYPE`. Reading "not a string" as "absent" generated an id instead: measured at
    /// the pin with `allowCustomObjectId` on, upstream answered 400 code 111 and wrote no row
    /// through either `POST /users` or `POST /classes/_User`, and parse-rust answered 201 with an
    /// id the client never asked for.
    #[test]
    fn a_truthy_non_string_object_id_is_refused_rather_than_replaced() {
        for literal in [
            r#"{"objectId":123,"username":"u"}"#,
            r#"{"objectId":true,"username":"u"}"#,
            r#"{"objectId":["a"],"username":"u"}"#,
            r#"{"objectId":{"a":1},"username":"u"}"#,
        ] {
            let mut b = body(literal);
            let e = ensure_user_identity_and_acl(&mut b).expect_err(literal);
            assert_eq!(e.code, ErrorCode::IncorrectType, "{literal}");
        }
    }

    /// **The one shape that is refused with a different code, and a deliberate difference from
    /// upstream rather than a match.** A `Delete` operation is truthy, so it is not a substitutable
    /// absent id, and upstream infers no type for it, skips the field check and answers 201 having
    /// stored the row under a Mongo-generated `_id` while echoing the operation back as the
    /// `objectId`. parse-rust refuses with `INVALID_JSON`.
    ///
    /// Pinned here rather than in Gate E, which may hold only assertions that pass against both
    /// servers, and this one does not.
    #[test]
    fn a_delete_operation_as_an_object_id_is_refused_with_invalid_json() {
        let mut b = body(r#"{"objectId":{"__op":"Delete"},"username":"u"}"#);
        let e = ensure_user_identity_and_acl(&mut b).expect_err("Delete op");
        assert_eq!(e.code, ErrorCode::InvalidJson);
        assert_eq!(e.message, "objectId is an invalid field name.");
    }

    /// The other side of that test, and the reason it is truthiness rather than presence: an empty
    /// string and a `null` are falsy, so upstream replaces them with a generated id exactly as it
    /// replaces an absent one.
    #[test]
    fn a_falsy_object_id_is_still_replaced_with_a_generated_one() {
        for literal in [
            r#"{"objectId":"","username":"u"}"#,
            r#"{"objectId":null,"username":"u"}"#,
            r#"{"username":"u"}"#,
        ] {
            let mut b = body(literal);
            let id = ensure_user_identity_and_acl(&mut b).expect(literal);
            assert_eq!(id.len(), 10, "{literal} produced {id}");
        }
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
