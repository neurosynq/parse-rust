//! `_Session` rows.
//!
//! Sessions are rows in a real Parse class, not entries in a process's memory. That is the whole
//! point of this module: a token minted here survives a restart, is visible to every node, and is
//! accepted by a parse-server pointed at the same database.
//!
//! **Everything here runs unauthenticated against storage, deliberately.** Upstream resolves a
//! session token with `auth: master(config)` (`Auth.js:168`). It has to: until the lookup
//! finishes there is no caller, so there is no ACL to evaluate and no CLP to consult. Creation is
//! the same, `new RestWrite(config, Auth.master(config), '_Session', null, sessionData)`
//! (`RestWrite.js:1225`). What keeps that narrow is that no query in this module comes from a
//! client. Each one is built here from a session token, a user objectId or a session objectId.
//!
//! The read side of `_Session` that a *client* reaches, `GET /sessions`, is a different path and
//! is not this module. Upstream narrows it to the caller's own user rather than master-gating it
//! (`RestQuery.js:117-133`), and that belongs with the router.
//!
//! Out of scope, and absent rather than half-present:
//!
//! - **Session renewal.** `extendSessionOnUse` defaults to `false` upstream, so sessions expire
//!   and are never extended. Matching the default configuration is the whole of it.
//! - **The user cache.** `getAuthForSessionToken` consults a cache before the query
//!   (`Auth.js:135-155`). Every resolution here is a query.
//! - **Legacy non-`r:` tokens.** `middlewares.js` routes a token without the prefix to a separate
//!   resolver that looks the user up by `_session_token` on `_User`. Not implemented.
//! - **`POST /upgradeToRevocableSession`**, and client-driven `_Session` create and update.

use indexmap::IndexMap;
use rand::CryptoRng;

use parse_rust_core::{new_object_id, ErrorCode, ParseDate, ParseError, ParseMap, ParseValue};
use parse_rust_schema::default_schema;
use parse_rust_storage::{
    ClassSchema, Comparison, Constraint, Query, QueryOptions, Row, StorageAdapter,
};

/// Upstream's revocable-session prefix (`RestWrite.js:1203`).
///
/// Load-bearing rather than decorative: `middlewares.js` routes a token *without* it to the
/// legacy resolver, which looks the token up on `_User` instead of `_Session`. A token minted
/// without the prefix is therefore not a session token at all.
pub const SESSION_TOKEN_PREFIX: &str = "r:";

/// `randomHexString(32)` is 32 hex characters, which is 16 bytes (`cryptoUtils.js:6-14`, `:41`).
const TOKEN_BYTES: usize = 16;

/// The class sessions live in.
const SESSION_CLASS: &str = "_Session";

/// Fill from a cryptographically secure generator.
///
/// The `CryptoRng` bound is the point. A session token is a bearer credential, so a generator
/// swapped for a faster non-cryptographic one has to fail to compile rather than pass the tests.
/// Note that `random_string` in `parse-rust-core` is not usable here even though it draws from
/// the same generator: its alphabet is the 62-character `objectId` set, and a session token's
/// character set is observable to a client.
fn fill_secure<R: CryptoRng>(rng: &mut R, buf: &mut [u8]) {
    rng.fill_bytes(buf);
}

/// A new session token: `r:` followed by 32 lowercase hex characters, 34 in total.
///
/// `'r:' + cryptoUtils.newToken()`, where `newToken` is `randomHexString(32)`
/// (`RestWrite.js:1203`, `cryptoUtils.js:41`).
pub fn new_session_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    fill_secure(&mut rand::rng(), &mut bytes);

    let mut token = String::with_capacity(SESSION_TOKEN_PREFIX.len() + TOKEN_BYTES * 2);
    token.push_str(SESSION_TOKEN_PREFIX);
    for b in bytes {
        // Lowercase, because that is what Node's `Buffer.toString('hex')` produces and a client
        // comparing tokens case-sensitively would see the difference.
        token.push(char::from(HEX[(b >> 4) as usize]));
        token.push(char::from(HEX[(b & 0x0f) as usize]));
    }
    token
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// What created a session.
///
/// Upstream stores this as a plain object with an `action` and, usually, an `authProvider`
/// (`RestWrite.js:941`). Two of the four shapes **omit `authProvider` entirely**:
/// `{action: 'upgrade'}` (`SessionsRouter.js:73`) and `{action: 'create'}`
/// (`RestWrite.js:1366`). Modelling the provider as `Option<String>` rather than defaulting it to
/// an empty string is what keeps those two writing the document parse-server writes: an empty
/// string is a present key, and a present key is a difference a mixed fleet can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAction {
    Signup,
    Login,
    /// `POST /upgradeToRevocableSession`. Out of scope for the route, modelled here so a row
    /// written by parse-server round-trips rather than failing to parse.
    Upgrade,
    /// A client creating a `_Session` directly. Same note as `Upgrade`.
    Create,
}

impl SessionAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionAction::Signup => "signup",
            SessionAction::Login => "login",
            SessionAction::Upgrade => "upgrade",
            SessionAction::Create => "create",
        }
    }
}

/// The `createdWith` column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedWith {
    pub action: SessionAction,
    /// Absent for `upgrade` and `create`, which build the object literally rather than through
    /// `buildCreatedWith`.
    pub auth_provider: Option<String>,
}

impl CreatedWith {
    /// `buildCreatedWith('signup', provider)`. A missing provider becomes `password`, which is
    /// upstream's `authProvider || 'password'` (`RestWrite.js:941-943`).
    pub fn signup(auth_provider: Option<&str>) -> Self {
        Self {
            action: SessionAction::Signup,
            auth_provider: Some(auth_provider.unwrap_or("password").to_string()),
        }
    }

    /// `buildCreatedWith('login', provider)`.
    pub fn login(auth_provider: Option<&str>) -> Self {
        Self {
            action: SessionAction::Login,
            auth_provider: Some(auth_provider.unwrap_or("password").to_string()),
        }
    }

    /// `{action: 'upgrade'}`, with no `authProvider` key (`SessionsRouter.js:73`).
    pub fn upgrade() -> Self {
        Self {
            action: SessionAction::Upgrade,
            auth_provider: None,
        }
    }

    /// `{action: 'create'}`, with no `authProvider` key (`RestWrite.js:1366`).
    pub fn create() -> Self {
        Self {
            action: SessionAction::Create,
            auth_provider: None,
        }
    }

    fn to_value(&self) -> ParseValue {
        let mut map = ParseMap::new();
        map.insert(
            "action".to_string(),
            ParseValue::String(self.action.as_str().to_string()),
        );
        if let Some(provider) = &self.auth_provider {
            map.insert(
                "authProvider".to_string(),
                ParseValue::String(provider.clone()),
            );
        }
        ParseValue::Object(map)
    }
}

/// The two options that decide a session's lifetime.
///
/// Taken as configuration rather than hardcoded, because both are server options and an operator
/// can set either. The defaults are upstream's: `sessionLength` 31536000 seconds, one year
/// (`Options/Definitions.js:635-640`), and `expireInactiveSessions` true
/// (`Options/Definitions.js:275-280`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    pub session_length_secs: i64,
    pub expire_inactive_sessions: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_length_secs: 31_536_000,
            expire_inactive_sessions: true,
        }
    }
}

impl SessionConfig {
    /// `config.generateSessionExpiresAt()` (`Config.js:915-921`).
    ///
    /// `None` when `expireInactiveSessions` is false, which is upstream's `undefined` and which
    /// produces a session that never expires. See [`resolve_session`].
    pub fn generate_expires_at(&self, now: ParseDate) -> Option<ParseDate> {
        if !self.expire_inactive_sessions {
            return None;
        }
        let millis = now
            .timestamp_millis()
            .checked_add(self.session_length_secs.saturating_mul(1000))?;
        chrono::DateTime::from_timestamp_millis(millis).map(ParseDate::from_datetime)
    }
}

/// What a caller must supply to mint a session.
#[derive(Debug, Clone)]
pub struct NewSession<'a> {
    pub user_object_id: &'a str,
    /// `None` writes no `createdWith` column at all, which is what a password-change replacement
    /// session gets. `setCreatedWith` computes an action of `login` only when an auth provider is
    /// in storage and `signup` only on a create, and returns early with neither set otherwise
    /// (`RestWrite.js:952-962`), so the column is simply absent. Modelled as an `Option` rather
    /// than a third `SessionAction`, because the difference is whether the key exists.
    pub created_with: Option<CreatedWith>,
    /// `X-Parse-Installation-Id`, when the client sent one. Its presence is what enables
    /// duplicate destruction; see [`create_session`].
    pub installation_id: Option<&'a str>,
}

/// A freshly minted session.
#[derive(Debug, Clone)]
pub struct CreatedSession {
    pub session_token: String,
    pub object_id: String,
    /// `None` when `expireInactiveSessions` is false.
    pub expires_at: Option<ParseDate>,
    pub created_at: ParseDate,
}

/// A session resolved from a token.
#[derive(Debug, Clone)]
pub struct ResolvedSession {
    pub object_id: String,
    pub user_object_id: String,
    pub session_token: String,
    pub installation_id: Option<String>,
    /// `None` for a session that never expires.
    pub expires_at: Option<ParseDate>,
    /// The row as stored, in Parse form. `GET /sessions/me` returns it; nothing else should need
    /// it, and it carries no secret beyond the token the caller already presented.
    pub row: Row,
}

fn invalid_session_token() -> ParseError {
    // No trailing period. Upstream's two session errors differ in punctuation and a client
    // matching on the message would see it (`Auth.js:185` versus `:191`).
    ParseError::new(ErrorCode::InvalidSessionToken, "Invalid session token")
}

fn session_expired() -> ParseError {
    ParseError::new(ErrorCode::InvalidSessionToken, "Session token is expired.")
}

/// `Auth.js:195-197`. A user objectId beginning with `role:` would be granted that role by every
/// ACL check, so upstream refuses to build an `Auth` from one.
fn role_prefixed_object_id() -> ParseError {
    ParseError::new(ErrorCode::InternalServerError, "Invalid object ID.")
}

/// The schema `_Session` rows are read and written against.
///
/// Built from the default columns rather than loaded, because every column this module touches is
/// a default column of `_Session` (`SchemaController.js:70-77`) and a client cannot redefine one.
/// The one thing the stored schema could add is an extra column from `additionalSessionData`,
/// which is a route this milestone does not serve, and which raises correctly anyway because the
/// stored form is self-describing.
fn session_schema() -> ClassSchema {
    default_schema(SESSION_CLASS)
}

/// Ensure `_SCHEMA` carries a `_Session` entry.
///
/// Worth stating why this exists at all. parse-server creates the `_SCHEMA` document for
/// `_Session` on its first session write. If parse-rust writes rows into the `_Session`
/// collection without ever writing that document, a parse-server pointed at the same database has
/// no `_Session` class to query, and every token parse-rust issued is invisible to it. That is
/// exactly the shared-state property this milestone claims, so it cannot be left to chance.
///
/// Reads first and writes only when the class is absent. The read is per session creation, not
/// per request, and it is cheaper than an unconditional upsert on every login. When it does
/// write, it is safe against a class parse-server already created: `upsert_schema` sets the field
/// keys it is given and leaves `_metadata` alone, so an existing CLP block survives.
pub async fn ensure_session_schema<S: StorageAdapter>(storage: &S) -> Result<(), ParseError> {
    let existing = storage.all_schemas().await?;
    if existing.iter().any(|s| s.class_name == SESSION_CLASS) {
        return Ok(());
    }
    storage.upsert_schema(&session_schema()).await
}

/// Mint a session and write its row.
///
/// The row is upstream's, key for key and in upstream's order (`RestWrite.js:1199-1227`, then the
/// default fields at `:423-431`): `sessionToken`, `user`, `createdWith`, `expiresAt`,
/// `installationId` when present, then `updatedAt`, `createdAt`, `objectId`.
///
/// **No ACL.** `_Session` rows carry none. Upstream refuses a client-supplied one outright,
/// `Cannot set ACL on a Session.` (`RestWrite.js:1323-1324`), and the two paths that add an ACL
/// automatically do not apply: the CLP-derived default ACL needs a non-default
/// `classLevelPermissions.ACL` (`RestWrite.js:438-455`), and the owner-private ACL is `_User`
/// only (`RestWrite.js:1813-1825`). An absent ACL means the row is public to anything reading the
/// collection directly, and what makes that safe is that the client-facing read of `_Session` is
/// narrowed to the caller's own user before it reaches storage (`RestQuery.js:117-133`). Adding
/// an ACL here would be inventing a column parse-server does not write.
pub async fn create_session<S: StorageAdapter>(
    storage: &S,
    config: &SessionConfig,
    new: NewSession<'_>,
) -> Result<CreatedSession, ParseError> {
    let schema = session_schema();
    let now = ParseDate::now();
    let token = new_session_token();
    let expires_at = config.generate_expires_at(now);
    let object_id = new_object_id();

    let user = ParseValue::Pointer {
        class_name: "_User".to_string(),
        object_id: new.user_object_id.to_string(),
    };

    let mut row: Row = IndexMap::new();
    row.insert(
        "sessionToken".to_string(),
        ParseValue::String(token.clone()),
    );
    row.insert("user".to_string(), user.clone());
    if let Some(created_with) = &new.created_with {
        row.insert("createdWith".to_string(), created_with.to_value());
    }
    // Deliberately omitted rather than written as null when there is no expiry. Upstream assigns
    // `Parse._encode(undefined)`, and what the Node BSON serializer then stores for an undefined
    // value is a driver-configuration question this has not been measured against a running
    // server. Both forms read identically upstream, because `session.expiresAt ? ... : undefined`
    // treats an absent key and a null one the same (`Auth.js:189`), so the choice is not
    // observable through any Parse API. An absent key is the form that also means "no expiry"
    // unambiguously in a SQL backend.
    if let Some(expires_at) = expires_at {
        row.insert("expiresAt".to_string(), ParseValue::Date(expires_at));
    }
    if let Some(installation_id) = new.installation_id {
        row.insert(
            "installationId".to_string(),
            ParseValue::String(installation_id.to_string()),
        );
    }
    row.insert("updatedAt".to_string(), ParseValue::Date(now));
    row.insert("createdAt".to_string(), ParseValue::Date(now));
    row.insert(
        "objectId".to_string(),
        ParseValue::String(object_id.clone()),
    );

    // Before the insert, not after. `destroyDuplicatedSessions` runs at `RestWrite.js:150`, which
    // is ahead of `runDatabaseOperation` at `:147`, so the new row is not yet a candidate for its
    // own dedup. The `sessionToken != token` guard upstream carries is kept anyway: it costs one
    // clause and it is what makes the order not matter.
    destroy_duplicated_sessions(storage, &schema, &user, new.installation_id, &token).await?;

    ensure_session_schema(storage).await?;
    storage.create(&schema, &row).await?;

    Ok(CreatedSession {
        session_token: token,
        object_id,
        expires_at,
        created_at: now,
    })
}

/// `destroyDuplicatedSessions` (`RestWrite.js:1245`).
///
/// **Note the conjunction.** The delete matches the same user *and* the same installationId, so
/// two sessions from two devices coexist and two from one device do not. It is skipped entirely
/// when there is no installationId, which is the common case for a REST client that sends no
/// `X-Parse-Installation-Id`: without one, every login would otherwise revoke every other
/// session the user has.
///
/// Upstream swallows `OBJECT_NOT_FOUND` from the destroy. There is nothing to swallow here,
/// because the adapter reports a match count rather than raising on zero.
async fn destroy_duplicated_sessions<S: StorageAdapter>(
    storage: &S,
    schema: &ClassSchema,
    user: &ParseValue,
    installation_id: Option<&str>,
    session_token: &str,
) -> Result<(), ParseError> {
    let Some(installation_id) = installation_id else {
        return Ok(());
    };

    let query = Query::from_constraints(vec![
        Constraint::equal("user", user.clone()),
        Constraint::equal(
            "installationId",
            ParseValue::String(installation_id.to_string()),
        ),
        Constraint {
            field: "sessionToken".to_string(),
            comparison: Comparison::NotEqual(ParseValue::String(session_token.to_string())),
        },
    ]);
    storage.delete(schema, &query).await?;
    Ok(())
}

/// Resolve a session token to its session.
///
/// `getAuthForSessionToken`'s miss path (`Auth.js:157-197`). The order of the three failures is
/// upstream's and is observable, because the first one reached is the error the client sees:
///
/// 1. no row, a row with no `user`, or a `user` naming no `_User` row: `INVALID_SESSION_TOKEN`
///    (209) `Invalid session token`
/// 2. `expiresAt` in the past: 209 `Session token is expired.`
/// 3. the user objectId starts with `role:`: `INTERNAL_SERVER_ERROR` (1) `Invalid object ID.`
///
/// **UPSTREAM-QUIRK: a session with no `expiresAt` never expires.** Upstream computes
/// `expiresAt = session.expiresAt ? new Date(session.expiresAt.iso) : undefined` and then tests
/// `expiresAt < now` (`Auth.js:188-192`). In JavaScript `undefined < now` is false, so the check
/// passes. That is intended, and it is what keeps a row written under
/// `expireInactiveSessions: false`, or by an older server, working. Reproduced exactly. See
/// `a_session_with_no_expiry_never_expires` for the test that makes "fixing" this fail loudly.
///
/// **The user must exist.** Upstream reads the session with `include: 'user'` (`Auth.js:158-172`),
/// and `replacePointers` turns a pointer whose row it did not find into `undefined`
/// (`RestQuery.js:1335-1338`), so a deleted user's token fails the `!results[0]['user']` test and
/// is 209. The `role:` guard then reads the included user's objectId, which is the pointer's.
pub async fn resolve_session<S: StorageAdapter>(
    storage: &S,
    session_token: &str,
) -> Result<ResolvedSession, ParseError> {
    let schema = session_schema();
    let query = Query::from_constraints(vec![Constraint::equal(
        "sessionToken",
        ParseValue::String(session_token.to_string()),
    )]);
    let options = QueryOptions {
        limit: Some(1),
        skip: None,
        order: Vec::new(),
        keys: None,
        case_insensitive: false,
        ..QueryOptions::default()
    };

    let rows = storage.find(&schema, &query, &options).await?;
    let Some(row) = rows.into_iter().next() else {
        return Err(invalid_session_token());
    };

    // Upstream's condition is `results.length !== 1 || !results[0]['user']`. A row whose `user`
    // is absent, null or not a pointer fails it.
    let user_object_id = match row.get("user") {
        Some(ParseValue::Pointer { object_id, .. }) => object_id.clone(),
        _ => return Err(invalid_session_token()),
    };
    if !user_exists(storage, &user_object_id).await? {
        return Err(invalid_session_token());
    }

    let expires_at = match row.get("expiresAt") {
        Some(ParseValue::Date(d)) => Some(*d),
        // A stored `expiresAt` that is not a Date is treated as absent, which is the never-expires
        // path. That is upstream's behavior for a null, and for a string it is the behavior the
        // Mongo transform's own note describes: a string `expiresAt` is compared against a Date
        // and never satisfies the check.
        _ => None,
    };
    if let Some(expires_at) = expires_at {
        if expires_at.timestamp_millis() < ParseDate::now().timestamp_millis() {
            return Err(session_expired());
        }
    }

    if user_object_id.starts_with("role:") {
        return Err(role_prefixed_object_id());
    }

    let object_id = match row.get("objectId") {
        Some(ParseValue::String(id)) => id.clone(),
        _ => return Err(invalid_session_token()),
    };
    let installation_id = match row.get("installationId") {
        Some(ParseValue::String(id)) => Some(id.clone()),
        _ => None,
    };

    Ok(ResolvedSession {
        object_id,
        user_object_id,
        session_token: session_token.to_string(),
        installation_id,
        expires_at,
        row,
    })
}

/// The user a session token names, with no expiry check and no check that the user exists.
///
/// `handleMe`'s own lookup (`UsersRouter.js:195-213`): it reads the `_Session` row with the master
/// key and takes `user.objectId`, then re-fetches the user, which is where a missing user fails.
/// An expired session is not refused there, so a master caller asking `/users/me` with an expired
/// token gets that token's user.
pub async fn session_user<S: StorageAdapter>(
    storage: &S,
    session_token: &str,
) -> Result<Option<String>, ParseError> {
    let query = Query::from_constraints(vec![Constraint::equal(
        "sessionToken",
        ParseValue::String(session_token.to_string()),
    )]);
    let options = QueryOptions {
        limit: Some(1),
        ..QueryOptions::default()
    };
    let rows = storage.find(&session_schema(), &query, &options).await?;
    Ok(rows
        .into_iter()
        .next()
        .and_then(|row| match row.get("user") {
            Some(ParseValue::Pointer { object_id, .. }) => Some(object_id.clone()),
            _ => None,
        }))
}

/// Is there a `_User` row with this objectId? The include's lookup, reduced to existence.
async fn user_exists<S: StorageAdapter>(storage: &S, object_id: &str) -> Result<bool, ParseError> {
    let query = Query::from_constraints(vec![Constraint::equal(
        "objectId",
        ParseValue::String(object_id.to_string()),
    )]);
    let options = QueryOptions {
        limit: Some(1),
        keys: Some(vec!["objectId".to_string()]),
        ..QueryOptions::default()
    };
    Ok(!storage
        .find(&default_schema("_User"), &query, &options)
        .await?
        .is_empty())
}

/// Delete one session by its token. Returns whether a row was removed.
pub async fn revoke<S: StorageAdapter>(
    storage: &S,
    session_token: &str,
) -> Result<bool, ParseError> {
    let query = Query::from_constraints(vec![Constraint::equal(
        "sessionToken",
        ParseValue::String(session_token.to_string()),
    )]);
    let deleted = storage.delete(&session_schema(), &query).await?;
    Ok(deleted > 0)
}

/// Delete every session belonging to a user. Returns how many.
///
/// This is what a password change needs. `revokeSessionOnPasswordReset` defaults to true
/// (`Options/Definitions.js:590-595`) and the destroy it performs is exactly this query, keyed on
/// the user pointer with nothing else (`RestWrite.js:1284-1296`).
///
/// Implemented ahead of any route that reaches it, on purpose. The alternative is that
/// `DELETE /sessions/:objectId` grows its own one-row delete and the password-change path grows a
/// second, similar one later, and the two then diverge. One function, two callers.
pub async fn revoke_all_for_user<S: StorageAdapter>(
    storage: &S,
    user_object_id: &str,
) -> Result<u64, ParseError> {
    let query = Query::from_constraints(vec![Constraint::equal(
        "user",
        ParseValue::Pointer {
            class_name: "_User".to_string(),
            object_id: user_object_id.to_string(),
        },
    )]);
    storage.delete(&session_schema(), &query).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeStorage;
    use std::collections::HashSet;

    fn cfg() -> SessionConfig {
        SessionConfig::default()
    }

    /// Storage holding the `_User` rows the tests' sessions point at. A session whose user does
    /// not exist resolves to 209, which `a_deleted_users_session_is_invalid` covers.
    fn with_users() -> FakeStorage {
        let s = FakeStorage::new();
        for id in ["u1", "u2", "alice", "bob", "user000001", "role:Admins"] {
            s.insert_row("_User", vec![("objectId", ParseValue::String(id.into()))]);
        }
        s
    }

    #[test]
    fn a_token_is_r_plus_thirty_two_lowercase_hex() {
        let t = new_session_token();
        assert_eq!(t.len(), 34, "r: plus 32 hex characters: {t}");
        let hex = t.strip_prefix("r:").expect("the r: prefix is load-bearing");
        assert_eq!(hex.len(), 32);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "lowercase hex only, matching Buffer.toString('hex'): {hex}"
        );
    }

    /// The failure this guards against is reusing the objectId alphabet, which is alphanumeric
    /// over 62 characters. Any uppercase letter or any digit above `f` proves it happened.
    #[test]
    fn tokens_do_not_use_the_object_id_alphabet() {
        let mut seen: HashSet<char> = HashSet::new();
        for _ in 0..500 {
            seen.extend(new_session_token()[2..].chars());
        }
        assert_eq!(seen.len(), 16, "a hex token uses exactly 16 characters");
        assert!(seen
            .iter()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn tokens_do_not_repeat() {
        let tokens: HashSet<String> = (0..1000).map(|_| new_session_token()).collect();
        assert_eq!(tokens.len(), 1000);
    }

    #[tokio::test]
    async fn the_row_is_upstreams_columns_in_upstreams_order() {
        let s = with_users();
        let created = create_session(
            &s,
            &cfg(),
            NewSession {
                user_object_id: "user000001",
                created_with: Some(CreatedWith::signup(None)),
                installation_id: Some("install-1"),
            },
        )
        .await
        .expect("create");

        let rows = s.rows("_Session");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        let keys: Vec<&str> = row.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "sessionToken",
                "user",
                "createdWith",
                "expiresAt",
                "installationId",
                "updatedAt",
                "createdAt",
                "objectId",
            ]
        );

        assert!(
            matches!(row.get("user"), Some(ParseValue::Pointer { class_name, object_id })
            if class_name == "_User" && object_id == "user000001")
        );
        assert!(
            matches!(row.get("objectId"), Some(ParseValue::String(id)) if id == &created.object_id)
        );
        assert!(
            matches!(row.get("sessionToken"), Some(ParseValue::String(t)) if t == &created.session_token)
        );
    }

    #[tokio::test]
    async fn created_with_carries_action_and_provider_for_signup_and_login() {
        for (built, action, provider) in [
            (CreatedWith::signup(None), "signup", Some("password")),
            (CreatedWith::login(None), "login", Some("password")),
            (
                CreatedWith::login(Some("facebook")),
                "login",
                Some("facebook"),
            ),
        ] {
            let ParseValue::Object(map) = built.to_value() else {
                panic!("createdWith is an object");
            };
            let keys: Vec<&str> = map.keys().map(String::as_str).collect();
            assert_eq!(keys, vec!["action", "authProvider"]);
            assert!(matches!(map.get("action"), Some(ParseValue::String(a)) if a == action));
            assert!(
                matches!(map.get("authProvider"), Some(ParseValue::String(p)) if Some(p.as_str()) == provider)
            );
        }
    }

    /// The two shapes that omit the key. An empty-string default would be a present key, and a
    /// present key is a difference a parse-server reading the same row can see.
    #[tokio::test]
    async fn upgrade_and_create_omit_the_auth_provider_key_entirely() {
        for (built, action) in [
            (CreatedWith::upgrade(), "upgrade"),
            (CreatedWith::create(), "create"),
        ] {
            assert_eq!(built.auth_provider, None);
            let ParseValue::Object(map) = built.to_value() else {
                panic!("createdWith is an object");
            };
            let keys: Vec<&str> = map.keys().map(String::as_str).collect();
            assert_eq!(
                keys,
                vec!["action"],
                "authProvider must be absent, not empty"
            );
            assert!(matches!(map.get("action"), Some(ParseValue::String(a)) if a == action));
        }
    }

    #[tokio::test]
    async fn a_session_row_has_no_acl() {
        let s = with_users();
        create_session(
            &s,
            &cfg(),
            NewSession {
                user_object_id: "u1",
                created_with: Some(CreatedWith::login(None)),
                installation_id: None,
            },
        )
        .await
        .expect("create");
        let rows = s.rows("_Session");
        assert!(
            rows[0].get("ACL").is_none(),
            "upstream refuses an ACL on _Session and adds none of its own"
        );
    }

    #[tokio::test]
    async fn creating_a_session_writes_the_session_schema() {
        let s = with_users();
        create_session(
            &s,
            &cfg(),
            NewSession {
                user_object_id: "u1",
                created_with: Some(CreatedWith::login(None)),
                installation_id: None,
            },
        )
        .await
        .expect("create");
        // Without this, a parse-server on the same database has no _Session class to query and
        // every token parse-rust issued is invisible to it.
        assert!(s.schema("_Session").is_some());
    }

    #[tokio::test]
    async fn expiry_is_now_plus_session_length_and_is_absent_when_disabled() {
        let s = with_users();
        let created = create_session(
            &s,
            &cfg(),
            NewSession {
                user_object_id: "u1",
                created_with: Some(CreatedWith::login(None)),
                installation_id: None,
            },
        )
        .await
        .expect("create");
        let expires = created.expires_at.expect("default config expires sessions");
        let delta = expires.timestamp_millis() - created.created_at.timestamp_millis();
        assert_eq!(delta, 31_536_000 * 1000, "one year, in milliseconds");

        let never = SessionConfig {
            expire_inactive_sessions: false,
            ..SessionConfig::default()
        };
        let created = create_session(
            &s,
            &never,
            NewSession {
                user_object_id: "u2",
                created_with: Some(CreatedWith::login(None)),
                installation_id: None,
            },
        )
        .await
        .expect("create");
        assert_eq!(created.expires_at, None);
        let row = s
            .rows("_Session")
            .into_iter()
            .find(|r| matches!(r.get("user"), Some(ParseValue::Pointer { object_id, .. }) if object_id == "u2"))
            .expect("row");
        assert!(row.get("expiresAt").is_none());
    }

    #[tokio::test]
    async fn a_minted_token_resolves_to_its_user() {
        let s = with_users();
        let created = create_session(
            &s,
            &cfg(),
            NewSession {
                user_object_id: "user000001",
                created_with: Some(CreatedWith::signup(None)),
                installation_id: Some("install-1"),
            },
        )
        .await
        .expect("create");

        let resolved = resolve_session(&s, &created.session_token)
            .await
            .expect("resolve");
        assert_eq!(resolved.user_object_id, "user000001");
        assert_eq!(resolved.object_id, created.object_id);
        assert_eq!(resolved.installation_id.as_deref(), Some("install-1"));
        assert_eq!(resolved.expires_at, created.expires_at);
    }

    #[tokio::test]
    async fn an_unknown_token_is_invalid_session_token() {
        let s = with_users();
        let e = resolve_session(&s, "r:nope").await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidSessionToken);
        assert_eq!(e.message, "Invalid session token");
    }

    #[tokio::test]
    async fn a_row_with_no_user_is_invalid_session_token() {
        let s = with_users();
        s.insert_row(
            "_Session",
            vec![
                ("objectId", ParseValue::String("s1".into())),
                ("sessionToken", ParseValue::String("r:orphan".into())),
            ],
        );
        let e = resolve_session(&s, "r:orphan").await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidSessionToken);
        assert_eq!(e.message, "Invalid session token");
    }

    /// Expiry is checked after the user check and before the `role:` check. The order is
    /// observable: a row that is both expired and role-prefixed reports expiry.
    #[tokio::test]
    async fn the_three_failures_are_checked_in_upstreams_order() {
        let s = with_users();
        let past = ParseDate::parse_iso("2000-01-01T00:00:00.000Z").expect("date");

        // Expired and role-prefixed at once: expiry wins.
        s.insert_row(
            "_Session",
            vec![
                ("objectId", ParseValue::String("s1".into())),
                ("sessionToken", ParseValue::String("r:both".into())),
                (
                    "user",
                    ParseValue::Pointer {
                        class_name: "_User".into(),
                        object_id: "role:Admins".into(),
                    },
                ),
                ("expiresAt", ParseValue::Date(past)),
            ],
        );
        let e = resolve_session(&s, "r:both").await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidSessionToken);
        assert_eq!(e.message, "Session token is expired.");

        // Role-prefixed but not expired: the internal error.
        s.insert_row(
            "_Session",
            vec![
                ("objectId", ParseValue::String("s2".into())),
                ("sessionToken", ParseValue::String("r:role".into())),
                (
                    "user",
                    ParseValue::Pointer {
                        class_name: "_User".into(),
                        object_id: "role:Admins".into(),
                    },
                ),
            ],
        );
        let e = resolve_session(&s, "r:role").await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InternalServerError);
        assert_eq!(e.message, "Invalid object ID.");

        // No user at all, and expired: the user check wins.
        s.insert_row(
            "_Session",
            vec![
                ("objectId", ParseValue::String("s3".into())),
                ("sessionToken", ParseValue::String("r:nouser".into())),
                ("expiresAt", ParseValue::Date(past)),
            ],
        );
        let e = resolve_session(&s, "r:nouser").await.unwrap_err();
        assert_eq!(e.message, "Invalid session token");
    }

    /// UPSTREAM-QUIRK, and the test exists so that "fixing" it fails loudly.
    ///
    /// `undefined < now` is false in JavaScript (`Auth.js:188-192`), so a `_Session` row with no
    /// `expiresAt` authenticates forever. Legacy rows and rows written under
    /// `expireInactiveSessions: false` depend on it. If this test ever fails because someone made
    /// a missing expiry mean "expired", they have logged out every such session on the database.
    #[tokio::test]
    async fn upstream_quirk_a_session_with_no_expiry_never_expires() {
        let s = with_users();
        s.insert_row(
            "_Session",
            vec![
                ("objectId", ParseValue::String("s1".into())),
                ("sessionToken", ParseValue::String("r:legacy".into())),
                (
                    "user",
                    ParseValue::Pointer {
                        class_name: "_User".into(),
                        object_id: "u1".into(),
                    },
                ),
            ],
        );
        let resolved = resolve_session(&s, "r:legacy").await.expect("resolve");
        assert_eq!(resolved.user_object_id, "u1");
        assert_eq!(resolved.expires_at, None);
    }

    #[tokio::test]
    async fn duplicate_destruction_is_per_user_and_per_installation() {
        let s = with_users();
        let mk = |user: &'static str, install: Option<&'static str>| NewSession {
            user_object_id: user,
            created_with: Some(CreatedWith::login(None)),
            installation_id: install,
        };

        let phone_a = create_session(&s, &cfg(), mk("alice", Some("phone")))
            .await
            .expect("create");
        let tablet_a = create_session(&s, &cfg(), mk("alice", Some("tablet")))
            .await
            .expect("create");
        let phone_b = create_session(&s, &cfg(), mk("bob", Some("phone")))
            .await
            .expect("create");

        // A second login from alice's phone destroys only alice's phone session.
        let phone_a2 = create_session(&s, &cfg(), mk("alice", Some("phone")))
            .await
            .expect("create");

        assert!(resolve_session(&s, &phone_a.session_token).await.is_err());
        assert!(resolve_session(&s, &phone_a2.session_token).await.is_ok());
        assert!(
            resolve_session(&s, &tablet_a.session_token).await.is_ok(),
            "two devices, two sessions: the match is on user AND installationId"
        );
        assert!(
            resolve_session(&s, &phone_b.session_token).await.is_ok(),
            "another user's session on the same installationId must survive"
        );
    }

    #[tokio::test]
    async fn without_an_installation_id_nothing_is_destroyed() {
        let s = with_users();
        let mk = || NewSession {
            user_object_id: "alice",
            created_with: Some(CreatedWith::login(None)),
            installation_id: None,
        };
        let first = create_session(&s, &cfg(), mk()).await.expect("create");
        let second = create_session(&s, &cfg(), mk()).await.expect("create");
        // Upstream skips the dedup when either half of the pair is missing. Doing otherwise would
        // make every REST login revoke every other session the user has.
        assert!(resolve_session(&s, &first.session_token).await.is_ok());
        assert!(resolve_session(&s, &second.session_token).await.is_ok());
    }

    #[tokio::test]
    async fn revoke_removes_one_session_and_revoke_all_removes_the_users() {
        let s = with_users();
        let mk = |user: &'static str| NewSession {
            user_object_id: user,
            created_with: Some(CreatedWith::login(None)),
            installation_id: None,
        };
        let a1 = create_session(&s, &cfg(), mk("alice")).await.expect("c");
        let a2 = create_session(&s, &cfg(), mk("alice")).await.expect("c");
        let b1 = create_session(&s, &cfg(), mk("bob")).await.expect("c");

        assert!(revoke(&s, &a1.session_token).await.expect("revoke"));
        assert!(
            !revoke(&s, &a1.session_token).await.expect("revoke"),
            "revoking twice reports the second as a miss"
        );
        assert!(resolve_session(&s, &a2.session_token).await.is_ok());

        assert_eq!(revoke_all_for_user(&s, "alice").await.expect("revoke"), 1);
        assert!(resolve_session(&s, &a2.session_token).await.is_err());
        assert!(
            resolve_session(&s, &b1.session_token).await.is_ok(),
            "another user's sessions must survive"
        );
    }

    #[tokio::test]
    async fn resolution_reads_at_most_one_row() {
        let s = with_users();
        let created = create_session(
            &s,
            &cfg(),
            NewSession {
                user_object_id: "u1",
                created_with: Some(CreatedWith::login(None)),
                installation_id: None,
            },
        )
        .await
        .expect("create");
        s.reset_find_count();
        resolve_session(&s, &created.session_token)
            .await
            .expect("resolve");
        assert_eq!(
            s.find_count(),
            2,
            "session resolution is on every authenticated request: the session and its user, \
             which is upstream's `include: 'user'` read, and nothing more"
        );
        assert_eq!(s.last_find_limit(), Some(Some(1)));
    }

    /// A deleted user's sessions stop working at once, as upstream's include finds no user.
    #[tokio::test]
    async fn a_deleted_users_session_is_invalid() {
        let s = FakeStorage::new();
        let created = create_session(
            &s,
            &cfg(),
            NewSession {
                user_object_id: "gone",
                created_with: Some(CreatedWith::login(None)),
                installation_id: None,
            },
        )
        .await
        .expect("create");
        let e = resolve_session(&s, &created.session_token)
            .await
            .expect_err("no such user");
        assert_eq!(e.code, ErrorCode::InvalidSessionToken);
        assert_eq!(e.message, "Invalid session token");
    }
}
