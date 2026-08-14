//! Server state: config plus the storage adapter.
//!
//! Concrete over `MongoAdapter` rather than generic or boxed. 0.1.0 is Mongo only, and a type
//! parameter threaded through every handler would be noise until a second backend exists. The
//! `StorageAdapter` trait is still what the pipelines are written against, so swapping this for a
//! generic later is a change in one file rather than in every route.

use std::sync::Arc;

use parse_rust_mongo::MongoAdapter;
use parse_rust_rest::AclScope;

use crate::config::ServerConfig;
use crate::sessions::SessionStore;

#[derive(Clone)]
pub struct AppState {
    config: Arc<ServerConfig>,
    storage: Arc<MongoAdapter>,
    sessions: Arc<SessionStore>,
}

impl AppState {
    pub fn new(config: ServerConfig, storage: MongoAdapter) -> Self {
        Self {
            config: Arc::new(config),
            storage: Arc::new(storage),
            sessions: Arc::new(SessionStore::default()),
        }
    }

    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    pub fn storage(&self) -> &MongoAdapter {
        &self.storage
    }

    pub fn sessions(&self) -> &SessionStore {
        &self.sessions
    }

    /// Create the indexes parse-server creates at boot.
    ///
    /// **The names are contract, not housekeeping.** Both adapters recover `duplicated_field` by
    /// regex over the index name, and the Mongo regex matches only auto-generated `<field>_1`
    /// names, so passing `None` here (which lets the driver auto-name) is what makes a username
    /// collision surface as 202 `USERNAME_TAKEN` rather than a bare 137. Naming them ourselves
    /// would silently change the error a client sees.
    ///
    /// Upstream gates each of these behind a `databaseOptions.createIndexUser*` flag. Those are
    /// not modeled yet; the indexes are unconditional here, which is the default behavior.
    pub async fn ensure_indexes(&self) -> Result<(), parse_rust_core::ParseError> {
        use parse_rust_storage::StorageAdapter;
        self.storage
            .ensure_unique_index("_User", &["username"], None)
            .await?;
        self.storage
            .ensure_unique_index("_User", &["email"], None)
            .await?;
        Ok(())
    }

    /// Resolve a session token to an ACL scope.
    ///
    /// **An unknown or expired token is an error, not anonymity.** Downgrading silently meant a
    /// client whose session had gone continued to work as a public caller: writes succeeded
    /// against public rows and reads returned public data, with no signal that authentication had
    /// failed. Upstream answers `INVALID_SESSION_TOKEN` (209), and so does this.
    pub fn scope_for_session(&self, token: &str) -> Result<AclScope, parse_rust_core::ParseError> {
        match self.sessions.user_for(token) {
            Some(object_id) => Ok(AclScope::User { object_id }),
            None => Err(parse_rust_core::ParseError::new(
                parse_rust_core::ErrorCode::InvalidSessionToken,
                "Invalid session token",
            )),
        }
    }
}

impl axum::extract::FromRef<AppState> for Arc<ServerConfig> {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}
