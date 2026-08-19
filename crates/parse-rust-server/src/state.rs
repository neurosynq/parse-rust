//! Server state: config plus the storage adapter.
//!
//! Concrete over `MongoAdapter` rather than generic or boxed. 0.2.0 is Mongo only, and a type
//! parameter threaded through every handler would be noise until a second backend exists. The
//! `StorageAdapter` trait is still what the pipelines are written against, so swapping this for a
//! generic later is a change in one file rather than in every route.

use std::sync::Arc;

use parse_rust_core::ParseError;
use parse_rust_mongo::MongoAdapter;

use crate::auth::Authority;
use crate::config::ServerConfig;
use crate::request::RequestContext;

#[derive(Clone)]
pub struct AppState {
    config: Arc<ServerConfig>,
    storage: Arc<MongoAdapter>,
}

impl AppState {
    pub fn new(config: ServerConfig, storage: MongoAdapter) -> Self {
        Self {
            config: Arc::new(config),
            storage: Arc::new(storage),
        }
    }

    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    pub fn storage(&self) -> &MongoAdapter {
        &self.storage
    }

    /// Create the indexes parse-server creates at boot.
    ///
    /// **The names are contract, not housekeeping.** Both adapters recover `duplicated_field` by
    /// regex over the index name, and the Mongo regex matches only auto-generated `<field>_1`
    /// names, so passing `None` here (which lets the driver auto-name) is what makes a username
    /// collision surface as 202 `USERNAME_TAKEN` rather than a bare 137. Naming them ourselves
    /// would silently change the error a client sees.
    ///
    /// Upstream gates each of these behind a `databaseOptions.createIndex*` flag
    /// (`DatabaseController.js:1981-2038`). Only `createIndexRoleName` is modeled; the two
    /// `_User` indexes are unconditional here, which is what their flags default to.
    pub async fn ensure_indexes(&self) -> Result<(), ParseError> {
        use parse_rust_storage::StorageAdapter;
        self.storage
            .ensure_index("_User", &["username"], None, true, false)
            .await?;
        self.storage
            .ensure_index("_User", &["email"], None, true, false)
            .await?;
        // **The case-insensitive pair, and note they are not unique**
        // (`DatabaseController.js:1988-2005`). Upstream's `ensureIndex` never sets `unique`, so
        // these exist to make the collated uniqueness *query* fast, not to enforce anything. The
        // enforcement is the query in `validate_user_identity`.
        //
        // Creating them unique looks stricter and is a mixed-fleet break: parse-server booting
        // against the same database asks for the non-unique form under the same name, gets
        // `IndexKeySpecsConflict` (86), and refuses to start. Gate D found exactly that.
        //
        // Named rather than auto-named, because upstream names them and a mixed fleet has to agree
        // on what exists.
        self.storage
            .ensure_index(
                "_User",
                &["username"],
                Some("case_insensitive_username"),
                false,
                true,
            )
            .await?;
        self.storage
            .ensure_index(
                "_User",
                &["email"],
                Some("case_insensitive_email"),
                false,
                true,
            )
            .await?;
        // `_Role.name`, `ensureUniqueness('_Role', requiredRoleFields, ['name'])`
        // (`DatabaseController.js:2033-2038`). Upstream passes no index name, so Mongo
        // auto-generates `name_1`, which is the form the `duplicated_field` regex matches.
        //
        // Without it two `_Role` rows can share a name, and an ACL entry of `role:X` then grants
        // every member of both. That is a privilege-escalation path, not a data-hygiene one.
        if self.config.create_index_role_name {
            self.storage
                .ensure_index("_Role", &["name"], None, true, false)
                .await?;
        }
        Ok(())
    }

    /// Resolve the request context: session, roles, ACL scope and the schema snapshot.
    ///
    /// Called **once** per HTTP request, including a `/batch` whose sub-requests then share it.
    pub async fn request_context(
        &self,
        authority: &Authority,
    ) -> Result<RequestContext, ParseError> {
        crate::request::resolve(&self.storage, &self.config, authority).await
    }
}

impl axum::extract::FromRef<AppState> for Arc<ServerConfig> {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}
