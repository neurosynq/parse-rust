//! Server configuration.
//!
//! A deliberately small slice of upstream's ~292 options: what the routes that exist actually
//! need. Options are added when a route needs one, not speculatively, so that every field here
//! has a behavior behind it. Each carries upstream's env var name and upstream's default; a
//! wrong default in this file is a security default.

use indexmap::IndexMap;
use parse_rust_auth::SessionConfig;
use parse_rust_core::ErrorDetail;
use parse_rust_rest::PermissionOptions;
use parse_rust_schema::{ClpValidation, ObjectIdForm, Unenforceable};

/// The parse-server version parse-rust reports as its own.
///
/// **This is a decision, not an oversight.** `/serverInfo` returns `parseServerVersion`, and
/// SDKs branch on it: the Ruby SDK warns below 7.0.0, and features gate on version comparisons.
/// Reporting `parse-rust 0.0.0` would fail every one of those checks, so the wire-compatible
/// answer is the parse-server version whose behavior this server implements. It is the same
/// number recorded in `PIN`.
///
/// If parse-rust ever needs to advertise itself distinctly, that belongs in a separate field
/// that upstream does not define, not in this one.
pub const REPORTED_PARSE_SERVER_VERSION: &str = "9.10.1-alpha.6";

/// What this server can actually do, as reported by `GET /serverInfo`.
///
/// **The key set and the nesting of the `features` object are wire contract. The booleans are
/// not.** Upstream hardcodes nearly all of them to `true` (`FeaturesRouter.js`) because upstream
/// implements the subsystems behind them. Transcribing those literals would advertise a schema
/// API, cloud jobs, hooks, a global config and a log API that all answer 404 here.
///
/// That matters because the object is not documentation: Parse Dashboard builds its UI from it,
/// so an advertised capability becomes a button that fails when a user presses it. This is a
/// deliberate difference from upstream, in the direction of telling the truth. Every field is
/// `false` until the subsystem behind it exists, and flipping one is part of landing that
/// subsystem rather than a follow-up.
#[derive(Debug, Clone)]
pub struct FeatureSupport {
    /// `/config`. Not implemented.
    pub global_config: bool,
    /// `/hooks`. Not implemented.
    pub hooks: bool,
    /// Cloud Code jobs. Not implemented; `TriggerHost` is the milestone that lands them.
    pub cloud_code_jobs: bool,
    /// The log API. Not implemented.
    pub logs: bool,
    /// The schema API, `/schemas` and `DELETE /purge/:className`.
    ///
    /// True as of 0.2.0, and every capability it drives has a route that does the thing:
    /// `addField` and `removeField` through `PUT`, `addClass` through `POST`, `removeClass`
    /// through `DELETE`, `clearAllDataFromClass` through `DELETE /purge/:className`,
    /// `editClassLevelPermissions` through the `classLevelPermissions` key on `POST` and `PUT`,
    /// and `editPointerPermissions` through per-operation `pointerFields` plus the class-wide
    /// `readUserFields` and `writeUserFields` arrays, all three of which the read and write
    /// pipelines enforce.
    pub schemas: bool,
    /// Push, including audiences and localization. Not implemented.
    pub push_audiences: bool,
}

impl Default for FeatureSupport {
    fn default() -> Self {
        Self {
            global_config: false,
            hooks: false,
            cloud_code_jobs: false,
            logs: false,
            schemas: true,
            push_audiences: false,
        }
    }
}

/// Server-level `protectedFields`: class name, then entity, then the fields that entity may not
/// see (`Options/Definitions.js:491-500`).
///
/// Order-preserving because the intersection that consumes it is order-sensitive on the wire.
pub type ProtectedFieldsConfig = IndexMap<String, IndexMap<String, Vec<String>>>;

/// The upstream default, `{_User: {'*': ['email']}}` (`Options/Definitions.js:495-499`).
///
/// **Merged as a set union per entity key over the class's own block**
/// (`SchemaController.js:577-586`), so it composes with a configured `protectedFields` rather
/// than replacing it. A class that protects `phone` from `*` ends up protecting `phone` and
/// `email`, which is what a parse-server node reading the same database would do.
pub fn default_protected_fields() -> ProtectedFieldsConfig {
    let mut entities = IndexMap::new();
    entities.insert("*".to_string(), vec!["email".to_string()]);
    let mut classes = ProtectedFieldsConfig::new();
    classes.insert("_User".to_string(), entities);
    classes
}

/// Fold the defaults into a configured `protectedFields`, as upstream does at option-resolution
/// time (`ParseServer.ts:657-673`).
///
/// **A configured block adds to the defaults, it does not replace them.** Assigning the parsed
/// configuration straight onto the config is the obvious translation and it is a data exposure: a
/// deployment that configures protection for one of its own classes and never mentions `_User`
/// thereby unprotects `email` on every user, which the operator did not ask for and cannot see in
/// their own configuration file.
///
/// Upstream's rule, per class present in the defaults:
///
/// - the configuration does not name the class at all, so the default block is used whole;
/// - the configuration names it, so each default entity key is unioned into the configured one.
///
/// The single exception is `protectedFieldsOwnerExempt == false`, where a configured entity key is
/// left exactly as written. That option means "apply `protectedFields` to the owner the same as to
/// anyone else", and merging a default the operator did not write would undo the point of setting
/// it.
pub fn merge_protected_fields_defaults(configured: &mut ProtectedFieldsConfig, owner_exempt: bool) {
    for (class_name, default_entities) in default_protected_fields() {
        let Some(entities) = configured.get_mut(&class_name) else {
            configured.insert(class_name, default_entities);
            continue;
        };
        for (entity, default_fields) in default_entities {
            match entities.get_mut(&entity) {
                // Configured and the owner is not exempt: upstream returns early and the
                // configured list stands alone.
                Some(_) if !owner_exempt => {}
                Some(fields) => {
                    for field in default_fields {
                        if !fields.contains(&field) {
                            fields.push(field);
                        }
                    }
                }
                None => {
                    entities.insert(entity, default_fields);
                }
            }
        }
    }
}

/// The keys and identity a request is checked against.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub app_id: String,
    pub master_key: String,
    /// The read-only master key sets `isMaster` upstream (`Auth.js:63`), with the restriction
    /// enforced by scattered checks. Not implemented yet; recorded so the gap is visible.
    pub maintenance_key: Option<String>,
    pub javascript_key: Option<String>,
    pub rest_api_key: Option<String>,
    pub client_key: Option<String>,
    pub dot_net_key: Option<String>,
    /// Where the API is mounted, e.g. `/parse`. A **builder input, never inferred from the
    /// request path**: axum's `nest` and Express's `app.use` differ here, and every generated
    /// file URL is built from this value.
    pub mount_path: String,
    /// `enableSanitizedErrorResponse`, default true (`Options/Definitions.js:253-258`).
    ///
    /// When true, every denial upstream routes through `createSanitizedError` or
    /// `createSanitizedHttpError` (`Error.js:13-43`) says `Permission denied` instead of naming
    /// the rule that refused. That is the configuration an unmodified deployment runs, so it is
    /// what every SDK sees by default. Read it as [`ServerConfig::error_detail`] rather than as a
    /// bare bool at a call site.
    pub enable_sanitized_error_response: bool,
    pub has_push_support: bool,
    pub has_push_scheduled_support: bool,
    pub security_check_enabled: bool,
    /// What `/serverInfo` advertises. Defaults to the truth: nothing unimplemented.
    pub features: FeatureSupport,

    /// `sessionLength` and `expireInactiveSessions`, which together decide `_Session.expiresAt`.
    /// Defaults are upstream's (`Options/Definitions.js:629-634`, `:269-274`).
    pub session: SessionConfig,

    /// `protectedFields`. See [`default_protected_fields`] for the merge rule.
    pub protected_fields: ProtectedFieldsConfig,

    /// `protectedFieldsOwnerExempt`, default true (`Options/Definitions.js:501-506`). When true a
    /// user reading their own `_User` row sees every field regardless of `protectedFields`.
    pub protected_fields_owner_exempt: bool,

    /// `protectedFieldsSaveResponseExempt`, default true (`Options/Definitions.js:507-512`).
    ///
    /// When true, a create or update response carries protected fields the write touched. When
    /// false they are stripped from the response as they are from a query result. parse-rust only
    /// ever echoes back the keys whose request value was an operation, so this narrows that echo
    /// rather than a whole object.
    pub protected_fields_save_response_exempt: bool,

    /// `allowCustomObjectId`, default false (`Options/Definitions.js:73-78`).
    ///
    /// Two effects, and the second is easy to forget because it is in a different file. It gates
    /// whether a create may carry its own `objectId` (`RestWrite.js:50-65`, enforced by
    /// `enforce_object_id_policy`), **and** it widens the objectId grammar a CLP entity key is
    /// matched against, from `^[a-zA-Z0-9]{1,}$` to `^.{1,}$` (`SchemaController.js:726-731`).
    ///
    /// The two are one option because a CLP naming a user by id has to be able to name a user
    /// whose id the client chose.
    pub allow_custom_object_id: bool,

    /// `allowClientClassCreation`, default **false** (`Options/Definitions.js:67-72`).
    ///
    /// Gates whether a write may bring a class into existence. Enforced by
    /// `validateClientClassCreation` in the write pipeline, which exempts master, maintenance and
    /// the classes Parse defines itself.
    ///
    /// The default matters more than the option. Left unimplemented, a server behaves as though
    /// this were `true`, which lets a caller holding only the app id and client key create classes
    /// without limit on a database parse-server nodes also read, each with a default-open CLP.
    pub allow_client_class_creation: bool,

    /// `allowOrigin`, default `["*"]` (`middlewares.js:407-408`).
    ///
    /// A list rather than one value, because upstream accepts either and echoes back whichever
    /// entry matches the request's `Origin`. An unmatched origin gets the first entry, so a
    /// single-element list is an allowlist of one rather than a wildcard.
    pub allow_origin: Vec<String>,

    /// `allowHeaders`. Appended to `DEFAULT_ALLOWED_HEADERS` rather than replacing it
    /// (`middlewares.js:402-405`), so a deployment adding one custom header does not have to
    /// restate the twelve a Parse SDK needs.
    pub allow_headers: Vec<String>,

    /// `requestComplexity.batchRequestLimit`, default `-1`, which disables it
    /// (`Options/Definitions.js:733-738`). Master and maintenance bypass it (`batch.js:73`).
    pub batch_request_limit: i64,

    /// `databaseOptions.createIndexRoleName`, default true (`Options/Definitions.js:1318-1323`),
    /// created at `DatabaseController.js:2033-2038`.
    ///
    /// **Not cosmetic.** Without the index two `_Role` rows can carry the same `name`, and an ACL
    /// entry of `role:X` then grants every member of both, which is a privilege-escalation path
    /// rather than a duplicate-data annoyance. Upstream tests `!== false`, so anything other than
    /// an explicit `false` creates it.
    pub create_index_role_name: bool,
}

impl ServerConfig {
    pub fn new(app_id: impl Into<String>, master_key: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            master_key: master_key.into(),
            maintenance_key: None,
            javascript_key: None,
            rest_api_key: None,
            client_key: None,
            dot_net_key: None,
            mount_path: "/parse".to_string(),
            enable_sanitized_error_response: true,
            has_push_support: false,
            has_push_scheduled_support: false,
            security_check_enabled: false,
            features: FeatureSupport::default(),
            session: SessionConfig::default(),
            protected_fields: default_protected_fields(),
            protected_fields_owner_exempt: true,
            protected_fields_save_response_exempt: true,
            allow_custom_object_id: false,
            allow_client_class_creation: false,
            allow_origin: vec!["*".to_string()],
            allow_headers: Vec::new(),
            batch_request_limit: -1,
            create_index_role_name: true,
        }
    }

    /// Whether a denial tells the client why.
    ///
    /// The one place `enable_sanitized_error_response` becomes an [`ErrorDetail`], so no call site
    /// has to remember which way round the bool runs.
    pub fn error_detail(&self) -> ErrorDetail {
        ErrorDetail::from_sanitized(self.enable_sanitized_error_response)
    }

    /// How a CLP entity key that looks like an objectId is matched.
    pub fn object_id_form(&self) -> ObjectIdForm {
        if self.allow_custom_object_id {
            ObjectIdForm::Custom
        } else {
            ObjectIdForm::Generated
        }
    }

    /// What CLP validation accepts.
    ///
    /// `Unenforceable::Accept`, because the read and write pipelines enforce all three of the
    /// features the toggle guards: per-operation `pointerFields`, the class-wide `readUserFields`
    /// and `writeUserFields` arrays (`ClassLevelPermissions::applicable_pointer_fields`), and
    /// `userField:` protected-field entries (`ProtectedFieldPlan::user_field_rules`). Refusing
    /// them would reject a CLP this server honors.
    pub fn clp_validation(&self) -> ClpValidation {
        ClpValidation {
            object_id: self.object_id_form(),
            unenforceable: Unenforceable::Accept,
        }
    }

    /// The permission options the read and write pipelines take.
    pub fn permission_options(&self) -> PermissionOptions {
        PermissionOptions {
            protected_fields_owner_exempt: self.protected_fields_owner_exempt,
            error_detail: self.error_detail(),
            allow_client_class_creation: self.allow_client_class_creation,
        }
    }

    pub fn javascript_key(mut self, k: impl Into<String>) -> Self {
        self.javascript_key = Some(k.into());
        self
    }

    pub fn rest_api_key(mut self, k: impl Into<String>) -> Self {
        self.rest_api_key = Some(k.into());
        self
    }

    pub fn mount_path(mut self, p: impl Into<String>) -> Self {
        self.mount_path = p.into();
        self
    }

    /// True when any client key is configured. Upstream's rule is all-or-nothing: if *any* of
    /// these is set, a non-master request must present one that matches
    /// (`middlewares.js:255-265`). If none is configured, none is required.
    pub fn requires_client_key(&self) -> bool {
        self.javascript_key.is_some()
            || self.rest_api_key.is_some()
            || self.client_key.is_some()
            || self.dot_net_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(config: &ProtectedFieldsConfig, class: &str, entity: &str) -> Vec<String> {
        config
            .get(class)
            .and_then(|e| e.get(entity))
            .cloned()
            .unwrap_or_default()
    }

    /// The exposure this merge exists to prevent. A deployment protecting one of its own classes
    /// and never mentioning `_User` must still protect `email`, or every user's address becomes
    /// readable by every other user without that appearing anywhere in the configuration.
    #[test]
    fn configuring_an_unrelated_class_still_protects_user_email() {
        let mut configured = ProtectedFieldsConfig::new();
        let mut post = IndexMap::new();
        post.insert("*".to_string(), vec!["secret".to_string()]);
        configured.insert("Post".to_string(), post);

        merge_protected_fields_defaults(&mut configured, true);

        assert_eq!(fields(&configured, "_User", "*"), vec!["email".to_string()]);
        assert_eq!(fields(&configured, "Post", "*"), vec!["secret".to_string()]);
    }

    /// Present but for a different entity key: the default `*` is added alongside rather than
    /// displacing what was configured.
    #[test]
    fn a_user_block_for_another_entity_gains_the_default_star() {
        let mut configured = ProtectedFieldsConfig::new();
        let mut user = IndexMap::new();
        user.insert("authenticated".to_string(), vec!["phone".to_string()]);
        configured.insert("_User".to_string(), user);

        merge_protected_fields_defaults(&mut configured, true);

        assert_eq!(fields(&configured, "_User", "*"), vec!["email".to_string()]);
        assert_eq!(
            fields(&configured, "_User", "authenticated"),
            vec!["phone".to_string()]
        );
    }

    /// Same entity key: a set union, and `email` is not duplicated if it was already named.
    #[test]
    fn the_same_entity_key_is_unioned_without_duplicating() {
        let mut configured = ProtectedFieldsConfig::new();
        let mut user = IndexMap::new();
        user.insert(
            "*".to_string(),
            vec!["phone".to_string(), "email".to_string()],
        );
        configured.insert("_User".to_string(), user);

        merge_protected_fields_defaults(&mut configured, true);

        assert_eq!(
            fields(&configured, "_User", "*"),
            vec!["phone".to_string(), "email".to_string()]
        );
    }

    /// `protectedFieldsOwnerExempt == false` is the one case where a configured entity key stands
    /// alone (`ParseServer.ts:664-666`). The operator asked for their list to apply to everyone
    /// including the owner, so a default they did not write is not folded in.
    #[test]
    fn owner_exempt_false_leaves_a_configured_entity_key_alone() {
        let mut configured = ProtectedFieldsConfig::new();
        let mut user = IndexMap::new();
        user.insert("*".to_string(), vec!["phone".to_string()]);
        configured.insert("_User".to_string(), user);

        merge_protected_fields_defaults(&mut configured, false);

        assert_eq!(fields(&configured, "_User", "*"), vec!["phone".to_string()]);
    }

    /// But an absent class is still filled in wholesale even then: upstream's early return is
    /// reached only when the entity key is already present.
    #[test]
    fn owner_exempt_false_still_fills_in_an_absent_class() {
        let mut configured = ProtectedFieldsConfig::new();
        let mut post = IndexMap::new();
        post.insert("*".to_string(), vec!["secret".to_string()]);
        configured.insert("Post".to_string(), post);

        merge_protected_fields_defaults(&mut configured, false);

        assert_eq!(fields(&configured, "_User", "*"), vec!["email".to_string()]);
    }
}
