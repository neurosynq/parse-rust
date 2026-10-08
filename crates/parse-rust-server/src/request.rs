//! Everything one HTTP request resolves once and then shares.
//!
//! Three things are built here and nowhere else, and each has a rule attached.
//!
//! - **One schema snapshot per request.** Upstream threads a `validSchemaController` down through
//!   every controller entry point so one request cannot evaluate half its work under one schema
//!   and half under another (`DatabaseController.js:554`). A `/batch` of twenty writes therefore
//!   takes one snapshot, and every sub-request sees the same table. Doing it per operation is not
//!   a performance bug, it is a correctness bug. The snapshot usually comes from the schema cache
//!   rather than the database; see [`crate::schema_cache`].
//! - **One role expansion per request.** Roles are uncached in 0.2.0, so expanding them per
//!   operation would issue two queries per level of the role graph per sub-request. It is also
//!   the same correctness argument: two operations in one batch must not disagree about who the
//!   caller is.
//! - **An unknown session token is an error, not anonymity.** Downgrading silently meant a client
//!   whose session had gone kept working as a public caller, with no signal that authentication
//!   had failed.

use std::sync::Arc;

use indexmap::IndexMap;
use parse_rust_auth::{expand_roles, resolve_session, RolePrincipal};
use parse_rust_core::{ClassLevelPermissions, ParseError, ParseMap, ParseValue};
use parse_rust_mongo::MongoAdapter;
use parse_rust_rest::{AclScope, Ctx, PermissionOptions, SchemaSnapshot};
use parse_rust_storage::ClassSchema;

use crate::auth::{Authority, Credentials};
use crate::config::ServerConfig;
use crate::schema_cache::{Freshness, SchemaCache};

/// The request-scoped state every handler runs against.
///
/// Owned rather than borrowed because [`Ctx`] borrows all three and a handler needs somewhere to
/// keep them. Build it once at the top of a route, hand out [`RequestContext::ctx`] as often as
/// needed.
pub struct RequestContext {
    /// Shared with the schema cache and every other request served from the same entry. Never
    /// mutated: a request that needs a different schema gets a different snapshot.
    pub snapshot: Arc<SchemaSnapshot>,
    pub scope: AclScope,
    pub options: PermissionOptions,
    /// The token this request presented, if any. `/users/me` and `/sessions/me` echo it back and
    /// `POST /logout` revokes it.
    pub session_token: Option<String>,
    /// The caller's `_User` objectId, or `None` for master, maintenance and anonymous callers.
    pub user_id: Option<String>,
    /// `X-Parse-Installation-Id`. Read by session creation and nothing else.
    pub installation_id: Option<String>,
    /// `protectedFieldsSaveResponseExempt` (`Options/Definitions.js:513-518`).
    pub save_response_exempt: bool,
    /// Authenticated with the maintenance key rather than the master key.
    pub is_maintenance: bool,
}

impl RequestContext {
    pub fn ctx<'a>(&'a self, storage: &'a MongoAdapter) -> Ctx<'a, MongoAdapter> {
        Ctx::new(storage, &self.snapshot, &self.scope, &self.options)
            .maintenance(self.is_maintenance)
    }

    /// Is this a master or maintenance request?
    pub fn is_master(&self) -> bool {
        self.scope.is_master()
    }
}

/// Resolve a request into its context: session, roles, scope, schemas.
///
/// The order is upstream's. The session is resolved first, because its three failures are what a
/// client sees before anything else happens, and roles are expanded from the user it produces.
pub async fn resolve(
    storage: &MongoAdapter,
    schemas: &SchemaCache,
    config: &ServerConfig,
    authority: &Authority,
    freshness: Freshness<'_>,
) -> Result<RequestContext, ParseError> {
    let (scope, user_id) = match (&authority.credentials, authority.session_token.as_deref()) {
        // Master and maintenance short-circuit before session resolution, matching
        // `middlewares.js:249-251`. A request carrying both a master key and a session token is a
        // master request and the token is never looked up.
        (Credentials::Master | Credentials::Maintenance, _) => (AclScope::Unrestricted, None),
        (Credentials::Client, None) => (AclScope::Anonymous, None),
        (Credentials::Client, Some(token)) => {
            let session = resolve_session(storage, token).await?;
            // Once per request, never per operation. A `/batch` of twenty writes expands the role
            // graph once, and its twenty operations cannot disagree about who the caller is.
            let roles = expand_roles(storage, RolePrincipal::User(&session.user_object_id)).await?;
            let names = roles.iter().map(|r| r.as_str().to_string()).collect();
            // The checked constructor. A user whose objectId began with `role:` would be granted
            // that role by every ACL check, and this is the one place a scope can be built.
            let scope = AclScope::user(session.user_object_id.clone(), names)?;
            (scope, Some(session.user_object_id))
        }
    };

    // One snapshot, with the option folded in before it is built. Taking a second one would
    // reintroduce exactly the mid-request schema change the snapshot exists to prevent.
    let snapshot = snapshot(storage, schemas, config, freshness).await?;

    Ok(RequestContext {
        snapshot,
        scope,
        options: config.permission_options(),
        session_token: authority.session_token.clone(),
        user_id,
        installation_id: authority.installation_id.clone(),
        save_response_exempt: config.protected_fields_save_response_exempt,
        // The scope cannot carry this: `Unrestricted` is master and maintenance alike. One
        // decision reads them differently; see `Ctx::is_maintenance`.
        is_maintenance: matches!(authority.credentials, Credentials::Maintenance),
    })
}

/// A snapshot from the cache, with the server's `protectedFields` folded in.
pub(crate) async fn snapshot(
    storage: &MongoAdapter,
    schemas: &SchemaCache,
    config: &ServerConfig,
    freshness: Freshness<'_>,
) -> Result<Arc<SchemaSnapshot>, ParseError> {
    schemas
        .snapshot(storage, freshness, |classes| {
            merge_server_protected_fields(classes, config)
        })
        .await
}

/// Fold the server-level `protectedFields` option into the snapshot's CLP blocks.
///
/// `SchemaController.js:577-586`: for each entity key the option names, the stored list and the
/// configured list are **set-unioned**, so the option composes with a class's own block rather
/// than replacing it.
///
/// **This never reaches storage.** The snapshot is request state; the schema routes read `_SCHEMA`
/// afresh rather than rendering this, so a `PUT /schemas` round trip cannot write the server's
/// option into a class's stored block and turn a configuration value into a database value for
/// every parse-server node reading it.
///
/// A class whose CLP is absent gets a synthetic block carrying `protectedFields` and nothing else.
/// That is equivalent to upstream's merge over `defaultCLPS`, whose operation entries are all
/// `{'*': true}`: an absent operation entry and a fully public one both evaluate as unrestricted.
fn merge_server_protected_fields(classes: &mut [ClassSchema], config: &ServerConfig) {
    if config.protected_fields.is_empty() {
        return;
    }
    for schema in classes.iter_mut() {
        let Some(configured) = config.protected_fields.get(&schema.class_name) else {
            continue;
        };
        let raw = schema
            .clp
            .as_ref()
            .map(|clp| clp.raw().clone())
            .unwrap_or_default();
        schema.clp = Some(ClassLevelPermissions::from_map(union_protected_fields(
            raw, configured,
        )));
    }
}

/// One CLP block with the configured entries unioned into its `protectedFields`.
fn union_protected_fields(
    mut raw: ParseMap,
    configured: &IndexMap<String, Vec<String>>,
) -> ParseMap {
    let mut protected = match raw.shift_remove("protectedFields") {
        Some(ParseValue::Object(map)) => map,
        // Anything that is not an object is replaced rather than merged into. Upstream would
        // throw on such a block at validation time, so reaching here means the database already
        // holds one and the safe reading is that no field is protected by it.
        _ => ParseMap::new(),
    };
    for (entity, fields) in configured {
        let mut merged: Vec<String> = match protected.get(entity) {
            Some(ParseValue::Array(items)) => items
                .iter()
                .filter_map(|v| match v {
                    ParseValue::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        for field in fields {
            if !merged.contains(field) {
                merged.push(field.clone());
            }
        }
        protected.insert(
            entity.clone(),
            ParseValue::Array(merged.into_iter().map(ParseValue::String).collect()),
        );
    }
    raw.insert("protectedFields".to_string(), ParseValue::Object(protected));
    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_core::PfEntity;

    fn configured(pairs: &[(&str, &[&str])]) -> IndexMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, v)| {
                (
                    (*k).to_string(),
                    v.iter().map(|s| (*s).to_string()).collect(),
                )
            })
            .collect()
    }

    fn parse(json: &str) -> ParseMap {
        match parse_rust_core::classify(serde_json::from_str(json).expect("test literal"))
            .expect("classify")
        {
            ParseValue::Object(m) => m,
            _ => panic!("expected an object"),
        }
    }

    /// The rule that makes the option compose rather than replace. Getting this backwards is a
    /// data-exposure bug in one direction and a compatibility break in the other.
    #[test]
    fn the_server_option_is_unioned_into_the_class_block() {
        let raw = parse(r#"{"find":{"*":true},"protectedFields":{"*":["phone"]}}"#);
        let merged = ClassLevelPermissions::from_map(union_protected_fields(
            raw,
            &configured(&[("*", &["email"])]),
        ));
        assert_eq!(
            merged.protected_fields().get(&PfEntity::Public),
            Some(&vec!["phone".to_string(), "email".to_string()]),
            "the stored list keeps its order and the configured entry is appended"
        );
        // Every other key survives the round trip.
        assert!(merged.raw().contains_key("find"));
    }

    #[test]
    fn a_class_with_no_block_gets_one_carrying_only_protected_fields() {
        let merged = ClassLevelPermissions::from_map(union_protected_fields(
            ParseMap::new(),
            &configured(&[("*", &["email"])]),
        ));
        assert_eq!(merged.raw().len(), 1, "no operation entry is invented");
        assert_eq!(
            merged.protected_fields().get(&PfEntity::Public),
            Some(&vec!["email".to_string()])
        );
        for op in parse_rust_core::Operation::ALL {
            assert!(
                merged.op(op).is_none(),
                "an absent operation entry stays absent, which is unrestricted"
            );
        }
    }

    #[test]
    fn a_field_already_protected_is_not_duplicated() {
        let raw = parse(r#"{"protectedFields":{"*":["email"]}}"#);
        let merged = ClassLevelPermissions::from_map(union_protected_fields(
            raw,
            &configured(&[("*", &["email"])]),
        ));
        assert_eq!(
            merged.protected_fields().get(&PfEntity::Public),
            Some(&vec!["email".to_string()])
        );
    }
}
