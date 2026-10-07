//! The schema cache: the request snapshot, kept between requests.
//!
//! Upstream reads `_SCHEMA` once and serves every later request from `SchemaCache`
//! (`SchemaController.js:773-793`). Without a cache every request costs a `_SCHEMA` read before
//! its own query, which on a single-object request is half the database work.
//!
//! **What invalidates it, and each one is upstream's:**
//!
//! - **A schema write by this server.** Upstream calls `reloadData({ clearCache: true })` after
//!   each mutation (`SchemaController.js:858`, `:928`, `:948`, `:1323`). Here the adapter counts
//!   its own `_SCHEMA` writes and an entry is stored with the count it was loaded under, so a write
//!   on any path, including one this module never hears about, makes the entry stale.
//! - **A class the request names and the entry lacks.** `getOneSchema` reloads on a miss
//!   (`SchemaController.js:812-822`), which is how a class another node created becomes visible
//!   without a restart.
//! - **The schema routes.** They load with `clearCache: true` (`SchemasRouter.js:19-20`, `:27`,
//!   `:49`, `:62`), so `GET /schemas` is an operator's way to force a refresh.
//! - **`databaseOptions.schemaCacheTtl`.** Milliseconds, despite the option's help text saying
//!   seconds: the comparison is against `Date.now()` (`SchemaController.js:742-750`). Unset or zero
//!   never expires, which is upstream's default.
//!
//! **What does not:** a field added or a CLP changed by another process, on a class this one has
//! already loaded. That stays stale until the TTL or a restart, exactly as it does between two
//! parse-server nodes. `enableSchemaHooks`, upstream's change-stream invalidation, is not
//! implemented and the binary refuses it by name rather than accept it and stay stale.
//!
//! **An empty list is never cached**, matching `getAllClasses`, which treats an empty cache as a
//! miss (`SchemaController.js:778-781`). A fresh database therefore reads `_SCHEMA` on every
//! request until its first class exists.
//!
//! The per-request rule is unchanged: one snapshot per request, shared by every operation in it.
//! The cache decides how new the next request's snapshot is, never what a request already holds.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use parse_rust_core::ParseError;
use parse_rust_mongo::MongoAdapter;
use parse_rust_rest::SchemaSnapshot;
use parse_rust_storage::{ClassSchema, StorageAdapter};

/// How a request wants its snapshot.
#[derive(Debug, Clone, Copy)]
pub enum Freshness<'a> {
    /// Any valid entry.
    Cached,
    /// A valid entry that contains this class, else a reload.
    Containing(&'a str),
    /// Always reload, and store the result.
    Reload,
}

struct Entry {
    snapshot: Arc<SchemaSnapshot>,
    epoch: u64,
    loaded_at: Instant,
}

pub struct SchemaCache {
    ttl: Option<Duration>,
    entry: RwLock<Option<Entry>>,
    /// Single flight. A burst of requests arriving at a stale entry reloads once, not once each.
    reload: tokio::sync::Mutex<()>,
}

impl SchemaCache {
    /// `ttl: None` never expires.
    pub fn new(ttl: Option<Duration>) -> Self {
        Self {
            ttl,
            entry: RwLock::new(None),
            reload: tokio::sync::Mutex::new(()),
        }
    }

    /// The snapshot for one request.
    ///
    /// `prepare` turns the stored rows into the snapshot a request reads (the server-level
    /// `protectedFields` merge). It runs once per load, not once per request, which is the other
    /// half of what the cache saves.
    pub async fn snapshot(
        &self,
        storage: &MongoAdapter,
        freshness: Freshness<'_>,
        prepare: impl FnOnce(&mut Vec<ClassSchema>),
    ) -> Result<Arc<SchemaSnapshot>, ParseError> {
        let asked_at = Instant::now();
        if let Some(hit) = self.valid(storage, freshness, None) {
            return Ok(hit);
        }
        let _flight = self.reload.lock().await;
        // Someone else may have loaded while this request waited. Only a load that began after
        // this request arrived counts: one from before cannot have seen a write this request
        // might be relying on.
        if let Some(hit) = self.valid(storage, freshness, Some(asked_at)) {
            return Ok(hit);
        }
        let epoch = storage.schema_epoch();
        let loaded_at = Instant::now();
        let mut classes = storage.all_schemas().await?;
        let empty = classes.is_empty();
        prepare(&mut classes);
        let snapshot = Arc::new(SchemaSnapshot::from_classes(classes));
        if !empty {
            if let Ok(mut slot) = self.entry.write() {
                *slot = Some(Entry {
                    snapshot: Arc::clone(&snapshot),
                    epoch,
                    loaded_at,
                });
            }
        }
        Ok(snapshot)
    }

    /// Drop the entry. The conformance reset uses it, as upstream's `afterEach` calls
    /// `SchemaCache.clear()`.
    pub fn clear(&self) {
        if let Ok(mut slot) = self.entry.write() {
            *slot = None;
        }
    }

    fn valid(
        &self,
        storage: &MongoAdapter,
        freshness: Freshness<'_>,
        loaded_since: Option<Instant>,
    ) -> Option<Arc<SchemaSnapshot>> {
        let slot = self.entry.read().ok()?;
        let entry = slot.as_ref()?;
        if entry.epoch != storage.schema_epoch() {
            return None;
        }
        if self.ttl.is_some_and(|ttl| entry.loaded_at.elapsed() > ttl) {
            return None;
        }
        let fresh_enough = loaded_since.is_some_and(|since| entry.loaded_at >= since);
        match freshness {
            Freshness::Cached => {}
            Freshness::Containing(class) if entry.snapshot.contains(class) => {}
            Freshness::Containing(_) | Freshness::Reload if fresh_enough => {}
            Freshness::Containing(_) | Freshness::Reload => return None,
        }
        Some(Arc::clone(&entry.snapshot))
    }
}

/// `databaseOptions.schemaCacheTtl` in milliseconds, as upstream reads it.
///
/// Zero is falsy and never expires (`SchemaController.js:743-745`). A negative value is truthy and
/// every elapsed time exceeds it, so it reloads on every request.
pub fn ttl_from_millis(ms: i64) -> Option<Duration> {
    match ms {
        0 => None,
        n if n < 0 => Some(Duration::ZERO),
        n => Some(Duration::from_millis(n.unsigned_abs())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_follows_upstream_truthiness() {
        assert_eq!(ttl_from_millis(0), None);
        assert_eq!(ttl_from_millis(-5), Some(Duration::ZERO));
        assert_eq!(ttl_from_millis(1000), Some(Duration::from_secs(1)));
    }
}
