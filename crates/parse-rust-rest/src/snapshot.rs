//! One schema snapshot per request.
//!
//! Upstream threads a `validSchemaController` down through every controller entry point
//! (`DatabaseController.js:554`, `:844`, `:907`, `:1408`) so that one request cannot evaluate half
//! its work under one schema and half under another. A batch that saw two schemas mid-flight would
//! decide what a caller may write and what a caller may see under two different rule sets, and the
//! second half would carry no error.
//!
//! It is also what makes `include` and `$relatedTo` expressible at all: both need the schema of a
//! class other than the one being queried, and a per-class fetch at the point of use would be a
//! second snapshot.
//!
//! No caching here: a snapshot is immutable once built. The server keeps one between requests in
//! its schema cache (`parse_rust_server::schema_cache`), which decides how new the next request's
//! snapshot is. A schema carries the CLP, so that cache's staleness window is the window in which a
//! revoked permission is still honored, and its invalidation rules are written down there.

use std::borrow::Cow;

use indexmap::IndexMap;
use parse_rust_core::{ClassLevelPermissions, ParseError};
use parse_rust_schema::default_schema;
use parse_rust_storage::{ClassSchema, StorageAdapter};

/// Every class schema, as of one point in time.
#[derive(Debug, Clone, Default)]
pub struct SchemaSnapshot {
    classes: IndexMap<String, ClassSchema>,
}

impl SchemaSnapshot {
    /// Load every schema from storage. Called once per request.
    pub async fn load<S: StorageAdapter>(storage: &S) -> Result<Self, ParseError> {
        Ok(Self::from_classes(storage.all_schemas().await?))
    }

    /// Build a snapshot from an already-loaded list. Cheap, and the constructor tests use.
    pub fn from_classes(classes: Vec<ClassSchema>) -> Self {
        Self {
            classes: classes
                .into_iter()
                .map(|s| (s.class_name.clone(), s))
                .collect(),
        }
    }

    pub fn get(&self, class_name: &str) -> Option<&ClassSchema> {
        self.classes.get(class_name)
    }

    /// Does this class exist? Upstream's `classExists`, which decides whether a count short
    /// circuits to zero rather than reaching the adapter (`DatabaseController.js:1525-1528`).
    pub fn contains(&self, class_name: &str) -> bool {
        self.classes.contains_key(class_name)
    }

    /// The schema to read a class under.
    ///
    /// A missing class behaves as `{fields: {}}` rather than as an error
    /// (`DatabaseController.js:1423-1433`), so a query against a class nobody has written yet
    /// returns nothing instead of failing. Note that this is **not** [`Self::resolve_for_write`]:
    /// the read fallback has no default columns at all, which is what makes every sort key on a
    /// non-existent class get dropped.
    pub fn get_or_default(&self, class_name: &str) -> Cow<'_, ClassSchema> {
        match self.classes.get(class_name) {
            Some(schema) => Cow::Borrowed(schema),
            None => Cow::Owned(ClassSchema::new(class_name)),
        }
    }

    /// The schema to write a class under.
    ///
    /// A missing class resolves to the injected default schema, matching `enforceClassExists`
    /// followed by `getOneSchema` on the create path (`DatabaseController.js:940-941`). The
    /// difference from [`Self::get_or_default`] is load bearing: without `_Role.users` typed as a
    /// Relation, the first write to a role infers it from whatever it happens to carry.
    pub fn resolve_for_write(&self, class_name: &str) -> ClassSchema {
        match self.classes.get(class_name) {
            Some(schema) => schema.clone(),
            None => default_schema(class_name),
        }
    }

    /// The class-level permissions for a class.
    ///
    /// **`None` means the class has no CLP block, which is unrestricted, not denied.** Every
    /// caller has to spell that out; see `parse_rust_core::clp`.
    pub fn clp(&self, class_name: &str) -> Option<&ClassLevelPermissions> {
        self.classes.get(class_name).and_then(|s| s.clp.as_ref())
    }

    /// Insert or replace a class. Used after a write reserves a new field, and by tests.
    pub fn insert(&mut self, schema: ClassSchema) {
        self.classes.insert(schema.class_name.clone(), schema);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse_rust_storage::FieldType;

    #[test]
    fn a_missing_class_reads_as_empty_and_writes_as_the_default_schema() {
        let snap = SchemaSnapshot::default();
        assert!(snap.get("Post").is_none());
        assert!(!snap.contains("Post"));
        assert!(
            snap.get_or_default("Post").fields.is_empty(),
            "the read fallback is {{fields: {{}}}}, with no default columns"
        );
        assert!(
            snap.resolve_for_write("Post").field("objectId").is_some(),
            "the write fallback carries the default columns"
        );
    }

    #[test]
    fn a_present_class_is_returned_borrowed() {
        let snap = SchemaSnapshot::from_classes(vec![
            ClassSchema::new("Post").with_field("title", FieldType::String)
        ]);
        assert!(matches!(snap.get_or_default("Post"), Cow::Borrowed(_)));
        assert_eq!(
            snap.get_or_default("Post").field("title"),
            Some(&FieldType::String)
        );
    }
}
