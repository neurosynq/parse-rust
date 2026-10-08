//! The `StorageAdapter` trait.
//!
//! **Shaped by two consumers, not one.** Building against Mongo alone bakes Mongo-isms into the
//! interface and the Postgres port then fights it, which is what produced the 55 catalogued
//! divergences upstream. The rule: if a method can only be implemented sensibly
//! for one backend, the trait is wrong.
//!
//! Three consequences visible in the signatures below:
//!
//! - **No `$` operators and no BSON.** Queries are an AST the adapter lowers. Postgres cannot
//!   lower a raw Mongo query document, so accepting one here would be the first Mongo-ism.
//! - **Schema is passed in, not fetched.** The adapter does not own a schema cache. A caller that
//!   already resolved the schema for a request threads it down, which is what keeps one request
//!   from evaluating half its work under two different schemas.
//! - **Updates are an op AST, not a row.** `Increment` is not a value; expressing it as one is
//!   how 0.1.0 came to store `{"__op":"Increment"}` as a literal object.

use std::future::Future;

use parse_rust_core::{ClassLevelPermissions, ParseError, ParseMap, ParseValue};

use crate::query::{Query, QueryOptions, Update};
use crate::schema::{ClassSchema, FieldType};

/// A row as stored: Parse-format values, no backend encoding.
pub type Row = ParseMap;

/// What a write returns.
///
/// Deliberately not the full row. Upstream's create response is `{objectId, createdAt}` and its
/// update response is `{updatedAt}`, and returning more here would tempt a caller into sending
/// more than parse-server does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResult {
    pub object_id: String,
}

/// What happened when a field type was reserved.
///
/// This replaces upstream's error-code sniffing. `enforceFieldExists` calls
/// `addFieldIfNotExists`, swallows every error that is not `INCORRECT_TYPE`, reloads the schema
/// and re-validates (`SchemaController.js:1184-1216`), which means "another writer won the race
/// with the same type" and "another writer won the race with a different type" are distinguished
/// only by what a *second* read finds. Making that an enum means a caller cannot conflate them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddFieldOutcome {
    /// This caller reserved the type.
    Added,
    /// Someone else got there first, with the same type. Not an error: concurrent writers
    /// inferring the same type both succeed upstream.
    AlreadyPresentSameType,
    /// Someone else got there first with an incompatible type. The caller's write must fail.
    Conflict { existing: FieldType },
}

/// Storage operations.
///
/// `async fn` in trait, so this is not object-safe. That is deliberate for now: the server holds
/// one concrete adapter chosen at construction, and boxing every call to support a `dyn` we do
/// not need would cost allocations on the hot path. If a deployment ever needs to swap adapters
/// at runtime, add a boxed wrapper rather than degrading this.
pub trait StorageAdapter: Send + Sync {
    /// Load every class schema. Upstream has no per-class fetch: a miss on any class triggers a
    /// full `getAllClasses`, and reproducing that shape keeps the caching behavior comparable.
    fn all_schemas(&self) -> impl Future<Output = Result<Vec<ClassSchema>, ParseError>> + Send;

    /// Does `_SCHEMA` hold this class? A read that reaches a class its snapshot lacks asks this to
    /// tell a class nobody has written from one another server created since.
    fn class_exists(
        &self,
        class_name: &str,
    ) -> impl Future<Output = Result<bool, ParseError>> + Send;

    /// Persist a class schema, creating the class if it does not exist.
    ///
    /// **Must not clobber metadata it was not given.** A field-adding write reaches here with
    /// `clp: None` simply because nothing loaded one, and rewriting the whole `_metadata` block
    /// from that would silently delete a class's permissions on every ordinary save. The
    /// implementation sets the field keys it knows about and leaves `_metadata` alone unless the
    /// corresponding field on [`ClassSchema`] is `Some`.
    fn upsert_schema(
        &self,
        schema: &ClassSchema,
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// Insert a class schema, failing if the class already exists.
    ///
    /// **The schema API's create path, and it is an insert rather than an upsert for the same
    /// reason `reserve_field` is a conditional update.** Upstream calls `insertSchema`, which is
    /// `insertOne`, and turns the backend's duplicate-key error into `DUPLICATE_VALUE`
    /// `Class already exists.` (`MongoSchemaCollection.js:183-195`); the caller then re-labels it
    /// as `INVALID_CLASS_NAME` (`SchemaController.js:861-864`).
    ///
    /// Reading the schema list and then upserting looks equivalent and is not. Two concurrent
    /// `POST /schemas` for one class both pass the read and both write, so both report success and
    /// the loser's field types and CLP silently replace the winner's. The class-already-exists
    /// answer has to come from the write, because only the write is atomic.
    ///
    /// Returns `DUPLICATE_VALUE` with upstream's message when the class exists.
    fn insert_schema(
        &self,
        schema: &ClassSchema,
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// Reserve a field type atomically, before any row is written, **together with its options**.
    ///
    /// This is the fix for the concurrent first-write race 0.1.0 shipped with. Upstream issues a
    /// conditional upsert, `{_id: class, field: {$exists: false}}` / `$set: {field: type}` /
    /// `upsert: true` (`MongoSchemaCollection.js:249-281`), so a losing writer fails the condition
    /// rather than overwriting the winner's type. Any backend that cannot express a conditional
    /// insert cannot implement Parse's schema semantics safely, which is why this is on the trait
    /// rather than inside the Mongo adapter.
    ///
    /// **`options` is part of the same conditional update, not a second write.** Upstream sets the
    /// type and `_metadata.fields_options.<field>` in one `$set` under the one `$exists: false`
    /// guard (`MongoSchemaCollection.js:251-269`). Splitting them lets a request reserve a type and
    /// then lose its options to a concurrent writer, which is the whole failure this method exists
    /// to prevent, one level down.
    fn reserve_field(
        &self,
        class_name: &str,
        field_name: &str,
        field_type: &FieldType,
        options: Option<&ParseMap>,
    ) -> impl Future<Output = Result<AddFieldOutcome, ParseError>> + Send;

    /// Set one field's options, for a field that already exists.
    ///
    /// `updateFieldOptions` (`MongoSchemaCollection.js:284-300`), reached when a submitted field
    /// matches the stored type and differs only in its options
    /// (`SchemaController.js:1174-1180`). Addressed **per field**, never as a block: the caller
    /// does not know what options its siblings carry and must not be able to erase them.
    fn set_field_options(
        &self,
        class_name: &str,
        field_name: &str,
        options: &ParseMap,
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// Replace `_metadata.indexes` with the block the request produced.
    ///
    /// The tail of `setIndexesWithSchemaFormat` (`MongoStorageAdapter.js:404-408`). Whole-block by
    /// design, unlike field options: the caller computed it by merging the submitted block into the
    /// stored one, which is the same read-modify-write upstream does.
    ///
    /// **Does not create the row.** Upstream uses `updateSchema`, not `upsertSchema`, so on a class
    /// that does not exist yet this is a no-op and the indexes reach `_SCHEMA` through the insert
    /// instead.
    fn set_indexes(
        &self,
        class_name: &str,
        indexes: &ParseMap,
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// Replace `_metadata.class_permissions`. `None` removes the key, which is not the same as
    /// storing an empty block: see [`ClassSchema::clp`].
    fn set_class_permissions(
        &self,
        class_name: &str,
        clp: Option<&ClassLevelPermissions>,
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// Drop a class: its rows, its schema entry and every join collection belonging to it.
    ///
    /// Upstream refuses on a non-empty class at the REST layer (code 255), not here, so this does
    /// what it is told.
    fn delete_class(
        &self,
        schema: &ClassSchema,
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// Remove fields from a class: the schema entry and the column on every row.
    ///
    /// Deliberately does **not** touch join collections, matching
    /// `MongoStorageAdapter.js:495-501`. Dropping a `Relation` field leaves its join collection
    /// in place, and a class recreated with the same field name inherits the old memberships.
    /// That is upstream behavior and a client can observe it.
    fn delete_fields(
        &self,
        schema: &ClassSchema,
        fields: &[String],
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// Insert one row. `object_id` is generated by the caller, not the adapter, because it is
    /// part of the Parse contract rather than a storage detail.
    fn create(
        &self,
        schema: &ClassSchema,
        row: &Row,
    ) -> impl Future<Output = Result<WriteResult, ParseError>> + Send;

    /// Insert a row, or do nothing if one already matches.
    ///
    /// Exists for join tables, whose membership rows carry no objectId and must be idempotent:
    /// adding a user to a role twice is one membership (`DatabaseController.js:795-807`).
    fn upsert_one(
        &self,
        schema: &ClassSchema,
        query: &Query,
        row: &Row,
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// Find rows matching the query.
    fn find(
        &self,
        schema: &ClassSchema,
        query: &Query,
        options: &QueryOptions,
    ) -> impl Future<Output = Result<Vec<Row>, ParseError>> + Send;

    /// Describe how the database would run a find, rather than running it.
    ///
    /// The result is the database's own explain document, returned to the client verbatim as
    /// `results` (`MongoStorageAdapter.js:774-776`). It is not a Parse value and nothing reads it
    /// back, so it is plain JSON rather than a [`Row`].
    fn explain(
        &self,
        schema: &ClassSchema,
        query: &Query,
        options: &QueryOptions,
        verbosity: crate::ExplainVerbosity,
    ) -> impl Future<Output = Result<serde_json::Value, ParseError>> + Send;

    /// Count rows matching the query.
    ///
    /// `options` carries the `hint` and `comment` a client sent with `count=1`. A backend that
    /// cannot honour a hint must refuse it rather than drop it, as `find` does.
    fn count(
        &self,
        schema: &ClassSchema,
        query: &Query,
        options: &crate::CountOptions,
    ) -> impl Future<Output = Result<u64, ParseError>> + Send;

    /// Update matching rows.
    ///
    /// Returns how many rows matched, so a caller can distinguish "updated nothing because the
    /// object does not exist" from "updated nothing because the ACL excluded it". Upstream
    /// conflates those into `OBJECT_NOT_FOUND`, which is the behavior to reproduce at the REST
    /// layer, but the adapter should not throw the information away before then.
    fn update(
        &self,
        schema: &ClassSchema,
        query: &Query,
        update: &Update,
    ) -> impl Future<Output = Result<u64, ParseError>> + Send;

    /// Update one row and return its post-image.
    ///
    /// Needed because an update carrying an op has to tell the client the resulting value:
    /// `_sanitizeDatabaseResult` reads it off the document the adapter returns
    /// (`DatabaseController.js:2141-2169`), and upstream gets it from `findOneAndUpdate` with
    /// `returnDocument: 'after'` (`MongoStorageAdapter.js:660-665`). `Ok(None)` means nothing
    /// matched.
    fn update_one_returning(
        &self,
        schema: &ClassSchema,
        query: &Query,
        update: &Update,
    ) -> impl Future<Output = Result<Option<Row>, ParseError>> + Send;

    /// Delete matching rows. Returns how many, for the same reason as `update`.
    fn delete(
        &self,
        schema: &ClassSchema,
        query: &Query,
    ) -> impl Future<Output = Result<u64, ParseError>> + Send;

    /// Create a unique index.
    ///
    /// **Index names are part of the contract.** Both adapters recover `duplicated_field` by regex
    /// over the index name, and the Mongo regex matches only auto-generated `<field>_1` names, so
    /// a differently-named index changes the error a client sees. `name: None` means "let the
    /// backend auto-name it", which is what produces `username_1`.
    /// `case_insensitive` builds it under upstream's collation, `{locale: "en_US", strength: 2}`
    /// (`MongoCollection.js:134-136`). Strength 2 ignores case and normalizes equivalent Unicode
    /// forms, and keeps diacritics significant, so `Café` and `Cafe` are different keys while a
    /// precomposed and a decomposed `Café` are one.
    /// `unique` is separate from `case_insensitive` and the two are not correlated. Upstream's
    /// `ensureIndex` never sets `unique` at all (`MongoStorageAdapter.js:782-812`), so its
    /// `case_insensitive_username` is a plain collated index that exists to make the collated
    /// uniqueness *query* fast. Creating it unique instead is a mixed-fleet break rather than a
    /// stricter local choice: parse-server booting against the same database asks for the
    /// non-unique form under the same name and gets `IndexKeySpecsConflict` (86), so it refuses to
    /// start. Found exactly that way, by Gate D.
    fn ensure_index(
        &self,
        class_name: &str,
        fields: &[&str],
        name: Option<&str>,
        unique: bool,
        case_insensitive: bool,
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// Create named indexes from the schema API's `indexes` block.
    ///
    /// Separate from [`StorageAdapter::ensure_index`] because these are not unique, are
    /// named by the caller rather than by the backend, and carry a caller-supplied key document
    /// including sort direction and `_p_`-prefixed pointer columns.
    ///
    /// **The write to `_metadata.indexes` is the caller's, and it must not happen before this
    /// resolves** (`MongoStorageAdapter.js:398-408`). A schema row claiming an index that was
    /// never built is worse than no index at all on a shared database: a parse-server node reading
    /// that row treats the index as present and will not create it either.
    fn create_indexes(
        &self,
        class_name: &str,
        indexes: &[SchemaIndex],
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// Drop an index by name, for the `{"__op":"Delete"}` form.
    fn drop_index(
        &self,
        class_name: &str,
        name: &str,
    ) -> impl Future<Output = Result<(), ParseError>> + Send;

    /// What each of a class's indexes reads, for authorization rather than for planning.
    ///
    /// A read can reach a field through an index without naming it, so the read path checks the
    /// fields an index covers against what the caller may see. Field names are Parse names, not
    /// storage columns. A class with no collection has no indexes.
    fn index_fields(
        &self,
        class_name: &str,
    ) -> impl Future<Output = Result<Vec<IndexFields>, ParseError>> + Send;
}

/// One index as [`StorageAdapter::index_fields`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexFields {
    pub name: String,
    /// The key names exactly as stored, in order, which is what a key-pattern `hint` names.
    pub columns: Vec<String>,
    /// The Parse fields the index reads. A wildcard index reports `$**`.
    pub fields: Vec<String>,
    /// A full-text index, which answers a text search on any field with the fields it covers.
    pub text: bool,
}

/// One entry of the schema API's `indexes` block: a name, and the key document under it.
///
/// The value of each key is passed through rather than normalized. Mongo reads `1` and `-1` as
/// ascending and descending, and `"text"`, `"2dsphere"` and `"hashed"` as index types, and which
/// of those a deployment used is recorded in `_SCHEMA` for every other node to read.
#[derive(Debug, Clone)]
pub struct SchemaIndex {
    pub name: String,
    pub keys: Vec<(String, ParseValue)>,
}
