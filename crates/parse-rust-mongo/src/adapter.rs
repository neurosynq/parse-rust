//! The MongoDB `StorageAdapter`.

use bson::{doc, Bson, Document};
use futures::TryStreamExt;
use mongodb::options::{IndexOptions, ReturnDocument};
use mongodb::{Client, Database, IndexModel};
use parse_rust_core::{
    ClassLevelPermissions, ErrorCode, ParseError, ParseMap, ParseValue, DUPLICATE_VALUE_MESSAGE,
};
use parse_rust_schema::storage_format::{
    field_type_to_storage, storage_to_field_type, NON_FIELD_KEYS,
};
use parse_rust_storage::{
    join_table_name, AddFieldOutcome, ClassSchema, FieldType, Query, QueryOptions, Row,
    SchemaIndex, SortDirection, StorageAdapter, Update, WriteResult,
};

use crate::transform::{
    bson_document_to_parse_map, index_key_to_bson, mongo_object_to_parse,
    parse_map_to_bson_document, parse_object_to_mongo_create, storage_key, transform_update,
    transform_where,
};

/// Where class schemas live. Not configurable: parse-server hardcodes it, and a mixed fleet has
/// to agree.
const SCHEMA_COLLECTION: &str = "_SCHEMA";

/// The three `_metadata` sub-keys parse-server writes.
///
/// **This list is closed.** A fourth key invented by parse-rust would travel into a database
/// parse-server also reads, and `_metadata` is the one place a stray key is read back rather than
/// rejected.
const METADATA_CLASS_PERMISSIONS: &str = "_metadata.class_permissions";
const METADATA_INDEXES: &str = "_metadata.indexes";
const METADATA_FIELDS_OPTIONS: &str = "_metadata.fields_options";

/// `emptyCLPS`, the merge base used when `class_permissions` **is** present
/// (`MongoSchemaCollection.js:67-76`).
///
/// Note that this is not `defaultCLPS`. The two differ in more than their values: `defaultCLPS`
/// carries an `ACL` key that this one does not, so a class whose CLP block is absent and a class
/// whose CLP block sets only `find` do not read back as the same document.
const EMPTY_CLPS_KEYS: [&str; 8] = [
    "find",
    "count",
    "get",
    "create",
    "update",
    "delete",
    "addField",
    "protectedFields",
];

pub struct MongoAdapter {
    db: Database,
}

impl MongoAdapter {
    pub async fn connect(uri: &str, database: &str) -> Result<Self, ParseError> {
        let client = Client::with_uri_str(uri).await.map_err(mongo_err)?;
        Ok(Self {
            db: client.database(database),
        })
    }

    /// Read the `_SCHEMA` document for one class.
    async fn schema_document(&self, class_name: &str) -> Result<Option<Document>, ParseError> {
        self.db
            .collection::<Document>(SCHEMA_COLLECTION)
            .find_one(doc! { "_id": class_name })
            .await
            .map_err(mongo_err)
    }

    /// Why a reservation matched nothing.
    ///
    /// Two conditions in the filter can refuse it and they need different answers, so the write
    /// stays one operation and only the *explanation* costs a read. The read cannot change the
    /// decision: it already happened.
    ///
    /// One place, deliberately: the driver reports "the upsert matched nothing" and "the upsert
    /// collided on `_id`" differently, and both mean the same thing here, that somebody else
    /// reserved the field first. Classifying in two places is how the two stop agreeing.
    async fn reservation_refused(
        &self,
        class_name: &str,
        field_name: &str,
        requested: &FieldType,
    ) -> Result<AddFieldOutcome, ParseError> {
        if matches!(requested, FieldType::GeoPoint) {
            let already = self
                .schema_document(class_name)
                .await?
                .map(|d| {
                    d.iter()
                        .any(|(key, value)| key != field_name && value.as_str() == Some("geopoint"))
                })
                .unwrap_or(false);
            if already {
                // The adapter's own message, not `SchemaController`'s. Upstream raises this one
                // from the Mongo schema collection (`MongoSchemaCollection.js:234`), and a client
                // adding a second GeoPoint by an ordinary write sees it rather than the
                // `validateObject` string. Measured against parse-server 9.10.1-alpha.6.
                return Err(ParseError::incorrect_type(
                    "MongoDB only supports one GeoPoint field in a class.".to_string(),
                ));
            }
        }
        self.classify_existing_field(class_name, field_name, requested)
            .await
    }

    /// Decide the outcome of a field reservation by reading back what is actually stored.
    async fn classify_existing_field(
        &self,
        class_name: &str,
        field_name: &str,
        requested: &FieldType,
    ) -> Result<AddFieldOutcome, ParseError> {
        let stored = self
            .schema_document(class_name)
            .await?
            .and_then(|d| d.get_str(field_name).ok().map(str::to_string));

        match stored.as_deref().and_then(storage_to_field_type) {
            Some(existing) if &existing == requested => Ok(AddFieldOutcome::AlreadyPresentSameType),
            Some(existing) => Ok(AddFieldOutcome::Conflict { existing }),
            // Two cases fall here and neither can produce a `FieldType` to report:
            //
            // - the stored type string is one parse-server itself cannot read, because
            //   `mongoFieldToParseSchemaField` is a `switch` with no default case
            //   (`MongoSchemaCollection.js:4-39`) and the field's parsed entry becomes
            //   `undefined`;
            // - the field is absent on re-read, meaning it was deleted between the failed upsert
            //   and this read.
            //
            // Upstream reaches the same place by a different route: `enforceFieldExists` swallows
            // the failure, reloads, and `ensureFields` then finds no usable expected type and
            // throws `INVALID_JSON` `Could not add field <name>` (`SchemaController.js:1205-1217`).
            // Reporting that error is closer to upstream than inventing a `FieldType` to put in a
            // `Conflict`, and it is loud rather than silent, which is what a caller needs when the
            // reservation did not stick.
            None => Err(ParseError::invalid_json(format!(
                "Could not add field {field_name}"
            ))),
        }
    }
}

/// Is this the duplicate-key error, whatever shape the driver wrapped it in?
fn is_duplicate_key(e: &mongodb::error::Error) -> bool {
    match e.kind.as_ref() {
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(we)) => {
            we.code == 11000
        }
        mongodb::error::ErrorKind::Command(ce) => ce.code == 11000,
        _ => false,
    }
}

/// Dropping a collection that is not there is not a failure.
///
/// The modern driver returns success, but upstream still guards for the old `ns not found`
/// (`MongoStorageAdapter.js:473-479`) and a class with no rows yet has no collection at all.
fn is_namespace_not_found(e: &mongodb::error::Error) -> bool {
    if let mongodb::error::ErrorKind::Command(ce) = e.kind.as_ref() {
        return ce.code == 26;
    }
    false
}

/// Is this an infrastructure failure rather than a query-level one?
///
/// `isTransientError` (`MongoStorageAdapter.js:35-57`) names four driver error classes plus the
/// `TransientTransactionError` label, and `handleError` turns them into a `Parse.Error` whose
/// message is the fixed `Database error` (`MongoStorageAdapter.js:291-293`). The Rust driver
/// splits the same territory differently, so this matches on the closest kinds rather than on
/// upstream's error-name strings, which do not exist here.
fn is_transient(e: &mongodb::error::Error) -> bool {
    if e.contains_label(mongodb::error::TRANSIENT_TRANSACTION_ERROR) {
        return true;
    }
    matches!(
        e.kind.as_ref(),
        mongodb::error::ErrorKind::ServerSelection { .. }
            | mongodb::error::ErrorKind::ConnectionPoolCleared { .. }
            | mongodb::error::ErrorKind::Io(_)
    )
}

/// The server's own `errmsg`, which is where the index name lives.
///
/// Never put this on the wire. It reads
/// `E11000 duplicate key error collection: <db>.<collection> index: <index> dup key: { <field>: <value> }`,
/// so it names the database and the value that collided.
fn driver_message(e: &mongodb::error::Error) -> Option<&str> {
    match e.kind.as_ref() {
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(we)) => {
            Some(we.message.as_str())
        }
        mongodb::error::ErrorKind::Command(ce) => Some(ce.message.as_str()),
        _ => None,
    }
}

/// The `_metadata.fields_options.<field>` path one field's options are addressed by.
///
/// A field name cannot contain a dot (`fieldNameIsValid`), so this cannot accidentally address
/// something nested.
fn field_options_path(field_name: &str) -> String {
    format!("{METADATA_FIELDS_OPTIONS}.{field_name}")
}

/// The field columns a class schema writes: field name to `_SCHEMA` type string.
fn schema_fields_document(schema: &ClassSchema) -> Document {
    let mut out = Document::new();
    for (name, ty) in &schema.fields {
        let s = field_type_to_storage(ty);
        // ACL renders empty and is never stored; writing it would be a phantom column.
        if s.is_empty() {
            continue;
        }
        out.insert(name.clone(), s);
    }
    out
}

/// The `_metadata` sub-document, **unprefixed**, and empty when the schema carries no metadata.
///
/// Kept separate from the field columns because the two writes need it in two different shapes and
/// the shapes are not interchangeable. `upsert_schema` needs dotted paths, so that `$set`ting one
/// metadata key leaves the others alone; `insert_schema` needs a real nested document, because a
/// key containing a dot inside an inserted document is stored **literally**, as a top-level column
/// named `_metadata.class_permissions`, which no reader on either server will ever look at.
///
/// Assembling one document for both is what this did for an hour, and the class it created had a
/// CLP no reader could see, which reads exactly like a class with no CLP: default-open.
fn schema_metadata_document(schema: &ClassSchema) -> Result<Document, ParseError> {
    let mut out = Document::new();
    if let Some(clp) = &schema.clp {
        out.insert("class_permissions", parse_map_to_bson_document(clp.raw())?);
    }
    if let Some(indexes) = &schema.indexes {
        out.insert("indexes", parse_map_to_bson_document(indexes)?);
    }
    if let Some(field_options) = &schema.field_options {
        out.insert("fields_options", parse_map_to_bson_document(field_options)?);
    }
    Ok(out)
}

/// The index name out of a duplicate-key `errmsg`: the token after `index:`.
fn index_name(message: &str) -> Option<&str> {
    let (_, rest) = message.split_once(" index: ")?;
    rest.split_whitespace().next()
}

/// Which field collided, or `None` when the index name does not say.
///
/// **Deliberately narrow.** Upstream reads only two index-name shapes: the auto-generated
/// `<field>_1` (`MongoStorageAdapter.js:582`, which also accepts the legacy `<db>.$<field>_1`
/// spelling) and the authData form `_auth_data_<provider>_id`
/// (`MongoStorageAdapter.js:588`), tried only when the first found nothing. A custom index name
/// yields no `duplicated_field` at all, which is why index names are contract: a differently
/// named unique index on `username` changes the error a client sees. Parsing any index name here
/// would hand `RestWrite`'s consumers a field upstream never gives them, and the two servers would
/// then disagree about which error a client sees.
///
/// One difference from upstream's regex, and it is upstream's bug rather than a choice here.
/// `/index:[\sa-zA-Z0-9_\-\.]+\$?([a-zA-Z_-]+)_1/` backtracks: against a modern MongoDB message
/// (`index: username_1`) the greedy leading class eats all but the last letter, so the capture is
/// `e`, not `username`. It captures correctly only against the legacy `index: <db>.$username_1`
/// spelling, where `$` is outside the class and stops the greed. Upstream therefore reaches 202
/// and 203 through the fallback queries at `RestWrite.js:1718-1755` rather than through
/// `duplicated_field`, and the wire result is the same either way. This returns the whole field
/// name, which is what the fast path was written to produce.
fn duplicated_field(message: &str) -> Option<String> {
    let name = index_name(message)?;
    if let Some(prefix) = name.strip_suffix("_1") {
        // The legacy spelling qualifies the index with the namespace: `<db>.$<field>_1`.
        let field = prefix.rsplit(['$', '.']).next().unwrap_or(prefix);
        // Upstream's capture class is `[a-zA-Z_-]`, so a field name containing a digit is not
        // recoverable there and is not recoverable here either.
        let recoverable = !field.is_empty()
            && field
                .chars()
                .all(|c| c.is_ascii_alphabetic() || c == '_' || c == '-');
        if recoverable {
            return Some(field.to_string());
        }
    }
    if name.starts_with("_auth_data_") && name.ends_with("_id") {
        return Some(name.to_string());
    }
    None
}

fn mongo_err(e: mongodb::error::Error) -> ParseError {
    // Duplicate key is the one storage error with a specific Parse code, because signup depends
    // on it: `username_1` colliding must become 202, not a generic failure. The message is fixed
    // and which field collided travels out of band, because the driver's text names the database
    // and the colliding value (`MongoStorageAdapter.js:574-597`).
    if is_duplicate_key(&e) {
        let err = ParseError::new(ErrorCode::DuplicateValue, DUPLICATE_VALUE_MESSAGE);
        return match driver_message(&e).and_then(duplicated_field) {
            Some(field) => err.with_duplicated_field(field),
            None => err,
        };
    }
    if is_transient(&e) {
        return ParseError::new(ErrorCode::InternalServerError, "Database error");
    }
    // Everything else is upstream's bare rethrow: a driver error that is not a `Parse.Error`, so
    // the client gets the generic 500 body and this text reaches the log only.
    ParseError::internal(format!("storage error: {e}"))
}

/// `{ ...emptyCLPS, ...stored }` (`MongoSchemaCollection.js:100`).
///
/// The merge is what makes an unspecified operation read back as `{}`, deny-all, rather than as
/// absent, which is unrestricted. Handing the merged block to `ClassLevelPermissions::from_map`
/// means `raw()` is the document that would be written back, so a round trip through parse-rust
/// produces the block parse-server produces rather than the narrower one that was stored.
fn merge_over_empty_clps(stored: &Document) -> Result<ParseMap, ParseError> {
    let mut out = ParseMap::new();
    for key in EMPTY_CLPS_KEYS {
        out.insert(key.to_string(), ParseValue::Object(ParseMap::new()));
    }
    // `IndexMap::insert` keeps an existing key's position, which is what the JavaScript spread
    // does, so the merged block has `emptyCLPS` order followed by any keys only the stored block
    // carries.
    for (key, value) in stored {
        out.insert(key.clone(), crate::transform::bson_to_parse_value(value)?);
    }
    Ok(out)
}

impl StorageAdapter for MongoAdapter {
    async fn all_schemas(&self) -> Result<Vec<ClassSchema>, ParseError> {
        let mut cursor = self
            .db
            .collection::<Document>(SCHEMA_COLLECTION)
            .find(doc! {})
            .await
            .map_err(mongo_err)?;

        let mut out = Vec::new();
        while let Some(doc) = cursor.try_next().await.map_err(mongo_err)? {
            let Some(class_name) = doc.get_str("_id").ok() else {
                continue;
            };
            let mut schema = parse_rust_schema::default_schema(class_name);
            for (key, value) in &doc {
                if NON_FIELD_KEYS.contains(&key.as_str()) {
                    continue;
                }
                let Bson::String(type_str) = value else {
                    continue;
                };
                // An unrecognised type string is skipped rather than erroring, which is what
                // upstream's missing default case amounts to. A mixed fleet can contain one.
                if let Some(ty) = storage_to_field_type(type_str) {
                    schema.fields.insert(key.clone(), ty);
                }
            }

            if let Ok(metadata) = doc.get_document("_metadata") {
                // **Only when the key is present.** Absent stays `None`, and `None` is not
                // "public": upstream reads an absent block back as `defaultCLPS`, a fully open
                // document including an `ACL` key that the present-but-partial case never carries
                // (`MongoSchemaCollection.js:95-101`). Materializing that default into the struct
                // would make an absent block indistinguishable from an explicitly-public one, and
                // the next write-back would then store a block parse-server never had, turning an
                // unset CLP into a set one for every node reading the same database.
                if let Ok(class_permissions) = metadata.get_document("class_permissions") {
                    schema.clp = Some(ClassLevelPermissions::from_map(merge_over_empty_clps(
                        class_permissions,
                    )?));
                }
                // Round-tripped verbatim and never interpreted.
                if let Ok(indexes) = metadata.get_document("indexes") {
                    schema.indexes = Some(bson_document_to_parse_map(indexes)?);
                }
                if let Ok(fields_options) = metadata.get_document("fields_options") {
                    schema.field_options = Some(bson_document_to_parse_map(fields_options)?);
                }
            }

            out.push(schema);
        }
        Ok(out)
    }

    async fn insert_schema(&self, schema: &ClassSchema) -> Result<(), ParseError> {
        let mut document = schema_fields_document(schema);
        document.insert("_id", &schema.class_name);
        // Nested, and omitted entirely when there is nothing in it, matching
        // `mongoSchemaFromFieldsAndClassNameAndCLP`'s `delete mongoObject._metadata`
        // (`MongoStorageAdapter.js:135-138`). An empty `_metadata` is a document parse-server
        // never writes.
        let metadata = schema_metadata_document(schema)?;
        if !metadata.is_empty() {
            document.insert("_metadata", metadata);
        }
        match self
            .db
            .collection::<Document>(SCHEMA_COLLECTION)
            .insert_one(document)
            .await
        {
            Ok(_) => Ok(()),
            // `insertSchema`'s own catch, message included (`MongoSchemaCollection.js:188-190`).
            // The caller re-labels it; this layer reports what the database said.
            Err(e) if is_duplicate_key(&e) => Err(ParseError::new(
                ErrorCode::DuplicateValue,
                "Class already exists.",
            )),
            Err(e) => Err(mongo_err(e)),
        }
    }

    async fn upsert_schema(&self, schema: &ClassSchema) -> Result<(), ParseError> {
        let mut set = schema_fields_document(schema);
        // Dotted paths, so that writing one metadata key leaves the other two alone. An ordinary
        // field-adding save arrives with `clp: None` simply because nothing loaded one, and
        // replacing `_metadata` wholesale from that would delete the class's permissions.
        for (key, value) in schema_metadata_document(schema)? {
            let path = match key.as_str() {
                "class_permissions" => METADATA_CLASS_PERMISSIONS,
                "indexes" => METADATA_INDEXES,
                _ => METADATA_FIELDS_OPTIONS,
            };
            set.insert(path, value);
        }

        if set.is_empty() {
            // Mongo rejects an empty update document, and `$set`ting `_id` to work around that
            // would try to modify an immutable field. A class with nothing storable still has to
            // have a row, so insert the bare one and treat an existing row as success.
            let mut bare = Document::new();
            bare.insert("_id", &schema.class_name);
            return match self
                .db
                .collection::<Document>(SCHEMA_COLLECTION)
                .insert_one(bare)
                .await
            {
                Ok(_) => Ok(()),
                Err(e) if is_duplicate_key(&e) => Ok(()),
                Err(e) => Err(mongo_err(e)),
            };
        }

        self.db
            .collection::<Document>(SCHEMA_COLLECTION)
            .update_one(doc! { "_id": &schema.class_name }, doc! { "$set": set })
            .upsert(true)
            .await
            .map_err(mongo_err)?;
        Ok(())
    }

    async fn reserve_field(
        &self,
        class_name: &str,
        field_name: &str,
        field_type: &FieldType,
        options: Option<&ParseMap>,
    ) -> Result<AddFieldOutcome, ParseError> {
        let type_string = field_type_to_storage(field_type);
        if type_string.is_empty() {
            // `ACL` has no `_SCHEMA` string; it is injected on read. Reserving it would write an
            // empty type string, which parse-server reads as a phantom field of unknown type.
            return Err(ParseError::invalid_json(format!(
                "Could not add field {field_name}"
            )));
        }

        // The conditional upsert (`MongoSchemaCollection.js:249-281`, reaching
        // `upsertSchema` at `:201-203`). The `$exists: false` guard is the whole mechanism: a
        // writer that loses the race fails the condition rather than overwriting the winner's
        // type, so the type a row is validated against cannot change under it.
        let mut filter = Document::new();
        filter.insert("_id", class_name);
        filter.insert(field_name, doc! { "$exists": false });

        let mut set = Document::new();
        set.insert(field_name, &type_string);
        // In the same `$set`, under the same guard (`MongoSchemaCollection.js:251-269`). A field
        // reserved without its options would be a field whose options a concurrent writer can win.
        if let Some(options) = options.filter(|o| !o.is_empty()) {
            set.insert(
                field_options_path(field_name),
                parse_map_to_bson_document(options)?,
            );
        }

        // **A class may hold only one GeoPoint field** (`MongoSchemaCollection.js:224-237`).
        // Upstream reads the schema, checks it for an existing GeoPoint, then upserts, which is
        // the read-decide-write split that two concurrent writers adding two *different* GeoPoint
        // fields both survive. This was previously left to `parse-rust-schema` on the reasoning
        // that it is a schema rule rather than a storage one; that is the wrong axis, because it
        // is a predicate over stored state paired with a mutation of that state.
        //
        // It cannot go in the upsert filter. An upsert builds its insert document from the
        // filter's equality terms, and `$expr` is not one, so Mongo refuses the whole operation and
        // an ordinary first GeoPoint 500s. So the guarded form runs without `upsert`, and the class
        // row is created by an explicit insert instead.
        //
        // **The insert is what closes the window, not a prior read.** Checking "does the class
        // exist?" and then upserting is the same read-decide-write split this guard exists to
        // remove: two writers can both observe absence, the first inserts GeoPoint `a`, and the
        // second's plain `{b: {$exists: false}}` filter then adds `b` happily. `insert_one` is
        // atomic on `_id`, so exactly one writer creates the row and the loser is told so by a
        // duplicate-key error, at which point the guarded update is the right thing to retry.
        //
        // `$objectToArray` is what makes the condition expressible without a prior read. `_id` is
        // a string and `_metadata` a subdocument, so neither can equal the type string.
        if matches!(field_type, FieldType::GeoPoint) {
            let mut guarded = filter.clone();
            guarded.insert(
                "$expr",
                doc! { "$eq": [ { "$size": { "$filter": {
                    "input": { "$objectToArray": "$$ROOT" },
                    "cond": { "$eq": ["$$this.v", &type_string] },
                } } }, 0 ] },
            );
            let guarded_update = || async {
                self.db
                    .collection::<Document>(SCHEMA_COLLECTION)
                    .update_one(guarded.clone(), doc! { "$set": set.clone() })
                    .await
                    .map_err(mongo_err)
            };

            if guarded_update().await?.modified_count > 0 {
                return Ok(AddFieldOutcome::Added);
            }

            // Matched nothing, so either the class row is absent or the guard refused. Try to
            // create it. **Nested, not dotted**: a dotted key is a path inside `$set` and a
            // literal key inside an inserted document, and writing `_metadata.fields_options.x`
            // here would create a top-level column whose name contains dots.
            let mut new_row = Document::new();
            new_row.insert("_id", class_name);
            new_row.insert(field_name, &type_string);
            if let Some(options) = options.filter(|o| !o.is_empty()) {
                new_row.insert(
                    "_metadata",
                    doc! { "fields_options": doc! {
                        field_name: parse_map_to_bson_document(options)?,
                    } },
                );
            }
            return match self
                .db
                .collection::<Document>(SCHEMA_COLLECTION)
                .insert_one(new_row)
                .await
            {
                Ok(_) => Ok(AddFieldOutcome::Added),
                // Somebody else created the class between the update and the insert. The row now
                // exists, so the guarded update is meaningful again.
                Err(e) if is_duplicate_key(&e) => {
                    if guarded_update().await?.modified_count > 0 {
                        return Ok(AddFieldOutcome::Added);
                    }
                    self.reservation_refused(class_name, field_name, field_type)
                        .await
                }
                Err(e) => Err(mongo_err(e)),
            };
        }

        let result = self
            .db
            .collection::<Document>(SCHEMA_COLLECTION)
            .update_one(filter, doc! { "$set": set })
            .upsert(true)
            .await;

        match result {
            Ok(r) if r.upserted_id.is_some() || r.modified_count > 0 => Ok(AddFieldOutcome::Added),
            // Matched nothing and did not error. The class document exists and the field does not,
            // yet nothing changed, which a concurrent write can produce. Same classification as a
            // collision.
            Ok(_) => {
                self.reservation_refused(class_name, field_name, field_type)
                    .await
            }
            // The filter matched nothing because the field already exists, so the upsert tried to
            // insert a second document with the same `_id` and collided.
            Err(e) if is_duplicate_key(&e) => {
                self.reservation_refused(class_name, field_name, field_type)
                    .await
            }
            Err(e) => Err(mongo_err(e)),
        }
    }

    async fn set_field_options(
        &self,
        class_name: &str,
        field_name: &str,
        options: &ParseMap,
    ) -> Result<(), ParseError> {
        // One path, one field, **under a `{field: {$exists: true}}` guard**
        // (`MongoSchemaCollection.js:284-297`). Without it a field deleted between the caller's
        // read and this write leaves options behind for a column that no longer exists, which
        // parse-server reads back as a `fields_options` entry with no field.
        //
        // No upsert, unlike upstream. Upstream passes `upsert: true`, and because `$exists` is not
        // an equality Mongo cannot derive the field from the filter, so the insert it attempts
        // collides on `_id` and surfaces a raw duplicate-key error for what is really a lost race.
        // Matching nothing and writing nothing is the same outcome without an error this layer
        // would then have to sanitize. Recorded under the deliberate differences in `CHANGELOG.md`.
        let mut filter = Document::new();
        filter.insert("_id", class_name);
        filter.insert(field_name, doc! { "$exists": true });
        self.db
            .collection::<Document>(SCHEMA_COLLECTION)
            .update_one(
                filter,
                doc! { "$set": { field_options_path(field_name): parse_map_to_bson_document(options)? } },
            )
            .await
            .map_err(mongo_err)?;
        Ok(())
    }

    async fn set_indexes(&self, class_name: &str, indexes: &ParseMap) -> Result<(), ParseError> {
        // No upsert, matching `updateSchema` (`MongoStorageAdapter.js:404-408`). On a class being
        // created this matches nothing and the indexes travel in the insert instead.
        self.db
            .collection::<Document>(SCHEMA_COLLECTION)
            .update_one(
                doc! { "_id": class_name },
                doc! { "$set": { METADATA_INDEXES: parse_map_to_bson_document(indexes)? } },
            )
            .await
            .map_err(mongo_err)?;
        Ok(())
    }

    async fn set_class_permissions(
        &self,
        class_name: &str,
        clp: Option<&ClassLevelPermissions>,
    ) -> Result<(), ParseError> {
        // `$set` on the one path when there is a block, `$unset` when there is not
        // (`MongoStorageAdapter.js:337-345` does the `$set` half). Removing the key is not the
        // same as storing an empty block: the key's absence is what makes a class read back as
        // `defaultCLPS`.
        let update = match clp {
            Some(clp) => {
                doc! { "$set": { METADATA_CLASS_PERMISSIONS: parse_map_to_bson_document(clp.raw())? } }
            }
            None => doc! { "$unset": { METADATA_CLASS_PERMISSIONS: "" } },
        };
        // No upsert, matching `updateSchema`: setting permissions on a class that does not exist
        // must not conjure one.
        self.db
            .collection::<Document>(SCHEMA_COLLECTION)
            .update_one(doc! { "_id": class_name }, update)
            .await
            .map_err(mongo_err)?;
        Ok(())
    }

    async fn delete_class(&self, schema: &ClassSchema) -> Result<(), ParseError> {
        // Collected before the first await so the iterator does not borrow across it.
        let joins: Vec<String> = schema
            .relation_fields()
            .map(|(field, _)| join_table_name(&schema.class_name, field))
            .collect();

        if let Err(e) = self
            .db
            .collection::<Document>(&schema.class_name)
            .drop()
            .await
        {
            if !is_namespace_not_found(&e) {
                return Err(mongo_err(e));
            }
        }

        self.db
            .collection::<Document>(SCHEMA_COLLECTION)
            .delete_one(doc! { "_id": &schema.class_name })
            .await
            .map_err(mongo_err)?;

        // Every join collection belonging to the class goes with it
        // (`DatabaseController.js:1631-1638`). Note that the join collections have no `_SCHEMA`
        // row, so there is nothing else to remove for them.
        for join in joins {
            if let Err(e) = self.db.collection::<Document>(&join).drop().await {
                if !is_namespace_not_found(&e) {
                    return Err(mongo_err(e));
                }
            }
        }
        Ok(())
    }

    async fn delete_fields(
        &self,
        schema: &ClassSchema,
        fields: &[String],
    ) -> Result<(), ParseError> {
        let mut column_unset = Document::new();
        let mut existence: Vec<Bson> = Vec::new();
        let mut schema_unset = Document::new();

        for name in fields {
            schema_unset.insert(name.clone(), Bson::Null);
            schema_unset.insert(format!("{METADATA_FIELDS_OPTIONS}.{name}"), Bson::Null);

            // A Relation has no column, so there is nothing to unset on the rows. Upstream issues
            // the unset anyway and says so in a comment (`MongoStorageAdapter.js:495-499`); the
            // difference is unobservable, because a stray column of that name is overwritten by
            // the synthesized Relation on every read.
            let column = match schema.field(name) {
                Some(FieldType::Relation { .. }) => continue,
                Some(FieldType::Pointer { .. }) => format!("_p_{name}"),
                _ => name.clone(),
            };
            existence.push(Bson::Document(doc! { &column: { "$exists": true } }));
            column_unset.insert(column, Bson::Null);
        }

        if !column_unset.is_empty() {
            self.db
                .collection::<Document>(&schema.class_name)
                .update_many(doc! { "$or": existence }, doc! { "$unset": column_unset })
                .await
                .map_err(mongo_err)?;
        }

        if !schema_unset.is_empty() {
            // **Deliberately does not touch join collections** (`MongoStorageAdapter.js:495-501`).
            // Dropping a Relation field leaves its memberships in place, and a class recreated
            // with the same field name inherits them. A client can observe that.
            self.db
                .collection::<Document>(SCHEMA_COLLECTION)
                .update_one(
                    doc! { "_id": &schema.class_name },
                    doc! { "$unset": schema_unset },
                )
                .await
                .map_err(mongo_err)?;
        }
        Ok(())
    }

    async fn create(&self, schema: &ClassSchema, row: &Row) -> Result<WriteResult, ParseError> {
        let doc = parse_object_to_mongo_create(schema, row)?;
        let object_id = doc
            .get_str("_id")
            .map_err(|_| ParseError::new(ErrorCode::MissingObjectId, "objectId is required"))?
            .to_string();
        self.db
            .collection::<Document>(&schema.class_name)
            .insert_one(doc)
            .await
            .map_err(mongo_err)?;
        Ok(WriteResult { object_id })
    }

    async fn upsert_one(
        &self,
        schema: &ClassSchema,
        query: &Query,
        row: &Row,
    ) -> Result<(), ParseError> {
        // Upstream hands the same document to `transformUpdate`, which lifts plain values onto
        // `$set` (`DatabaseController.js:794-806` calling `upsertOneObject`). A join membership is
        // exactly `{relatedId, owningId}`, so adding a user to a role twice is one row.
        //
        // Nothing here writes to `_SCHEMA`. Join collections have no schema document upstream, and
        // creating one would add a class every parse-server node reading the database would see.
        let filter = transform_where(schema, query)?;
        let set = parse_object_to_mongo_create(schema, row)?;
        if set.is_empty() {
            return Err(ParseError::invalid_json(
                "upsert requires at least one value".to_string(),
            ));
        }
        self.db
            .collection::<Document>(&schema.class_name)
            .update_one(filter, doc! { "$set": set })
            .upsert(true)
            .await
            .map_err(mongo_err)?;
        Ok(())
    }

    async fn find(
        &self,
        schema: &ClassSchema,
        query: &Query,
        options: &QueryOptions,
    ) -> Result<Vec<Row>, ParseError> {
        let filter = transform_where(schema, query)?;
        // Bind the collection first: the driver's fluent builder borrows it, so building
        // directly off a temporary would drop it while still in use.
        let collection = self.db.collection::<Document>(&schema.class_name);
        let mut find = collection.find(filter);

        if options.case_insensitive {
            // `{caseInsensitive: true}` resolves to this collation
            // (`MongoStorageAdapter.js:801-803`, `MongoCollection.js:134-136`). Applied to the
            // find rather than approximated in the filter, because strength 2 normalizes as well
            // as folding case, which no regex over the stored value can reproduce.
            find = find.collation(
                mongodb::options::Collation::builder()
                    .locale("en_US".to_string())
                    .strength(mongodb::options::CollationStrength::Secondary)
                    .build(),
            );
        }

        if let Some(limit) = options.limit {
            // The driver reads 0 as "no limit", which is the opposite of what a caller asking for
            // zero rows means. Short-circuit instead.
            if limit == 0 {
                return Ok(Vec::new());
            }
            find = find.limit(limit as i64);
        }
        if let Some(skip) = options.skip {
            find = find.skip(skip as u64);
        }
        if !options.order.is_empty() {
            let mut sort = Document::new();
            for (key, dir) in &options.order {
                let dir = match dir {
                    SortDirection::Ascending => 1,
                    SortDirection::Descending => -1,
                };
                sort.insert(storage_key(schema, key), dir);
            }
            find = find.sort(sort);
        }
        if let Some(keys) = &options.keys {
            let mut projection = Document::new();
            for k in keys {
                projection.insert(storage_key(schema, k), 1);
            }
            // Always projected regardless of `keys`:
            //  - the permission columns, because ACL filtering happens after the read and
            //    projecting them away would make every row look public;
            //  - the timestamps, which Parse returns on every object whether asked for or not.
            for always in ["_rperm", "_wperm", "_created_at", "_updated_at"] {
                projection.insert(always, 1);
            }
            find = find.projection(projection);
        }

        let mut cursor = find.await.map_err(mongo_err)?;
        let mut out = Vec::new();
        while let Some(doc) = cursor.try_next().await.map_err(mongo_err)? {
            out.push(mongo_object_to_parse(schema, &doc)?);
        }
        Ok(out)
    }

    async fn count(&self, schema: &ClassSchema, query: &Query) -> Result<u64, ParseError> {
        let filter = transform_where(schema, query)?;
        self.db
            .collection::<Document>(&schema.class_name)
            .count_documents(filter)
            .await
            .map_err(mongo_err)
    }

    async fn update(
        &self,
        schema: &ClassSchema,
        query: &Query,
        update: &Update,
    ) -> Result<u64, ParseError> {
        let filter = transform_where(schema, query)?;
        let compiled = transform_update(schema, update)?;
        // An update carrying nothing storable, a lone Relation for instance, compiles to an empty
        // document, and Mongo rejects that. Nothing matched because nothing was asked for.
        if compiled.is_empty() {
            return Ok(0);
        }
        let res = self
            .db
            .collection::<Document>(&schema.class_name)
            .update_many(filter, compiled)
            .await
            .map_err(mongo_err)?;
        Ok(res.matched_count)
    }

    async fn update_one_returning(
        &self,
        schema: &ClassSchema,
        query: &Query,
        update: &Update,
    ) -> Result<Option<Row>, ParseError> {
        let filter = transform_where(schema, query)?;
        let compiled = transform_update(schema, update)?;
        if compiled.is_empty() {
            return Ok(None);
        }
        // `returnDocument: 'after'` (`MongoStorageAdapter.js:660-665`). The post-image is what
        // `_sanitizeDatabaseResult` reads an op's resulting value off, so the *before* image would
        // report the old value and look like the op silently did nothing.
        let collection = self.db.collection::<Document>(&schema.class_name);
        let found = collection
            .find_one_and_update(filter, compiled)
            .return_document(ReturnDocument::After)
            .await
            .map_err(mongo_err)?;
        found
            .as_ref()
            .map(|doc| mongo_object_to_parse(schema, doc))
            .transpose()
    }

    async fn delete(&self, schema: &ClassSchema, query: &Query) -> Result<u64, ParseError> {
        let filter = transform_where(schema, query)?;
        let res = self
            .db
            .collection::<Document>(&schema.class_name)
            .delete_many(filter)
            .await
            .map_err(mongo_err)?;
        Ok(res.deleted_count)
    }

    async fn ensure_index(
        &self,
        class_name: &str,
        fields: &[&str],
        name: Option<&str>,
        unique: bool,
        case_insensitive: bool,
    ) -> Result<(), ParseError> {
        let mut keys = Document::new();
        for f in fields {
            keys.insert(f.to_string(), 1);
        }
        // Sparse and background, matching `ensureIndex`'s defaults
        // (`MongoStorageAdapter.js:797`). A non-sparse unique index would refuse a second row
        // with the field absent, which is not upstream's behavior.
        let mut opts = IndexOptions::builder().unique(unique).sparse(true).build();
        opts.name = name.map(str::to_string);
        if case_insensitive {
            // `caseInsensitiveCollation` (`MongoCollection.js:134-136`). Strength 2 ignores case
            // and normalizes equivalent Unicode forms; it does **not** ignore diacritics, so
            // `Café` and `Cafe` stay distinct. Normalization is the part a regex cannot reproduce.
            opts.collation = Some(
                mongodb::options::Collation::builder()
                    .locale("en_US".to_string())
                    .strength(mongodb::options::CollationStrength::Secondary)
                    .build(),
            );
        }

        self.db
            .collection::<Document>(class_name)
            .create_index(IndexModel::builder().keys(keys).options(opts).build())
            .await
            .map_err(mongo_err)?;
        Ok(())
    }

    async fn create_indexes(
        &self,
        class_name: &str,
        indexes: &[SchemaIndex],
    ) -> Result<(), ParseError> {
        if indexes.is_empty() {
            return Ok(());
        }
        let mut models = Vec::with_capacity(indexes.len());
        for index in indexes {
            let mut keys = Document::new();
            for (field, direction) in &index.keys {
                // Passed through rather than coerced to `1`. `-1` is a descending key and
                // `"text"`, `"hashed"` and `"2dsphere"` are index types, and all four are what a
                // parse-server node reading `_metadata.indexes` will expect to find built.
                keys.insert(
                    field.clone(),
                    index_key_to_bson(&index.name, field, direction)?,
                );
            }
            let mut opts = IndexOptions::default();
            // Named by the caller, never auto-generated. The name is the key `_metadata.indexes`
            // is stored under and the handle `dropIndex` needs later.
            opts.name = Some(index.name.clone());
            models.push(IndexModel::builder().keys(keys).options(opts).build());
        }
        self.db
            .collection::<Document>(class_name)
            .create_indexes(models)
            .await
            .map_err(mongo_err)?;
        Ok(())
    }

    async fn drop_index(&self, class_name: &str, name: &str) -> Result<(), ParseError> {
        self.db
            .collection::<Document>(class_name)
            .drop_index(name)
            .await
            .map_err(mongo_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clp_doc() -> Document {
        doc! { "find": { "*": true }, "protectedFields": { "*": ["email"] } }
    }

    /// The message the server actually sends, so the parser is tested against the real shape
    /// rather than against a convenient one.
    fn e11000(namespace: &str, index: &str, field: &str, value: &str) -> String {
        format!(
            "E11000 duplicate key error collection: {namespace} index: {index} dup key: {{ {field}: \"{value}\" }}"
        )
    }

    #[test]
    fn the_auto_generated_index_name_yields_its_field() {
        for (index, field) in [
            ("username_1", "username"),
            ("email_1", "email"),
            ("name_1", "name"),
        ] {
            let message = e11000("appdb._User", index, field, "alice");
            assert_eq!(duplicated_field(&message).as_deref(), Some(field));
        }
    }

    /// The pre-4.2 spelling qualifies the index with the namespace.
    #[test]
    fn the_legacy_namespace_qualified_index_name_yields_its_field() {
        let message =
            "E11000 duplicate key error index: appdb.$username_1 dup key: { : \"alice\" }";
        assert_eq!(duplicated_field(message).as_deref(), Some("username"));
    }

    /// `_throwIfAuthDataDuplicate` reads this prefix, so the whole index name is the field.
    #[test]
    fn the_auth_data_index_name_is_carried_whole() {
        let message = e11000(
            "appdb._User",
            "_auth_data_facebook_id",
            "authData.facebook.id",
            "7",
        );
        assert_eq!(
            duplicated_field(&message).as_deref(),
            Some("_auth_data_facebook_id")
        );
    }

    /// A name upstream cannot read must not be read here either. Recovering a field from
    /// `case_insensitive_username` would produce a `duplicated_field` upstream never produces,
    /// and the two servers would then answer a collision differently.
    #[test]
    fn an_index_name_outside_the_two_shapes_yields_nothing() {
        for index in [
            "case_insensitive_username",
            "username_2",
            "field1_1", // upstream's capture class excludes digits
            "_id_",
        ] {
            let message = e11000("appdb._User", index, "username", "alice");
            assert_eq!(duplicated_field(&message), None, "{index}");
        }
        assert_eq!(duplicated_field("some unrelated driver text"), None);
    }

    /// The field name comes out; the database name and the colliding value do not.
    #[test]
    fn nothing_but_the_field_name_survives_the_parse() {
        let message = e11000("secret_prod_db._User", "username_1", "username", "alice");
        let field = duplicated_field(&message).expect("field");
        assert!(!field.contains("secret_prod_db"));
        assert!(!field.contains("alice"));
    }

    /// The merge that makes an unspecified operation read back as deny-all rather than as absent.
    #[test]
    fn a_present_clp_block_merges_over_empty_clps() {
        let merged = merge_over_empty_clps(&clp_doc()).expect("merge");

        // Every operation is present, and the ones the stored block did not mention are `{}`.
        for key in EMPTY_CLPS_KEYS {
            assert!(merged.contains_key(key), "{key} must be present");
        }
        assert!(
            matches!(merged.get("update"), Some(ParseValue::Object(m)) if m.is_empty()),
            "an unmentioned operation reads back as deny-all, not as absent"
        );
        assert!(
            matches!(merged.get("find"), Some(ParseValue::Object(m)) if m.contains_key("*")),
            "the stored value wins over the empty base"
        );
        // `defaultCLPS` carries an `ACL` key; `emptyCLPS` does not, and merging must not add one.
        assert!(
            !merged.contains_key("ACL"),
            "the present-but-partial case never carries an ACL key"
        );
    }

    #[test]
    fn the_merged_block_keeps_empty_clps_key_order() {
        let merged =
            merge_over_empty_clps(&doc! { "delete": { "*": true }, "later": {} }).expect("merge");
        let keys: Vec<&str> = merged.keys().map(String::as_str).collect();
        assert_eq!(&keys[..8], &EMPTY_CLPS_KEYS);
        assert_eq!(
            keys[8], "later",
            "a key only the stored block has goes last"
        );
    }

    /// The CLP block is what gets written back, so it has to survive a full round trip through
    /// BSON without losing a key parse-rust does not model.
    #[test]
    fn a_clp_block_round_trips_through_bson() {
        let mut stored = clp_doc();
        stored.insert("someFutureKey", doc! { "x": 1 });
        let merged = merge_over_empty_clps(&stored).expect("merge");
        let clp = ClassLevelPermissions::from_map(merged);
        let written = parse_map_to_bson_document(clp.raw()).expect("lower");

        assert_eq!(
            written.get_document("someFutureKey").expect("kept"),
            &doc! { "x": 1 }
        );
        assert!(written.get_document("update").expect("update").is_empty());
    }
}
