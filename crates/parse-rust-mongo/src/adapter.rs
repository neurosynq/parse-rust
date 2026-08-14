//! The MongoDB `StorageAdapter`.

use bson::{doc, Bson, Document};
use futures::TryStreamExt;
use mongodb::options::IndexOptions;
use mongodb::{Client, Database, IndexModel};
use parse_rust_core::{ErrorCode, ParseError, ParseValue};
use parse_rust_schema::storage_format::{
    field_type_to_storage, storage_to_field_type, NON_FIELD_KEYS,
};
use parse_rust_storage::{
    ClassSchema, Comparison, Constraint, QueryOptions, Row, SortDirection, StorageAdapter,
    WriteResult,
};

use crate::transform::{
    mongo_object_to_parse, parse_object_to_mongo_create, value_to_bson_for_query,
};

/// Where class schemas live. Not configurable: parse-server hardcodes it, and a mixed fleet has
/// to agree.
const SCHEMA_COLLECTION: &str = "_SCHEMA";

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

    /// Translate a constraint list into a Mongo filter.
    ///
    /// Every branch is total over [`Comparison`], so adding a comparison fails to compile here
    /// rather than silently matching everything.
    fn build_filter(
        schema: &ClassSchema,
        constraints: &[Constraint],
    ) -> Result<Document, ParseError> {
        let mut filter = Document::new();
        for c in constraints {
            let key = crate::transform::storage_key(schema, &c.field);
            let value = |v: &ParseValue| value_to_bson_for_query(schema, &c.field, v);

            let entry: Bson = match &c.comparison {
                Comparison::Equal(v) => value(v)?,
                Comparison::NotEqual(v) => Bson::Document(doc! { "$ne": value(v)? }),
                Comparison::GreaterThan(v) => Bson::Document(doc! { "$gt": value(v)? }),
                Comparison::GreaterThanOrEqual(v) => Bson::Document(doc! { "$gte": value(v)? }),
                Comparison::LessThan(v) => Bson::Document(doc! { "$lt": value(v)? }),
                Comparison::LessThanOrEqual(v) => Bson::Document(doc! { "$lte": value(v)? }),
                Comparison::In(items) => Bson::Document(doc! {
                    "$in": items.iter().map(value).collect::<Result<Vec<_>, _>>()?
                }),
                Comparison::NotIn(items) => Bson::Document(doc! {
                    "$nin": items.iter().map(value).collect::<Result<Vec<_>, _>>()?
                }),
                Comparison::Exists(b) => Bson::Document(doc! { "$exists": *b }),
            };

            // Several constraints on one field must merge rather than overwrite. Overwriting is
            // the bug the `tbraun96/parse-rs` query builder shipped, and it silently drops a
            // constraint, which broadens the result set.
            merge_constraint(&mut filter, key, entry)?;
        }
        Ok(filter)
    }
}

/// Merge a new constraint into an existing filter entry for the same field.
fn merge_constraint(filter: &mut Document, key: String, entry: Bson) -> Result<(), ParseError> {
    match filter.remove(&key) {
        None => {
            filter.insert(key, entry);
        }
        Some(existing) => match (existing, entry) {
            // Two operator documents merge key-wise: `{$gt: 1}` plus `{$lt: 5}` is a range.
            (Bson::Document(mut a), Bson::Document(b)) => {
                for (k, v) in b {
                    a.insert(k, v);
                }
                filter.insert(key, Bson::Document(a));
            }
            // Anything involving a bare equality cannot merge: Mongo has no way to express
            // "equals 1 and equals 2", and silently keeping one would drop the other.
            _ => {
                return Err(ParseError::invalid_query(format!(
                    "conflicting constraints on field {key}"
                )))
            }
        },
    }
    Ok(())
}

fn mongo_err(e: mongodb::error::Error) -> ParseError {
    // Duplicate key is the one storage error with a specific Parse code, because signup depends
    // on it: `username_1` colliding must become 202, not a generic failure.
    if let mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(we)) =
        e.kind.as_ref()
    {
        if we.code == 11000 {
            return ParseError::new(ErrorCode::DuplicateValue, we.message.clone());
        }
    }
    ParseError::new(
        ErrorCode::InternalServerError,
        format!("storage error: {e}"),
    )
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
            out.push(schema);
        }
        Ok(out)
    }

    async fn upsert_schema(&self, schema: &ClassSchema) -> Result<(), ParseError> {
        let mut set = Document::new();
        for (name, ty) in &schema.fields {
            let s = field_type_to_storage(ty);
            // ACL renders empty and is never stored; writing it would be a phantom column.
            if s.is_empty() {
                continue;
            }
            set.insert(name.clone(), s);
        }
        self.db
            .collection::<Document>(SCHEMA_COLLECTION)
            .update_one(doc! { "_id": &schema.class_name }, doc! { "$set": set })
            .upsert(true)
            .await
            .map_err(mongo_err)?;
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

    async fn find(
        &self,
        schema: &ClassSchema,
        constraints: &[Constraint],
        options: &QueryOptions,
    ) -> Result<Vec<Row>, ParseError> {
        let filter = Self::build_filter(schema, constraints)?;
        // Bind the collection first: the driver's fluent builder borrows it, so building
        // directly off a temporary would drop it while still in use.
        let collection = self.db.collection::<Document>(&schema.class_name);
        let mut find = collection.find(filter);

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
                sort.insert(crate::transform::storage_key(schema, key), dir);
            }
            find = find.sort(sort);
        }
        if let Some(keys) = &options.keys {
            let mut projection = Document::new();
            for k in keys {
                projection.insert(crate::transform::storage_key(schema, k), 1);
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
            out.push(mongo_object_to_parse(&doc)?);
        }
        Ok(out)
    }

    async fn count(
        &self,
        schema: &ClassSchema,
        constraints: &[Constraint],
    ) -> Result<u64, ParseError> {
        let filter = Self::build_filter(schema, constraints)?;
        self.db
            .collection::<Document>(&schema.class_name)
            .count_documents(filter)
            .await
            .map_err(mongo_err)
    }

    async fn update(
        &self,
        schema: &ClassSchema,
        constraints: &[Constraint],
        values: &Row,
    ) -> Result<u64, ParseError> {
        let filter = Self::build_filter(schema, constraints)?;
        let set = parse_object_to_mongo_create(schema, values)?;
        if set.is_empty() {
            return Ok(0);
        }
        let res = self
            .db
            .collection::<Document>(&schema.class_name)
            .update_many(filter, doc! { "$set": set })
            .await
            .map_err(mongo_err)?;
        Ok(res.matched_count)
    }

    async fn delete(
        &self,
        schema: &ClassSchema,
        constraints: &[Constraint],
    ) -> Result<u64, ParseError> {
        let filter = Self::build_filter(schema, constraints)?;
        let res = self
            .db
            .collection::<Document>(&schema.class_name)
            .delete_many(filter)
            .await
            .map_err(mongo_err)?;
        Ok(res.deleted_count)
    }

    async fn ensure_unique_index(
        &self,
        class_name: &str,
        fields: &[&str],
        name: Option<&str>,
    ) -> Result<(), ParseError> {
        let mut keys = Document::new();
        for f in fields {
            keys.insert(f.to_string(), 1);
        }
        // Sparse and background, matching `ensureIndex`'s defaults
        // (`MongoStorageAdapter.js:797`). A non-sparse unique index would refuse a second row
        // with the field absent, which is not upstream's behavior.
        let mut opts = IndexOptions::builder().unique(true).sparse(true).build();
        opts.name = name.map(str::to_string);

        self.db
            .collection::<Document>(class_name)
            .create_index(IndexModel::builder().keys(keys).options(opts).build())
            .await
            .map_err(mongo_err)?;
        Ok(())
    }
}
