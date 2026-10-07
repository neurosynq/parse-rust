//! An in-memory [`StorageAdapter`] for this crate's unit tests.
//!
//! Deliberately small and deliberately faithful on the two things the tests actually assert
//! about: it **applies `limit`, `skip` and the projection**, and it matches the constraint
//! vocabulary this crate emits. A fake that ignores `limit` would let the more-than-a-hundred
//! roles test pass while the real adapter truncated, which is the shape of green check that means
//! nothing.
//!
//! It panics on anything outside that vocabulary rather than returning an empty result, because a
//! silently unsupported constraint in a test double is how an authorization test comes to assert
//! against a query nobody ran.
//!
//! Rows are held in Parse form, which is what [`StorageAdapter`] deals in. There is no `_p_`
//! prefixing, no `_id` renaming and no BSON here: that is the Mongo adapter's job and it has its
//! own tests against a real server. What this fake is for is the logic in this crate.

use std::collections::HashMap;
use std::sync::Mutex;

use parse_rust_core::{deep_strict_eq, ClassLevelPermissions, ParseError, ParseValue};
use parse_rust_storage::{
    AddFieldOutcome, ClassSchema, Clause, Comparison, Constraint, FieldType, Query, QueryOptions,
    Row, SchemaIndex, SortDirection, StorageAdapter, Update, UpdateValue, WriteResult,
};

#[derive(Default)]
struct State {
    rows: HashMap<String, Vec<Row>>,
    schemas: HashMap<String, ClassSchema>,
    find_count: usize,
    last_find_limit: Option<Option<u32>>,
}

#[derive(Default)]
pub struct FakeStorage {
    state: Mutex<State>,
}

impl FakeStorage {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // Test code. A poisoned lock means another test thread panicked, and surfacing that is
        // more useful than swallowing it.
        self.state.lock().expect("fake storage lock")
    }

    /// Seed a row directly, bypassing the write path.
    pub fn insert_row(&self, class_name: &str, pairs: Vec<(&str, ParseValue)>) {
        let mut row = Row::new();
        for (k, v) in pairs {
            row.insert(k.to_string(), v);
        }
        self.lock()
            .rows
            .entry(class_name.to_string())
            .or_default()
            .push(row);
    }

    pub fn rows(&self, class_name: &str) -> Vec<Row> {
        self.lock()
            .rows
            .get(class_name)
            .cloned()
            .unwrap_or_default()
    }

    pub fn schema(&self, class_name: &str) -> Option<ClassSchema> {
        self.lock().schemas.get(class_name).cloned()
    }

    pub fn find_count(&self) -> usize {
        self.lock().find_count
    }

    pub fn reset_find_count(&self) {
        self.lock().find_count = 0;
    }

    /// The `limit` the most recent `find` was given, so a test can assert a query was bounded (or
    /// deliberately unbounded) rather than inferring it from the result.
    pub fn last_find_limit(&self) -> Option<Option<u32>> {
        self.lock().last_find_limit
    }
}

fn value_matches(value: Option<&ParseValue>, comparison: &Comparison) -> bool {
    match comparison {
        Comparison::Equal(want) | Comparison::EqualOperator(want) => {
            value.is_some_and(|v| deep_strict_eq(v, want))
        }
        // A missing field matches `$ne`, which is Mongo's behavior and the reason
        // `destroyDuplicatedSessions` can carry the guard unconditionally.
        Comparison::NotEqual(want) => !value.is_some_and(|v| deep_strict_eq(v, want)),
        Comparison::In(wants) => {
            value.is_some_and(|v| wants.iter().any(|want| deep_strict_eq(v, want)))
        }
        Comparison::NotIn(wants) => {
            !value.is_some_and(|v| wants.iter().any(|want| deep_strict_eq(v, want)))
        }
        Comparison::Exists(want) => value.is_some() == *want,
        other => panic!(
            "the fake storage adapter does not implement {other:?}; add it rather than letting \
             the constraint be dropped"
        ),
    }
}

fn constraint_matches(row: &Row, constraint: &Constraint) -> bool {
    value_matches(row.get(&constraint.field), &constraint.comparison)
}

fn query_matches(row: &Row, query: &Query) -> bool {
    query.clauses.iter().all(|clause| match clause {
        Clause::Field(c) => constraint_matches(row, c),
        Clause::Or(qs) => qs.iter().any(|q| query_matches(row, q)),
        Clause::And(qs) => qs.iter().all(|q| query_matches(row, q)),
        Clause::Nor(qs) => !qs.iter().any(|q| query_matches(row, q)),
    })
}

fn sort_key(row: &Row, key: &str) -> String {
    match row.get(key) {
        Some(ParseValue::String(s)) => s.clone(),
        Some(ParseValue::Number(n)) => format!("{n:020.6}"),
        Some(other) => other.to_json(),
        None => String::new(),
    }
}

impl StorageAdapter for FakeStorage {
    async fn all_schemas(&self) -> Result<Vec<ClassSchema>, ParseError> {
        Ok(self.lock().schemas.values().cloned().collect())
    }

    async fn insert_schema(&self, schema: &ClassSchema) -> Result<(), ParseError> {
        let mut state = self.lock();
        if state.schemas.contains_key(&schema.class_name) {
            return Err(ParseError::new(
                parse_rust_core::ErrorCode::DuplicateValue,
                "Class already exists.",
            ));
        }
        state
            .schemas
            .insert(schema.class_name.clone(), schema.clone());
        Ok(())
    }

    async fn upsert_schema(&self, schema: &ClassSchema) -> Result<(), ParseError> {
        let mut state = self.lock();
        let entry = state
            .schemas
            .entry(schema.class_name.clone())
            .or_insert_with(|| ClassSchema::new(&schema.class_name));
        for (name, ty) in &schema.fields {
            entry.fields.insert(name.clone(), ty.clone());
        }
        // Matching the real adapter: metadata is only touched when it was supplied.
        if schema.clp.is_some() {
            entry.clp = schema.clp.clone();
        }
        Ok(())
    }

    async fn reserve_field(
        &self,
        class_name: &str,
        field_name: &str,
        field_type: &FieldType,
        _options: Option<&parse_rust_core::ParseMap>,
    ) -> Result<AddFieldOutcome, ParseError> {
        let mut state = self.lock();
        let entry = state
            .schemas
            .entry(class_name.to_string())
            .or_insert_with(|| ClassSchema::new(class_name));
        match entry.fields.get(field_name) {
            None => {
                entry
                    .fields
                    .insert(field_name.to_string(), field_type.clone());
                Ok(AddFieldOutcome::Added)
            }
            Some(existing) if existing == field_type => Ok(AddFieldOutcome::AlreadyPresentSameType),
            Some(existing) => Ok(AddFieldOutcome::Conflict {
                existing: existing.clone(),
            }),
        }
    }

    /// Nothing in this crate reaches the schema API, so these are inert here.
    async fn set_field_options(
        &self,
        _class_name: &str,
        _field_name: &str,
        _options: &parse_rust_core::ParseMap,
    ) -> Result<(), ParseError> {
        Ok(())
    }

    async fn set_indexes(
        &self,
        _class_name: &str,
        _indexes: &parse_rust_core::ParseMap,
    ) -> Result<(), ParseError> {
        Ok(())
    }

    async fn set_class_permissions(
        &self,
        class_name: &str,
        clp: Option<&ClassLevelPermissions>,
    ) -> Result<(), ParseError> {
        let mut state = self.lock();
        if let Some(schema) = state.schemas.get_mut(class_name) {
            schema.clp = clp.cloned();
        }
        Ok(())
    }

    async fn delete_class(&self, schema: &ClassSchema) -> Result<(), ParseError> {
        let mut state = self.lock();
        state.rows.remove(&schema.class_name);
        state.schemas.remove(&schema.class_name);
        Ok(())
    }

    async fn delete_fields(
        &self,
        schema: &ClassSchema,
        fields: &[String],
    ) -> Result<(), ParseError> {
        let mut state = self.lock();
        if let Some(stored) = state.schemas.get_mut(&schema.class_name) {
            for f in fields {
                stored.fields.shift_remove(f);
            }
        }
        if let Some(rows) = state.rows.get_mut(&schema.class_name) {
            for row in rows.iter_mut() {
                for f in fields {
                    row.shift_remove(f);
                }
            }
        }
        Ok(())
    }

    async fn create(&self, schema: &ClassSchema, row: &Row) -> Result<WriteResult, ParseError> {
        let object_id = match row.get("objectId") {
            Some(ParseValue::String(id)) => id.clone(),
            _ => String::new(),
        };
        self.lock()
            .rows
            .entry(schema.class_name.clone())
            .or_default()
            .push(row.clone());
        Ok(WriteResult { object_id })
    }

    async fn upsert_one(
        &self,
        schema: &ClassSchema,
        query: &Query,
        row: &Row,
    ) -> Result<(), ParseError> {
        let mut state = self.lock();
        let rows = state.rows.entry(schema.class_name.clone()).or_default();
        if !rows.iter().any(|r| query_matches(r, query)) {
            rows.push(row.clone());
        }
        Ok(())
    }

    async fn find(
        &self,
        schema: &ClassSchema,
        query: &Query,
        options: &QueryOptions,
    ) -> Result<Vec<Row>, ParseError> {
        let mut state = self.lock();
        state.find_count += 1;
        state.last_find_limit = Some(options.limit);

        let mut rows: Vec<Row> = state
            .rows
            .get(&schema.class_name)
            .map(|rows| {
                rows.iter()
                    .filter(|row| query_matches(row, query))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        if let Some((key, direction)) = options.order.first() {
            rows.sort_by(|a, b| {
                let ord = sort_key(a, key).cmp(&sort_key(b, key));
                match direction {
                    SortDirection::Ascending => ord,
                    SortDirection::Descending => ord.reverse(),
                    SortDirection::TextScore => std::cmp::Ordering::Equal,
                }
            });
        }
        if let Some(skip) = options.skip {
            rows = rows
                .into_iter()
                .skip(usize::try_from(skip).unwrap_or(0))
                .collect();
        }
        if let Some(limit) = options.limit {
            rows.truncate(limit as usize);
        }
        if let Some(keys) = &options.keys {
            // The Mongo adapter projects the requested keys, and Mongo returns `_id` regardless
            // of an inclusion projection, so `objectId` and the timestamps survive too.
            rows = rows
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .filter(|(k, _)| {
                            keys.contains(k)
                                || matches!(k.as_str(), "objectId" | "createdAt" | "updatedAt")
                        })
                        .collect()
                })
                .collect();
        }
        Ok(rows)
    }

    /// A fixed document naming the verbosity. Only the plumbing is under test here; what a real
    /// database says is the adapter integration test's business.
    async fn explain(
        &self,
        _schema: &ClassSchema,
        _query: &Query,
        _options: &QueryOptions,
        verbosity: parse_rust_storage::ExplainVerbosity,
    ) -> Result<serde_json::Value, ParseError> {
        Ok(serde_json::json!({ "fake": verbosity.as_str() }))
    }

    async fn count(
        &self,
        schema: &ClassSchema,
        query: &Query,
        _options: &parse_rust_storage::CountOptions,
    ) -> Result<u64, ParseError> {
        let state = self.lock();
        Ok(state
            .rows
            .get(&schema.class_name)
            .map(|rows| rows.iter().filter(|r| query_matches(r, query)).count() as u64)
            .unwrap_or(0))
    }

    async fn update(
        &self,
        schema: &ClassSchema,
        query: &Query,
        update: &Update,
    ) -> Result<u64, ParseError> {
        let mut state = self.lock();
        let mut matched = 0u64;
        if let Some(rows) = state.rows.get_mut(&schema.class_name) {
            for row in rows.iter_mut().filter(|r| query_matches(r, query)) {
                matched += 1;
                apply_update(row, update);
            }
        }
        Ok(matched)
    }

    async fn update_one_returning(
        &self,
        schema: &ClassSchema,
        query: &Query,
        update: &Update,
    ) -> Result<Option<Row>, ParseError> {
        let mut state = self.lock();
        let Some(rows) = state.rows.get_mut(&schema.class_name) else {
            return Ok(None);
        };
        let Some(row) = rows.iter_mut().find(|r| query_matches(r, query)) else {
            return Ok(None);
        };
        apply_update(row, update);
        Ok(Some(row.clone()))
    }

    async fn delete(&self, schema: &ClassSchema, query: &Query) -> Result<u64, ParseError> {
        let mut state = self.lock();
        let Some(rows) = state.rows.get_mut(&schema.class_name) else {
            return Ok(0);
        };
        let before = rows.len();
        rows.retain(|row| !query_matches(row, query));
        Ok((before - rows.len()) as u64)
    }

    async fn ensure_index(
        &self,
        _class_name: &str,
        _fields: &[&str],
        _name: Option<&str>,
        _unique: bool,
        _case_insensitive: bool,
    ) -> Result<(), ParseError> {
        Ok(())
    }

    /// Nothing in this crate reaches the schema API, so these are inert here.
    async fn create_indexes(
        &self,
        _class_name: &str,
        _indexes: &[SchemaIndex],
    ) -> Result<(), ParseError> {
        Ok(())
    }

    async fn drop_index(&self, _class_name: &str, _name: &str) -> Result<(), ParseError> {
        Ok(())
    }

    async fn index_fields(
        &self,
        _class_name: &str,
    ) -> Result<Vec<parse_rust_storage::IndexFields>, ParseError> {
        Ok(Vec::new())
    }
}

fn apply_update(row: &mut Row, update: &Update) {
    for (key, value) in update {
        match value {
            UpdateValue::Set(v) => {
                row.insert(key.clone(), v.clone());
            }
            UpdateValue::Unset => {
                row.shift_remove(key);
            }
            // These fakes never insert through `update`, so `$setOnInsert` is always a no-op
            // here. Spelled out rather than folded into a catch-all so a future upsert path
            // cannot silently inherit the wrong behavior.
            UpdateValue::SetOnInsert(_) => {}
            UpdateValue::Increment(by) => {
                let current = match row.get(key) {
                    Some(ParseValue::Number(n)) => *n,
                    _ => 0.0,
                };
                row.insert(key.clone(), ParseValue::Number(current + by));
            }
            other => panic!(
                "the fake storage adapter does not implement {other:?}; add it rather than \
                 letting the update be dropped"
            ),
        }
    }
}
