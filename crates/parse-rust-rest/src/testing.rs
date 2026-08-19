//! An in-memory `StorageAdapter`, so the pipeline is testable without MongoDB.
//!
//! Deliberately strict about what it does not implement: an unsupported comparison is an error
//! rather than a silent non-match. A fake that quietly answers "no rows" for a construct it does
//! not understand would make an authorization test pass for the wrong reason, which is the exact
//! failure mode this project's own notes warn about.
//!
//! Test-only. It is not a second storage backend and nothing outside `#[cfg(test)]` may reach it.

use std::sync::Mutex;

use indexmap::IndexMap;
use parse_rust_core::{
    deep_strict_eq, recognize_atom, AtomPosition, ErrorCode, ParseError, ParseMap, ParseValue,
};
use parse_rust_storage::{
    AddFieldOutcome, ClassSchema, Clause, Comparison, Constraint, FieldType, Query, QueryOptions,
    Row, SchemaIndex, SortDirection, StorageAdapter, Update, UpdateValue, WriteResult,
};

#[derive(Default)]
struct Inner {
    schemas: IndexMap<String, ClassSchema>,
    rows: IndexMap<String, Vec<ParseMap>>,
}

/// An in-memory store.
#[derive(Default)]
pub struct FakeStorage {
    inner: Mutex<Inner>,
    /// Every index built, as `(class, name)`. Separate from `inner` so a test can read it without
    /// holding the row lock.
    indexes: Mutex<Vec<(String, String)>>,
}

impl FakeStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a class schema without going through a write.
    pub fn with_schema(self, schema: ClassSchema) -> Self {
        if let Ok(mut inner) = self.inner.lock() {
            inner.schemas.insert(schema.class_name.clone(), schema);
        }
        self
    }

    /// Seed a row without going through a write, so a test can set up state the pipeline would
    /// refuse to create.
    pub fn with_row(self, class_name: &str, row: ParseMap) -> Self {
        if let Ok(mut inner) = self.inner.lock() {
            inner
                .rows
                .entry(class_name.to_string())
                .or_default()
                .push(row);
        }
        self
    }

    /// Every stored row of a class, for assertions.
    pub fn rows(&self, class_name: &str) -> Vec<ParseMap> {
        self.inner
            .lock()
            .map(|inner| inner.rows.get(class_name).cloned().unwrap_or_default())
            .unwrap_or_default()
    }

    /// The stored schema of a class, for assertions.
    pub fn schema(&self, class_name: &str) -> Option<ClassSchema> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.schemas.get(class_name).cloned())
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Inner>, ParseError> {
        self.inner
            .lock()
            .map_err(|_| ParseError::new(ErrorCode::InternalServerError, "fake storage poisoned"))
    }
}

/// Does one row satisfy a query?
///
/// Takes the schema because a query operand arrives **raw**: no `__type` envelope is interpreted by
/// the parser, since which envelopes count is a property of the field. A backend is the layer that
/// resolves that, so this fake has to resolve it too. Comparing a raw operand against a decoded
/// stored value otherwise fails to match every pointer and date a test queries by, and the failure
/// looks like an authorization result rather than a decoding one.
fn matches(schema: &ClassSchema, row: &ParseMap, query: &Query) -> Result<bool, ParseError> {
    for clause in &query.clauses {
        let ok = match clause {
            Clause::Field(constraint) => matches_constraint(schema, row, constraint)?,
            Clause::Or(branches) => {
                let mut any = false;
                for branch in branches {
                    any |= matches(schema, row, branch)?;
                }
                any
            }
            Clause::And(branches) => {
                let mut all = true;
                for branch in branches {
                    all &= matches(schema, row, branch)?;
                }
                all
            }
            Clause::Nor(branches) => {
                let mut none = true;
                for branch in branches {
                    none &= !matches(schema, row, branch)?;
                }
                none
            }
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

fn matches_constraint(
    schema: &ClassSchema,
    row: &ParseMap,
    constraint: &Constraint,
) -> Result<bool, ParseError> {
    let value = row.get(&constraint.field);
    // The same three rules `parse-rust-mongo` applies, for the same reason. See the note on
    // `comparison_to_bson`: an operator inside a constraint document uses `inArray || isNestedKey`,
    // shorthand equality uses the dotted-key test alone, and `$all` is interior unconditionally.
    let dotted = constraint.field.contains('.');
    let in_array = matches!(schema.field(&constraint.field), Some(FieldType::Array));
    let at = |interior: bool| {
        if interior {
            AtomPosition::Interior
        } else {
            AtomPosition::TopLevel
        }
    };
    let constraint_position = at(in_array || dotted);
    let shorthand_position = at(dotted);

    // **The top-level refusal, reproduced.** Without it this adapter answers questions the Mongo
    // lowering refuses with 107, so a pipeline test could pass against a predicate production never
    // executes. A fake that is more permissive than the backend is the same failure as one that
    // silently answers "no rows": the test measures something that cannot happen.
    let atom = |v: &ParseValue, position, shorthand: bool| -> Result<ParseValue, ParseError> {
        let atom = recognize_atom(v.clone(), position);
        if position == AtomPosition::TopLevel
            && matches!(atom, ParseValue::Object(_) | ParseValue::Array(_))
        {
            return Err(ParseError::invalid_json(if shorthand {
                format!(
                    "You cannot use {} as a query parameter.",
                    parse_rust_core::js_number::to_ecma_display(&atom)
                )
            } else {
                format!("bad atom: {}", atom.to_json())
            }));
        }
        Ok(atom)
    };
    let operand = |v: &ParseValue| atom(v, constraint_position, false);
    let interior_atom = |v: &ParseValue| recognize_atom(v.clone(), AtomPosition::Interior);

    Ok(match &constraint.comparison {
        Comparison::Equal(expected) => {
            // The empty-collection arms, which are answered before either of the two below:
            // `{field: {}}`, an equality against an empty document.
            if matches!(expected, ParseValue::Array(a) if a.is_empty())
                || matches!(expected, ParseValue::Object(m) if m.is_empty())
            {
                equals(value, &ParseValue::Object(ParseMap::new()))
            } else if in_array && !matches!(expected, ParseValue::Array(_)) {
                // **The `$all` wrap.** A non-array value against an `Array` field is a containment
                // test through the *interior* transform, not a top-level equality. Using top-level
                // recognition here is a different predicate: it rebuilds envelopes the interior
                // list does not admit, and it applies a refusal the `$all` path does not have.
                let wanted = interior_atom(expected);
                match value {
                    Some(ParseValue::Array(items)) => {
                        items.iter().any(|item| deep_strict_eq(item, &wanted))
                    }
                    _ => false,
                }
            } else {
                equals(value, &atom(expected, shorthand_position, true)?)
            }
        }
        Comparison::EqualOperator(expected) => equals(value, &operand(expected)?),
        Comparison::NotEqual(expected) => !equals(value, &operand(expected)?),
        // **`$in` and `$nin` flatten one level**, so an element that is itself an array
        // contributes its own elements rather than nesting (`MongoTransform.js:721-735`, mirrored
        // in `comparison_to_bson`'s `flatten_each`). Without it this adapter tried to lower `[1]`
        // as a top-level atom and answered 107, where production matches a `Number` field holding
        // `1`. A fake that refuses what the backend answers sends a pipeline test looking for a
        // bug that is not there, which is the same defect as one that answers what the backend
        // refuses.
        Comparison::In(list) => flatten_any(value, list, &operand)?,
        Comparison::NotIn(list) => !flatten_any(value, list, &operand)?,
        Comparison::Exists(want) => value.is_some() == *want,
        Comparison::All(list) => match value {
            Some(ParseValue::Array(items)) => list.iter().all(|wanted| {
                let wanted = interior_atom(wanted);
                items.iter().any(|item| deep_strict_eq(item, &wanted))
            }),
            _ => false,
        },
        Comparison::GreaterThan(bound) => order_matches(value, &operand(bound)?, |o| o > 0),
        Comparison::GreaterThanOrEqual(bound) => order_matches(value, &operand(bound)?, |o| o >= 0),
        Comparison::LessThan(bound) => order_matches(value, &operand(bound)?, |o| o < 0),
        Comparison::LessThanOrEqual(bound) => order_matches(value, &operand(bound)?, |o| o <= 0),
        // Not implemented rather than silently false. See the module note.
        Comparison::Regex { .. } => {
            return Err(ParseError::new(
                ErrorCode::CommandUnavailable,
                "the in-memory adapter does not implement $regex",
            ))
        }
    })
}

/// Does any element match, flattening one level first?
///
/// The set operators are the only place upstream flattens, and it is exactly one level: an element
/// that is itself an array contributes its own elements, and nothing deeper is unwrapped.
fn flatten_any(
    value: Option<&ParseValue>,
    list: &[ParseValue],
    operand: &dyn Fn(&ParseValue) -> Result<ParseValue, ParseError>,
) -> Result<bool, ParseError> {
    let mut any = false;
    for item in list {
        match item {
            ParseValue::Array(inner) => {
                for nested in inner {
                    any |= equals(value, &operand(nested)?);
                }
            }
            other => any |= equals(value, &operand(other)?),
        }
    }
    Ok(any)
}

/// Equality with Mongo's array and missing-field semantics, which the ACL clause depends on.
///
/// A missing field matches `null`, which is what keeps a row saved without an ACL readable. An
/// array field matches if any element does, which is what makes `_rperm: ["*"]` match.
fn equals(value: Option<&ParseValue>, expected: &ParseValue) -> bool {
    match value {
        None => matches!(expected, ParseValue::Null),
        Some(ParseValue::Array(items)) => {
            items.iter().any(|item| deep_strict_eq(item, expected))
                || deep_strict_eq(&ParseValue::Array(items.clone()), expected)
        }
        Some(actual) => deep_strict_eq(actual, expected),
    }
}

fn order_matches(
    value: Option<&ParseValue>,
    bound: &ParseValue,
    accept: impl Fn(i8) -> bool,
) -> bool {
    match compare(value, Some(bound)) {
        Some(ordering) => accept(ordering),
        None => false,
    }
}

/// A total-enough ordering for the value kinds a test sorts or ranges over.
fn compare(a: Option<&ParseValue>, b: Option<&ParseValue>) -> Option<i8> {
    let sign = |o: std::cmp::Ordering| match o {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    match (a?, b?) {
        (ParseValue::Number(x), ParseValue::Number(y)) => x.partial_cmp(y).map(sign),
        (ParseValue::String(x), ParseValue::String(y)) => Some(sign(x.cmp(y))),
        (ParseValue::Date(x), ParseValue::Date(y)) => Some(sign(x.to_iso().cmp(&y.to_iso()))),
        (ParseValue::Bool(x), ParseValue::Bool(y)) => Some(sign(x.cmp(y))),
        _ => None,
    }
}

fn project(row: &ParseMap, keys: &[String]) -> ParseMap {
    let mut out = ParseMap::new();
    for (key, value) in row {
        // `ACL` in a projection keeps the two storage columns, matching what the Mongo adapter
        // does when it lowers the key.
        let wanted = keys
            .iter()
            .any(|k| k == key || (k == "ACL" && (key == "_rperm" || key == "_wperm")));
        if wanted {
            out.insert(key.clone(), value.clone());
        }
    }
    out
}

fn apply_update(row: &mut ParseMap, update: &Update) {
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
            UpdateValue::Increment(amount) => {
                let current = match row.get(key) {
                    Some(ParseValue::Number(n)) => *n,
                    _ => 0.0,
                };
                row.insert(key.clone(), ParseValue::Number(current + amount));
            }
            UpdateValue::Add(items) => {
                let mut current = existing_array(row, key);
                current.extend(items.iter().cloned());
                row.insert(key.clone(), ParseValue::Array(current));
            }
            UpdateValue::AddUnique(items) => {
                let mut current = existing_array(row, key);
                for item in items {
                    if !current.iter().any(|c| deep_strict_eq(c, item)) {
                        current.push(item.clone());
                    }
                }
                row.insert(key.clone(), ParseValue::Array(current));
            }
            UpdateValue::Remove(items) => {
                let current = existing_array(row, key);
                row.insert(
                    key.clone(),
                    ParseValue::Array(
                        current
                            .into_iter()
                            .filter(|c| !items.iter().any(|item| deep_strict_eq(c, item)))
                            .collect(),
                    ),
                );
            }
        }
    }
}

fn existing_array(row: &ParseMap, key: &str) -> Vec<ParseValue> {
    match row.get(key) {
        Some(ParseValue::Array(items)) => items.clone(),
        _ => Vec::new(),
    }
}

impl StorageAdapter for FakeStorage {
    async fn all_schemas(&self) -> Result<Vec<ClassSchema>, ParseError> {
        Ok(self.locked()?.schemas.values().cloned().collect())
    }

    async fn insert_schema(&self, schema: &ClassSchema) -> Result<(), ParseError> {
        let mut inner = self.locked()?;
        if inner.schemas.contains_key(&schema.class_name) {
            return Err(ParseError::new(
                ErrorCode::DuplicateValue,
                "Class already exists.",
            ));
        }
        inner
            .schemas
            .insert(schema.class_name.clone(), schema.clone());
        Ok(())
    }

    async fn upsert_schema(&self, schema: &ClassSchema) -> Result<(), ParseError> {
        let mut inner = self.locked()?;
        match inner.schemas.get_mut(&schema.class_name) {
            Some(existing) => {
                for (name, ty) in &schema.fields {
                    existing.fields.entry(name.clone()).or_insert(ty.clone());
                }
                // Metadata is only replaced when it was supplied, matching the trait's rule that
                // an upsert must not clobber what it was not given.
                if schema.clp.is_some() {
                    existing.clp = schema.clp.clone();
                }
                if schema.indexes.is_some() {
                    existing.indexes = schema.indexes.clone();
                }
                if schema.field_options.is_some() {
                    existing.field_options = schema.field_options.clone();
                }
            }
            None => {
                inner
                    .schemas
                    .insert(schema.class_name.clone(), schema.clone());
            }
        }
        Ok(())
    }

    async fn reserve_field(
        &self,
        class_name: &str,
        field_name: &str,
        field_type: &FieldType,
        options: Option<&ParseMap>,
    ) -> Result<AddFieldOutcome, ParseError> {
        let mut inner = self.locked()?;
        let schema = inner
            .schemas
            .entry(class_name.to_string())
            .or_insert_with(|| ClassSchema::new(class_name));
        match schema.fields.get(field_name) {
            None => {
                schema
                    .fields
                    .insert(field_name.to_string(), field_type.clone());
                // In the same step as the type, matching the real adapter's single conditional
                // update rather than modelling it as a second write.
                if let Some(options) = options.filter(|o| !o.is_empty()) {
                    schema
                        .field_options
                        .get_or_insert_with(Default::default)
                        .insert(field_name.to_string(), ParseValue::Object(options.clone()));
                }
                Ok(AddFieldOutcome::Added)
            }
            Some(existing) if existing == field_type => Ok(AddFieldOutcome::AlreadyPresentSameType),
            Some(existing) => Ok(AddFieldOutcome::Conflict {
                existing: existing.clone(),
            }),
        }
    }

    async fn set_field_options(
        &self,
        class_name: &str,
        field_name: &str,
        options: &ParseMap,
    ) -> Result<(), ParseError> {
        let mut inner = self.locked()?;
        if let Some(schema) = inner.schemas.get_mut(class_name) {
            schema
                .field_options
                .get_or_insert_with(Default::default)
                .insert(field_name.to_string(), ParseValue::Object(options.clone()));
        }
        Ok(())
    }

    async fn set_indexes(&self, class_name: &str, indexes: &ParseMap) -> Result<(), ParseError> {
        let mut inner = self.locked()?;
        if let Some(schema) = inner.schemas.get_mut(class_name) {
            schema.indexes = Some(indexes.clone());
        }
        Ok(())
    }

    async fn set_class_permissions(
        &self,
        class_name: &str,
        clp: Option<&parse_rust_core::ClassLevelPermissions>,
    ) -> Result<(), ParseError> {
        let mut inner = self.locked()?;
        if let Some(schema) = inner.schemas.get_mut(class_name) {
            schema.clp = clp.cloned();
        }
        Ok(())
    }

    async fn delete_class(&self, schema: &ClassSchema) -> Result<(), ParseError> {
        let mut inner = self.locked()?;
        inner.schemas.shift_remove(&schema.class_name);
        inner.rows.shift_remove(&schema.class_name);
        Ok(())
    }

    async fn delete_fields(
        &self,
        schema: &ClassSchema,
        fields: &[String],
    ) -> Result<(), ParseError> {
        let mut inner = self.locked()?;
        if let Some(stored) = inner.schemas.get_mut(&schema.class_name) {
            for field in fields {
                stored.fields.shift_remove(field);
            }
        }
        if let Some(rows) = inner.rows.get_mut(&schema.class_name) {
            for row in rows {
                for field in fields {
                    row.shift_remove(field);
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
        let mut inner = self.locked()?;
        inner
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
        let mut inner = self.locked()?;
        let rows = inner.rows.entry(schema.class_name.clone()).or_default();
        for existing in rows.iter() {
            if matches(schema, existing, query)? {
                return Ok(());
            }
        }
        rows.push(row.clone());
        Ok(())
    }

    async fn find(
        &self,
        schema: &ClassSchema,
        query: &Query,
        options: &QueryOptions,
    ) -> Result<Vec<Row>, ParseError> {
        let inner = self.locked()?;
        let empty = Vec::new();
        let rows = inner.rows.get(&schema.class_name).unwrap_or(&empty);
        let mut out: Vec<ParseMap> = Vec::new();
        for row in rows {
            if matches(schema, row, query)? {
                out.push(row.clone());
            }
        }

        for (field, direction) in options.order.iter().rev() {
            out.sort_by(|a, b| {
                let ordering = compare(a.get(field), b.get(field)).unwrap_or(0);
                let ordering = match ordering {
                    o if o < 0 => std::cmp::Ordering::Less,
                    0 => std::cmp::Ordering::Equal,
                    _ => std::cmp::Ordering::Greater,
                };
                match direction {
                    SortDirection::Ascending => ordering,
                    SortDirection::Descending => ordering.reverse(),
                }
            });
        }

        if let Some(skip) = options.skip {
            out = out.into_iter().skip(skip as usize).collect();
        }
        if let Some(limit) = options.limit {
            out.truncate(limit as usize);
        }
        if let Some(keys) = &options.keys {
            out = out.iter().map(|row| project(row, keys)).collect();
        }
        Ok(out)
    }

    async fn count(&self, schema: &ClassSchema, query: &Query) -> Result<u64, ParseError> {
        let inner = self.locked()?;
        let empty = Vec::new();
        let rows = inner.rows.get(&schema.class_name).unwrap_or(&empty);
        let mut total = 0;
        for row in rows {
            if matches(schema, row, query)? {
                total += 1;
            }
        }
        Ok(total)
    }

    async fn update(
        &self,
        schema: &ClassSchema,
        query: &Query,
        update: &Update,
    ) -> Result<u64, ParseError> {
        let mut inner = self.locked()?;
        let Some(rows) = inner.rows.get_mut(&schema.class_name) else {
            return Ok(0);
        };
        let mut matched = 0;
        for row in rows.iter_mut() {
            if matches(schema, row, query)? {
                apply_update(row, update);
                matched += 1;
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
        let mut inner = self.locked()?;
        let Some(rows) = inner.rows.get_mut(&schema.class_name) else {
            return Ok(None);
        };
        for row in rows.iter_mut() {
            if matches(schema, row, query)? {
                apply_update(row, update);
                return Ok(Some(row.clone()));
            }
        }
        Ok(None)
    }

    async fn delete(&self, schema: &ClassSchema, query: &Query) -> Result<u64, ParseError> {
        let mut inner = self.locked()?;
        let Some(rows) = inner.rows.get_mut(&schema.class_name) else {
            return Ok(0);
        };
        let mut deleted = 0;
        let mut kept = Vec::with_capacity(rows.len());
        for row in rows.iter() {
            if matches(schema, row, query)? {
                deleted += 1;
            } else {
                kept.push(row.clone());
            }
        }
        *rows = kept;
        Ok(deleted)
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

    /// Recorded rather than ignored: the ordering rule this exists to protect is that the schema
    /// write happens after the index build, and a fake that forgets the call cannot show it.
    async fn create_indexes(
        &self,
        class_name: &str,
        indexes: &[SchemaIndex],
    ) -> Result<(), ParseError> {
        let mut built = self.indexes.lock().expect("lock");
        for index in indexes {
            built.push((class_name.to_string(), index.name.clone()));
        }
        Ok(())
    }

    async fn drop_index(&self, class_name: &str, name: &str) -> Result<(), ParseError> {
        self.indexes
            .lock()
            .expect("lock")
            .retain(|(c, n)| c != class_name || n != name);
        Ok(())
    }
}

#[cfg(test)]
mod mirror_tests {
    use super::*;

    /// **This adapter must refuse exactly what the Mongo lowering refuses.**
    ///
    /// A fake that is more permissive than the backend fails the same way as one that quietly
    /// answers "no rows": the test passes, and it measured a predicate production never executes.
    /// These are the two refusals `comparison_to_bson` applies in the top-level position, with the
    /// two different messages that come from its two throw sites.
    #[test]
    fn the_fake_refuses_the_non_atoms_the_backend_refuses() {
        let schema = ClassSchema::new("P")
            .with_field("meta", FieldType::Object)
            .with_field("tags", FieldType::Array);
        let row = ParseMap::new();
        let obj = || {
            let mut m = ParseMap::new();
            m.insert("a".into(), ParseValue::Number(1.0));
            ParseValue::Object(m)
        };
        let run = |field: &str, comparison: Comparison| {
            matches_constraint(
                &schema,
                &row,
                &Constraint {
                    field: field.into(),
                    comparison,
                },
            )
        };

        // Shorthand equality against a generic object.
        let err = run("meta", Comparison::Equal(obj())).expect_err("refused");
        assert_eq!(
            err.message,
            "You cannot use [object Object] as a query parameter."
        );
        // The same operand under an operator reaches the other throw site.
        let err = run("meta", Comparison::NotEqual(obj())).expect_err("refused");
        assert_eq!(err.message, r#"bad atom: {"a":1}"#);

        // The interior position has no refusal, so a dotted key compares whatever it was given.
        assert!(run("meta.a", Comparison::Equal(obj())).is_ok());
        // Nor does the `$all` wrap: a non-array value on an `Array` field is a containment test
        // through the interior transform, not a top-level equality.
        assert!(run("tags", Comparison::Equal(obj())).is_ok());
        // And the empty collections are answered before either.
        assert!(run(
            "meta",
            Comparison::Equal(ParseValue::Object(ParseMap::new()))
        )
        .is_ok());
        assert!(run("tags", Comparison::Equal(ParseValue::Array(Vec::new()))).is_ok());
    }

    /// **`$in` and `$nin` flatten one level, as the Mongo lowering does.**
    ///
    /// Measured against a server at the pin on a `Number` field holding `1`: `{"$in": [[1]]}`
    /// matches, `{"$in": [[1,2],3]}` matches rows 1, 2 and 3, and `{"$nin": [[1]]}` excludes it.
    /// Without the flatten this adapter tried to lower `[1]` as a top-level atom and refused with
    /// 107, so a pipeline test would have been measuring a refusal production never issues.
    #[test]
    fn the_set_operators_flatten_one_level() {
        let schema = ClassSchema::new("P").with_field("n", FieldType::Number);
        let mut row = ParseMap::new();
        row.insert("n".into(), ParseValue::Number(1.0));
        let run = |comparison: Comparison| {
            matches_constraint(
                &schema,
                &row,
                &Constraint {
                    field: "n".into(),
                    comparison,
                },
            )
        };
        let nested = |v: f64| ParseValue::Array(vec![ParseValue::Number(v)]);

        assert!(run(Comparison::In(vec![nested(1.0)])).expect("flattened"));
        assert!(!run(Comparison::In(vec![nested(2.0)])).expect("flattened"));
        assert!(!run(Comparison::NotIn(vec![nested(1.0)])).expect("flattened"));
        // A mix of nested and bare elements, which is the shape upstream's `flatMap` produces.
        assert!(run(Comparison::In(vec![
            ParseValue::Array(vec![ParseValue::Number(5.0), ParseValue::Number(1.0)]),
            ParseValue::Number(9.0),
        ]))
        .expect("flattened"));
        // Exactly one level: a doubly nested array is still an array at the atom position and is
        // refused, which is what production does with it.
        assert!(run(Comparison::In(vec![ParseValue::Array(vec![nested(1.0)])])).is_err());
    }

    /// Shorthand equality on an `Array` field takes the `$all` interior path, which recognizes a
    /// shorter tag list than the top-level one. Using top-level recognition here executes a
    /// different predicate from production.
    #[test]
    fn shorthand_equality_on_an_array_field_is_a_containment_test() {
        let schema = ClassSchema::new("P").with_field("tags", FieldType::Array);
        let mut row = ParseMap::new();
        row.insert(
            "tags".into(),
            ParseValue::Array(vec![ParseValue::String("a".into())]),
        );
        let run = |comparison: Comparison| {
            matches_constraint(
                &schema,
                &row,
                &Constraint {
                    field: "tags".into(),
                    comparison,
                },
            )
            .expect("lowers")
        };
        assert!(run(Comparison::Equal(ParseValue::String("a".into()))));
        assert!(!run(Comparison::Equal(ParseValue::String("b".into()))));
    }
}
