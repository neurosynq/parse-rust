//! The read and write pipelines.
//!
//! Generic over [`StorageAdapter`] rather than taking a `dyn`, so the storage boundary costs
//! nothing at runtime and a future Postgres adapter drops in by type rather than by trait object.
//!
//! Schema handling here is deliberately simple for 0.1.0: every call loads all schemas from the
//! adapter. Upstream caches instead, and caching is deferred here rather than skipped by
//! accident. When it lands, the staleness window is a decision to make deliberately and not a
//! tuning knob: a schema read from cache decides what a write may contain and what a caller may
//! see, so a tightened rule that has not propagated yet is still being enforced in its old,
//! looser form. Correctness and authorization are the same question here.

use parse_rust_core::{new_object_id, ErrorCode, ParseDate, ParseError, ParseMap, ParseValue};
use parse_rust_schema::{apply, default_schema, validate_write};
use parse_rust_storage::{ClassSchema, Constraint, QueryOptions, StorageAdapter};

use crate::acl::{lower_acl, raise_acl, AclScope};

/// What a create returns to the client: `{objectId, createdAt}` and nothing else.
#[derive(Debug, Clone)]
pub struct CreateResponse {
    pub object_id: String,
    pub created_at: ParseDate,
}

/// What an update returns: `{updatedAt}`.
#[derive(Debug, Clone)]
pub struct UpdateResponse {
    pub updated_at: ParseDate,
}

/// Load the schema for a class, or the default if the class does not exist yet.
async fn load_schema<S: StorageAdapter>(
    storage: &S,
    class_name: &str,
) -> Result<ClassSchema, ParseError> {
    let all = storage.all_schemas().await?;
    Ok(all
        .into_iter()
        .find(|s| s.class_name == class_name)
        .unwrap_or_else(|| default_schema(class_name)))
}

/// Create an object.
///
/// Order matters and is upstream's: validate the schema *before* writing, persist the schema
/// change only after the row commits. A schema applied before a failed write leaves a phantom
/// column that no later write can remove.
pub async fn create<S: StorageAdapter>(
    storage: &S,
    class_name: &str,
    body: ParseMap,
    scope: &AclScope,
) -> Result<CreateResponse, ParseError> {
    let mut schema = load_schema(storage, class_name).await?;

    // Signup pre-generates an objectId so it can build the user's private ACL before the write.
    // Honour one if it is already present rather than overwriting it, which would leave the ACL
    // pointing at an id the row does not have.
    let object_id = match body.get("objectId") {
        Some(ParseValue::String(id)) => id.clone(),
        _ => new_object_id(),
    };
    let now = ParseDate::now();

    let mut row = body;
    row.insert(
        "objectId".to_string(),
        ParseValue::String(object_id.clone()),
    );
    row.insert("createdAt".to_string(), ParseValue::Date(now));
    row.insert("updatedAt".to_string(), ParseValue::Date(now));

    let delta = validate_write(&schema, &row)?;

    // ACL is split into columns after validation, because `_rperm` and `_wperm` are not fields and
    // would otherwise be validated as though a client had named them.
    let stored = lower_acl(row);

    apply(&mut schema, &delta);
    storage.create(&schema, &stored).await?;
    if !delta.is_empty() {
        storage.upsert_schema(&schema).await?;
    }

    let _ = scope; // ACL does not gate creation; CLP would, and is out of scope for 0.1.0.
    Ok(CreateResponse {
        object_id,
        created_at: now,
    })
}

/// Find objects.
pub async fn find<S: StorageAdapter>(
    storage: &S,
    class_name: &str,
    mut constraints: Vec<Constraint>,
    options: QueryOptions,
    scope: &AclScope,
) -> Result<Vec<ParseMap>, ParseError> {
    let schema = load_schema(storage, class_name).await?;
    if let Some(acl) = scope.read_constraint() {
        constraints.push(acl);
    }
    let rows = storage.find(&schema, &constraints, &options).await?;
    Ok(rows.into_iter().map(raise_acl).collect())
}

/// Fetch one object by id.
///
/// A row the caller cannot read is `OBJECT_NOT_FOUND`, the same as one that does not exist.
/// Upstream conflates them deliberately: distinguishing them would tell an unauthorized caller
/// that the object exists.
pub async fn get<S: StorageAdapter>(
    storage: &S,
    class_name: &str,
    object_id: &str,
    scope: &AclScope,
) -> Result<ParseMap, ParseError> {
    let rows = find(
        storage,
        class_name,
        vec![Constraint::equal(
            "objectId",
            ParseValue::String(object_id.to_string()),
        )],
        QueryOptions {
            limit: Some(1),
            ..Default::default()
        },
        scope,
    )
    .await?;

    rows.into_iter().next().ok_or_else(object_not_found)
}

pub async fn count<S: StorageAdapter>(
    storage: &S,
    class_name: &str,
    mut constraints: Vec<Constraint>,
    scope: &AclScope,
) -> Result<u64, ParseError> {
    let schema = load_schema(storage, class_name).await?;
    if let Some(acl) = scope.read_constraint() {
        constraints.push(acl);
    }
    storage.count(&schema, &constraints).await
}

/// Update one object by id.
pub async fn update<S: StorageAdapter>(
    storage: &S,
    class_name: &str,
    object_id: &str,
    body: ParseMap,
    scope: &AclScope,
) -> Result<UpdateResponse, ParseError> {
    let mut schema = load_schema(storage, class_name).await?;

    let now = ParseDate::now();
    let mut row = body;
    // A client cannot move an object or rewrite its creation time.
    row.shift_remove("objectId");
    row.shift_remove("createdAt");
    row.insert("updatedAt".to_string(), ParseValue::Date(now));

    let delta = validate_write(&schema, &row)?;
    let values = lower_acl(row);

    let mut constraints = vec![Constraint::equal(
        "objectId",
        ParseValue::String(object_id.to_string()),
    )];
    if let Some(acl) = scope.write_constraint() {
        constraints.push(acl);
    }

    apply(&mut schema, &delta);
    let matched = storage.update(&schema, &constraints, &values).await?;
    if matched == 0 {
        return Err(object_not_found());
    }
    if !delta.is_empty() {
        storage.upsert_schema(&schema).await?;
    }

    Ok(UpdateResponse { updated_at: now })
}

/// Delete one object by id.
pub async fn delete<S: StorageAdapter>(
    storage: &S,
    class_name: &str,
    object_id: &str,
    scope: &AclScope,
) -> Result<(), ParseError> {
    let schema = load_schema(storage, class_name).await?;
    let mut constraints = vec![Constraint::equal(
        "objectId",
        ParseValue::String(object_id.to_string()),
    )];
    if let Some(acl) = scope.write_constraint() {
        constraints.push(acl);
    }
    let deleted = storage.delete(&schema, &constraints).await?;
    if deleted == 0 {
        return Err(object_not_found());
    }
    Ok(())
}

/// The error both "does not exist" and "you cannot see it" produce.
fn object_not_found() -> ParseError {
    ParseError::new(ErrorCode::ObjectNotFound, "Object not found.")
}
